#include "store/SqliteStore.h"
#include "store/CallSignalling.h"
#include "store/MediaReferences.h"
#include "auth/LocalAuth.h"
#include "core/Logger.h"
#include "identity/Localpart.h"
#include "store/Migrations.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <set>
#include <stdexcept>
#include <unordered_set>

// For tightening the mode on the database file. POSIX-only, which matches the
// only platforms the server is deployed on; the Windows build of the server is
// not a supported target.
#include <sys/stat.h>
#include <sys/types.h>

namespace bsfchat {

namespace {

struct StmtDeleter {
    void operator()(sqlite3_stmt* stmt) {
        if (stmt) sqlite3_finalize(stmt);
    }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

StmtPtr prepare(sqlite3* db, const std::string& sql) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("SQL prepare error: ") + sqlite3_errmsg(db) + " [" + sql + "]");
    }
    return StmtPtr(stmt);
}

// ── Timeline reads and edit reconciliation ────────────────────────────────
//
// Every timeline read selects the same columns in the same order and goes
// through read_event_row(), so no read path can quietly skip edit resolution
// the way they all used to: the server stored an m.replace as a sibling event
// and then returned the PRE-EDIT content forever.
//
// STATE reads (get_state_events, get_state_event) are the exception and build
// their own RoomEvent: they resolve the current value of one (type, state_key)
// and an m.replace never targets a state event, so edit resolution would be
// dead code there. Anything that must apply to EVERY event a client receives —
// stamp_bot_flag() is the current example — therefore has to be applied in
// three places, not one. Check both when adding another.
//
// Column order: 0 event_id, 1 room_id, 2 sender, 3 event_type, 4 state_key,
// 5 content, 6 origin_server_ts, then the winning replacement (if any):
// 7 rep.event_id, 8 rep.sender, 9 rep.origin_server_ts, 10 rep.content.
// Queries that also need the stream position append it as column 11.
constexpr const char* kEventColumns =
    "e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content, "
    "e.origin_server_ts, rep.event_id, rep.sender, rep.origin_server_ts, rep.content";

// A replacement that has itself been redacted must not win, hence the
// redacted_by guard; redact_event() additionally re-points the target at the
// newest surviving replacement.
constexpr const char* kEditJoin =
    " LEFT JOIN events rep ON rep.event_id = e.edited_by AND rep.redacted_by IS NULL ";

const char* column_text_or_empty(sqlite3_stmt* stmt, int col) {
    auto* p = sqlite3_column_text(stmt, col);
    return p ? reinterpret_cast<const char*>(p) : "";
}

// Wall clock in milliseconds, for the tables that timestamp their rows in C++
// rather than with a SQL default: audit_log (whose caller may supply the exact
// timestamp of the action being recorded) and consumed_refresh_tokens (whose
// retention window is compared against the same millisecond clock the token
// expiries use, not a second-granular SQL default).
int64_t audit_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// The content a replacement event contributes. Matrix puts the authoritative
// version in `m.new_content`; the top-level body is only a "* edited text"
// fallback for clients that predate edits, so it is used only if
// `m.new_content` is absent, with the conventional prefix stripped.
nlohmann::json replacement_content(const nlohmann::json& rep_content) {
    if (!rep_content.is_object()) return nlohmann::json();
    auto it = rep_content.find("m.new_content");
    if (it != rep_content.end() && it->is_object()) return *it;

    nlohmann::json fallback = rep_content;
    fallback.erase("m.relates_to");
    if (fallback.contains("body") && fallback["body"].is_string()) {
        auto body = fallback["body"].get<std::string>();
        if (body.rfind("* ", 0) == 0) fallback["body"] = body.substr(2);
    }
    return fallback;
}

// The event id an m.replace replacement targets, or nullopt for anything else.
// Parsed in C++ rather than with json_extract() for the same reason the
// migration does: the path would be `$."m.relates_to".event_id`, and quoted
// JSON path labels only parse on recent SQLite builds.
std::optional<std::string> replacement_target(const std::string& content_json) {
    auto j = nlohmann::json::parse(content_json, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    auto it = j.find("m.relates_to");
    if (it == j.end() || !it->is_object()) return std::nullopt;
    if (it->value("rel_type", "") != "m.replace") return std::nullopt;
    auto target = it->value("event_id", "");
    if (target.empty()) return std::nullopt;
    return target;
}

// Stamps `bsfchat.bot` onto an m.room.member event's content, DERIVED from the
// member's user id rather than read back from what was stored.
//
// Why derived and not stored. The obvious alternative is to write the key in
// member_event_content() when the event is emitted, and backfill the existing
// ones with a migration — which is what v18 did for is_direct. That is the wrong
// shape here, for three reasons:
//
//   * It would be a MIRROR of an account fact into room state, and Nickname.h
//     already documents where that leads: a value that lives in room state is
//     silently reverted by whichever unrelated path next rewrites a member event.
//     Bot-ness happens to be immutable today, so a mirror would not actually
//     drift — but it would be one more thing that has to STAY immutable for the
//     roster to keep telling the truth, and nothing would notice if it stopped.
//   * A backfill only fixes the events that exist when it runs. Every member
//     event written by a path that builds content by hand — handle_invite for a
//     human, project_membership_everywhere for a kick or ban — would still be
//     missing the key, and those paths have no reason to know about bots.
//   * Derivation needs no migration and costs no query: the member's id IS the
//     state_key, already in hand, and bot::is_bot_user_id is a constexpr prefix
//     test. Doing it from users.kind instead would be a database read per member
//     event, under the store's global mutex, on the initial-sync path.
//
// SET-OR-ERASE, not set-if-bot. Whatever the stored content says is replaced by
// the server's own answer, so a forged "bsfchat.bot": true cannot survive a read
// even if some future write path lets one be stored. Today it cannot be stored
// at all (handle_set_state rebuilds self-membership content through
// member_event_content and discards the client's body), which makes this the
// second lock rather than the only one.
//
// Absent means "not a bot", matching /profile and /whoami — a client reads it as
// content.value("bsfchat.bot", false) on all three.
//
// Applied to every membership, including leave and ban, unlike displayname and
// nickname. Those are omitted for a departing member because they are profile
// data the event does not need and that a client would cache from a forged
// value. This is neither: it is a fact about the user id already in the
// state_key, so a client could compute it itself and nothing is disclosed by
// stating it.
void stamp_bot_flag(RoomEvent& ev) {
    if (ev.type != event_type::kRoomMember) return;
    if (!ev.state_key.has_value()) return;
    if (!ev.content.data.is_object()) return;

    const std::string key{bot::kProfileKey};
    if (bot::is_bot_user_id(*ev.state_key)) {
        ev.content.data[key] = true;
    } else {
        ev.content.data.erase(key);
    }
}

RoomEvent read_event_row_raw(sqlite3_stmt* stmt) {
    RoomEvent ev;
    ev.event_id = column_text_or_empty(stmt, 0);
    ev.room_id = column_text_or_empty(stmt, 1);
    ev.sender = column_text_or_empty(stmt, 2);
    ev.type = column_text_or_empty(stmt, 3);
    if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) {
        ev.state_key = column_text_or_empty(stmt, 4);
    }
    ev.content.data = nlohmann::json::parse(column_text_or_empty(stmt, 5), nullptr, false);
    if (ev.content.data.is_discarded()) ev.content.data = nlohmann::json::object();
    ev.origin_server_ts = sqlite3_column_int64(stmt, 6);

    if (sqlite3_column_type(stmt, 7) == SQLITE_NULL) return ev; // not edited
    auto rep_content = nlohmann::json::parse(column_text_or_empty(stmt, 10), nullptr, false);
    auto new_content = replacement_content(rep_content);
    if (!new_content.is_object() || new_content.empty()) return ev;

    // An edited reply must keep pointing at what it replied to. m.new_content
    // carries no relation of its own, so the original's survives.
    if (!new_content.contains("m.relates_to") && ev.content.data.is_object()) {
        auto rel = ev.content.data.find("m.relates_to");
        if (rel != ev.content.data.end()) new_content["m.relates_to"] = *rel;
    }

    // Spec-shaped bundled aggregation: the original keeps its identity and the
    // replacement stays discoverable (it is also still an ordinary event in the
    // timeline). `bsfchat.original_content` is our own addition — it lets a
    // client render edit history faithfully without having to have been
    // connected when the edit happened.
    nlohmann::json unsigned_data = nlohmann::json::object();
    unsigned_data["m.relations"]["m.replace"] = {
        {"event_id", column_text_or_empty(stmt, 7)},
        {"sender", column_text_or_empty(stmt, 8)},
        {"origin_server_ts", sqlite3_column_int64(stmt, 9)},
    };
    unsigned_data["bsfchat.original_content"] = ev.content.data;
    ev.unsigned_data = EventContent{.data = std::move(unsigned_data)};
    ev.content.data = std::move(new_content);
    return ev;
}

// The read choke point proper: raw row, then the derived fields.
//
// Wrapped rather than stamped inline because read_event_row_raw has several
// returns and one of them replaces content.data wholesale with the edit's
// content. Stamping inside it would be correct only for whichever return the
// author happened to think about — here it is correct for all of them, by
// construction, and stays correct if another branch is added.
RoomEvent read_event_row(sqlite3_stmt* stmt) {
    RoomEvent ev = read_event_row_raw(stmt);
    stamp_bot_flag(ev);
    return ev;
}

} // namespace

SqliteStore::SqliteStore(const std::string& db_path) : db_path_(db_path) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error(std::string("Failed to open database: ") + sqlite3_errmsg(db_));
    }
    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA foreign_keys=ON");
    exec("PRAGMA busy_timeout=5000");

    // Overwrite deleted content instead of just returning its pages to the
    // freelist. Without this, "deleted" is a bookkeeping change only: the bytes
    // stay in the file until some later insert happens to reuse that page, and
    // `strings bsfchat.db` recovers them in the meantime. Three of our deletes
    // are deletes of secrets and exist precisely so the data stops existing:
    //
    //   * migration v7 dropped the pre-hash `access_tokens` table, which held
    //     bearer tokens in plaintext;
    //   * redaction rewrites `content` to '{}', which frees the old body;
    //   * the recurring call-signalling prune (and migration v17's one-time
    //     purge) deletes rows *because* they carry participants' LAN and public
    //     IP addresses.
    //
    // A logical delete finishes none of those jobs. This pragma is per
    // connection rather than a property of the file, so it has to be set on
    // every open — do not move it into a migration.
    //
    // Cost: SQLite zeroes the freed region on the page before writing it back,
    // so deletes do more work and dirty more pages. For this workload — where
    // deletes are rare and small next to the message insert path — that is not
    // measurable, and it is the correct trade for the three cases above.
    //
    // This only governs deletes from here on. Pages already on the freelist
    // still hold their old contents; `vacuum_freelist_once_locked()` below
    // deals with those, once.
    exec("PRAGMA secure_delete=ON");

    restrict_database_file_mode();
}

SqliteStore::~SqliteStore() {
    if (db_) sqlite3_close(db_);
}

void SqliteStore::exec(const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("SQL exec error: " + msg);
    }
}

namespace {

// True for the forms sqlite3_open() treats as "no file on disk", where there is
// nothing to chmod and stat() would fail for an uninteresting reason.
bool is_in_memory_path(const std::string& path) {
    return path.empty() || path == ":memory:" || path.rfind("file::memory:", 0) == 0 ||
           path.find("mode=memory") != std::string::npos;
}

} // namespace

// The database is the most sensitive file this process owns: every message
// body, a second full copy of each body in the search index, queued push
// payloads and the audit log, all in plaintext. Nothing in the server, the
// image or deploy/setup.sh ever set a mode on it, so it was created at the
// process umask — 0644 in the shipped container — and readable by every local
// user. On the current production host the parent directory happens to be under
// /root, and that accident is the only thing that was protecting it.
//
// So take the mode away here rather than relying on the deployment to do it:
// the server is the one component that is present in every install, however the
// operator laid the host out.
//
// The group and other bits are stripped rather than the mode being set to a
// fixed 0600, because the owner bits are not ours to decide and stripping can
// only ever remove access. It does mean a deliberately group-readable database
// (say, for a backup user) is narrowed on the next start — that is intended;
// run backups as the owning user, or as root, and see deploy/backup.sh.
//
// -wal and -shm get the same treatment. SQLite copies the main file's mode onto
// them when it creates them, but they can predate this code, and an operator's
// own chmod of the database usually misses them.
void SqliteStore::restrict_database_file_mode() {
    if (is_in_memory_path(db_path_)) return;

    for (const char* suffix : {"", "-wal", "-shm"}) {
        const std::string path = db_path_ + suffix;
        struct stat st {};
        if (::stat(path.c_str(), &st) != 0) continue; // not created yet, or not ours to see
        const mode_t current = st.st_mode & 07777;
        const mode_t wanted = current & ~static_cast<mode_t>(S_IRWXG | S_IRWXO);
        if (current == wanted) continue;
        if (::chmod(path.c_str(), wanted) == 0) {
            get_logger()->info("Tightened mode on {} from {:04o} to {:04o} (owner only)", path,
                               current, wanted);
        } else {
            // Not fatal: a read-only bind mount or a file owned by another uid
            // is a deployment choice, not a reason to refuse to start. But say
            // so, because the operator is now relying on the directory.
            get_logger()->warn(
                "Could not restrict {} to owner-only access (mode is {:04o}). Every local user "
                "on this host can read every message, the search index and the audit log. Fix "
                "the ownership of the data directory, or chmod it yourself.",
                path, current);
        }
    }
}

// PRAGMA secure_delete stops NEW deletes from leaving their bytes behind. It
// does nothing about what is already on the freelist, and on any database that
// predates this change that freelist is the interesting part: dropped plaintext
// access tokens (migration v7), pre-redaction message bodies, and the ICE
// candidates that migration v17 deleted specifically because they carry
// participants' IP addresses. VACUUM rewrites the file from the live pages
// only, so the freelist — and everything in it — is gone afterwards.
//
// Once, not on every start: VACUUM rewrites the entire database and needs room
// for a second copy of it while it runs, which is not something to do at every
// restart for no gain. The marker lives in server_meta rather than being tied to
// a schema version because it is a property of the FILE, not of the schema, and
// because an operator who needs to skip it (a database too large for the disk
// headroom, say) can set the marker by hand:
//
//   INSERT OR REPLACE INTO server_meta (key, value)
//     VALUES ('maintenance.freelist_vacuumed', '1');
//
// Caller must hold mutex_, and must not be inside a transaction: SQLite refuses
// to VACUUM within one. That is why this runs after run_migrations() returns
// rather than as a migration step.
void SqliteStore::vacuum_freelist_once_locked(bool fresh_database) {
    bool already_done = false;
    {
        auto stmt = prepare(
            db_, "SELECT value FROM server_meta WHERE key = 'maintenance.freelist_vacuumed'");
        already_done = sqlite3_step(stmt.get()) == SQLITE_ROW;
    }
    if (already_done) return;

    const auto mark_done = [&] {
        exec("INSERT OR REPLACE INTO server_meta (key, value) "
             "VALUES ('maintenance.freelist_vacuumed', '1')");
    };

    // A database this server created has never held any of the above, so there
    // is nothing to shred. Record it as done so the check is a single indexed
    // lookup on every subsequent start.
    if (fresh_database) {
        mark_done();
        return;
    }

    int64_t free_pages = 0;
    int64_t page_size = 0;
    {
        auto stmt = prepare(db_, "PRAGMA freelist_count");
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) free_pages = sqlite3_column_int64(stmt.get(), 0);
    }
    {
        auto stmt = prepare(db_, "PRAGMA page_size");
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) page_size = sqlite3_column_int64(stmt.get(), 0);
    }

    get_logger()->info(
        "One-time VACUUM: rewriting the database to discard {} free pages ({} KiB) that may still "
        "contain deleted tokens, redacted message text and purged call-signalling IP addresses. "
        "This runs once. Startup will pause until it finishes; do not interrupt it.",
        free_pages, (free_pages * page_size) / 1024);

    const auto started = std::chrono::steady_clock::now();
    try {
        exec("VACUUM");
    } catch (const std::exception& e) {
        // Almost always "database or disk is full" — VACUUM needs headroom for a
        // second copy. Leaving the marker unset means the next start retries,
        // which is what an operator who frees up disk would expect.
        get_logger()->error(
            "One-time VACUUM failed: {}. Deleted secrets remain recoverable from free pages in "
            "this database file. VACUUM needs free disk space roughly equal to the database "
            "size; free some and restart, or run `sqlite3 <db> VACUUM` yourself. Starting anyway.",
            e.what());
        return;
    }
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                              started);

    mark_done();
    get_logger()->info("One-time VACUUM finished in {} ms.", elapsed.count());

    // VACUUM writes a brand new file and moves it into place, so whatever mode
    // we set at open is not necessarily the mode of the file that is there now.
    restrict_database_file_mode();

    get_logger()->warn(
        "VACUUM has cleaned this database, but any EXISTING BACKUP still contains the deleted "
        "plaintext access tokens, pre-redaction message bodies and purged IP addresses. Rotate "
        "old backups out; see 'Backup and restore' in deploy/README.md.");
}

void SqliteStore::initialize() {
    std::lock_guard lock(mutex_);

    // Detect "brand new database" BEFORE creating anything, so migrations can
    // skip the one-time data repairs that only apply to legacy deployments.
    bool fresh_database = true;
    {
        auto stmt = prepare(db_,
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'");
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            fresh_database = sqlite3_column_int(stmt.get(), 0) == 0;
        }
    }

    exec(R"(
        CREATE TABLE IF NOT EXISTS users (
            user_id         TEXT PRIMARY KEY,
            password_hash   TEXT NOT NULL,
            display_name    TEXT,
            avatar_url      TEXT,
            created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");

    // NOTE: this is the ORIGINAL access_tokens shape and is deliberately left
    // as-is. Migration v7 replaces it with the hashed/expiring table — a fresh
    // database gets this one and then immediately has it rebuilt, and an
    // already-migrated database ignores this statement because a table of that
    // name exists. Do not "fix" it to match the current schema: that is exactly
    // the trap the migration runner exists to avoid.
    exec(R"(
        CREATE TABLE IF NOT EXISTS access_tokens (
            token       TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(user_id),
            device_id   TEXT NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS rooms (
            room_id     TEXT PRIMARY KEY,
            creator     TEXT NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS room_members (
            room_id     TEXT NOT NULL REFERENCES rooms(room_id),
            user_id     TEXT NOT NULL,
            membership  TEXT NOT NULL DEFAULT 'join',
            updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (room_id, user_id)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS events (
            event_id            TEXT PRIMARY KEY,
            room_id             TEXT NOT NULL REFERENCES rooms(room_id),
            sender              TEXT NOT NULL,
            event_type          TEXT NOT NULL,
            state_key           TEXT,
            content             TEXT NOT NULL,
            origin_server_ts    INTEGER NOT NULL,
            stream_position     INTEGER NOT NULL UNIQUE
        )
    )");

    exec("CREATE INDEX IF NOT EXISTS idx_events_room_stream ON events(room_id, stream_position)");
    exec("CREATE INDEX IF NOT EXISTS idx_events_room_type_state ON events(room_id, event_type, state_key) WHERE state_key IS NOT NULL");
    exec("CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id, membership)");

    exec(R"(
        CREATE TABLE IF NOT EXISTS read_markers (
            user_id         TEXT NOT NULL,
            room_id         TEXT NOT NULL,
            last_read_pos   INTEGER NOT NULL,
            PRIMARY KEY (user_id, room_id)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS media (
            media_id        TEXT PRIMARY KEY,
            uploader        TEXT NOT NULL,
            content_type    TEXT NOT NULL,
            filename        TEXT,
            file_size       INTEGER NOT NULL,
            file_path       TEXT NOT NULL,
            created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");

    // Versioned migrations for everything added after the original schema.
    // Anything new belongs in Migrations.cpp, NOT above — `CREATE TABLE IF NOT
    // EXISTS` silently does nothing on an existing deployment, so a column
    // added to a block above would never appear there.
    run_migrations(db_, fresh_database);

    // After the migrations and outside any transaction — see the function.
    vacuum_freelist_once_locked(fresh_database);

    // Load the monotonic stream counter, never letting it go backwards past
    // what the events table already contains (covers a database last written
    // by a build that derived positions from MAX(stream_position) + 1).
    {
        int64_t from_meta = 0;
        auto stmt = prepare(db_,
            "SELECT CAST(value AS INTEGER) FROM server_meta WHERE key = 'next_stream_position'");
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) from_meta = sqlite3_column_int64(stmt.get(), 0);

        auto max_stmt = prepare(db_, "SELECT COALESCE(MAX(stream_position), 0) + 1 FROM events");
        sqlite3_step(max_stmt.get());
        int64_t from_events = sqlite3_column_int64(max_stmt.get(), 0);

        next_stream_position_ = std::max<int64_t>({1, from_meta, from_events});
    }
    {
        auto stmt = prepare(db_,
            "INSERT INTO server_meta (key, value) VALUES ('next_stream_position', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
        auto v = std::to_string(next_stream_position_);
        sqlite3_bind_text(stmt.get(), 1, v.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt.get());
    }
}

// Users

bool SqliteStore::create_user(const std::string& user_id, const std::string& password_hash) {
    // The skeleton is derived HERE rather than passed in, so that no caller can
    // create an account that is invisible to the lookalike check by forgetting
    // to compute one. A row with a stale or empty skeleton is not a cosmetic
    // defect: it is an account nobody can be warned about.
    //
    // A user id that will not parse falls back to folding the whole string. It
    // cannot then collide with a real localpart's skeleton — `@` and `:` are
    // outside the registration charset — which is the right failure: unparseable
    // in, unmatchable out.
    auto parsed = UserId::parse(user_id);
    const std::string skeleton = localpart_skeleton(parsed ? parsed->localpart : user_id);

    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "INSERT OR IGNORE INTO users (user_id, password_hash, "
                             "localpart_skeleton) VALUES (?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, skeleton.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

std::optional<std::string>
SqliteStore::find_user_by_localpart_skeleton(const std::string& skeleton) {
    // An empty skeleton would match every row the column's default left behind,
    // so it is never a question worth asking. handle_register refuses a
    // username that folds to nothing before it gets here.
    if (skeleton.empty()) return std::nullopt;
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT user_id FROM users WHERE localpart_skeleton = ? LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, skeleton.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return column_text_or_empty(stmt.get(), 0);
    }
    return std::nullopt;
}

SqliteStore::SkeletonCollisions SqliteStore::count_localpart_skeleton_collisions() {
    std::lock_guard lock(mutex_);
    SkeletonCollisions out;
    {
        auto stmt = prepare(db_,
            "SELECT COUNT(*) FROM (SELECT 1 FROM users WHERE localpart_skeleton <> '' "
            "                       GROUP BY localpart_skeleton HAVING COUNT(*) > 1)");
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) out.groups = sqlite3_column_int(stmt.get(), 0);
    }
    {
        auto stmt = prepare(db_,
            "SELECT COUNT(*) FROM users WHERE localpart_skeleton <> '' "
            "   AND localpart_skeleton IN (SELECT localpart_skeleton FROM users "
            "                               WHERE localpart_skeleton <> '' "
            "                               GROUP BY localpart_skeleton HAVING COUNT(*) > 1)");
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            out.accounts = sqlite3_column_int(stmt.get(), 0);
        }
    }
    return out;
}

void SqliteStore::update_password_hash(const std::string& user_id, const std::string& password_hash) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE users SET password_hash = ? WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::optional<std::string> SqliteStore::get_password_hash(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    // `kind = 'user'` is load-bearing, not a tidy-up. It is what makes "a bot can
    // never log in with a password" a property of the schema rather than a check
    // somebody has to remember to write. See the header for the full reasoning.
    auto stmt = prepare(db_,
        "SELECT password_hash FROM users WHERE user_id = ? AND kind = 'user'");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

bool SqliteStore::user_exists(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM users WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

bool SqliteStore::username_exists(const std::string& localpart) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM users WHERE user_id LIKE '@' || ? || ':%'");
    sqlite3_bind_text(stmt.get(), 1, localpart.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

// Linked identity-provider identities

std::optional<std::string> SqliteStore::find_linked_user(const std::string& issuer,
                                                          const std::string& subject) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT user_id FROM linked_identities WHERE issuer = ? AND subject = ?");
    sqlite3_bind_text(stmt.get(), 1, issuer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, subject.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

bool SqliteStore::link_identity(const std::string& issuer, const std::string& subject,
                                 const std::string& user_id, const std::string& linked_by,
                                 int64_t when_ms) {
    std::lock_guard lock(mutex_);
    // Plain INSERT: no ON CONFLICT clause, and that omission is the point. An
    // upsert here would silently re-point an identity that is already linked
    // at whichever account asked last, which is the one operation this feature
    // must never perform — the losing account would keep its roles and history
    // while quietly losing the only way its owner signs in.
    auto stmt = prepare(db_,
        "INSERT OR IGNORE INTO linked_identities "
        "(issuer, subject, user_id, linked_at, linked_by) VALUES (?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, issuer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, subject.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 4, when_ms);
    sqlite3_bind_text(stmt.get(), 5, linked_by.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to link identity: ") + sqlite3_errmsg(db_));
    }
    // sqlite3_changes(), not a preceding SELECT: whichever of two racing
    // callers actually inserted the row is the one told it succeeded, and the
    // other gets false and reports the conflict.
    return sqlite3_changes(db_) > 0;
}

std::vector<SqliteStore::LinkedIdentity>
SqliteStore::list_linked_identities(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT issuer, subject, user_id, linked_at, linked_by FROM linked_identities "
        "WHERE user_id = ? ORDER BY linked_at ASC");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    std::vector<LinkedIdentity> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        LinkedIdentity row;
        row.issuer = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        row.subject = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        row.user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        row.linked_at = sqlite3_column_int64(stmt.get(), 3);
        row.linked_by = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        out.push_back(std::move(row));
    }
    return out;
}

// Access tokens
//
// Only SHA-256 digests of tokens ever reach the database; see
// hash_access_token() in auth/LocalAuth.h for why a fast hash is the right
// choice for a 256-bit random bearer secret that must be looked up by index on
// every request.

void SqliteStore::store_access_token(const std::string& token, const std::string& user_id,
                                      const std::string& device_id, int64_t lifetime_ms,
                                      const std::optional<std::string>& refresh_token,
                                      const std::string& family_id) {
    if (lifetime_ms <= 0) lifetime_ms = kDefaultAccessTokenLifetimeMs;
    std::lock_guard lock(mutex_);
    // Timestamps come from the C++ clock, not strftime('%s','now') * 1000: the
    // latter is only second-granular, so expiry maths would be up to a second
    // out of step with the millisecond `now` that get_user_by_token compares
    // against.
    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto stmt = prepare(db_,
        "INSERT INTO access_tokens "
        "  (token_hash, user_id, device_id, created_at, expires_at, last_used_at, "
        "   lifetime_ms, refresh_hash, family_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    auto token_hash = hash_access_token(token);
    sqlite3_bind_text(stmt.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, device_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 4, now);
    sqlite3_bind_int64(stmt.get(), 5, now + lifetime_ms);
    sqlite3_bind_int64(stmt.get(), 6, now);
    sqlite3_bind_int64(stmt.get(), 7, lifetime_ms);
    std::string refresh_hash;
    if (refresh_token && !refresh_token->empty()) {
        refresh_hash = hash_access_token(*refresh_token);
        sqlite3_bind_text(stmt.get(), 8, refresh_hash.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt.get(), 8);
    }
    // A login with no family yet starts one. Generated rather than derived
    // from the token so that the id survives every rotation unchanged — that
    // persistence is the whole point of it.
    const std::string family = family_id.empty() ? generate_access_token() : family_id;
    sqlite3_bind_text(stmt.get(), 9, family.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to store access token: ") + sqlite3_errmsg(db_));
    }
}

std::optional<std::string> SqliteStore::get_user_by_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto token_hash = hash_access_token(token);

    std::string user_id;
    int64_t expires_at = 0;
    int64_t lifetime_ms = kDefaultAccessTokenLifetimeMs;
    int64_t last_used_at = 0;  // NULL reads as 0 = "never", which is what we want
    {
        auto stmt = prepare(db_,
            "SELECT user_id, expires_at, lifetime_ms, COALESCE(last_used_at, 0) "
            "FROM access_tokens WHERE token_hash = ?");
        sqlite3_bind_text(stmt.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
        user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        expires_at = sqlite3_column_int64(stmt.get(), 1);
        lifetime_ms = sqlite3_column_int64(stmt.get(), 2);
        last_used_at = sqlite3_column_int64(stmt.get(), 3);
    }

    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // lifetime_ms == 0 means "this credential does not expire", and the only
    // thing that writes such a row is rotate_bot_token(). It is separated out
    // here rather than being expressed as a far-future expires_at, because a
    // sentinel date is a thing a future reader has to recognise, whereas "no
    // lifetime, therefore no expiry and no slide" says what it means.
    //
    // Why a bot token must not expire: the 90-day slide assumes there is a human
    // who can log in again when a session lapses. A bot has none. An expiring bot
    // token is an integration that stops working on a date nobody wrote down,
    // with a 401 as its only explanation. Rotation and revocation are how a bot
    // credential ends, and both are explicit operator actions.
    if (lifetime_ms > 0) {
        if (expires_at <= now) {
            // Reap it rather than leaving a dead row to be re-checked forever.
            auto del = prepare(db_, "DELETE FROM access_tokens WHERE token_hash = ?");
            sqlite3_bind_text(del.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(del.get());
            return std::nullopt;
        }

        // Sliding renewal. Only written once the session is past the halfway
        // point of its lifetime, so an ordinary request burst costs no writes: a
        // client polling /sync stays logged in indefinitely, while a token nobody
        // uses still dies at its expiry.
        if ((expires_at - now) < lifetime_ms / 2) {
            auto upd = prepare(db_,
                "UPDATE access_tokens SET expires_at = ?, last_used_at = ? WHERE token_hash = ?");
            sqlite3_bind_int64(upd.get(), 1, now + lifetime_ms);
            sqlite3_bind_int64(upd.get(), 2, now);
            sqlite3_bind_text(upd.get(), 3, token_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(upd.get());
        }
    } else if (last_used_at + kBotLastSeenIntervalMs <= now) {
        // A non-expiring token never slides, so it would otherwise never record
        // that it was used — and "when did this bot last do anything" is the
        // first question asked about a bot that has gone quiet, and the only way
        // to find the integrations nobody has decommissioned.
        //
        // Throttled for exactly the reason the slide above is: a busy bot makes
        // many requests a second, and a write on each one would put the store's
        // global mutex on the hot path of every authenticated request it makes.
        // The cost of the throttle is that last_seen_at is coarse, which is fine
        // — nobody needs it to the millisecond.
        auto upd = prepare(db_,
            "UPDATE access_tokens SET last_used_at = ? WHERE token_hash = ?");
        sqlite3_bind_int64(upd.get(), 1, now);
        sqlite3_bind_text(upd.get(), 2, token_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(upd.get());
    }

    return user_id;
}

std::optional<int64_t> SqliteStore::get_token_expiry(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto token_hash = hash_access_token(token);
    auto stmt = prepare(db_, "SELECT expires_at FROM access_tokens WHERE token_hash = ?");
    sqlite3_bind_text(stmt.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    return sqlite3_column_int64(stmt.get(), 0);
}

void SqliteStore::delete_access_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto token_hash = hash_access_token(token);
    auto stmt = prepare(db_, "DELETE FROM access_tokens WHERE token_hash = ?");
    sqlite3_bind_text(stmt.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

int SqliteStore::delete_all_tokens_for_user(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM access_tokens WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return sqlite3_changes(db_);
}

int SqliteStore::delete_other_tokens_for_user(const std::string& user_id,
                                              const std::string& keep_token) {
    std::lock_guard lock(mutex_);
    auto keep_hash = hash_access_token(keep_token);
    auto stmt = prepare(db_,
        "DELETE FROM access_tokens WHERE user_id = ? AND token_hash != ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, keep_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return sqlite3_changes(db_);
}

std::optional<SqliteStore::TokenSession>
SqliteStore::get_session_by_token(const std::string& token) {
    if (token.empty()) return std::nullopt;
    std::lock_guard lock(mutex_);
    auto token_hash = hash_access_token(token);
    auto stmt = prepare(db_,
        "SELECT user_id, device_id FROM access_tokens WHERE token_hash = ?");
    sqlite3_bind_text(stmt.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    TokenSession session;
    session.user_id = column_text_or_empty(stmt.get(), 0);
    session.device_id = column_text_or_empty(stmt.get(), 1);
    return session;
}

std::optional<SqliteStore::TokenSession>
SqliteStore::consume_refresh_token(const std::string& refresh_token) {
    if (refresh_token.empty()) return std::nullopt;
    std::lock_guard lock(mutex_);
    auto refresh_hash = hash_access_token(refresh_token);

    TokenSession session;
    {
        auto stmt = prepare(db_,
            "SELECT user_id, device_id, family_id FROM access_tokens WHERE refresh_hash = ?");
        sqlite3_bind_text(stmt.get(), 1, refresh_hash.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
        session.user_id = column_text_or_empty(stmt.get(), 0);
        session.device_id = column_text_or_empty(stmt.get(), 1);
        session.family_id = column_text_or_empty(stmt.get(), 2);
    }

    // Remember that this secret has been spent, BEFORE the row that holds it
    // goes away. Recorded whether or not anything ever replays it: the record
    // is the only difference between "that refresh token is not valid" and
    // "that refresh token was valid once, and someone is presenting it a
    // second time".
    {
        auto note = prepare(db_,
            "INSERT OR REPLACE INTO consumed_refresh_tokens "
            "  (refresh_hash, family_id, user_id, consumed_at) VALUES (?, ?, ?, ?)");
        sqlite3_bind_text(note.get(), 1, refresh_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(note.get(), 2, session.family_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(note.get(), 3, session.user_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(note.get(), 4, audit_now_ms());
        sqlite3_step(note.get());
    }

    // Rotate: the old access token dies with the refresh token that minted it.
    auto del = prepare(db_, "DELETE FROM access_tokens WHERE refresh_hash = ?");
    sqlite3_bind_text(del.get(), 1, refresh_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(del.get());

    prune_consumed_refresh_tokens_locked();
    return session;
}

int SqliteStore::revoke_family_for_replayed_refresh_token(const std::string& refresh_token) {
    if (refresh_token.empty()) return 0;
    std::lock_guard lock(mutex_);
    auto refresh_hash = hash_access_token(refresh_token);

    std::string family_id;
    std::string user_id;
    {
        auto stmt = prepare(db_,
            "SELECT family_id, user_id FROM consumed_refresh_tokens WHERE refresh_hash = ?");
        sqlite3_bind_text(stmt.get(), 1, refresh_hash.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) return 0;
        family_id = column_text_or_empty(stmt.get(), 0);
        user_id = column_text_or_empty(stmt.get(), 1);
    }
    // A pre-v19 session carries its own token_hash as its family, so it is a
    // family of one and this degrades to revoking just that session. Never
    // treat an empty family as a wildcard: that would match every row the
    // migration missed and log the entire server out.
    if (family_id.empty()) return 0;

    int revoked = 0;
    {
        auto del = prepare(db_, "DELETE FROM access_tokens WHERE family_id = ?");
        sqlite3_bind_text(del.get(), 1, family_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(del.get());
        revoked = sqlite3_changes(db_);
    }
    // The family is finished, so its spent-token records have nothing left to
    // protect. Dropping them also makes the revocation idempotent rather than
    // something an attacker can replay to generate log noise indefinitely.
    {
        auto del = prepare(db_, "DELETE FROM consumed_refresh_tokens WHERE family_id = ?");
        sqlite3_bind_text(del.get(), 1, family_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(del.get());
    }

    get_logger()->warn(
        "Refresh token for {} was redeemed twice — the chain has been copied. Revoked {} "
        "session(s) in that family; both the legitimate client and whoever else holds a "
        "copy must sign in again.", user_id, revoked);
    return revoked;
}

void SqliteStore::prune_consumed_refresh_tokens_locked() {
    // A spent-token record only has to outlive the window in which a replay is
    // still meaningful. Tokens in a family that is still rotating are refreshed
    // (and re-recorded) long before this; anything older belongs to a chain
    // that has not been touched in a full token lifetime, which cannot be
    // revoked usefully because its sessions have expired anyway.
    constexpr int64_t kRetentionMs = kDefaultAccessTokenLifetimeMs;
    auto del = prepare(db_, "DELETE FROM consumed_refresh_tokens WHERE consumed_at < ?");
    sqlite3_bind_int64(del.get(), 1, audit_now_ms() - kRetentionMs);
    sqlite3_step(del.get());
}

// Rooms

std::string SqliteStore::create_room(const std::string& room_id, const std::string& creator,
                                      bool is_direct) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "INSERT INTO rooms (room_id, creator, is_direct) VALUES (?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, creator.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 3, is_direct ? 1 : 0);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to create room: ") + sqlite3_errmsg(db_));
    }
    return room_id;
}

bool SqliteStore::is_direct_room(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT is_direct FROM rooms WHERE room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return false;
    return sqlite3_column_int(stmt.get(), 0) != 0;
}

std::vector<std::pair<std::string, std::string>> SqliteStore::get_direct_rooms(
    const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, R"(
        SELECT me.room_id, peer.user_id
        FROM room_members me
        JOIN rooms r ON r.room_id = me.room_id AND r.is_direct = 1
        JOIN room_members peer ON peer.room_id = me.room_id AND peer.user_id != me.user_id
        WHERE me.user_id = ? AND me.membership = 'join'
        ORDER BY r.rowid
    )");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<std::pair<std::string, std::string>> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        out.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)),
                         reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1)));
    }
    return out;
}

std::optional<std::string> SqliteStore::find_direct_room(const std::string& user_a,
                                                         const std::string& user_b) {
    std::lock_guard lock(mutex_);
    // The joined-member count is part of the predicate, and it is the READ half
    // of the rule handle_create_room now enforces on the write side.
    //
    // Without it this function answers "the oldest direct room these two are
    // both in", which is not the same question as "their DM" the moment a
    // direct room can hold three people — and before the shape rule landed, any
    // account could manufacture one that did. That made this a confused deputy
    // rather than a missing feature: given a direct room holding {mallory,
    // alice, bob}, the next time alice opened a DM with bob this handed back
    // MALLORY'S room, and the two of them would have held a private
    // conversation in it. Ordered oldest-first, so the manufactured room wins
    // against a real one created later.
    //
    // Enforcing it here as well as at creation is the same argument
    // PermissionsEngine::compute() makes for clearing channel overrides on a
    // direct room: refusing the write stops NEW ones, and does nothing for a
    // database that already carries one from a build without the refusal. A
    // three-person direct room simply stops matching, so alice and bob get a
    // clean two-person room minted instead — the repair happens by itself, on
    // the next attempt, with nothing to migrate.
    //
    // It counts JOINED members only, and deliberately does not constrain
    // get_direct_rooms() the same way: that function reports the peer whatever
    // their own membership is, because a DM the other side has left is still
    // that person's conversation, and a count rule there would delete it from
    // their m.direct. The two are asking different questions.
    auto stmt = prepare(db_, R"(
        SELECT r.room_id
        FROM rooms r
        JOIN room_members a ON a.room_id = r.room_id AND a.user_id = ? AND a.membership = 'join'
        JOIN room_members b ON b.room_id = r.room_id AND b.user_id = ? AND b.membership = 'join'
        WHERE r.is_direct = 1
          AND (SELECT COUNT(*) FROM room_members m
               WHERE m.room_id = r.room_id AND m.membership = 'join') = 2
        ORDER BY r.rowid LIMIT 1
    )");
    sqlite3_bind_text(stmt.get(), 1, user_a.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_b.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    return std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
}

void SqliteStore::delete_room(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    // foreign_keys=ON means rooms can't be deleted while events or members
    // reference them — delete the dependents first, wrapped in a transaction
    // so we don't end up with a half-removed room.
    exec("BEGIN IMMEDIATE");
    try {
        auto run = [&](const char* sql) {
            auto s = prepare(db_, sql);
            sqlite3_bind_text(s.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(s.get());
        };
        run("DELETE FROM read_markers WHERE room_id = ?");
        // event_mentions also cascades off events(event_id), but deleting by
        // room_id explicitly means a deployment that somehow has foreign_keys
        // off still can't leave mention badges pointing at a deleted channel.
        run("DELETE FROM event_mentions WHERE room_id = ?");
        // Search index: external-content FTS5 needs each document's own text to
        // forget it, so this goes row by row through the one reindex helper
        // rather than as a bulk DELETE that would leave the index still matching
        // a deleted channel's messages.
        {
            std::vector<std::string> stale;
            auto sel = prepare(db_, "SELECT event_id FROM event_search WHERE room_id = ?");
            sqlite3_bind_text(sel.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
            while (sqlite3_step(sel.get()) == SQLITE_ROW) {
                stale.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(sel.get(), 0)));
            }
            for (const auto& id : stale) {
                reindex_search_locked(id, room_id, "", 0, std::nullopt);
            }
        }
        // Media grants die with the room. Not doing this would leave every
        // attachment ever posted in a deleted channel fetchable by whoever was
        // in it, keyed off a room whose permissions can no longer be evaluated.
        run("DELETE FROM media_refs WHERE room_id = ?");

        // Undelivered notifications for this channel's messages, before the
        // events they name disappear and leave the rows unmatchable. Deleting a
        // channel is the same promise redaction makes — the content is gone —
        // and a queued push would otherwise keep delivering its text for as
        // long as the retry schedule allows.
        run("DELETE FROM push_queue WHERE event_id IN "
            "(SELECT event_id FROM events WHERE room_id = ?)");
        run("DELETE FROM events WHERE room_id = ?");
        run("DELETE FROM room_members WHERE room_id = ?");
        run("DELETE FROM rooms WHERE room_id = ?");
        exec("COMMIT");
    } catch (...) {
        exec("ROLLBACK");
        throw;
    }
}

bool SqliteStore::room_exists(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM rooms WHERE room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

std::vector<std::string> SqliteStore::get_joined_rooms(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT room_id FROM room_members WHERE user_id = ? AND membership = 'join'");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

// Bot accounts
//
// Everything below writes through the same `users` table ordinary accounts live
// in. There is no second account table and no second authentication path,
// because the moment a bot stops being a user it stops inheriting every
// permission check, every role, every endpoint and every audit record that
// already works — and the shape this replaces (a "service account" bolted on
// beside users) is exactly how a system ends up with two half-enforced
// permission models.

namespace {

// Fills a BotRecord from a row shaped by kBotSelectColumns below.
SqliteStore::BotRecord bot_from_row(sqlite3_stmt* stmt) {
    SqliteStore::BotRecord bot;
    bot.user_id = column_text_or_empty(stmt, 0);
    bot.display_name = column_text_or_empty(stmt, 1);
    bot.description = column_text_or_empty(stmt, 2);
    bot.owner_id = column_text_or_empty(stmt, 3);
    bot.created_at = sqlite3_column_int64(stmt, 4);
    bot.created_by = column_text_or_empty(stmt, 5);
    if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
        bot.deactivated_at = sqlite3_column_int64(stmt, 6);
    }
    if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
        bot.last_seen_at = sqlite3_column_int64(stmt, 7);
    }
    return bot;
}

// One column list for get_bot and list_bots, so the two can never drift into
// disagreeing about what a bot record contains.
//
// last_seen_at is a correlated MAX over the bot's tokens rather than a column on
// `bots`: the fact lives on the token that was used, and copying it onto the bot
// row would mean a second write on the request path that a token's own
// last_used_at update already covers.
constexpr const char* kBotSelectColumns =
    "SELECT b.user_id, COALESCE(u.display_name, ''), COALESCE(b.description, ''), "
    "       b.owner_id, b.created_at, b.created_by, b.deactivated_at, "
    "       (SELECT MAX(t.last_used_at) FROM access_tokens t WHERE t.user_id = b.user_id) "
    "FROM bots b JOIN users u ON u.user_id = b.user_id ";

} // namespace

bool SqliteStore::create_bot(const BotRecord& bot) {
    // The namespace is enforced HERE as well as in the handler, because the
    // server now derives bot-ness from the user id on a hot path:
    // stamp_bot_flag() reads bot::is_bot_user_id(state_key) rather than querying
    // users.kind, so that the initial-sync roster costs no query per member.
    //
    // That derivation is only sound while "kind = 'bot'" and "localpart starts
    // bot_" name the same set. The handler's grammar check keeps them aligned
    // today; this keeps them aligned for any future caller, including an admin
    // script or a test reaching past the handler. A bot the roster would not
    // badge is not a bot this store is willing to create.
    if (!bsfchat::bot::is_bot_user_id(bot.user_id)) return false;

    std::lock_guard lock(mutex_);

    // One transaction for both rows. A users row whose bots row failed to land
    // would be an account that is a bot as far as login is concerned (kind =
    // 'bot', so no password path) but invisible to every bot endpoint — nobody
    // could list it, rotate it or deactivate it, and the localpart would be taken
    // forever. Both or neither.
    exec("BEGIN IMMEDIATE");
    try {
        {
            // Empty password hash, and kind = 'bot'. Two independent reasons the
            // same account cannot take the password path: get_password_hash()
            // will not return a bot's hash at all, and there is no hash to
            // return. Belt and braces, on purpose — this is the one property of a
            // bot that must not have a single point of failure.
            auto stmt = prepare(db_,
                "INSERT INTO users (user_id, password_hash, display_name, kind) "
                "VALUES (?, '', ?, 'bot')");
            sqlite3_bind_text(stmt.get(), 1, bot.user_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt.get(), 2, bot.display_name.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
                // Almost always a PRIMARY KEY collision: the localpart is taken.
                // A refusal, not a fault, so roll back and report it as one.
                exec("ROLLBACK");
                return false;
            }
        }
        {
            auto stmt = prepare(db_,
                "INSERT INTO bots (user_id, owner_id, description, created_at, created_by) "
                "VALUES (?, ?, ?, ?, ?)");
            sqlite3_bind_text(stmt.get(), 1, bot.user_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt.get(), 2, bot.owner_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt.get(), 3, bot.description.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt.get(), 4, bot.created_at);
            sqlite3_bind_text(stmt.get(), 5, bot.created_by.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("Failed to create bot record: ") +
                                         sqlite3_errmsg(db_));
            }
        }
        exec("COMMIT");
        return true;
    } catch (...) {
        try {
            exec("ROLLBACK");
        } catch (...) {
        }
        throw;
    }
}

bool SqliteStore::is_bot(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM users WHERE user_id = ? AND kind = 'bot'");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

std::optional<SqliteStore::BotRecord> SqliteStore::get_bot(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kBotSelectColumns) + "WHERE b.user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    return bot_from_row(stmt.get());
}

std::vector<SqliteStore::BotRecord> SqliteStore::list_bots() {
    std::lock_guard lock(mutex_);
    // Newest first, tie-broken by user_id so the order is total and a listing
    // does not reshuffle between two calls when bots share a creation
    // millisecond (a scripted setup creates several in the same tick).
    auto stmt = prepare(db_,
        std::string(kBotSelectColumns) + "ORDER BY b.created_at DESC, b.user_id ASC");
    std::vector<BotRecord> bots;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) bots.push_back(bot_from_row(stmt.get()));
    return bots;
}

bool SqliteStore::rotate_bot_token(const std::string& user_id, const std::string& token,
                                   const std::string& device_id) {
    std::lock_guard lock(mutex_);

    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto token_hash = hash_access_token(token);

    exec("BEGIN IMMEDIATE");
    try {
        // Re-checked inside the transaction rather than trusted from the handler.
        // This is the only thing in the server that mints a credential which
        // never expires; it must not be possible to talk it into minting one for
        // a person, whatever the caller believed when it looked the account up.
        {
            auto chk = prepare(db_, "SELECT 1 FROM users WHERE user_id = ? AND kind = 'bot'");
            sqlite3_bind_text(chk.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(chk.get()) != SQLITE_ROW) {
                exec("ROLLBACK");
                return false;
            }
        }

        // Every prior token dies here, in the same transaction that mints the
        // replacement. An operator rotates because the old secret is suspect, so
        // a window in which both work would defeat the exercise — and deleting
        // the ROW takes any refresh secret attached to it with it, the same
        // property delete_all_tokens_for_user relies on.
        {
            auto del = prepare(db_, "DELETE FROM access_tokens WHERE user_id = ?");
            sqlite3_bind_text(del.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(del.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("Failed to revoke bot tokens: ") +
                                         sqlite3_errmsg(db_));
            }
        }

        // lifetime_ms = 0 is what get_user_by_token reads as "never expires,
        // never slides". expires_at is NOT NULL in the schema, so it is written
        // as `now`; nothing consults it on this row, because the lifetime check
        // short-circuits before expiry is considered. A far-future date there
        // would be a second, contradictory claim about when this token dies.
        // refresh_hash stays NULL: a bot has no re-authentication flow to refresh
        // into, and rotation is the operator action that replaces one.
        {
            auto ins = prepare(db_,
                "INSERT INTO access_tokens "
                "  (token_hash, user_id, device_id, created_at, expires_at, last_used_at, "
                "   lifetime_ms, refresh_hash, token_kind) "
                "VALUES (?, ?, ?, ?, ?, NULL, 0, NULL, 'bot')");
            sqlite3_bind_text(ins.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins.get(), 3, device_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(ins.get(), 4, now);
            sqlite3_bind_int64(ins.get(), 5, now);
            if (sqlite3_step(ins.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("Failed to store bot token: ") +
                                         sqlite3_errmsg(db_));
            }
        }
        exec("COMMIT");
        return true;
    } catch (...) {
        try {
            exec("ROLLBACK");
        } catch (...) {
        }
        throw;
    }
}

bool SqliteStore::deactivate_bot(const std::string& user_id, int64_t when_ms) {
    std::lock_guard lock(mutex_);

    exec("BEGIN IMMEDIATE");
    try {
        // The UPDATE's own WHERE clause is the idempotency test, rather than a
        // read followed by a write: `deactivated_at IS NULL` matches exactly once
        // however many callers race, and sqlite3_changes() then says whether THIS
        // call was the one that did it. A read-then-write would let two
        // concurrent deletes both believe they were first and both write an audit
        // record for the same event.
        {
            auto upd = prepare(db_,
                "UPDATE bots SET deactivated_at = ? "
                "WHERE user_id = ? AND deactivated_at IS NULL");
            sqlite3_bind_int64(upd.get(), 1, when_ms);
            sqlite3_bind_text(upd.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(upd.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("Failed to deactivate bot: ") +
                                         sqlite3_errmsg(db_));
            }
        }
        const bool changed = sqlite3_changes(db_) > 0;

        // Tokens are revoked unconditionally, even when the bot was already
        // deactivated. `changed` reports who got there first; it must not decide
        // whether the credentials actually die. A repeat call finding a live
        // token — because an earlier attempt half-failed, or because somebody
        // rotated one onto an already-dead bot — must still kill it. Revocation
        // is the part that has to be true after this returns, not the part that
        // has to be attributable.
        {
            auto del = prepare(db_, "DELETE FROM access_tokens WHERE user_id = ?");
            sqlite3_bind_text(del.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(del.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("Failed to revoke bot tokens: ") +
                                         sqlite3_errmsg(db_));
            }
        }
        exec("COMMIT");
        return changed;
    } catch (...) {
        try {
            exec("ROLLBACK");
        } catch (...) {
        }
        throw;
    }
}

std::vector<std::string> SqliteStore::list_all_users() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT user_id FROM users");
    std::vector<std::string> users;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        users.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return users;
}

std::vector<std::string> SqliteStore::list_all_non_category_rooms() {
    std::lock_guard lock(mutex_);
    // Direct rooms are excluded: a DM is not a category, so without this
    // filter every server-wide sweep over "all non-category rooms" would
    // treat private conversations as ordinary channels.
    const char* sql = R"(
        SELECT r.room_id FROM rooms r
        WHERE r.is_direct = 0
          AND COALESCE((
            SELECT json_extract(content, '$.type')
            FROM events
            WHERE room_id = r.room_id
              AND event_type = 'bsfchat.room.type'
              AND state_key = ''
            ORDER BY stream_position DESC LIMIT 1
        ), '') != 'category'
    )";
    auto stmt = prepare(db_, sql);
    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

std::vector<std::string> SqliteStore::list_legacy_untyped_rooms() {
    std::lock_guard lock(mutex_);
    // handle_create_room has always emitted bsfchat.room.type since the
    // Discord-like channel model landed. A room without one therefore predates
    // that model and is the only kind the historical publicize migration is
    // allowed to touch — a room created private by the CURRENT code was made
    // private deliberately and must stay that way.
    const char* sql = R"(
        SELECT r.room_id FROM rooms r
        WHERE r.is_direct = 0
          AND NOT EXISTS (
            SELECT 1 FROM events
            WHERE room_id = r.room_id
              AND event_type = 'bsfchat.room.type'
              AND state_key = ''
        )
    )";
    auto stmt = prepare(db_, sql);
    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

std::vector<SqliteStore::RoomDirectoryRow> SqliteStore::list_room_directory_rows() {
    std::lock_guard lock(mutex_);

    // Categories are IN this result, unlike every other list_* above — the
    // directory has to name the containers so a channel's parent resolves to
    // something the caller was also shown. Filtering them out here and adding
    // them back in the caller would be a second definition of "is a category".
    //
    // `ORDER BY stream_position DESC LIMIT 1` per subquery is how the rest of
    // this file resolves "the latest state event of this type", and it is what
    // makes each subquery an index seek on idx_events_room_type_state rather
    // than a scan: room_id is the leading column, so a grouped
    // `WHERE event_type = 'm.room.name'` across all rooms would miss the index
    // and walk the whole events table — on a server whose events table is
    // overwhelmingly message history.
    //
    // Built from the event_type constants rather than spelled inline: these
    // three are the entire wire contract of the directory, and a typo in a
    // string literal inside SQL fails silently as "no such state event", i.e.
    // as an unnamed channel rather than as an error.
    const std::string sql =
        "SELECT r.room_id,"
        " COALESCE((SELECT json_extract(content, '$.name') FROM events"
        "           WHERE room_id = r.room_id AND event_type = '" +
        std::string(event_type::kRoomName) +
        "' AND state_key = ''"
        "           ORDER BY stream_position DESC LIMIT 1), ''),"
        " COALESCE((SELECT json_extract(content, '$.type') FROM events"
        "           WHERE room_id = r.room_id AND event_type = '" +
        std::string(event_type::kRoomType) +
        "' AND state_key = ''"
        "           ORDER BY stream_position DESC LIMIT 1), ''),"
        " COALESCE((SELECT json_extract(content, '$.parent_id') FROM events"
        "           WHERE room_id = r.room_id AND event_type = '" +
        std::string(event_type::kRoomCategory) +
        "' AND state_key = ''"
        "           ORDER BY stream_position DESC LIMIT 1), ''),"
        " COALESCE((SELECT json_extract(content, '$.order') FROM events"
        "           WHERE room_id = r.room_id AND event_type = '" +
        std::string(event_type::kRoomCategory) +
        "' AND state_key = ''"
        "           ORDER BY stream_position DESC LIMIT 1), 0)"
        " FROM rooms r WHERE r.is_direct = 0";

    auto stmt = prepare(db_, sql);
    std::vector<RoomDirectoryRow> rows;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        // COALESCE guarantees a non-NULL column, but json_extract on a
        // malformed or differently-typed content yields whatever it yields —
        // so every text read goes through a null-tolerant helper rather than
        // straight into std::string, which is UB on a null pointer.
        auto text = [&](int col) -> std::string {
            const auto* p = sqlite3_column_text(stmt.get(), col);
            return p ? reinterpret_cast<const char*>(p) : std::string();
        };
        RoomDirectoryRow row;
        row.room_id = text(0);
        row.name = text(1);
        row.type = text(2);
        row.parent_id = text(3);
        row.sort_order = sqlite3_column_int(stmt.get(), 4);
        rows.push_back(std::move(row));
    }
    return rows;
}

std::vector<std::string> SqliteStore::list_public_rooms() {
    std::lock_guard lock(mutex_);
    // Return rooms where the latest m.room.join_rules state event has join_rule == "public"
    // AND the latest bsfchat.room.type (if any) is NOT "category"
    // AND the room is not a DM. The is_direct guard is what stops a direct
    // conversation from ever being treated as a room everyone should join,
    // even if some historical join_rules event on it still says "public".
    const char* sql = R"(
        SELECT r.room_id FROM rooms r
        WHERE r.is_direct = 0
        AND (
            SELECT json_extract(content, '$.join_rule')
            FROM events
            WHERE room_id = r.room_id
              AND event_type = 'm.room.join_rules'
              AND state_key = ''
            ORDER BY stream_position DESC LIMIT 1
        ) = 'public'
        AND COALESCE((
            SELECT json_extract(content, '$.type')
            FROM events
            WHERE room_id = r.room_id
              AND event_type = 'bsfchat.room.type'
              AND state_key = ''
            ORDER BY stream_position DESC LIMIT 1
        ), '') != 'category'
    )";
    auto stmt = prepare(db_, sql);
    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

bool SqliteStore::is_room_member(const std::string& room_id, const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ? AND membership = 'join'");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

// Room membership

void SqliteStore::set_membership(const std::string& room_id, const std::string& user_id, const std::string& membership) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO room_members (room_id, user_id, membership, updated_at) VALUES (?, ?, ?, strftime('%s','now') * 1000) "
        "ON CONFLICT(room_id, user_id) DO UPDATE SET membership = excluded.membership, updated_at = excluded.updated_at");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, membership.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::optional<std::string> SqliteStore::find_membership(const std::string& room_id,
                                                        const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT membership FROM room_members WHERE room_id = ? AND user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return std::nullopt;
}

std::vector<std::string> SqliteStore::get_invited_rooms(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT room_id FROM room_members WHERE user_id = ? AND membership = 'invite'");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

std::string SqliteStore::get_membership(const std::string& room_id, const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT membership FROM room_members WHERE room_id = ? AND user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return "leave";
}

std::vector<std::pair<std::string, std::string>> SqliteStore::get_room_members(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT user_id, membership FROM room_members WHERE room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<std::pair<std::string, std::string>> members;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        members.emplace_back(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1))
        );
    }
    return members;
}

std::vector<std::pair<std::string, std::string>>
SqliteStore::get_user_memberships(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT room_id, membership FROM room_members WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<std::pair<std::string, std::string>> rows;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rows.emplace_back(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1))
        );
    }
    return rows;
}

std::vector<SqliteStore::MalformedDirectRoom> SqliteStore::list_malformed_direct_rooms() {
    std::lock_guard lock(mutex_);
    // The count is of JOINED rows only, matching the predicate
    // handle_delete_room applies and the one find_direct_room now requires.
    // Counting every row instead would list every DM either side ever left,
    // which is the opposite of the point: this must surface the broken rooms
    // WITHOUT surfacing the ordinary ones.
    auto stmt = prepare(db_, R"(
        SELECT r.room_id, r.creator,
               (SELECT COUNT(*) FROM room_members m
                WHERE m.room_id = r.room_id AND m.membership = 'join') AS joined
        FROM rooms r
        WHERE r.is_direct = 1 AND joined != 2
        ORDER BY r.room_id
    )");

    std::vector<MalformedDirectRoom> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        MalformedDirectRoom row;
        row.room_id = column_text_or_empty(stmt.get(), 0);
        row.creator = column_text_or_empty(stmt.get(), 1);
        row.joined = static_cast<size_t>(sqlite3_column_int64(stmt.get(), 2));
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<SqliteStore::OrphanMembership> SqliteStore::list_orphan_memberships() {
    std::lock_guard lock(mutex_);
    // NOT NOT IN (SELECT user_id FROM users): `users.user_id` is the primary
    // key and cannot be NULL, so the two are equivalent here — but NOT IN goes
    // silently empty the moment a subquery yields one NULL, and a diagnostic
    // that reports "nothing wrong" by accident is worse than no diagnostic.
    // NOT EXISTS has no such failure mode and uses the same index.
    //
    // Bots count as accounts: bot creation writes a users row with kind='bot',
    // so a bot's membership is not an orphan. server_bans is deliberately NOT
    // examined — a ban on an unregistered id is a reservation, not a mistake.
    auto stmt = prepare(db_, R"(
        SELECT m.room_id, m.user_id, m.membership, m.updated_at
        FROM room_members m
        WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.user_id = m.user_id)
        ORDER BY m.room_id, m.user_id
    )");

    std::vector<OrphanMembership> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        OrphanMembership row;
        row.room_id = column_text_or_empty(stmt.get(), 0);
        row.user_id = column_text_or_empty(stmt.get(), 1);
        row.membership = column_text_or_empty(stmt.get(), 2);
        row.updated_at = sqlite3_column_int64(stmt.get(), 3);
        out.push_back(std::move(row));
    }
    return out;
}

// Server-wide bans

void SqliteStore::set_server_ban(const std::string& user_id, const std::string& actor,
                                 const std::string& reason, int64_t created_at) {
    std::lock_guard lock(mutex_);
    const int64_t ts = created_at != 0 ? created_at : audit_now_ms();
    auto stmt = prepare(db_,
        "INSERT INTO server_bans (user_id, actor, reason, created_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET actor = excluded.actor, reason = excluded.reason, "
        "created_at = excluded.created_at");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, actor.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 4, ts);
    sqlite3_step(stmt.get());
}

bool SqliteStore::clear_server_ban(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM server_bans WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return sqlite3_changes(db_) > 0;
}

bool SqliteStore::is_server_banned(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM server_bans WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

std::optional<SqliteStore::ServerBan> SqliteStore::get_server_ban(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT user_id, actor, reason, created_at FROM server_bans WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    ServerBan ban;
    ban.user_id = column_text_or_empty(stmt.get(), 0);
    ban.actor = column_text_or_empty(stmt.get(), 1);
    ban.reason = column_text_or_empty(stmt.get(), 2);
    ban.created_at = sqlite3_column_int64(stmt.get(), 3);
    return ban;
}

std::vector<SqliteStore::ServerBan> SqliteStore::list_server_bans() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT user_id, actor, reason, created_at FROM server_bans ORDER BY created_at DESC");
    std::vector<ServerBan> bans;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        ServerBan ban;
        ban.user_id = column_text_or_empty(stmt.get(), 0);
        ban.actor = column_text_or_empty(stmt.get(), 1);
        ban.reason = column_text_or_empty(stmt.get(), 2);
        ban.created_at = sqlite3_column_int64(stmt.get(), 3);
        bans.push_back(std::move(ban));
    }
    return bans;
}

SqliteStore::ServerBanPage SqliteStore::list_server_bans(
    int limit, const std::optional<std::string>& after) {
    std::lock_guard lock(mutex_);
    if (limit < 1) limit = 1;

    ServerBanPage page;

    // Ordered by user_id, not created_at. See the header for why: created_at is
    // neither unique nor stable under set_server_ban's REPLACE, so a cursor on it
    // can hand a paging reader the same ban twice or hide one. user_id is the
    // primary key and never moves.
    //
    // Over-fetch one row to learn whether a further page exists without a second
    // query — the same trick get_room_events_paginated and list_audit_records use.
    std::string sql = "SELECT user_id, actor, reason, created_at FROM server_bans ";
    if (after) sql += "WHERE user_id > ? ";
    sql += "ORDER BY user_id ASC LIMIT ?";

    auto stmt = prepare(db_, sql);
    int bind_index = 1;
    if (after) {
        sqlite3_bind_text(stmt.get(), bind_index++, after->c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt.get(), bind_index, limit + 1);

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        ServerBan ban;
        ban.user_id = column_text_or_empty(stmt.get(), 0);
        ban.actor = column_text_or_empty(stmt.get(), 1);
        ban.reason = column_text_or_empty(stmt.get(), 2);
        ban.created_at = sqlite3_column_int64(stmt.get(), 3);
        page.bans.push_back(std::move(ban));
    }

    if (page.bans.size() > static_cast<size_t>(limit)) {
        page.bans.pop_back();
        // Exclusive cursor: the next page is everything strictly after the last
        // row we are returning, so no ban can be served twice or skipped.
        page.next_from = page.bans.back().user_id;
    }

    auto count = prepare(db_, "SELECT COUNT(*) FROM server_bans");
    if (sqlite3_step(count.get()) == SQLITE_ROW) {
        page.total = sqlite3_column_int64(count.get(), 0);
    }
    return page;
}

// Events

int64_t SqliteStore::claim_stream_position_locked() {
    int64_t pos = next_stream_position_++;
    // Persist the new head so a restart never hands out a position twice,
    // even if the events table has since had its newest rows deleted.
    auto stmt = prepare(db_,
        "INSERT INTO server_meta (key, value) VALUES ('next_stream_position', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    auto v = std::to_string(next_stream_position_);
    sqlite3_bind_text(stmt.get(), 1, v.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return pos;
}

int64_t SqliteStore::insert_event(const std::string& event_id, const std::string& room_id,
                                   const std::string& sender, const std::string& event_type,
                                   const std::optional<std::string>& state_key,
                                   const std::string& content_json, int64_t origin_server_ts,
                                   const MediaReferences& media) {
    std::lock_guard lock(mutex_);

    // ONE TRANSACTION over the event row, the stream-position head and the search
    // index. These are three writes that must not be observable apart.
    //
    // The failure this closes: the events INSERT succeeded, then the FTS5 index
    // write threw (a prepare failure, a constraint, a disk error), and the caller
    // saw an exception — but the event row was already committed. The message was
    // in the timeline and permanently invisible to /search, with nothing to notice
    // it and no reindex path to repair it. Small window, local writes only, but the
    // damage is silent and permanent, which is the combination worth a transaction.
    //
    // Same shape as delete_room: BEGIN IMMEDIATE / COMMIT / ROLLBACK, taken under
    // the store's global mutex that is already held. IMMEDIATE (not DEFERRED)
    // because this transaction writes and would otherwise only take the write lock
    // on first write, turning a busy database into a mid-transaction SQLITE_BUSY.
    //
    // Nothing between BEGIN and COMMIT blocks on I/O beyond the local SQLite file:
    // a stream-position claim, one INSERT, a JSON parse of content already in
    // memory, and the index write. No network, no filesystem outside the database,
    // no callback into a handler — so holding the mutex here is no longer than the
    // uninstrumented version already did.
    exec("BEGIN IMMEDIATE");
    try {
        // Monotonic — deriving this from MAX(stream_position) + 1 meant that
        // deleting a room's newest events made positions get reused, and clients
        // holding a sync token at or above a reused position silently stopped
        // receiving anything.
        //
        // Inside the transaction, so a rollback also undoes the persisted head.
        // The in-memory next_stream_position_ is deliberately NOT rewound: a gap
        // in the sequence is harmless (positions only ever need to increase),
        // whereas rewinding could hand the same position out twice, which is the
        // exact defect v4 exists to fix.
        const int64_t stream_pos = claim_stream_position_locked();

        // `replaces` is derived here rather than passed in, so no caller can
        // forget to set it and quietly reintroduce "an edit counts as a new
        // message". It is an immutable property of the event's own content.
        std::optional<std::string> replaces;
        if (event_type == std::string(event_type::kRoomMessage)) {
            replaces = replacement_target(content_json);
        }

        // Derived here for the same reason `replaces` is, and it matters more:
        // this column is what stops an event full of IP addresses being handed
        // to the whole room. Deriving it in the handler instead would mean a
        // new send path — a future federation ingress, a bulk import, a test
        // helper — could insert signalling with signal_to NULL and silently
        // reinstate the leak, with nothing failing to say so. insert_event is
        // the one door into this table; the rule lives on the door.
        const std::optional<std::string> signal_to =
            call_signal_addressee(event_type, content_json);

        auto stmt = prepare(db_,
            "INSERT INTO events (event_id, room_id, sender, event_type, state_key, content, origin_server_ts, stream_position, replaces, signal_to) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 3, sender.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, event_type.c_str(), -1, SQLITE_TRANSIENT);
        if (state_key) {
            sqlite3_bind_text(stmt.get(), 5, state_key->c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt.get(), 5);
        }
        sqlite3_bind_text(stmt.get(), 6, content_json.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 7, origin_server_ts);
        sqlite3_bind_int64(stmt.get(), 8, stream_pos);
        if (replaces) {
            sqlite3_bind_text(stmt.get(), 9, replaces->c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt.get(), 9);
        }
        if (signal_to) {
            sqlite3_bind_text(stmt.get(), 10, signal_to->c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt.get(), 10);
        }

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            throw std::runtime_error(std::string("Failed to insert event: ") +
                                     sqlite3_errmsg(db_));
        }

        // Search index. Derived here rather than by the caller for the same reason
        // `replaces` is: insert_event is the one place every event passes through,
        // so an index maintained here cannot be bypassed by a new call site.
        //
        // A replacement is deliberately NOT indexed as itself — apply_edit folds
        // its text onto the event it replaces, so an edited message stays a single
        // search hit whose text is current.
        if (event_type == std::string(event_type::kRoomMessage) && !replaces) {
            auto content = nlohmann::json::parse(content_json, nullptr, false);
            std::string body;
            if (!content.is_discarded() && content.is_object()) {
                body = content.value("body", "");
            }
            if (!body.empty()) {
                reindex_search_locked(event_id, room_id, sender, stream_pos, body);
            }
        }

        // Media ACL index, on the door for the same reason `signal_to` is.
        //
        // Upload is not room-scoped — POST /upload has no room in it — so this
        // is the only moment at which the server learns which channel a media
        // object belongs to. Recorded inside the same transaction as the event
        // so a reader can never see an event whose attachment the ACL would
        // then refuse, nor the reverse.
        //
        // State events go in too, not just messages: a channel icon set by
        // PUT /state is read through the same VIEW_CHANNEL gate as the rest of
        // that room's state, so binding it to the room is exactly right.
        //
        // TWO conditions now, and they are enforced in two different places on
        // purpose (audit F5):
        //
        //   * the content NAMES the uri — media_uris_in_content(), here, on the
        //     door, exactly as before, so no caller can bind an object the
        //     event does not mention; and
        //   * the event's author MAY READ it — `media`, computed before this
        //     call by MediaAccess::vet() via insert_event_vetted().
        //
        // The second one cannot live here. It needs PermissionsEngine, which
        // reads this store, and we are inside its mutex and inside BEGIN
        // IMMEDIATE — the transaction comment above promises no callback into a
        // handler from in here, and it is worth keeping. So the door keeps the
        // half it can enforce and is handed the half it cannot.
        //
        // An event inserted through the bare insert_event() binds nothing. That
        // is deliberate and it is the fail-closed direction: a future ingestion
        // path that does not vet its content produces attachments that 404 for
        // everyone but their uploader, not a revocation bypass. Before F5 the
        // default was the other way round and it was a value the caller wrote.
        for (const auto& uri : media_uris_in_content(content_json)) {
            if (!media.permits(uri)) continue;
            auto ref = prepare(db_,
                "INSERT OR IGNORE INTO media_refs (mxc_uri, room_id, event_id) "
                "VALUES (?, ?, ?)");
            sqlite3_bind_text(ref.get(), 1, uri.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ref.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ref.get(), 3, event_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(ref.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("Failed to index media reference: ") +
                                         sqlite3_errmsg(db_));
            }
        }

        exec("COMMIT");
        return stream_pos;
    } catch (...) {
        // Best-effort rollback: some SQLite errors (SQLITE_FULL, SQLITE_IOERR)
        // roll the transaction back themselves, and a ROLLBACK that then fails
        // with "no transaction is active" must not replace the real exception
        // with a misleading one. Either way the transaction is not left open.
        try {
            exec("ROLLBACK");
        } catch (...) {
        }
        throw;
    }
}

std::pair<std::vector<RoomEvent>, std::optional<int64_t>>
SqliteStore::get_room_events_paginated(const std::string& room_id, int limit,
                                        const std::string& direction,
                                        const std::optional<std::string>& from,
                                        const std::optional<std::string>& viewer) {
    std::lock_guard lock(mutex_);

    // Same query shape as get_room_events, but we also pull stream_position
    // so the handler can construct the `end` pagination token without a
    // second lookup. We over-fetch by 1 row to cheaply detect whether more
    // history exists in the scanned direction — if the fetch size equals
    // `limit+1`, there's at least one more page; otherwise we've reached
    // the end and return nullopt as the token.
    // A client-supplied token like "sabc" or "s99999999999999999999" used to
    // throw std::invalid_argument / std::out_of_range straight out of the
    // handler; treat anything unparseable as "no token".
    auto parse_token = [](const std::optional<std::string>& tok) -> int64_t {
        if (!tok || tok->size() < 2 || (*tok)[0] != 's') return 0;
        try {
            int64_t v = std::stoll(tok->substr(1));
            return v < 0 ? 0 : v;
        } catch (const std::exception&) {
            return 0;
        }
    };

    std::string sql = std::string("SELECT ") + kEventColumns + ", e.stream_position "
                      "FROM events e" + kEditJoin + "WHERE e.room_id = ?";

    // Addressed call signalling is not room content — see store/CallSignalling.h.
    //
    // With no `viewer` this is the HISTORY path (/messages), and history is
    // exactly the thing that made the leak permanent: a member who joins in
    // September can page back to April and read the LAN and public address of
    // everyone who has ever been in a call in this channel. None of it is
    // excluded from `viewer`'s own sync — this is history, and a client that
    // needs a signalling event has already had it live or has missed the call
    // entirely.
    //
    // With a `viewer` this is the INITIAL-SYNC timeline, which is a delivery
    // path and not a history one: a client that has just reconnected must still
    // receive an invite addressed to it that landed while it was away, so the
    // sender/addressee pair is admitted and everybody else is not. (Little
    // survives to be admitted — the sweep keeps only the last two minutes — but
    // "little" is not "none", and a dropped invite is a call that never starts.)
    if (viewer) {
        sql += " AND (e.signal_to IS NULL OR e.signal_to = ?2 OR e.sender = ?2)";
    } else {
        sql += " AND e.signal_to IS NULL";
    }

    if (from) {
        if (direction == "b") {
            sql += " AND e.stream_position < ?3 ORDER BY e.stream_position DESC";
        } else {
            sql += " AND e.stream_position > ?3 ORDER BY e.stream_position ASC";
        }
    } else {
        if (direction == "b") {
            sql += " ORDER BY e.stream_position DESC";
        } else {
            sql += " ORDER BY e.stream_position ASC";
        }
    }
    sql += " LIMIT ?4";

    // EVERY placeholder in this statement is numbered explicitly, and that is
    // not a style choice. `?2` is bound once and read twice, and an unnumbered
    // `?` takes "one past the highest number used so far" — so the `from` and
    // `LIMIT` placeholders would land on different indices depending on whether
    // the viewer clause was appended, and binding them by a running counter
    // would be right in one branch and wrong in the other. A misbound LIMIT
    // reads as zero and returns an empty page: a channel that looks empty, not
    // an error anyone would see.
    auto stmt = prepare(db_, sql);
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (viewer) {
        sqlite3_bind_text(stmt.get(), 2, viewer->c_str(), -1, SQLITE_TRANSIENT);
    }
    if (from) {
        sqlite3_bind_int64(stmt.get(), 3, parse_token(from));
    }
    sqlite3_bind_int(stmt.get(), 4, limit + 1);

    std::vector<RoomEvent> events;
    std::vector<int64_t> positions;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        events.push_back(read_event_row(stmt.get()));
        positions.push_back(sqlite3_column_int64(stmt.get(), 11));
    }

    // If we fetched the probe row, there's more history in this direction.
    // Trim the probe and derive the next token from the last KEPT row.
    std::optional<int64_t> next_token;
    if (static_cast<int>(events.size()) > limit) {
        events.resize(limit);
        positions.resize(limit);
        if (!positions.empty()) next_token = positions.back();
    }
    return {std::move(events), next_token};
}

std::vector<RoomEvent> SqliteStore::get_room_events(const std::string& room_id, int limit,
                                                     const std::string& direction,
                                                     const std::optional<std::string>& from) {
    // Legacy non-paginated wrapper. New callers should prefer the
    // _paginated form so they can build `end` tokens.
    return get_room_events_paginated(room_id, limit, direction, from).first;
}

std::vector<RoomEvent> SqliteStore::get_state_events(const std::string& room_id) {
    std::lock_guard lock(mutex_);

    // Get the latest state event for each (event_type, state_key) pair.
    //
    // `signal_to IS NULL` is the addressee rule, and this read is where it was
    // missing. Every other read of `events` carries it; this one did not, and
    // its result goes to every joined member through /sync and out whole from
    // GET /rooms/{id}/state. A signalling event written WITH a state_key —
    // reachable through PUT /rooms/{id}/state/m.call.candidates/{key}, which
    // needs kManageChannels — therefore broadcast the sender's LAN and public
    // address to the room despite being addressed to one peer.
    //
    // The clause is on signal_to rather than on event type, so the voice
    // roster (m.call.member, which carries no address and which the UI cannot
    // work without) and unaddressed legacy signalling both keep today's
    // behaviour. It is inside the subquery as well as the outer WHERE so a
    // filtered row cannot win the MAX(stream_position) race and suppress the
    // legitimate state event underneath it.
    //
    // See store/CallSignalling.h for what the rule is and why.
    auto stmt = prepare(db_,
        "SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content, e.origin_server_ts "
        "FROM events e "
        "INNER JOIN (SELECT event_type, state_key, MAX(stream_position) as max_pos "
        "            FROM events WHERE room_id = ? AND state_key IS NOT NULL "
        "                          AND signal_to IS NULL "
        "            GROUP BY event_type, state_key) latest "
        "ON e.event_type = latest.event_type AND e.state_key = latest.state_key AND e.stream_position = latest.max_pos "
        "WHERE e.room_id = ? AND e.signal_to IS NULL");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<RoomEvent> events;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        RoomEvent ev;
        ev.event_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        ev.room_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        ev.sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        ev.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        if (sqlite3_column_type(stmt.get(), 4) != SQLITE_NULL) {
            ev.state_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        }
        ev.content.data = nlohmann::json::parse(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5)));
        ev.origin_server_ts = sqlite3_column_int64(stmt.get(), 6);
        // State reads build their own RoomEvent rather than going through
        // read_event_row (they resolve no edits, so they never needed it), which
        // means the derived fields have to be applied here too. This is the path
        // /sync serves room state from, so it is the one an ordinary member's
        // roster comes out of at startup.
        stamp_bot_flag(ev);
        events.push_back(std::move(ev));
    }
    return events;
}

std::optional<RoomEvent> SqliteStore::get_event_by_id(const std::string& event_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        std::string("SELECT ") + kEventColumns + " FROM events e" + kEditJoin +
        "WHERE e.event_id = ? LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    return read_event_row(stmt.get());
}

bool SqliteStore::apply_edit(const std::string& target_event_id,
                             const std::string& replacement_event_id) {
    std::lock_guard lock(mutex_);
    // Refuses on a redacted target: an edit must never resurrect content that
    // was deleted.
    auto stmt = prepare(db_,
        "UPDATE events SET edited_by = ? WHERE event_id = ? AND redacted_by IS NULL");
    sqlite3_bind_text(stmt.get(), 1, replacement_event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, target_event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    const bool applied = sqlite3_changes(db_) > 0;
    // Search must match what the timeline now shows. Re-derived from stored state
    // rather than from the replacement passed in, so this is correct however the
    // edit pointer got where it is.
    if (applied) refresh_search_for_event_locked(target_event_id);
    return applied;
}

std::optional<std::string> SqliteStore::get_edit_pointer(const std::string& event_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT edited_by FROM events WHERE event_id = ?");
    sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    if (sqlite3_column_type(stmt.get(), 0) == SQLITE_NULL) return std::nullopt;
    return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
}

std::optional<std::string> SqliteStore::find_reaction_event(const std::string& room_id,
                                                           const std::string& sender,
                                                           const std::string& target_event_id,
                                                           const std::string& key) {
    if (room_id.empty() || sender.empty() || target_event_id.empty()) return std::nullopt;
    std::lock_guard lock(mutex_);
    // The relation lives inside the content JSON, so this reads it with
    // json_extract rather than a column. `m.relates_to` has to be quoted in the
    // path: an unquoted dot is a path separator, so '$.m.relates_to.event_id'
    // would look for a member "relates_to" of a member "m" and always miss.
    //
    // Narrowed by (room_id, event_type, sender) before any JSON is touched, and
    // reactions are a small slice of a room, so this is not the scan it looks
    // like. redacted_by IS NULL is what keeps un-react/re-react working.
    auto stmt = prepare(db_,
        "SELECT event_id FROM events "
        " WHERE room_id = ? AND event_type = ? AND sender = ? AND redacted_by IS NULL "
        "   AND json_valid(content) "
        "   AND json_extract(content, '$.\"m.relates_to\".event_id') = ? "
        "   AND IFNULL(json_extract(content, '$.\"m.relates_to\".key'), '') = ? "
        " ORDER BY stream_position ASC LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, std::string(event_type::kReaction).c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, sender.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, target_event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, key.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    return column_text_or_empty(stmt.get(), 0);
}

bool SqliteStore::is_event_redacted(const std::string& event_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT redacted_by FROM events WHERE event_id = ?");
    sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return false;
    return sqlite3_column_type(stmt.get(), 0) != SQLITE_NULL;
}

void SqliteStore::reresolve_edit_locked(const std::string& room_id,
                                        const std::string& target_event_id) {
    // Find the newest surviving replacement of `target_event_id`. The candidate
    // set is narrowed with a LIKE on the target's event id — event ids are
    // random and unique, so this is highly selective — and then confirmed by
    // parsing the relation in C++. Deliberately NOT json_extract(): the path
    // would be `$."m.relates_to".rel_type`, and quoted JSON path labels are
    // only supported by recent SQLite builds.
    std::optional<std::string> winner;
    {
        auto sel = prepare(db_,
            "SELECT event_id, content FROM events "
            "WHERE room_id = ? AND event_type = 'm.room.message' AND redacted_by IS NULL "
            "  AND content LIKE '%' || ? || '%' "
            "ORDER BY stream_position DESC");
        sqlite3_bind_text(sel.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(sel.get(), 2, target_event_id.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(sel.get()) == SQLITE_ROW) {
            auto content = nlohmann::json::parse(column_text_or_empty(sel.get(), 1), nullptr, false);
            if (content.is_discarded() || !content.is_object()) continue;
            auto rel = content.find("m.relates_to");
            if (rel == content.end() || !rel->is_object()) continue;
            if (rel->value("rel_type", "") != "m.replace") continue;
            if (rel->value("event_id", "") != target_event_id) continue;
            winner = column_text_or_empty(sel.get(), 0);
            break;
        }
    }

    auto upd = prepare(db_, "UPDATE events SET edited_by = ? WHERE event_id = ?");
    if (winner) {
        sqlite3_bind_text(upd.get(), 1, winner->c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(upd.get(), 1);
    }
    sqlite3_bind_text(upd.get(), 2, target_event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(upd.get());
}

std::vector<std::string> SqliteStore::edit_family_locked(const std::string& event_id) {
    // A ceiling rather than a correctness bound: the walk already refuses to
    // revisit an id, so this only caps how much work one request can cause if
    // somebody points ten thousand relations at one message. Exceeding it is
    // logged, because it would mean a redaction that did not finish.
    constexpr size_t kMaxFamily = 512;

    std::vector<std::string> family{event_id};
    std::unordered_set<std::string> seen{event_id};
    for (size_t i = 0; i < family.size(); ++i) {
        auto sel = prepare(db_, "SELECT event_id FROM events WHERE replaces = ?");
        sqlite3_bind_text(sel.get(), 1, family[i].c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(sel.get()) == SQLITE_ROW) {
            std::string child = column_text_or_empty(sel.get(), 0);
            if (child.empty() || !seen.insert(child).second) continue;
            if (family.size() >= kMaxFamily) {
                get_logger()->error(
                    "Redaction of {} stopped after {} related events; some edits may still "
                    "carry the redacted text and must be removed by hand.",
                    event_id, kMaxFamily);
                return family;
            }
            family.push_back(std::move(child));
        }
    }
    return family;
}

bool SqliteStore::redact_event(const std::string& event_id, const std::string& redacted_by) {
    std::lock_guard lock(mutex_);

    // Capture the relation before the content is stripped: if this event is
    // itself a replacement, its target has to be re-resolved afterwards.
    std::string room_id;
    std::optional<std::string> replaced_target;
    {
        auto sel = prepare(db_, "SELECT room_id, content FROM events WHERE event_id = ?");
        sqlite3_bind_text(sel.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(sel.get()) != SQLITE_ROW) return false;
        room_id = column_text_or_empty(sel.get(), 0);
        auto content = nlohmann::json::parse(column_text_or_empty(sel.get(), 1), nullptr, false);
        if (!content.is_discarded() && content.is_object()) {
            auto rel = content.find("m.relates_to");
            if (rel != content.end() && rel->is_object() &&
                rel->value("rel_type", "") == "m.replace") {
                auto target = rel->value("event_id", "");
                if (!target.empty()) replaced_target = target;
            }
        }
    }

    // One transaction for the whole family. A redaction that stripped the
    // original and then failed before reaching its edits would leave the text
    // on display under a message the user has been told is deleted, which is
    // the worst of the three possible outcomes; all-or-nothing means a failed
    // redaction can be retried and still means something.
    exec("BEGIN IMMEDIATE");
    try {
        // Everything that can carry this message's text, target first.
        const auto family = edit_family_locked(event_id);

        // Matrix redaction: the event row survives as a tombstone (same id,
        // type, sender and timestamp) but its content is stripped. Previously
        // the server only appended an m.room.redaction event and left the
        // original intact, so "deleted" messages were still fully readable from
        // /rooms/{id}/messages.
        //
        // edited_by is cleared in the same statement: deleting a message that
        // had been edited must not leave the edit behind to be resolved back
        // into view.
        auto stmt = prepare(db_,
            "UPDATE events SET content = '{}', edited_by = NULL, redacted_by = ? "
            "WHERE event_id = ? AND redacted_by IS NULL");
        sqlite3_bind_text(stmt.get(), 1, redacted_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, event_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt.get());
        const bool newly_redacted = sqlite3_changes(db_) > 0;

        // The replacements are stripped whether or not the target was newly
        // redacted, and that is deliberate: a message redacted by an earlier
        // build still has its edits intact, and re-running /redact on it is the
        // one thing an operator or a user can do to finish the job. Migration
        // v20 repairs the ones nobody thinks to redact twice.
        //
        // A tombstoned replacement keeps its relation and nothing else. The
        // spec preserves content.m.relates_to through redaction, and it is what
        // lets a client recognise the empty row as an edit and hide it instead
        // of drawing a blank message under the one it just saw deleted.
        {
            // The relation is rebuilt from the row's own `replaces` column, not
            // from the id being redacted: an edit of an edit must keep pointing
            // at the version it actually replaced.
            auto strip = prepare(db_,
                "UPDATE events "
                "   SET content = json_object('m.relates_to', "
                "                             json_object('rel_type', 'm.replace', "
                "                                         'event_id', replaces)), "
                "       edited_by = NULL, redacted_by = ? "
                " WHERE event_id = ? AND redacted_by IS NULL");
            auto drop_mentions = prepare(db_, "DELETE FROM event_mentions WHERE event_id = ?");
            for (size_t i = 1; i < family.size(); ++i) {
                sqlite3_reset(strip.get());
                sqlite3_bind_text(strip.get(), 1, redacted_by.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(strip.get(), 2, family[i].c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(strip.get());

                // An edit never records mentions (EventHandler skips extraction
                // for replacements), so this normally deletes nothing. It costs
                // one statement and removes the need to be sure of that.
                sqlite3_reset(drop_mentions.get());
                sqlite3_bind_text(drop_mentions.get(), 1, family[i].c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(drop_mentions.get());

                // A replacement is not indexed as itself, so this is a no-op
                // today. It goes through the one choke point anyway: if that
                // ever changes, the index must not be the thing that remembers.
                refresh_search_for_event_locked(family[i]);
            }
        }

        // A redacted message must stop badging anybody: its content is gone, so
        // a mention inside it can no longer be read and must not keep a
        // highlight lit. Inlined rather than calling delete_mentions_for_event()
        // — mutex_ is already held here.
        if (newly_redacted) {
            auto del = prepare(db_, "DELETE FROM event_mentions WHERE event_id = ?");
            sqlite3_bind_text(del.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(del.get());
        }


        // ...and stop granting media access through it. The content no longer
        // names the mxc id, so leaving the ACL row would keep the object
        // fetchable by everyone who had already seen the event. Inside the
        // transaction with the rest, so a rollback cannot strip the grant from
        // a redaction that did not land.
        //
        // The blob itself still survives — nothing deletes media (audit B11) —
        // so someone who noted the id keeps their copy. Narrowing the grant is
        // what this row can do.
        if (newly_redacted) {
            auto delm = prepare(db_, "DELETE FROM media_refs WHERE event_id = ?");
            sqlite3_bind_text(delm.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(delm.get());
        }

        // Deleting an edit rolls its target back to the newest edit that
        // survives, or to the pristine original when none does.
        if (newly_redacted && replaced_target) {
            reresolve_edit_locked(room_id, *replaced_target);
            // ...and search follows it back, so a deleted edit's words stop
            // matching and the surviving text starts matching again.
            refresh_search_for_event_locked(*replaced_target);
        }
        // Redacted content must not be searchable. refresh_ recomputes to
        // "nothing" because the row now has redacted_by set.
        if (newly_redacted) refresh_search_for_event_locked(event_id);

        // The last copy: a notification carrying this text may already be
        // queued for a gateway that was unreachable when the message was sent.
        // Delivery is out of band and can be an hour behind, so a redaction
        // that does not reach the queue is a redaction the recipient's phone
        // will contradict.
        delete_queued_pushes_for_events_locked(family);

        exec("COMMIT");
    } catch (...) {
        try {
            exec("ROLLBACK");
        } catch (...) {
        }
        throw;
    }
    return true; // the row exists; already-redacted counts as success
}

std::optional<std::string> SqliteStore::get_transaction_event(const TransactionKey& key) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT event_id FROM event_transactions "
        " WHERE user_id = ? AND device_id = ? AND room_id = ? AND txn_id = ?");
    sqlite3_bind_text(stmt.get(), 1, key.user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, key.device_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, key.room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, key.txn_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return column_text_or_empty(stmt.get(), 0);
    }
    return std::nullopt;
}

void SqliteStore::record_transaction(const TransactionKey& key, const std::string& event_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR IGNORE INTO event_transactions "
        "  (user_id, device_id, room_id, txn_id, event_id) VALUES (?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, key.user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, key.device_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, key.room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, key.txn_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::optional<std::string>
SqliteStore::get_redaction_transaction_event(const RedactionKey& key) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT event_id FROM redaction_transactions "
        " WHERE user_id = ? AND device_id = ? AND room_id = ? AND target_event_id = ? "
        "   AND txn_id = ?");
    sqlite3_bind_text(stmt.get(), 1, key.user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, key.device_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, key.room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, key.target_event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, key.txn_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return column_text_or_empty(stmt.get(), 0);
    }
    return std::nullopt;
}

void SqliteStore::record_redaction_transaction(const RedactionKey& key,
                                                const std::string& event_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR IGNORE INTO redaction_transactions "
        "  (user_id, device_id, room_id, target_event_id, txn_id, event_id) "
        "  VALUES (?, ?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, key.user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, key.device_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, key.room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, key.target_event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, key.txn_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

SqliteStore::ServerStateWrite SqliteStore::set_server_state(
    const std::string& event_type, const std::string& state_key, const std::string& sender,
    const std::string& content_json, const ExpectedServerState* expected) {
    std::lock_guard lock(mutex_);

    // The content about to be replaced, read under the same lock as the write so
    // the caller's audit record cannot attribute a "before" that another writer
    // already overwrote. Inlined rather than calling get_server_state(), which
    // would deadlock on the same non-recursive mutex.
    std::optional<std::string> previous;
    {
        auto sel = prepare(db_,
            "SELECT content FROM server_state WHERE event_type = ? AND state_key = ?");
        sqlite3_bind_text(sel.get(), 1, event_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(sel.get(), 2, state_key.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(sel.get()) == SQLITE_ROW) {
            previous = reinterpret_cast<const char*>(sqlite3_column_text(sel.get(), 0));
        }
    }

    // The compare half, still under the same lock as the read above and the
    // write below — which is the whole of the guarantee. Compared as raw text
    // rather than as parsed JSON: every writer of this table serialises through
    // the same nlohmann to_json/dump, so a semantically identical document is
    // byte-identical, and a caller that somehow produced different key ordering
    // gets a spurious conflict and a retry rather than a lost update. Failing
    // in that direction is the only acceptable way to be wrong here.
    if (expected != nullptr && previous != *expected) {
        return {/*applied=*/false, std::move(previous)};
    }

    auto stmt = prepare(db_,
        "INSERT INTO server_state (event_type, state_key, sender, content, updated_at) "
        "VALUES (?, ?, ?, ?, strftime('%s','now') * 1000) "
        "ON CONFLICT(event_type, state_key) DO UPDATE SET "
        "  sender = excluded.sender, content = excluded.content, updated_at = excluded.updated_at");
    sqlite3_bind_text(stmt.get(), 1, event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, state_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, sender.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, content_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return {/*applied=*/true, std::move(previous)};
}

std::optional<std::string> SqliteStore::get_server_state(const std::string& event_type,
                                                          const std::string& state_key) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT content FROM server_state WHERE event_type = ? AND state_key = ?");
    sqlite3_bind_text(stmt.get(), 1, event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, state_key.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

std::optional<std::string> SqliteStore::get_meta(const std::string& key) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT value FROM server_meta WHERE key = ?");
    sqlite3_bind_text(stmt.get(), 1, key.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

void SqliteStore::set_meta(const std::string& key, const std::string& value) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO server_meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    sqlite3_bind_text(stmt.get(), 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::vector<RoomEvent> SqliteStore::get_invite_state(const std::string& room_id,
                                                      const std::string& invitee) {
    std::lock_guard lock(mutex_);

    // Latest event per (type, state_key), like get_state_events — but the
    // whitelist is inside the subquery, so a row outside it is never read at
    // all. See the header for what is on the list and why.
    //
    // No kEditJoin: state events are not editable, and an invitee has no
    // business resolving edits in a room they have not joined.
    const std::string room_level_types =
        std::string("'") + std::string(event_type::kRoomCreate) + "','" +
        std::string(event_type::kRoomName) + "','" +
        std::string(event_type::kRoomTopic) + "','" +
        std::string(event_type::kRoomAvatar) + "','" +
        std::string(event_type::kRoomJoinRules) + "','" +
        std::string(event_type::kRoomCanonicalAlias) + "','" +
        std::string(event_type::kRoomType) + "'";

    // ?1 room, ?2 the member state key wanted on this pass. `with_room_level`
    // is false on the second pass: the room's own state does not depend on
    // which member is being asked for, and re-selecting it would put every
    // name, topic and join rule in the response twice.
    auto build_sql = [&](bool with_room_level) {
        std::string want =
            with_room_level
                ? "((state_key = '' AND event_type IN (" + room_level_types + ")) OR "
                : "(";
        want += "(event_type = '" + std::string(event_type::kRoomMember) +
                "' AND state_key = ?2))";
        return "SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content, "
               "       e.origin_server_ts, e.stream_position "
               "FROM events e "
               "INNER JOIN (SELECT event_type, state_key, MAX(stream_position) AS max_pos "
               "            FROM events "
               "            WHERE room_id = ?1 AND state_key IS NOT NULL "
               "              AND " + want + " "
               "            GROUP BY event_type, state_key) latest "
               "ON e.event_type = latest.event_type AND e.state_key = latest.state_key "
               "   AND e.stream_position = latest.max_pos "
               "WHERE e.room_id = ?1";
    };

    // (stream_position, event), so the caller gets them in the order the room
    // acquired them regardless of which pass found them. Deterministic output
    // is what makes this testable.
    std::vector<std::pair<int64_t, RoomEvent>> found;
    auto run = [&](const std::string& member_state_key, bool with_room_level) {
        auto stmt = prepare(db_, build_sql(with_room_level));
        sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, member_state_key.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            RoomEvent ev;
            ev.event_id = column_text_or_empty(stmt.get(), 0);
            ev.room_id = column_text_or_empty(stmt.get(), 1);
            ev.sender = column_text_or_empty(stmt.get(), 2);
            ev.type = column_text_or_empty(stmt.get(), 3);
            if (sqlite3_column_type(stmt.get(), 4) != SQLITE_NULL) {
                ev.state_key = column_text_or_empty(stmt.get(), 4);
            }
            ev.content.data =
                nlohmann::json::parse(column_text_or_empty(stmt.get(), 5), nullptr, false);
            if (ev.content.data.is_discarded()) ev.content.data = nlohmann::json::object();
            ev.origin_server_ts = sqlite3_column_int64(stmt.get(), 6);
            found.emplace_back(sqlite3_column_int64(stmt.get(), 7), std::move(ev));
        }
    };

    run(invitee, true);

    // The inviter is whoever sent the invitee's member event — there is no
    // other record of it, which is why this is a second pass rather than one
    // query with both state keys bound up front.
    std::string inviter;
    for (const auto& [pos, ev] : found) {
        if (ev.type == std::string(event_type::kRoomMember) && ev.state_key == invitee) {
            inviter = ev.sender;
        }
    }
    if (!inviter.empty() && inviter != invitee) run(inviter, false);

    std::sort(found.begin(), found.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::vector<RoomEvent> events;
    events.reserve(found.size());
    for (auto& [pos, ev] : found) events.push_back(std::move(ev));
    return events;
}

uint64_t SqliteStore::voice_key_generation_locked(const std::string& room_id) {
    // One statement, so a channel with no row and a channel whose row was just
    // written are answered by the same read and cannot disagree. The trailing
    // 0 is unreachable in practice — migration v20 always writes the baseline —
    // and is here only so a hand-edited database cannot make this throw.
    auto stmt = prepare(db_,
        "SELECT COALESCE("
        "  (SELECT generation FROM voice_key_generations WHERE room_id = ?1),"
        "  (SELECT CAST(value AS INTEGER) FROM server_meta"
        "    WHERE key = 'voice.key_generation_baseline'),"
        "  0)");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return 0;
    const int64_t value = sqlite3_column_int64(stmt.get(), 0);
    return value < 0 ? 0 : static_cast<uint64_t>(value);
}

uint64_t SqliteStore::get_voice_key_generation(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    return voice_key_generation_locked(room_id);
}

SqliteStore::VoiceKeyRotation SqliteStore::bump_voice_key_generation(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    exec("BEGIN IMMEDIATE");
    try {
        const uint64_t current = voice_key_generation_locked(room_id);
        const auto now_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        // See the header: the clock floor is what a restored backup cannot
        // rewind, and current + 1 is what a rewound clock cannot break.
        const uint64_t next = std::max(current + 1, now_ms);

        auto stmt = prepare(db_,
            "INSERT INTO voice_key_generations (room_id, generation, rotated_at) "
            "VALUES (?1, ?2, ?3) "
            "ON CONFLICT(room_id) DO UPDATE SET "
            // MAX(), not a plain assignment. Belt to the braces of the read
            // above: no path through this statement can lower a generation.
            "  generation = MAX(excluded.generation, voice_key_generations.generation), "
            "  rotated_at = excluded.rotated_at");
        sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 2, static_cast<int64_t>(next));
        sqlite3_bind_int64(stmt.get(), 3, static_cast<int64_t>(now_ms));
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            throw std::runtime_error(std::string("could not persist the media-key generation: ") +
                                     sqlite3_errmsg(db_));
        }

        // Read back rather than return `next`: the caller derives a key from
        // this number and tells every client it is the current one, so it has
        // to be the number on disk and not the one we hoped to write.
        const uint64_t stored = voice_key_generation_locked(room_id);
        exec("COMMIT");
        return VoiceKeyRotation{current, stored};
    } catch (...) {
        exec("ROLLBACK");
        throw;
    }
}

std::optional<RoomEvent> SqliteStore::get_state_event(const std::string& room_id,
                                                       const std::string& event_type,
                                                       const std::string& state_key) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT event_id, room_id, sender, event_type, state_key, content, origin_server_ts "
        "FROM events WHERE room_id = ? AND event_type = ? AND state_key = ? "
        "ORDER BY stream_position DESC LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, state_key.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        RoomEvent ev;
        ev.event_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        ev.room_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        ev.sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        ev.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        if (sqlite3_column_type(stmt.get(), 4) != SQLITE_NULL) {
            ev.state_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        }
        ev.content.data = nlohmann::json::parse(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5)));
        ev.origin_server_ts = sqlite3_column_int64(stmt.get(), 6);
        // Same reason as in get_state_events above.
        stamp_bot_flag(ev);
        return ev;
    }
    return std::nullopt;
}

// Sync

std::vector<RoomEvent> SqliteStore::get_events_since(const std::string& user_id, int64_t since_position,
                                                     int64_t& out_max_position, int limit) {
    int64_t ignored_head = since_position;
    return get_events_since(user_id, since_position, out_max_position, ignored_head, limit);
}

std::vector<RoomEvent> SqliteStore::get_events_since(const std::string& user_id, int64_t since_position,
                                                     int64_t& out_max_position,
                                                     int64_t& out_stream_head, int limit) {
    std::lock_guard lock(mutex_);

    out_max_position = since_position;
    // Sampled inside the lock, together with the scan below. insert_event
    // claims its position and commits its transaction while holding this same
    // mutex_, so while we hold it there is no position that has been issued
    // but not yet committed: everything at or below this head is in the table
    // now and is therefore offered to the statement we are about to run.
    out_stream_head = next_stream_position_ - 1;

    // The recipient filter. Addressed call signalling reaches exactly two
    // people: the sender and the addressee named in its content. Room
    // membership is no longer enough to see one, and that is the whole of
    // deliverable 1 on the /sync side — see store/CallSignalling.h.
    //
    // A NULL `signal_to` is every ordinary event and every unaddressed one, and
    // passes untouched, so nothing about chat, state or legacy clients changes
    // here.
    //
    // This is a residual test over a range scan on stream_position, not an
    // index lookup: the scan is already bounded by `since_position` and the
    // limit, and the column is NULL for all but a two-minute window of rows.
    //
    // Filtered rows are NOT a hole in the sync token. Excluding a row makes the
    // scan return fewer than `limit`, and the caller (SyncEngine) then advances
    // next_batch to the scan's own head — so a poll woken by somebody else's
    // candidate batch comes back with a token that has MOVED, and the client's
    // no-progress backoff never sees it. That interplay is why this filter is
    // here and not in the loop above SyncEngine's own permission check.
    //
    // The membership filter used to be `rm.membership = 'join'` in the JOIN
    // condition, which is why a human account could not see it had been
    // invited anywhere: an invite writes a room_members row with membership
    // 'invite', that row matched nothing, and so the m.room.member event
    // announcing the invite was never on any stream the invitee polled.
    //
    // A joined member still gets the whole room. An INVITED one gets exactly
    // one kind of row from it — their own m.room.member — and never any other
    // event, whatever its type. That is the leak boundary, and it is here in
    // the SQL rather than in SyncEngine's loop on purpose: a room the reader
    // has not joined must not be able to put history on the wire because some
    // caller further out forgot to filter it. SyncEngine reads those rows as a
    // trigger to build rooms.invite from the stripped state, never as timeline.
    //
    // It also means the invite advances out_max_position like any other row, so
    // next_batch covers it and no later sync has a hole where it was.
    auto stmt = prepare(db_,
        std::string("SELECT ") + kEventColumns + ", e.stream_position "
        "FROM events e "
        "INNER JOIN room_members rm ON e.room_id = rm.room_id AND rm.user_id = ?1 " +
        kEditJoin +
        "WHERE e.stream_position > ?2 "
        "AND (rm.membership = 'join' "
        "     OR (rm.membership = 'invite' "
        "         AND e.event_type = '" + std::string(event_type::kRoomMember) + "' "
        "         AND e.state_key = ?1)) "
        "AND (e.signal_to IS NULL OR e.signal_to = ?1 OR e.sender = ?1) "
        "ORDER BY e.stream_position ASC "
        "LIMIT ?3");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, since_position);
    sqlite3_bind_int(stmt.get(), 3, limit);

    std::vector<RoomEvent> events;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        // Explicit template argument: int64_t is `long` on 64-bit Linux but
        // `long long` on macOS, while sqlite3_int64 is always `long long`.
        // Unqualified std::max() therefore deduces two different types and
        // fails to compile on Linux — which is what the Docker image builds.
        out_max_position = std::max<int64_t>(
            out_max_position, sqlite3_column_int64(stmt.get(), 11));
        events.push_back(read_event_row(stmt.get()));
    }
    return events;
}

std::vector<RoomEvent> SqliteStore::get_events_since(const std::string& user_id, int64_t since_position,
                                                     int limit) {
    int64_t ignored = since_position;
    return get_events_since(user_id, since_position, ignored, limit);
}

int64_t SqliteStore::get_current_stream_position() {
    std::lock_guard lock(mutex_);
    // The highest position ever issued, NOT MAX(stream_position) — deleting a
    // room must not rewind the stream head under clients that already hold a
    // token past it.
    return next_stream_position_ - 1;
}

int SqliteStore::prune_expired_call_signalling(int64_t now_ms) {
    std::lock_guard lock(mutex_);
    const int64_t cutoff = now_ms - limits::kCallSignallingTtlMs;

    // Two statements, one transaction. The event rows are the point; the
    // idempotency rows are bookkeeping that would otherwise accumulate one row
    // per candidate batch per call, forever, pointing at events that no longer
    // exist. Nothing else references events(event_id) for these types:
    // event_mentions is only ever written for messages, and event_search only
    // indexes m.room.message.
    exec("BEGIN IMMEDIATE");
    try {
        std::vector<std::string> doomed;
        {
            auto sel = prepare(db_,
                "SELECT event_id FROM events "
                "WHERE signal_to IS NOT NULL AND origin_server_ts < ?");
            sqlite3_bind_int64(sel.get(), 1, cutoff);
            while (sqlite3_step(sel.get()) == SQLITE_ROW) {
                doomed.emplace_back(column_text_or_empty(sel.get(), 0));
            }
        }
        if (!doomed.empty()) {
            auto del = prepare(db_, "DELETE FROM events WHERE event_id = ?");
            auto del_txn = prepare(db_, "DELETE FROM event_transactions WHERE event_id = ?");
            for (const auto& id : doomed) {
                sqlite3_reset(del.get());
                sqlite3_bind_text(del.get(), 1, id.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(del.get()) != SQLITE_DONE) {
                    throw std::runtime_error(std::string("signalling prune failed: ") +
                                             sqlite3_errmsg(db_));
                }
                sqlite3_reset(del_txn.get());
                sqlite3_bind_text(del_txn.get(), 1, id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(del_txn.get());
            }
        }
        exec("COMMIT");
        return static_cast<int>(doomed.size());
    } catch (...) {
        try {
            exec("ROLLBACK");
        } catch (...) {
        }
        throw;
    }
}

int64_t SqliteStore::get_room_max_stream_position(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT COALESCE(MAX(stream_position), 0) FROM events WHERE room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return sqlite3_column_int64(stmt.get(), 0);
}

// Read markers

void SqliteStore::set_read_marker(const std::string& user_id, const std::string& room_id, int64_t stream_pos) {
    std::lock_guard lock(mutex_);
    // Upsert, but only move forward. ON CONFLICT uses MAX(existing, new).
    auto stmt = prepare(db_,
        "INSERT INTO read_markers (user_id, room_id, last_read_pos) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id, room_id) DO UPDATE SET last_read_pos = "
        "CASE WHEN excluded.last_read_pos > read_markers.last_read_pos "
        "THEN excluded.last_read_pos ELSE read_markers.last_read_pos END");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, stream_pos);
    sqlite3_step(stmt.get());
}

int64_t SqliteStore::get_read_marker(const std::string& user_id, const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT last_read_pos FROM read_markers WHERE user_id = ? AND room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return sqlite3_column_int64(stmt.get(), 0);
    }
    return 0;
}

int SqliteStore::count_unread(const std::string& user_id, const std::string& room_id) {
    std::lock_guard lock(mutex_);
    // `replaces IS NULL` — an m.replace replacement is a rewrite of a message
    // the reader has already been told about, not a new message. Without this,
    // anyone editing their own text bumped the unread badge for every other
    // member of the room.
    //
    // `redacted_by IS NULL` — the same bug in the other direction: a deleted
    // message kept its badge lit forever, inviting the reader to open a room to
    // find content that no longer exists.
    auto stmt = prepare(db_,
        "SELECT COUNT(*) FROM events "
        "WHERE room_id = ? AND event_type = 'm.room.message' "
        "AND sender != ? "
        "AND replaces IS NULL "
        "AND redacted_by IS NULL "
        "AND stream_position > COALESCE("
        "  (SELECT last_read_pos FROM read_markers WHERE user_id = ? AND room_id = ?), 0)");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return sqlite3_column_int(stmt.get(), 0);
    }
    return 0;
}

bool SqliteStore::room_has_messages(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    // LIMIT 1 rather than COUNT(*): the caller only needs existence, and
    // counting would walk every message in a channel that may hold years of
    // history to answer a yes/no. idx_events_room_stream confines the scan to
    // this room; the worst case is a room with no messages at all, whose rows
    // are its state events and therefore few. This runs only on an
    // administrator retyping a room, so it is not on any hot path.
    auto stmt = prepare(db_,
        "SELECT 1 FROM events "
        "WHERE room_id = ? AND event_type = 'm.room.message' LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

// Mentions
//
// Every write here originates from the send path, which has already established
// that (a) `sender` is the authenticated user and (b) each mentioned user is a
// joined member of the room with VIEW_CHANNEL. There is no handler that lets a
// client name the `sender` of a mention, which is what makes the badge
// unforgeable.

void SqliteStore::record_mentions(const std::string& event_id, const std::string& room_id,
                                  const std::string& sender, int64_t stream_position,
                                  const std::vector<std::string>& mentioned_user_ids) {
    if (mentioned_user_ids.empty()) return;
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR IGNORE INTO event_mentions "
        "  (event_id, room_id, user_id, sender, stream_position) VALUES (?, ?, ?, ?, ?)");
    for (const auto& target : mentioned_user_ids) {
        if (target.empty()) continue;
        // Mentioning yourself must never badge your own room. Enforced here as
        // well as at extraction time so the invariant holds for every caller.
        if (target == sender) continue;
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 3, target.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, sender.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 5, stream_position);
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            throw std::runtime_error(std::string("Failed to record mention: ") +
                                     sqlite3_errmsg(db_));
        }
    }
}

std::vector<std::string> SqliteStore::get_event_mentions(const std::string& event_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT user_id FROM event_mentions WHERE event_id = ?");
    sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    std::vector<std::string> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        out.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return out;
}

void SqliteStore::delete_mentions_for_event(const std::string& event_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM event_mentions WHERE event_id = ?");
    sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

// Every "user id" a read of `user_id`'s mentions must match: the user
// themselves, the @room sentinel, and one sentinel per role they hold.
//
// This is the whole of the role-mention fan-out, and it is why a role with 500
// members costs nothing to mention. The alternative — expanding the role to its
// holders at SEND time — writes one row per member, on the request thread,
// while holding the store's global mutex, for a message that most of those
// members will never come back to read. Here the send writes one row and each
// reader pays for their own badge, at their own /sync, proportional to the
// number of roles THEY hold (in practice one to three) rather than to the size
// of the role.
//
// MUST be called before taking mutex_: get_member_role_ids() reads server_state
// and takes the lock itself, and mutex_ is not recursive.
std::vector<std::string> SqliteStore::mention_match_keys(const std::string& user_id) {
    std::vector<std::string> keys;
    auto role_ids = get_member_role_ids(user_id);
    keys.reserve(role_ids.size() + 2);
    keys.push_back(user_id);
    keys.emplace_back(kRoomMentionSentinel);
    for (const auto& role_id : role_ids) {
        // @everyone is every member's role, so a sentinel for it would be an
        // @room mention that skipped the MENTION_EVERYONE gate. The send path
        // refuses to record one; matching it here would be the second half of
        // that bug, so this end declines too.
        if (role_id.empty() || role_id == permission::role_id::kEveryone) continue;
        keys.push_back(role_mention_sentinel(role_id));
    }
    return keys;
}

namespace {
// "?, ?, ?" for an IN list of `n` values.
std::string placeholders(size_t n) {
    std::string out;
    for (size_t i = 0; i < n; ++i) out += (i == 0) ? "?" : ", ?";
    return out;
}
} // namespace

int SqliteStore::count_unread_mentions(const std::string& user_id, const std::string& room_id) {
    // Before the lock — see mention_match_keys().
    const auto keys = mention_match_keys(user_id);

    std::lock_guard lock(mutex_);
    // Pure index range scan on idx_event_mentions_target — no join back to
    // events, because stream_position is denormalised onto the mention row.
    // The `user_id IN (...)` list picks up a direct mention, a room-wide one,
    // and a mention of any role the reader holds; `sender != ?` drops mentions
    // the reader made themselves.
    auto stmt = prepare(db_,
        "SELECT COUNT(*) FROM event_mentions "
        "WHERE room_id = ? AND user_id IN (" + placeholders(keys.size()) + ") AND sender != ? "
        "AND stream_position > COALESCE("
        "  (SELECT last_read_pos FROM read_markers WHERE user_id = ? AND room_id = ?), 0)");
    int p = 1;
    sqlite3_bind_text(stmt.get(), p++, room_id.c_str(), -1, SQLITE_TRANSIENT);
    for (const auto& key : keys) {
        sqlite3_bind_text(stmt.get(), p++, key.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt.get(), p++, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), p++, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), p++, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return sqlite3_column_int(stmt.get(), 0);
    }
    return 0;
}

std::map<std::string, int> SqliteStore::get_unread_mention_counts(const std::string& user_id) {
    // Before the lock — see mention_match_keys(). One extra server_state read
    // per /sync, not per room, so the grouped-query property this function
    // exists for is preserved.
    const auto keys = mention_match_keys(user_id);

    std::lock_guard lock(mutex_);
    // One grouped query for every room, rather than count_unread_mentions() in a
    // loop: /sync asks about every joined room on every poll, and each of those
    // calls would serialise behind this store's single global mutex.
    //
    // NOTE ON VISIBILITY: this answers "what has been aimed at this user",
    // across every room, with no VIEW_CHANNEL filter — and it must not grow
    // one, because it has no PermissionsEngine and adding a per-room permission
    // check here would put the thing this function was written to avoid (a
    // per-room query under the global mutex) back in. The filter belongs to the
    // caller, and SyncEngine applies it: a room the reader cannot view is never
    // in response.rooms.join at all, and a category stub is skipped before
    // highlight_count is set, so a count for such a room is computed and then
    // discarded. That matters more for role and @room sentinels than for direct
    // mentions, because a direct mention is ALSO filtered at write time (the
    // send path drops a target without VIEW_CHANNEL) whereas a sentinel row
    // cannot be — it names no one in particular. See the PushService for the
    // other delivery path, which does its own per-candidate check.
    auto stmt = prepare(db_,
        "SELECT m.room_id, COUNT(*) FROM event_mentions m "
        "WHERE m.user_id IN (" + placeholders(keys.size()) + ") AND m.sender != ? "
        "AND m.stream_position > COALESCE("
        "  (SELECT last_read_pos FROM read_markers r "
        "   WHERE r.user_id = ? AND r.room_id = m.room_id), 0) "
        "GROUP BY m.room_id");
    int p = 1;
    for (const auto& key : keys) {
        sqlite3_bind_text(stmt.get(), p++, key.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt.get(), p++, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), p++, user_id.c_str(), -1, SQLITE_TRANSIENT);

    std::map<std::string, int> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        out.emplace(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)),
                    sqlite3_column_int(stmt.get(), 1));
    }
    return out;
}

// Permissions / roles

std::vector<ServerRole> SqliteStore::get_server_roles() {
    // Reads server_state (primary-key lookup), not events. The old query
    // filtered events on (event_type, state_key) with no room_id, which the
    // only usable index — (room_id, event_type, state_key) — could not serve,
    // so every permission check full-scanned and sorted the entire events
    // table under the store's single global mutex.
    auto content_json = get_server_state(std::string(event_type::kServerRoles), "");
    if (!content_json) return {};
    auto json = nlohmann::json::parse(*content_json, nullptr, false);
    if (json.is_discarded()) return {};
    ServerRolesContent content;
    from_json(json, content);
    return content.roles;
}

std::vector<std::string> SqliteStore::get_member_role_ids(const std::string& user_id) {
    auto content_json = get_server_state(std::string(event_type::kMemberRoles), user_id);
    if (!content_json) return {};
    auto json = nlohmann::json::parse(*content_json, nullptr, false);
    if (json.is_discarded()) return {};
    MemberRolesContent content;
    from_json(json, content);
    return content.role_ids;
}

std::vector<std::string> SqliteStore::rooms_with_channel_overrides() {
    std::lock_guard lock(mutex_);
    std::string type(event_type::kChannelPermissions);
    auto stmt = prepare(db_,
        "SELECT DISTINCT room_id FROM events WHERE event_type = ? AND state_key IS NOT NULL");
    sqlite3_bind_text(stmt.get(), 1, type.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

std::map<std::string, ChannelPermissionOverride>
SqliteStore::get_channel_overrides(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    // Latest event per state_key for this room and type.
    std::string type(event_type::kChannelPermissions);
    auto stmt = prepare(db_,
        "SELECT e.state_key, e.content FROM events e "
        "INNER JOIN (SELECT state_key, MAX(stream_position) AS mp FROM events "
        "            WHERE room_id = ? AND event_type = ? AND state_key IS NOT NULL "
        "            GROUP BY state_key) latest "
        "ON e.state_key = latest.state_key AND e.stream_position = latest.mp "
        "WHERE e.room_id = ? AND e.event_type = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, type.c_str(), -1, SQLITE_TRANSIENT);

    std::map<std::string, ChannelPermissionOverride> overrides;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        std::string key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        auto json = nlohmann::json::parse(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1)), nullptr, false);
        if (json.is_discarded()) continue;
        ChannelPermissionOverride ov;
        from_json(json, ov);
        if (ov.allow == 0 && ov.deny == 0) continue; // skip empty
        overrides[std::move(key)] = ov;
    }
    return overrides;
}

int SqliteStore::get_channel_slowmode(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    std::string type(event_type::kChannelSettings);
    auto stmt = prepare(db_,
        "SELECT content FROM events "
        "WHERE room_id = ? AND event_type = ? AND state_key = '' "
        "ORDER BY stream_position DESC LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, type.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return 0;
    auto json = nlohmann::json::parse(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)), nullptr, false);
    if (json.is_discarded()) return 0;
    return json.value("slowmode_seconds", 0);
}

int64_t SqliteStore::get_last_message_ts(const std::string& user_id, const std::string& room_id) {
    std::lock_guard lock(mutex_);
    std::string type(event_type::kRoomMessage);
    auto stmt = prepare(db_,
        "SELECT MAX(origin_server_ts) FROM events "
        "WHERE room_id = ? AND sender = ? AND event_type = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, type.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return 0;
    if (sqlite3_column_type(stmt.get(), 0) == SQLITE_NULL) return 0;
    return sqlite3_column_int64(stmt.get(), 0);
}

std::vector<std::pair<std::string, int64_t>> SqliteStore::list_users_with_created_at() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT user_id, created_at FROM users ORDER BY created_at ASC");
    std::vector<std::pair<std::string, int64_t>> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        out.emplace_back(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)),
            sqlite3_column_int64(stmt.get(), 1));
    }
    return out;
}

// ── Message search (FTS5, external content over event_search) ─────────────

bool SqliteStore::fts5_available_locked() {
    if (fts5_available_ < 0) {
        auto stmt = prepare(db_,
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'event_search_fts'");
        fts5_available_ = (sqlite3_step(stmt.get()) == SQLITE_ROW &&
                           sqlite3_column_int(stmt.get(), 0) > 0) ? 1 : 0;
    }
    return fts5_available_ == 1;
}

bool SqliteStore::search_index_available() {
    std::lock_guard lock(mutex_);
    return fts5_available_locked();
}

void SqliteStore::reindex_search_locked(const std::string& event_id, const std::string& room_id,
                                        const std::string& sender, int64_t stream_position,
                                        const std::optional<std::string>& body) {
    const bool fts5 = fts5_available_locked();

    // Existing shadow row, if any. Its rowid and OLD body are both required: an
    // external-content FTS5 index is told to forget a document by replaying the
    // exact text it was indexed with.
    std::optional<int64_t> existing_rowid;
    std::string old_body;
    {
        auto sel = prepare(db_, "SELECT rowid, body FROM event_search WHERE event_id = ?");
        sqlite3_bind_text(sel.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(sel.get()) == SQLITE_ROW) {
            existing_rowid = sqlite3_column_int64(sel.get(), 0);
            old_body = column_text_or_empty(sel.get(), 1);
        }
    }

    auto forget = [&](int64_t rowid, const std::string& text) {
        if (!fts5) return;
        auto del = prepare(db_,
            "INSERT INTO event_search_fts (event_search_fts, rowid, body) "
            "VALUES ('delete', ?, ?)");
        sqlite3_bind_int64(del.get(), 1, rowid);
        sqlite3_bind_text(del.get(), 2, text.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(del.get());
    };
    auto remember = [&](int64_t rowid, const std::string& text) {
        if (!fts5) return;
        auto ins = prepare(db_, "INSERT INTO event_search_fts (rowid, body) VALUES (?, ?)");
        sqlite3_bind_int64(ins.get(), 1, rowid);
        sqlite3_bind_text(ins.get(), 2, text.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(ins.get());
    };

    const bool want_indexed = body.has_value() && !body->empty();

    if (existing_rowid && !want_indexed) {
        // Removal: redacted, or edited down to nothing.
        forget(*existing_rowid, old_body);
        auto del = prepare(db_, "DELETE FROM event_search WHERE rowid = ?");
        sqlite3_bind_int64(del.get(), 1, *existing_rowid);
        sqlite3_step(del.get());
        return;
    }
    if (!want_indexed) return;

    if (existing_rowid) {
        if (old_body == *body) return; // nothing changed
        forget(*existing_rowid, old_body);
        auto upd = prepare(db_,
            "UPDATE event_search SET room_id = ?, sender = ?, stream_position = ?, body = ? "
            "WHERE rowid = ?");
        sqlite3_bind_text(upd.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(upd.get(), 2, sender.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(upd.get(), 3, stream_position);
        sqlite3_bind_text(upd.get(), 4, body->c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(upd.get(), 5, *existing_rowid);
        sqlite3_step(upd.get());
        remember(*existing_rowid, *body);
        return;
    }

    auto ins = prepare(db_,
        "INSERT INTO event_search (event_id, room_id, sender, stream_position, body) "
        "VALUES (?, ?, ?, ?, ?)");
    sqlite3_bind_text(ins.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins.get(), 3, sender.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins.get(), 4, stream_position);
    sqlite3_bind_text(ins.get(), 5, body->c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(ins.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to index message for search: ") +
                                 sqlite3_errmsg(db_));
    }
    remember(sqlite3_last_insert_rowid(db_), *body);
}

void SqliteStore::refresh_search_for_event_locked(const std::string& event_id) {
    // Read the event's current state and derive what should be searchable:
    // nothing if it is redacted or is itself a replacement, otherwise the
    // resolved (post-edit) body.
    std::string room_id;
    std::string sender;
    int64_t stream_position = 0;
    std::string own_content;
    bool redacted = false;
    bool is_replacement = false;
    std::string edited_by;
    {
        auto sel = prepare(db_,
            "SELECT room_id, sender, stream_position, content, redacted_by, replaces, edited_by "
            "FROM events WHERE event_id = ?");
        sqlite3_bind_text(sel.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(sel.get()) != SQLITE_ROW) {
            reindex_search_locked(event_id, "", "", 0, std::nullopt);
            return;
        }
        room_id = column_text_or_empty(sel.get(), 0);
        sender = column_text_or_empty(sel.get(), 1);
        stream_position = sqlite3_column_int64(sel.get(), 2);
        own_content = column_text_or_empty(sel.get(), 3);
        redacted = sqlite3_column_type(sel.get(), 4) != SQLITE_NULL;
        is_replacement = sqlite3_column_type(sel.get(), 5) != SQLITE_NULL;
        if (sqlite3_column_type(sel.get(), 6) != SQLITE_NULL) {
            edited_by = column_text_or_empty(sel.get(), 6);
        }
    }

    // A replacement is not its own search result — it would be a duplicate hit
    // for a message that already has one.
    if (redacted || is_replacement) {
        reindex_search_locked(event_id, room_id, sender, stream_position, std::nullopt);
        return;
    }

    std::string body;
    if (!edited_by.empty()) {
        // Resolve through the winning replacement so search matches what the
        // timeline currently shows, not the pristine original.
        auto sel = prepare(db_,
            "SELECT content FROM events WHERE event_id = ? AND redacted_by IS NULL");
        sqlite3_bind_text(sel.get(), 1, edited_by.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(sel.get()) == SQLITE_ROW) {
            auto rep = nlohmann::json::parse(column_text_or_empty(sel.get(), 0), nullptr, false);
            auto resolved = replacement_content(rep);
            if (resolved.is_object()) body = resolved.value("body", "");
        }
    }
    if (body.empty()) {
        auto content = nlohmann::json::parse(own_content, nullptr, false);
        if (!content.is_discarded() && content.is_object()) body = content.value("body", "");
    }
    reindex_search_locked(event_id, room_id, sender, stream_position,
                          body.empty() ? std::nullopt : std::optional<std::string>(body));
}

SqliteStore::SearchResult
SqliteStore::search_messages(const std::vector<std::string>& room_ids,
                             const std::vector<std::string>& terms,
                             const std::vector<std::string>& senders,
                             int limit, int offset, bool order_recent) {
    SearchResult result;
    // Fail closed. An empty permitted-room set must return nothing, never
    // degenerate into an unrestricted search.
    if (room_ids.empty() || terms.empty()) return result;
    if (limit < 1) limit = 1;
    if (offset < 0) offset = 0;

    std::lock_guard lock(mutex_);
    if (!fts5_available_locked()) return result;

    // Build the MATCH expression from bare terms, each wrapped as a quoted FTS5
    // phrase. Quoting is what makes this safe: inside double quotes FTS5 treats
    // the contents as literal text, so no term can become an operator. Embedded
    // quotes are escaped by doubling, per FTS5's string literal rules.
    std::string match;
    for (const auto& term : terms) {
        if (!match.empty()) match += " AND ";
        match += '"';
        for (char c : term) {
            if (c == '"') match += "\"\"";
            else match += c;
        }
        match += '"';
    }

    auto placeholders = [](size_t n) {
        std::string s;
        for (size_t i = 0; i < n; ++i) s += (i ? ",?" : "?");
        return s;
    };

    std::string where =
        " FROM event_search_fts f "
        "INNER JOIN event_search s ON s.rowid = f.rowid "
        "WHERE f.event_search_fts MATCH ? "
        "  AND s.room_id IN (" + placeholders(room_ids.size()) + ")";
    if (!senders.empty()) {
        where += " AND s.sender IN (" + placeholders(senders.size()) + ")";
    }

    auto bind_common = [&](sqlite3_stmt* stmt) {
        int i = 1;
        sqlite3_bind_text(stmt, i++, match.c_str(), -1, SQLITE_TRANSIENT);
        for (const auto& r : room_ids) {
            sqlite3_bind_text(stmt, i++, r.c_str(), -1, SQLITE_TRANSIENT);
        }
        for (const auto& s : senders) {
            sqlite3_bind_text(stmt, i++, s.c_str(), -1, SQLITE_TRANSIENT);
        }
        return i;
    };

    // FTS5 reports a bad MATCH expression at STEP time, not at prepare time. A
    // plain `while (step() == SQLITE_ROW)` therefore turns any such error into a
    // silent empty result set — indistinguishable from "nothing matched", which
    // would have hidden a broken query behind a plausible-looking answer. Check
    // explicitly and throw so the handler can answer honestly.
    auto step_checked = [&](sqlite3_stmt* stmt) {
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
            throw std::runtime_error(std::string("search query failed: ") + sqlite3_errmsg(db_));
        }
        return rc == SQLITE_ROW;
    };

    {
        auto stmt = prepare(db_, "SELECT COUNT(*)" + where);
        bind_common(stmt.get());
        if (step_checked(stmt.get())) {
            result.total = sqlite3_column_int(stmt.get(), 0);
        }
    }

    // bm25() is ascending-better (more negative = stronger match), so "rank"
    // order is plain ASC. Ties broken by recency so paging is stable.
    const std::string order = order_recent
        ? " ORDER BY s.stream_position DESC "
        : " ORDER BY bm25(f.event_search_fts) ASC, s.stream_position DESC ";

    auto stmt = prepare(db_,
        "SELECT s.event_id, s.room_id, s.stream_position, bm25(f.event_search_fts)" + where +
        order + "LIMIT ? OFFSET ?");
    int i = bind_common(stmt.get());
    sqlite3_bind_int(stmt.get(), i++, limit);
    sqlite3_bind_int(stmt.get(), i, offset);

    while (step_checked(stmt.get())) {
        SearchHit hit;
        hit.event_id = column_text_or_empty(stmt.get(), 0);
        hit.room_id = column_text_or_empty(stmt.get(), 1);
        hit.stream_position = sqlite3_column_int64(stmt.get(), 2);
        hit.rank = sqlite3_column_double(stmt.get(), 3);
        result.hits.push_back(std::move(hit));
    }
    result.more = offset + static_cast<int>(result.hits.size()) < result.total;
    return result;
}

int SqliteStore::count_search_index_rows() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT COUNT(*) FROM event_search");
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) return sqlite3_column_int(stmt.get(), 0);
    return 0;
}

// ── Push notifications ────────────────────────────────────────────────────

namespace {

SqliteStore::Pusher read_pusher_row(sqlite3_stmt* stmt) {
    SqliteStore::Pusher p;
    p.user_id = column_text_or_empty(stmt, 0);
    p.app_id = column_text_or_empty(stmt, 1);
    p.pushkey = column_text_or_empty(stmt, 2);
    p.device_id = column_text_or_empty(stmt, 3);
    p.kind = column_text_or_empty(stmt, 4);
    p.app_display_name = column_text_or_empty(stmt, 5);
    p.device_display_name = column_text_or_empty(stmt, 6);
    p.profile_tag = column_text_or_empty(stmt, 7);
    p.lang = column_text_or_empty(stmt, 8);
    p.url = column_text_or_empty(stmt, 9);
    p.format = column_text_or_empty(stmt, 10);
    p.data_json = column_text_or_empty(stmt, 11);
    return p;
}

constexpr const char* kPusherColumns =
    "user_id, app_id, pushkey, device_id, kind, app_display_name, "
    "device_display_name, profile_tag, lang, url, format, data";

} // namespace

void SqliteStore::upsert_pusher(const Pusher& p) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO pushers (user_id, app_id, pushkey, device_id, kind, app_display_name, "
        "  device_display_name, profile_tag, lang, url, format, data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(user_id, app_id, pushkey) DO UPDATE SET "
        "  device_id = excluded.device_id, kind = excluded.kind, "
        "  app_display_name = excluded.app_display_name, "
        "  device_display_name = excluded.device_display_name, "
        "  profile_tag = excluded.profile_tag, lang = excluded.lang, "
        "  url = excluded.url, format = excluded.format, data = excluded.data");
    int i = 1;
    for (const auto* v : {&p.user_id, &p.app_id, &p.pushkey, &p.device_id, &p.kind,
                          &p.app_display_name, &p.device_display_name, &p.profile_tag,
                          &p.lang, &p.url, &p.format, &p.data_json}) {
        sqlite3_bind_text(stmt.get(), i++, v->c_str(), -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to store pusher: ") + sqlite3_errmsg(db_));
    }
}

std::vector<SqliteStore::Pusher> SqliteStore::get_pushers(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string("SELECT ") + kPusherColumns +
                             " FROM pushers WHERE user_id = ? ORDER BY created_at ASC");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    std::vector<Pusher> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) out.push_back(read_pusher_row(stmt.get()));
    return out;
}

void SqliteStore::delete_pusher(const std::string& user_id, const std::string& app_id,
                                const std::string& pushkey) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "DELETE FROM pushers WHERE user_id = ? AND app_id = ? AND pushkey = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, app_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, pushkey.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());

    // The queue is addressed to a pusher, so unregistering one must take its
    // undelivered notifications with it. Otherwise removing a device leaves
    // rows that keep POSTing that user's message text to the gateway URL the
    // device used to have — for as long as the retry schedule allows.
    auto del = prepare(db_,
        "DELETE FROM push_queue WHERE user_id = ? AND app_id = ? AND pushkey = ?");
    sqlite3_bind_text(del.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(del.get(), 2, app_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(del.get(), 3, pushkey.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(del.get());
}

int SqliteStore::delete_pushers_by_pushkey_except(const std::string& pushkey,
                                                 const std::string& app_id,
                                                 const std::string& keep_user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "DELETE FROM pushers WHERE pushkey = ? AND app_id = ? AND user_id != ?");
    sqlite3_bind_text(stmt.get(), 1, pushkey.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, app_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, keep_user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    const int removed = sqlite3_changes(db_);

    // The gateway has told us this device is gone. Retrying its queued
    // notifications can only send message text to a pushkey that is no longer
    // anybody's.
    auto del = prepare(db_, "DELETE FROM push_queue WHERE pushkey = ?");
    sqlite3_bind_text(del.get(), 1, pushkey.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(del.get());
    return removed;
}

std::vector<SqliteStore::Pusher>
SqliteStore::list_room_pusher_candidates(const std::string& room_id,
                                         const std::string& exclude_user) {
    std::lock_guard lock(mutex_);
    // Joining against room_members means the result is bounded by "members who
    // registered a pusher", not by room size — a 5000-member channel where three
    // people use mobile push costs three rows. `kind = 'http'` and a non-empty
    // url filter out pushers that have nowhere to deliver to.
    auto stmt = prepare(db_,
        "SELECT p.user_id, p.app_id, p.pushkey, p.device_id, p.kind, p.app_display_name, "
        "       p.device_display_name, p.profile_tag, p.lang, p.url, p.format, p.data "
        "FROM pushers p "
        "INNER JOIN room_members rm ON rm.user_id = p.user_id "
        "WHERE rm.room_id = ? AND rm.membership = 'join' "
        "  AND p.user_id != ? AND p.kind = 'http' AND p.url != ''");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, exclude_user.c_str(), -1, SQLITE_TRANSIENT);
    std::vector<Pusher> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) out.push_back(read_pusher_row(stmt.get()));
    return out;
}

std::map<std::string, std::string>
SqliteStore::get_room_notify_levels(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT user_id, level FROM room_notify_settings WHERE room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    std::map<std::string, std::string> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        out.emplace(column_text_or_empty(stmt.get(), 0), column_text_or_empty(stmt.get(), 1));
    }
    return out;
}

std::optional<std::string> SqliteStore::get_room_notify_level(const std::string& user_id,
                                                              const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT level FROM room_notify_settings WHERE user_id = ? AND room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    return column_text_or_empty(stmt.get(), 0);
}

void SqliteStore::set_room_notify_level(const std::string& user_id, const std::string& room_id,
                                        const std::string& level) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO room_notify_settings (user_id, room_id, level, updated_at) "
        "VALUES (?, ?, ?, strftime('%s','now') * 1000) "
        "ON CONFLICT(user_id, room_id) DO UPDATE SET "
        "  level = excluded.level, updated_at = excluded.updated_at");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, level.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

bool SqliteStore::is_event_redacted_locked(const std::string& event_id) {
    if (event_id.empty()) return false;
    auto stmt = prepare(db_, "SELECT redacted_by FROM events WHERE event_id = ?");
    sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return false;
    return sqlite3_column_type(stmt.get(), 0) != SQLITE_NULL;
}

void SqliteStore::delete_queued_pushes_for_events_locked(const std::vector<std::string>& event_ids) {
    auto del = prepare(db_, "DELETE FROM push_queue WHERE event_id = ?");
    for (const auto& id : event_ids) {
        if (id.empty()) continue;
        sqlite3_reset(del.get());
        sqlite3_bind_text(del.get(), 1, id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(del.get());
    }
}

void SqliteStore::enqueue_pushes(const std::vector<QueuedPush>& pushes) {
    if (pushes.empty()) return;
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO push_queue (user_id, app_id, pushkey, url, payload, event_id, next_attempt_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 0)");
    for (const auto& p : pushes) {
        // The ordering this guards: the event is inserted, /sync hands it to a
        // moderator, the moderator redacts it — all before this call, which is
        // the last thing the send path does. The redaction found no queue rows
        // because there were none yet. Without this check the notification is
        // queued after the message it describes has been deleted.
        if (is_event_redacted_locked(p.event_id)) continue;

        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_text(stmt.get(), 1, p.user_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, p.app_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 3, p.pushkey.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, p.url.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 5, p.payload.c_str(), -1, SQLITE_TRANSIENT);
        if (p.event_id.empty()) {
            sqlite3_bind_null(stmt.get(), 6);
        } else {
            sqlite3_bind_text(stmt.get(), 6, p.event_id.c_str(), -1, SQLITE_TRANSIENT);
        }
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            throw std::runtime_error(std::string("Failed to enqueue push: ") +
                                     sqlite3_errmsg(db_));
        }
    }
}

std::vector<SqliteStore::QueuedPush>
SqliteStore::claim_due_pushes(int64_t now_ms, int limit, int64_t lease_ms) {
    std::lock_guard lock(mutex_);

    std::vector<QueuedPush> out;
    std::vector<int64_t> redacted_rows;
    {
        auto stmt = prepare(db_,
            "SELECT id, user_id, app_id, pushkey, url, payload, attempts, event_id FROM push_queue "
            "WHERE next_attempt_at <= ? ORDER BY id ASC LIMIT ?");
        sqlite3_bind_int64(stmt.get(), 1, now_ms);
        sqlite3_bind_int(stmt.get(), 2, limit);
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            QueuedPush q;
            q.id = sqlite3_column_int64(stmt.get(), 0);
            q.user_id = column_text_or_empty(stmt.get(), 1);
            q.app_id = column_text_or_empty(stmt.get(), 2);
            q.pushkey = column_text_or_empty(stmt.get(), 3);
            q.url = column_text_or_empty(stmt.get(), 4);
            q.payload = column_text_or_empty(stmt.get(), 5);
            q.attempts = sqlite3_column_int(stmt.get(), 6);
            q.event_id = column_text_or_empty(stmt.get(), 7);
            // Dispatch-time gate. Redaction already deletes these rows, so
            // reaching one here means the redaction landed while the row was
            // leased to a worker whose gateway was slow — the exact window the
            // queue exists to create. An event that has merely been deleted
            // along with its room is NOT treated as redacted: the row is gone,
            // not tombstoned, and a missing event id is how the test harness
            // and any future non-event notification look.
            if (is_event_redacted_locked(q.event_id)) {
                redacted_rows.push_back(q.id);
                continue;
            }
            out.push_back(std::move(q));
        }
    }
    if (!redacted_rows.empty()) {
        auto del = prepare(db_, "DELETE FROM push_queue WHERE id = ?");
        for (int64_t id : redacted_rows) {
            sqlite3_reset(del.get());
            sqlite3_bind_int64(del.get(), 1, id);
            sqlite3_step(del.get());
        }
        get_logger()->info(
            "Push: dropped {} queued notification(s) for redacted message(s) before delivery",
            redacted_rows.size());
    }
    if (out.empty()) return out;

    // Lease the claimed rows. Without this a crash (or simply a slow gateway
    // alongside a second worker) could hand the same row out twice; with it the
    // row becomes invisible until the lease lapses and is then retried.
    auto upd = prepare(db_, "UPDATE push_queue SET next_attempt_at = ? WHERE id = ?");
    for (const auto& q : out) {
        sqlite3_reset(upd.get());
        sqlite3_bind_int64(upd.get(), 1, now_ms + lease_ms);
        sqlite3_bind_int64(upd.get(), 2, q.id);
        sqlite3_step(upd.get());
    }
    return out;
}

void SqliteStore::delete_queued_push(int64_t id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM push_queue WHERE id = ?");
    sqlite3_bind_int64(stmt.get(), 1, id);
    sqlite3_step(stmt.get());
}

bool SqliteStore::reschedule_queued_push(int64_t id, int max_attempts, int64_t next_attempt_at) {
    std::lock_guard lock(mutex_);
    {
        auto upd = prepare(db_,
            "UPDATE push_queue SET attempts = attempts + 1, next_attempt_at = ? WHERE id = ?");
        sqlite3_bind_int64(upd.get(), 1, next_attempt_at);
        sqlite3_bind_int64(upd.get(), 2, id);
        sqlite3_step(upd.get());
    }
    auto del = prepare(db_, "DELETE FROM push_queue WHERE id = ? AND attempts >= ?");
    sqlite3_bind_int64(del.get(), 1, id);
    sqlite3_bind_int(del.get(), 2, max_attempts);
    sqlite3_step(del.get());
    return sqlite3_changes(db_) == 0; // still queued?
}

int SqliteStore::count_queued_pushes() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT COUNT(*) FROM push_queue");
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) return sqlite3_column_int(stmt.get(), 0);
    return 0;
}

// ── Moderation audit log ──────────────────────────────────────────────────
//
// One INSERT and one SELECT, and that is the complete surface: no UPDATE, no
// DELETE, no "fix up a record" helper. See the header for why retention is
// unbounded, and migration v13 for the triggers that make append-only a property
// of the database rather than of this file.

int64_t SqliteStore::append_audit_record(const AuditRecord& record) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO audit_log "
        "  (created_at, actor, action, target_user, target_room, target_key, reason, "
        "   before_json, after_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    const int64_t created_at = record.created_at != 0 ? record.created_at : audit_now_ms();
    sqlite3_bind_int64(stmt.get(), 1, created_at);
    sqlite3_bind_text(stmt.get(), 2, record.actor.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, record.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, record.target_user.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, record.target_room.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, record.target_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, record.reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 8, record.before_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 9, record.after_json.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        // Deliberately fatal to the request rather than swallowed. An audited
        // action whose record could not be written must not quietly succeed as if
        // it had been logged.
        throw std::runtime_error(std::string("Failed to append audit record: ") +
                                 sqlite3_errmsg(db_));
    }
    return sqlite3_last_insert_rowid(db_);
}

namespace {

// The WHERE clause for an audit filter, and the values to bind to it in the same
// order. Built once and reused by the page query and the matching-count query, so
// the two can never disagree about what "matching" means.
//
// The `<> ''` guards on the target columns are not redundant belt-and-braces: the
// v16 indexes on those columns are PARTIAL (WHERE target_user <> ''), and SQLite
// will only use a partial index when the statement itself implies the index's
// condition. A bound `target_user = ?` does not prove `? <> ''`, so without the
// literal guard the planner falls back to a full table scan. Verified with
// EXPLAIN QUERY PLAN both ways.
SqliteStore::AuditQuery build_audit_where(const SqliteStore::AuditFilter& filter) {
    SqliteStore::AuditQuery out;
    std::vector<std::string> clauses;
    const auto add = [&](const std::optional<std::string>& value, const char* column,
                         bool partial_index) {
        if (!value) return;
        std::string clause = std::string(column) + " = ?";
        if (partial_index) clause += " AND " + std::string(column) + " <> ''";
        clauses.push_back(std::move(clause));
        out.binds.push_back(*value);
    };
    add(filter.actor, "actor", false);
    add(filter.action, "action", false);
    add(filter.target_user, "target_user", true);
    add(filter.target_room, "target_room", true);

    for (size_t i = 0; i < clauses.size(); ++i) {
        out.sql += (i == 0 ? " " : " AND ") + clauses[i];
    }
    return out;
}

} // namespace

SqliteStore::AuditQuery SqliteStore::audit_page_query(const AuditFilter& filter,
                                                      bool with_cursor) {
    auto where = build_audit_where(filter);

    // Over-fetch one row to learn whether a further page exists without a second
    // query — the same trick get_room_events_paginated uses. (The caller binds
    // limit + 1 to the trailing LIMIT parameter.)
    //
    // The cursor stays an id predicate whether or not a filter is present, which
    // is what keeps pagination stable: ids come from an AUTOINCREMENT rowid, so a
    // concurrent insert always lands ABOVE any cursor a reader is holding and can
    // neither duplicate nor hide a record on a later page.
    std::string sql =
        "SELECT id, created_at, actor, action, target_user, target_room, target_key, "
        "       reason, before_json, after_json FROM audit_log ";
    std::string conditions = where.sql;
    if (with_cursor) conditions += (conditions.empty() ? " " : " AND ") + std::string("id < ?");
    if (!conditions.empty()) sql += "WHERE" + conditions + " ";
    sql += "ORDER BY id DESC LIMIT ?";

    where.sql = std::move(sql);
    return where;
}

SqliteStore::AuditQuery SqliteStore::audit_match_count_query(const AuditFilter& filter) {
    auto where = build_audit_where(filter);
    where.sql = "SELECT COUNT(*) FROM audit_log" +
                (where.sql.empty() ? std::string() : " WHERE" + where.sql);
    return where;
}

SqliteStore::AuditPage SqliteStore::list_audit_records(int limit,
                                                       std::optional<int64_t> before_id,
                                                       const AuditFilter& filter) {
    std::lock_guard lock(mutex_);
    if (limit < 1) limit = 1;

    AuditPage page;
    const auto query = audit_page_query(filter, before_id.has_value());

    auto stmt = prepare(db_, query.sql);
    int bind_index = 1;
    for (const auto& value : query.binds) {
        sqlite3_bind_text(stmt.get(), bind_index++, value.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (before_id) sqlite3_bind_int64(stmt.get(), bind_index++, *before_id);
    sqlite3_bind_int(stmt.get(), bind_index, limit + 1);

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        AuditRecord r;
        r.id = sqlite3_column_int64(stmt.get(), 0);
        r.created_at = sqlite3_column_int64(stmt.get(), 1);
        r.actor = column_text_or_empty(stmt.get(), 2);
        r.action = column_text_or_empty(stmt.get(), 3);
        r.target_user = column_text_or_empty(stmt.get(), 4);
        r.target_room = column_text_or_empty(stmt.get(), 5);
        r.target_key = column_text_or_empty(stmt.get(), 6);
        r.reason = column_text_or_empty(stmt.get(), 7);
        r.before_json = column_text_or_empty(stmt.get(), 8);
        r.after_json = column_text_or_empty(stmt.get(), 9);
        page.records.push_back(std::move(r));
    }

    if (page.records.size() > static_cast<size_t>(limit)) {
        page.records.pop_back();
        // Exclusive cursor: the next page is everything strictly older than the
        // last row we are returning, so no record can be served twice or skipped.
        page.next_from = page.records.back().id;
    }

    // Growth visibility. Unbounded retention is a decision, not an oversight, so
    // the number an operator would need in order to revisit it is in every
    // response rather than only in the database. This stays WHOLE-TABLE even when
    // a filter is applied — a reader who filtered must not come away with a
    // smaller idea of how big the log is.
    auto count = prepare(db_, "SELECT COUNT(*) FROM audit_log");
    if (sqlite3_step(count.get()) == SQLITE_ROW) {
        page.total = sqlite3_column_int64(count.get(), 0);
    }

    // How many records the filter matches, in total, across all pages. Only for a
    // filtered request: unfiltered it would just repeat `total`, and it costs a
    // second query. Served by the same index as the page itself, so it is a walk
    // of the matching key run rather than a table scan. Deliberately ignores
    // `before_id`: it describes the whole result set, not the tail after a cursor,
    // which is what makes it useful on page three.
    if (filter.any()) {
        const auto count_query = audit_match_count_query(filter);
        auto matching = prepare(db_, count_query.sql);
        int idx = 1;
        for (const auto& value : count_query.binds) {
            sqlite3_bind_text(matching.get(), idx++, value.c_str(), -1, SQLITE_TRANSIENT);
        }
        if (sqlite3_step(matching.get()) == SQLITE_ROW) {
            page.matching = sqlite3_column_int64(matching.get(), 0);
        }
    }
    return page;
}

// Profile

void SqliteStore::set_display_name(const std::string& user_id, const std::string& display_name) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE users SET display_name = ? WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, display_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

void SqliteStore::set_avatar_url(const std::string& user_id, const std::string& avatar_url) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE users SET avatar_url = ? WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, avatar_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::optional<std::string> SqliteStore::get_display_name(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT display_name FROM users WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW && sqlite3_column_type(stmt.get(), 0) != SQLITE_NULL) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

void SqliteStore::set_nickname(const std::string& user_id,
                              const std::optional<std::string>& nickname) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE users SET nickname = ? WHERE user_id = ?");
    // Clearing binds SQL NULL rather than '': get_nickname treats NULL as "none",
    // and an empty-string nickname would otherwise round-trip as a real nickname
    // that renders as a blank name in every member list.
    if (nickname) {
        sqlite3_bind_text(stmt.get(), 1, nickname->c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt.get(), 1);
    }
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::optional<std::string> SqliteStore::get_nickname(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT nickname FROM users WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW && sqlite3_column_type(stmt.get(), 0) != SQLITE_NULL) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

std::optional<std::string> SqliteStore::get_avatar_url(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT avatar_url FROM users WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW && sqlite3_column_type(stmt.get(), 0) != SQLITE_NULL) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

// Media

void SqliteStore::insert_media(const std::string& media_id, const std::string& uploader,
                                const std::string& content_type, const std::string& filename,
                                int64_t file_size, const std::string& file_path) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO media (media_id, uploader, content_type, filename, file_size, file_path) "
        "VALUES (?, ?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, media_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, uploader.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, content_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 5, file_size);
    sqlite3_bind_text(stmt.get(), 6, file_path.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to insert media: ") + sqlite3_errmsg(db_));
    }
}

std::optional<SqliteStore::MediaMeta> SqliteStore::get_media(const std::string& media_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT media_id, uploader, content_type, filename, file_size, file_path "
        "FROM media WHERE media_id = ?");
    sqlite3_bind_text(stmt.get(), 1, media_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        MediaMeta meta;
        meta.media_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        meta.uploader = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        meta.content_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        auto fn = sqlite3_column_text(stmt.get(), 3);
        meta.filename = fn ? reinterpret_cast<const char*>(fn) : "";
        meta.file_size = sqlite3_column_int64(stmt.get(), 4);
        meta.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5));
        return meta;
    }
    return std::nullopt;
}

std::vector<std::string> SqliteStore::get_media_rooms(const std::string& mxc_uri) {
    std::lock_guard lock(mutex_);
    std::vector<std::string> rooms;
    auto stmt = prepare(db_, "SELECT DISTINCT room_id FROM media_refs WHERE mxc_uri = ?");
    sqlite3_bind_text(stmt.get(), 1, mxc_uri.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(column_text_or_empty(stmt.get(), 0));
    }
    return rooms;
}

bool SqliteStore::is_avatar_of(const std::string& mxc_uri, const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT 1 FROM users WHERE user_id = ? AND avatar_url = ? LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, mxc_uri.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

std::vector<SqliteStore::MediaMeta> SqliteStore::find_orphaned_media(
    const std::string& server_name, int64_t created_before_ms, int limit) {
    std::lock_guard lock(mutex_);

    // server_state first, in C++. It holds server-scoped documents that are
    // NOT events (bsfchat.server.roles, bsfchat.member.roles) and therefore
    // never reach media_refs, so an mxc named in one of them would look
    // unreferenced to the SQL below. The table holds a handful of rows on any
    // deployment, and using media_uris_in_content() rather than a second
    // extraction rule is what stops this drifting from what insert_event
    // indexes.
    std::set<std::string> server_state_uris;
    {
        auto stmt = prepare(db_, "SELECT content FROM server_state");
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            for (auto& uri : media_uris_in_content(column_text_or_empty(stmt.get(), 0))) {
                server_state_uris.insert(std::move(uri));
            }
        }
    }

    const std::string prefix = "mxc://" + server_name + "/";

    // `u.user_id = m.uploader` in the avatar clause is not an optimisation: it
    // is the same rule is_avatar_of() applies on the read side, and the two
    // have to agree or this sweep either deletes bytes that are still being
    // served or spares bytes that are not. An avatar worn by somebody who did
    // not upload it grants nothing (audit F5's laundering variant), so it must
    // not protect anything either.
    //
    // The two NOT EXISTS clauses are correlated subqueries over indexed
    // columns: media_refs' primary key leads with mxc_uri, and users.avatar_url
    // is compared whole. `limit` bounds the work per sweep so a deployment with
    // a large backlog pays for it over several passes instead of holding the
    // store's global mutex for the whole of one.
    auto stmt = prepare(db_,
        "SELECT m.media_id, m.uploader, m.content_type, m.filename, m.file_size, m.file_path "
        "FROM media m "
        "WHERE m.created_at < ? "
        "  AND NOT EXISTS (SELECT 1 FROM media_refs r WHERE r.mxc_uri = ? || m.media_id) "
        "  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.avatar_url = ? || m.media_id "
        "                     AND u.user_id = m.uploader) "
        "ORDER BY m.created_at "
        "LIMIT ?");
    sqlite3_bind_int64(stmt.get(), 1, created_before_ms);
    sqlite3_bind_text(stmt.get(), 2, prefix.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, prefix.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 4, limit);

    std::vector<MediaMeta> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        MediaMeta meta;
        meta.media_id = column_text_or_empty(stmt.get(), 0);
        if (server_state_uris.count(prefix + meta.media_id)) continue;
        meta.uploader = column_text_or_empty(stmt.get(), 1);
        meta.content_type = column_text_or_empty(stmt.get(), 2);
        meta.filename = column_text_or_empty(stmt.get(), 3);
        meta.file_size = sqlite3_column_int64(stmt.get(), 4);
        meta.file_path = column_text_or_empty(stmt.get(), 5);
        out.push_back(std::move(meta));
    }
    return out;
}

bool SqliteStore::delete_media(const std::string& media_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM media WHERE media_id = ?");
    sqlite3_bind_text(stmt.get(), 1, media_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return sqlite3_changes(db_) > 0;
}

} // namespace bsfchat
