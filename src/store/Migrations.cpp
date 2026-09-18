#include "store/Migrations.h"
#include "auth/LocalAuth.h"
#include "core/Logger.h"
#include "store/CallSignalling.h"

#include <bsfchat/Constants.h>

#include <nlohmann/json.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace bsfchat {

namespace {

void exec(sqlite3* db, const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("migration SQL error: " + msg + " [" + sql + "]");
    }
}

struct StmtDeleter {
    void operator()(sqlite3_stmt* stmt) {
        if (stmt) sqlite3_finalize(stmt);
    }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

StmtPtr prepare(sqlite3* db, const std::string& sql) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("migration prepare error: ") + sqlite3_errmsg(db) +
                                 " [" + sql + "]");
    }
    return StmtPtr(stmt);
}

int scalar_int(sqlite3* db, const std::string& sql) {
    auto stmt = prepare(db, sql);
    int out = 0;
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) out = sqlite3_column_int(stmt.get(), 0);
    return out;
}

const char* text_or_empty(sqlite3_stmt* stmt, int col) {
    auto* p = sqlite3_column_text(stmt, col);
    return p ? reinterpret_cast<const char*>(p) : "";
}

// If `content_json` is an m.replace relation, returns the id of the event it
// replaces. Parsed in C++ rather than with json_extract() so the migration
// never depends on SQLite's quoted-JSON-path support — "m.relates_to" contains
// a dot, which needs `$."m.relates_to".event_id`, and that only parses on
// recent SQLite builds.
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

bool column_exists(sqlite3* db, const std::string& table, const std::string& column) {
    // table_info() is a table-valued function in modern SQLite; quoting the
    // table name keeps this safe for our fixed, internal table names.
    return scalar_int(db,
        "SELECT COUNT(*) FROM pragma_table_info('" + table + "') WHERE name = '" + column + "'") > 0;
}

// ── Migration steps ───────────────────────────────────────────────────────
// Each step takes (db, fresh_database). NEVER edit or reorder an existing
// step — deployments have already applied it and only later steps will run.

// v1: generic key/value store for server-level metadata (migration markers,
// the monotonic stream counter, one-time-repair flags).
void migrate_v1(sqlite3* db, bool fresh_database) {
    exec(db, R"(
        CREATE TABLE IF NOT EXISTS server_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    )");

    // The historical "publicize every non-category room" backfill only ever
    // made sense for deployments whose channels predate the Discord-like
    // model. A brand-new database has no such channels, so mark the one-time
    // migration as already-applied and it will never run there.
    if (fresh_database) {
        exec(db, "INSERT OR IGNORE INTO server_meta (key, value) "
                 "VALUES ('migration.publicize_legacy_channels', 'skipped-fresh-db')");
    }
}

// v2: mark direct-message rooms so they are never swept into the "everyone
// joins every public room" model. Retro-detects DMs on existing databases and
// undoes the force-joins the old backfill performed on them.
void migrate_v2(sqlite3* db, bool fresh_database) {
    if (!column_exists(db, "rooms", "is_direct")) {
        exec(db, "ALTER TABLE rooms ADD COLUMN is_direct INTEGER NOT NULL DEFAULT 0");
    }

    if (fresh_database) return;

    // Retro-detection for pre-existing databases, where `is_direct` was never
    // persisted. The client creates DMs with visibility=private,
    // preset=trusted_private_chat, is_direct=true, exactly one invite, and no
    // name/topic. Channels always carry an m.room.name. So a room qualifies as
    // a DM when it has no name, is not a category, has at least one explicit
    // `invite` membership event, and the creator plus everyone ever invited
    // numbers at most two people.
    exec(db, R"(
        UPDATE rooms SET is_direct = 1
        WHERE room_id IN (
            SELECT r.room_id FROM rooms r
            WHERE NOT EXISTS (
                    SELECT 1 FROM events
                    WHERE room_id = r.room_id AND event_type = 'm.room.name')
              AND COALESCE((
                    SELECT json_extract(content, '$.type') FROM events
                    WHERE room_id = r.room_id AND event_type = 'bsfchat.room.type'
                      AND state_key = ''
                    ORDER BY stream_position DESC LIMIT 1), '') != 'category'
              AND EXISTS (
                    SELECT 1 FROM events
                    WHERE room_id = r.room_id AND event_type = 'm.room.member'
                      AND json_extract(content, '$.membership') = 'invite')
              AND (
                    SELECT COUNT(*) FROM (
                        SELECT r.creator AS participant
                        UNION
                        SELECT state_key FROM events
                        WHERE room_id = r.room_id AND event_type = 'm.room.member'
                          AND json_extract(content, '$.membership') = 'invite'
                    )) <= 2
        )
    )");

    int detected = scalar_int(db, "SELECT COUNT(*) FROM rooms WHERE is_direct = 1");
    if (detected == 0) return;

    // Repair: evict everyone the old backfill force-joined into those DMs.
    // Only the creator and users who were explicitly invited stay. We touch
    // room_members only — no events are deleted, so nothing is unrecoverable.
    int before = scalar_int(db,
        "SELECT COUNT(*) FROM room_members m "
        "JOIN rooms r ON r.room_id = m.room_id WHERE r.is_direct = 1");

    exec(db, R"(
        DELETE FROM room_members
        WHERE room_id IN (SELECT room_id FROM rooms WHERE is_direct = 1)
          AND user_id NOT IN (
                SELECT creator FROM rooms WHERE room_id = room_members.room_id
                UNION
                SELECT state_key FROM events
                WHERE room_id = room_members.room_id
                  AND event_type = 'm.room.member'
                  AND json_extract(content, '$.membership') = 'invite'
          )
    )");

    int after = scalar_int(db,
        "SELECT COUNT(*) FROM room_members m "
        "JOIN rooms r ON r.room_id = m.room_id WHERE r.is_direct = 1");

    get_logger()->warn(
        "Schema migration: detected {} direct-message room(s) and removed {} "
        "membership(s) that the old auto-join backfill had force-joined into them. "
        "DMs are now excluded from public-room auto-join.",
        detected, before - after);
}

// v3: server-wide state gets its own home, independent of any room.
//
// Server roles and member-role assignments used to live as events inside an
// arbitrary channel picked by RoleBootstrap; deleting that channel destroyed
// every role definition and assignment server-wide. They now live here, and
// room events are only a mirror for client sync.
void migrate_v3(sqlite3* db, bool /*fresh_database*/) {
    exec(db, R"(
        CREATE TABLE IF NOT EXISTS server_state (
            event_type  TEXT NOT NULL,
            state_key   TEXT NOT NULL,
            sender      TEXT NOT NULL,
            content     TEXT NOT NULL,
            updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (event_type, state_key)
        )
    )");

    // Carry over whatever the events table already holds: the newest
    // bsfchat.server.roles overall, and the newest bsfchat.member.roles per
    // user. Matches the read semantics the old code had.
    exec(db, R"(
        INSERT OR REPLACE INTO server_state (event_type, state_key, sender, content)
        SELECT event_type, state_key, sender, content FROM events
        WHERE event_type = 'bsfchat.server.roles' AND state_key = ''
        ORDER BY stream_position DESC LIMIT 1
    )");
    exec(db, R"(
        INSERT OR REPLACE INTO server_state (event_type, state_key, sender, content)
        SELECT e.event_type, e.state_key, e.sender, e.content FROM events e
        INNER JOIN (
            SELECT state_key, MAX(stream_position) AS mp FROM events
            WHERE event_type = 'bsfchat.member.roles' AND state_key IS NOT NULL
            GROUP BY state_key) latest
        ON e.state_key = latest.state_key AND e.stream_position = latest.mp
        WHERE e.event_type = 'bsfchat.member.roles'
    )");
}

// v4: monotonic stream position counter.
//
// insert_event used to derive its position from MAX(stream_position) + 1, so
// delete_room removing the newest events made positions get REUSED — a client
// holding a sync token at or above a reused position never saw new events
// again. The counter below only ever moves forward.
void migrate_v4(sqlite3* db, bool /*fresh_database*/) {
    exec(db, R"(
        INSERT OR IGNORE INTO server_meta (key, value)
        SELECT 'next_stream_position', CAST(COALESCE(MAX(stream_position), 0) + 1 AS TEXT)
        FROM events
    )");
}

// v5: server-side redaction. Redacting used to insert an m.room.redaction
// event and leave the target untouched, so "deleted" messages were still
// fully readable via /rooms/{id}/messages.
void migrate_v5(sqlite3* db, bool /*fresh_database*/) {
    if (!column_exists(db, "events", "redacted_by")) {
        exec(db, "ALTER TABLE events ADD COLUMN redacted_by TEXT");
    }
}

// v6: transaction-id idempotency for message sends. Without this, any client
// retry of PUT /rooms/{id}/send/{type}/{txnId} duplicated the message.
void migrate_v6(sqlite3* db, bool /*fresh_database*/) {
    exec(db, R"(
        CREATE TABLE IF NOT EXISTS event_transactions (
            user_id    TEXT NOT NULL,
            txn_id     TEXT NOT NULL,
            event_id   TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (user_id, txn_id)
        )
    )");
}

// v7: access tokens stop being plaintext, gain an expiry, and gain a refresh
// slot.
//
// The old table was (token TEXT PRIMARY KEY, user_id, device_id, created_at):
// the bearer secret itself was readable in the database, it never expired, and
// there was no way to invalidate one beyond deleting the row by its plaintext.
// A leaked database or backup was a permanent session for every account.
//
// Existing sessions are preserved: we still hold the plaintext at this moment,
// so each one is hashed in place rather than dropped. Nobody is logged out by
// this migration. Rows are given a fresh full lifetime rather than one measured
// from `created_at`, so a long-lived session that predates expiry tracking
// isn't retroactively expired the instant the server restarts.
void migrate_v7(sqlite3* db, bool /*fresh_database*/) {
    // Keep in sync with kDefaultAccessTokenLifetimeMs in SqliteStore.h. Not
    // shared as a constant on purpose: a migration must keep behaving the way
    // it did when it was written, even if the default policy later changes.
    constexpr int64_t kGraceMs = 90LL * 24 * 60 * 60 * 1000;

    exec(db, R"(
        CREATE TABLE access_tokens_v7 (
            token_hash   TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL REFERENCES users(user_id),
            device_id    TEXT NOT NULL,
            created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            expires_at   INTEGER NOT NULL,
            last_used_at INTEGER,
            lifetime_ms  INTEGER NOT NULL,
            refresh_hash TEXT UNIQUE
        )
    )");

    // ON CONFLICT does not apply to FOREIGN KEY constraints, so a token row
    // whose user no longer exists would abort the whole migration. Those rows
    // are unusable anyway (authenticate() joins nothing) — skip and report.
    const int total = scalar_int(db, "SELECT COUNT(*) FROM access_tokens");
    std::vector<std::tuple<std::string, std::string, std::string, int64_t>> rows;
    {
        auto sel = prepare(db,
            "SELECT token, user_id, device_id, created_at FROM access_tokens "
            "WHERE user_id IN (SELECT user_id FROM users)");
        while (sqlite3_step(sel.get()) == SQLITE_ROW) {
            rows.emplace_back(text_or_empty(sel.get(), 0), text_or_empty(sel.get(), 1),
                              text_or_empty(sel.get(), 2), sqlite3_column_int64(sel.get(), 3));
        }
    }

    {
        auto ins = prepare(db,
            "INSERT OR IGNORE INTO access_tokens_v7 "
            "  (token_hash, user_id, device_id, created_at, expires_at, last_used_at, lifetime_ms) "
            "VALUES (?, ?, ?, ?, strftime('%s','now') * 1000 + ?, NULL, ?)");
        for (const auto& [token, user_id, device_id, created_at] : rows) {
            auto hashed = hash_access_token(token);
            sqlite3_reset(ins.get());
            sqlite3_clear_bindings(ins.get());
            sqlite3_bind_text(ins.get(), 1, hashed.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins.get(), 3, device_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(ins.get(), 4, created_at);
            sqlite3_bind_int64(ins.get(), 5, kGraceMs);
            sqlite3_bind_int64(ins.get(), 6, kGraceMs);
            if (sqlite3_step(ins.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("failed to rehash access token: ") +
                                         sqlite3_errmsg(db));
            }
        }
    }

    exec(db, "DROP TABLE access_tokens");
    exec(db, "ALTER TABLE access_tokens_v7 RENAME TO access_tokens");
    exec(db, "CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_id)");

    if (total > 0) {
        get_logger()->info(
            "Schema migration: hashed {} of {} stored access token(s) at rest and gave them a "
            "{}-day expiry. Existing sessions keep working; nobody is logged out.",
            rows.size(), total, kGraceMs / (24 * 60 * 60 * 1000));
    }
    if (static_cast<int>(rows.size()) != total) {
        get_logger()->warn(
            "Schema migration: dropped {} access token(s) belonging to users that no longer "
            "exist.", total - static_cast<int>(rows.size()));
    }
}

// v8: server-side reconciliation of message edits (m.replace).
//
// An edit used to be stored as an ordinary sibling event and nothing else: the
// server checked authorship and then never reconciled, so /messages, /sync and
// /event all kept returning the PRE-EDIT text. Edits were enforced purely by
// client cooperation — anyone reading the API directly saw the original.
//
// `events.edited_by` now points at the replacement event that currently wins
// for a given event, and reads resolve through it. The original event keeps its
// own id, sender, timestamp and pristine content; the replacement stays in the
// timeline as a first-class event, so history is still discoverable.
void migrate_v8(sqlite3* db, bool /*fresh_database*/) {
    if (!column_exists(db, "events", "edited_by")) {
        exec(db, "ALTER TABLE events ADD COLUMN edited_by TEXT");
    }

    // Backfill: every edit accepted before this release is currently invisible
    // through the API. Walk the timeline in stream order so the newest
    // surviving replacement for each target is the one that sticks.
    std::unordered_map<std::string, std::string> winner; // target -> replacement
    {
        auto sel = prepare(db,
            "SELECT event_id, content FROM events "
            "WHERE event_type = 'm.room.message' AND redacted_by IS NULL "
            "ORDER BY stream_position ASC");
        while (sqlite3_step(sel.get()) == SQLITE_ROW) {
            std::string event_id = text_or_empty(sel.get(), 0);
            auto target = replacement_target(text_or_empty(sel.get(), 1));
            if (target) winner[*target] = std::move(event_id);
        }
    }
    if (winner.empty()) return;

    int applied = 0;
    {
        auto upd = prepare(db,
            "UPDATE events SET edited_by = ? WHERE event_id = ? AND redacted_by IS NULL");
        for (const auto& [target, replacement] : winner) {
            sqlite3_reset(upd.get());
            sqlite3_bind_text(upd.get(), 1, replacement.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(upd.get(), 2, target.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(upd.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("failed to backfill edit: ") +
                                         sqlite3_errmsg(db));
            }
            applied += sqlite3_changes(db);
        }
    }

    get_logger()->info(
        "Schema migration: reconciled {} previously advisory-only message edit(s); "
        "the API now returns edited content.", applied);
}

// v9: denormalise "this event is an m.replace replacement" into a column.
//
// Three separate features need to ask that question cheaply and none of them
// can afford to parse every row's JSON to find out:
//   * count_unread() counted a replacement as a brand-new message, so editing
//     your own text bumped everyone else's unread badge.
//   * mention extraction must never fire a fresh notification for an edit.
//   * the search index must update the ORIGINAL's text rather than adding the
//     replacement as a second, duplicate hit.
//
// `replaces` holds the target event id for a replacement and NULL for
// everything else. Set once at insert time and never updated — unlike
// `edited_by` (which points the other way and moves as edits are added and
// redacted), this records an immutable property of the event itself.
void migrate_v9(sqlite3* db, bool /*fresh_database*/) {
    if (!column_exists(db, "events", "replaces")) {
        exec(db, "ALTER TABLE events ADD COLUMN replaces TEXT");
    }

    // Backfill from stored content. Parsed in C++ for the same reason
    // replacement_target() exists: the JSON path would need quoted labels.
    std::vector<std::pair<std::string, std::string>> rows; // event_id -> target
    {
        auto sel = prepare(db,
            "SELECT event_id, content FROM events WHERE event_type = 'm.room.message'");
        while (sqlite3_step(sel.get()) == SQLITE_ROW) {
            auto target = replacement_target(text_or_empty(sel.get(), 1));
            if (target) rows.emplace_back(text_or_empty(sel.get(), 0), *target);
        }
    }

    if (!rows.empty()) {
        auto upd = prepare(db, "UPDATE events SET replaces = ? WHERE event_id = ?");
        for (const auto& [event_id, target] : rows) {
            sqlite3_reset(upd.get());
            sqlite3_bind_text(upd.get(), 1, target.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(upd.get(), 2, event_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(upd.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("failed to backfill replaces: ") +
                                         sqlite3_errmsg(db));
            }
        }
        get_logger()->info(
            "Schema migration: marked {} message edit(s) as replacements; they no longer "
            "count towards other users' unread badges.", rows.size());
    }
}

// v10: @mention storage (MSC3952 `m.mentions`).
//
// Mentions previously did not exist at all. They are extracted from the
// sender's own `m.mentions` at send time, validated against room membership and
// VIEW_CHANNEL, and recorded here — never scraped out of the body on read, and
// never writable directly by a client.
//
// A row is (event, mentioned user). `@room` mentions store the sentinel user id
// "@room" rather than fanning out one row per member: a real Matrix user id is
// always "@localpart:server" and so always contains a colon, making "@room"
// unforgeable as an actual account. That keeps a room-wide mention O(1) to
// write and lets one index serve both halves of the unread query
// (`user_id IN (?, '@room')`).
//
// `stream_position` is denormalised from the event so the unread-mention count
// is a pure index range scan against read_markers, with no join back to events.
// `sender` is the AUTHENTICATED sender of the event, which is what makes a
// mention non-forgeable: nothing a client puts in the request body can make a
// row claim it came from somebody else.
//
// ON DELETE CASCADE ties rows to the event's lifetime, so delete_room (which
// hard-deletes a room's events) cannot leave orphaned mention badges behind.
void migrate_v10(sqlite3* db, bool /*fresh_database*/) {
    exec(db, R"(
        CREATE TABLE IF NOT EXISTS event_mentions (
            event_id        TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
            room_id         TEXT NOT NULL,
            user_id         TEXT NOT NULL,
            sender          TEXT NOT NULL,
            stream_position INTEGER NOT NULL,
            created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (event_id, user_id)
        )
    )");
    // Serves both the per-room badge count and the "@room" branch of it.
    exec(db, "CREATE INDEX IF NOT EXISTS idx_event_mentions_target "
             "ON event_mentions(user_id, room_id, stream_position)");
    // Used when a room's mentions are swept (redaction re-resolution).
    exec(db, "CREATE INDEX IF NOT EXISTS idx_event_mentions_room "
             "ON event_mentions(room_id)");
}

// v11: push notifications (Matrix pusher API + an out-of-band delivery queue).
//
// Three tables, because the three things have three different lifetimes:
//
// `pushers` is the registration: one row per (user, app_id, pushkey), which is
// the Matrix spec's identity for a pusher. `url` is the push GATEWAY endpoint,
// so the server stays provider-agnostic — FCM/APNs credentials live in the
// gateway a deployment runs, never here.
//
// `push_queue` exists so that delivery is out of band. Evaluating an event
// enqueues rows (a local INSERT) and returns; nothing on the /send or /sync path
// ever waits on an outbound HTTP request. The payload is snapshotted at enqueue
// time rather than re-derived at delivery time, so a message that is edited or
// redacted between enqueue and delivery cannot change what was already queued,
// and the worker never needs to read the events table. `next_attempt_at`
// doubles as the retry schedule and as a lease: the worker moves it into the
// future when it claims a row, so a crash mid-delivery retries later instead of
// losing or duplicating the notification indefinitely.
//
// `room_notify_settings` is the per-(user, room) override of what deserves a
// push. Absent means "use the default", which is every message in a DM and
// mentions only in a channel.
void migrate_v11(sqlite3* db, bool /*fresh_database*/) {
    exec(db, R"(
        CREATE TABLE IF NOT EXISTS pushers (
            user_id             TEXT NOT NULL,
            app_id              TEXT NOT NULL,
            pushkey             TEXT NOT NULL,
            device_id           TEXT NOT NULL DEFAULT '',
            kind                TEXT NOT NULL,
            app_display_name    TEXT NOT NULL DEFAULT '',
            device_display_name TEXT NOT NULL DEFAULT '',
            profile_tag         TEXT NOT NULL DEFAULT '',
            lang                TEXT NOT NULL DEFAULT '',
            url                 TEXT NOT NULL DEFAULT '',
            format              TEXT NOT NULL DEFAULT '',
            data                TEXT NOT NULL DEFAULT '{}',
            created_at          INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (user_id, app_id, pushkey)
        )
    )");
    exec(db, "CREATE INDEX IF NOT EXISTS idx_pushers_user ON pushers(user_id)");
    // A gateway rejection names a pushkey, not a user, so removal is by pushkey.
    exec(db, "CREATE INDEX IF NOT EXISTS idx_pushers_pushkey ON pushers(pushkey)");

    exec(db, R"(
        CREATE TABLE IF NOT EXISTS push_queue (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         TEXT NOT NULL,
            app_id          TEXT NOT NULL,
            pushkey         TEXT NOT NULL,
            url             TEXT NOT NULL,
            payload         TEXT NOT NULL,
            attempts        INTEGER NOT NULL DEFAULT 0,
            next_attempt_at INTEGER NOT NULL DEFAULT 0,
            created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");
    exec(db, "CREATE INDEX IF NOT EXISTS idx_push_queue_due ON push_queue(next_attempt_at)");

    exec(db, R"(
        CREATE TABLE IF NOT EXISTS room_notify_settings (
            user_id    TEXT NOT NULL,
            room_id    TEXT NOT NULL,
            level      TEXT NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (user_id, room_id)
        )
    )");
    exec(db, "CREATE INDEX IF NOT EXISTS idx_room_notify_room ON room_notify_settings(room_id)");
}

// v12: full-text message search (SQLite FTS5, external content).
//
// Shape: a plain `event_search` shadow table holding one row per searchable
// message (id, room, sender, position, extracted plain-text body) plus an
// external-content FTS5 index over it. External content means the FTS5 table
// stores only the inverted index and reads the text back from `event_search`, so
// the body is not held twice.
//
// Why a shadow table rather than pointing FTS5 straight at `events`:
//   * `events` has no plain-text column — the body lives inside a JSON blob, and
//     FTS5 external content requires a real column of the indexed name.
//   * The searchable text is not the stored text. An edited message must match
//     its CURRENT wording, which means resolving `edited_by` to the winning
//     replacement's `m.new_content.body` — JSON work this codebase has already
//     settled on doing in C++ rather than with quoted json_extract() paths.
//   * A redacted message must not be searchable at all, and a replacement must
//     not appear as a second duplicate hit. Both are decisions, not projections.
// So the shadow is maintained explicitly at the same choke points the edit and
// redaction work established (insert_event / apply_edit / redact_event /
// delete_room), all funnelled through one reindex helper in SqliteStore.
//
// FTS5 is a compile-time option in SQLite. If this build lacks it the index is
// skipped rather than failing startup — the shadow table is still populated, so
// a later build WITH fts5 can index it from local data with no loss.
void migrate_v12(sqlite3* db, bool /*fresh_database*/) {
    exec(db, R"(
        CREATE TABLE IF NOT EXISTS event_search (
            rowid           INTEGER PRIMARY KEY,
            event_id        TEXT NOT NULL UNIQUE,
            room_id         TEXT NOT NULL,
            sender          TEXT NOT NULL,
            stream_position INTEGER NOT NULL,
            body            TEXT NOT NULL
        )
    )");
    exec(db, "CREATE INDEX IF NOT EXISTS idx_event_search_room "
             "ON event_search(room_id, stream_position)");

    bool fts5 = true;
    try {
        exec(db, "CREATE VIRTUAL TABLE IF NOT EXISTS event_search_fts USING fts5("
                 "  body, content='event_search', content_rowid='rowid')");
    } catch (const std::exception& e) {
        // "no such module: fts5". A statement-level prepare failure does not
        // abort the enclosing transaction, so the rest of this step still stands.
        fts5 = false;
        get_logger()->error(
            "Schema migration: this SQLite build has no FTS5 module, so message search is "
            "DISABLED (POST /_matrix/client/v3/search will report it unavailable). Rebuild or "
            "reinstall SQLite with -DSQLITE_ENABLE_FTS5 to enable it; message text is still "
            "being recorded locally, so no history is lost in the meantime. ({})", e.what());
        exec(db, "INSERT OR REPLACE INTO server_meta (key, value) "
                 "VALUES ('search.fts5_unavailable', '1')");
    }
    if (fts5) {
        exec(db, "DELETE FROM server_meta WHERE key = 'search.fts5_unavailable'");
    }

    // Backfill. Indexing existing history is the whole point on an upgrade — a
    // search feature that only sees messages sent after the deploy is not one.
    // Replacements are skipped and their text is folded onto the event they
    // replace; redacted events are skipped entirely.
    std::unordered_map<std::string, std::string> replacement_body; // target -> newest text
    struct Row {
        std::string event_id, room_id, sender, body;
        int64_t stream_position = 0;
    };
    std::vector<Row> originals;
    {
        auto sel = prepare(db,
            "SELECT event_id, room_id, sender, stream_position, content, replaces "
            "FROM events WHERE event_type = 'm.room.message' AND redacted_by IS NULL "
            "ORDER BY stream_position ASC");
        while (sqlite3_step(sel.get()) == SQLITE_ROW) {
            auto content = nlohmann::json::parse(text_or_empty(sel.get(), 4), nullptr, false);
            if (content.is_discarded() || !content.is_object()) continue;

            const bool is_replacement = sqlite3_column_type(sel.get(), 5) != SQLITE_NULL;
            if (is_replacement) {
                // Ascending order means the last one wins, which matches the
                // resolution the timeline performs.
                std::string body;
                auto nc = content.find("m.new_content");
                if (nc != content.end() && nc->is_object()) {
                    body = nc->value("body", "");
                } else {
                    body = content.value("body", "");
                    if (body.rfind("* ", 0) == 0) body = body.substr(2);
                }
                replacement_body[text_or_empty(sel.get(), 5)] = std::move(body);
                continue;
            }
            Row r;
            r.event_id = text_or_empty(sel.get(), 0);
            r.room_id = text_or_empty(sel.get(), 1);
            r.sender = text_or_empty(sel.get(), 2);
            r.stream_position = sqlite3_column_int64(sel.get(), 3);
            r.body = content.value("body", "");
            originals.push_back(std::move(r));
        }
    }

    int indexed = 0;
    auto ins_shadow = prepare(db,
        "INSERT OR REPLACE INTO event_search "
        "  (event_id, room_id, sender, stream_position, body) VALUES (?, ?, ?, ?, ?)");
    auto ins_fts = fts5
        ? prepare(db, "INSERT INTO event_search_fts (rowid, body) VALUES (?, ?)")
        : StmtPtr{};
    for (const auto& r : originals) {
        // An edit supersedes the original's text for search purposes.
        auto edited = replacement_body.find(r.event_id);
        const std::string& body = edited != replacement_body.end() ? edited->second : r.body;
        if (body.empty()) continue;

        sqlite3_reset(ins_shadow.get());
        sqlite3_clear_bindings(ins_shadow.get());
        sqlite3_bind_text(ins_shadow.get(), 1, r.event_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins_shadow.get(), 2, r.room_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins_shadow.get(), 3, r.sender.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(ins_shadow.get(), 4, r.stream_position);
        sqlite3_bind_text(ins_shadow.get(), 5, body.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(ins_shadow.get()) != SQLITE_DONE) {
            throw std::runtime_error(std::string("failed to backfill search shadow: ") +
                                     sqlite3_errmsg(db));
        }
        if (fts5) {
            const int64_t rowid = sqlite3_last_insert_rowid(db);
            sqlite3_reset(ins_fts.get());
            sqlite3_bind_int64(ins_fts.get(), 1, rowid);
            sqlite3_bind_text(ins_fts.get(), 2, body.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(ins_fts.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("failed to backfill search index: ") +
                                         sqlite3_errmsg(db));
            }
        }
        ++indexed;
    }

    if (indexed > 0) {
        get_logger()->info("Schema migration: indexed {} existing message(s) for search.",
                           indexed);
    }
}

// v13: append-only moderation audit log.
//
// Moderation left no trace. A kick, a ban, a role's permission bitfield being
// rewritten, a channel or category being deleted, a per-channel override being
// flipped — none of it was recorded anywhere a server owner could read back, so
// "who deleted #announcements" and "who granted themselves ADMINISTRATOR" simply
// had no answer.
//
// Why this cannot be reconstructed from the timeline, which is the obvious
// cheaper alternative: delete_room HARD-deletes every event in a room, so the
// m.room.member events a kick or a ban emits are destroyed by the very next
// destructive act — and channel deletion is itself one of the things that has to
// be audited. Server-wide role state hit the same wall and is exactly why
// `server_state` exists (see v3). Audit records therefore live in a table of
// their own, and deliberately carry NO foreign key: a record must outlive the
// room, the category and the account it talks about, and REFERENCES
// rooms(room_id) would either block the deletion or (with ON DELETE CASCADE)
// destroy precisely the evidence this table exists to preserve.
//
// `id` is INTEGER PRIMARY KEY AUTOINCREMENT, not a plain INTEGER PRIMARY KEY,
// and that keyword is the whole reason pagination here is safe. Without it
// SQLite hands out max(rowid) + 1, so a row that ever went away would let its id
// be REUSED — the same defect v4 exists to fix for events.stream_position, where
// reuse silently broke every client holding a sync token at or above the reused
// position. AUTOINCREMENT keeps a high-water mark in sqlite_sequence and never
// issues an id twice for the lifetime of the database, so "give me the records
// older than id N" is a cursor that stays correct forever, including across
// concurrent inserts.
//
// Append-only is enforced by the SCHEMA rather than by convention. Code review
// cannot be the guarantee for a tamper-evidence feature: the two triggers below
// abort any UPDATE or DELETE against the table, in every deployment, including
// one running a future call site nobody reviewed. There is no UPDATE and no
// DELETE path in the server today (SqliteStore exposes append and read only);
// the triggers are what keeps that true.
//
// Retention is deliberately unbounded — see the note above
// SqliteStore::append_audit_record for the sizing argument, why deletion-based
// retention would be the wrong default for this particular table, and the
// documented escape hatch for an operator who must prune anyway.
//
// Columns are NOT NULL with an empty-string default rather than nullable: a user
// id, a room id and an action are never legitimately empty, so "" is an
// unambiguous "not applicable" and every read path is spared a NULL check.
// `before_json`/`after_json` hold the state either side of the change (role
// permission bitfields as hex, membership transitions, override allow/deny) and
// are empty when a side does not exist — a role that was just created has no
// before, a deleted channel has no after.
void migrate_v13(sqlite3* db, bool /*fresh_database*/) {
    exec(db, R"(
        CREATE TABLE IF NOT EXISTS audit_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   INTEGER NOT NULL,
            actor        TEXT NOT NULL,
            action       TEXT NOT NULL,
            target_user  TEXT NOT NULL DEFAULT '',
            target_room  TEXT NOT NULL DEFAULT '',
            target_key   TEXT NOT NULL DEFAULT '',
            reason       TEXT NOT NULL DEFAULT '',
            before_json  TEXT NOT NULL DEFAULT '',
            after_json   TEXT NOT NULL DEFAULT ''
        )
    )");

    // No secondary indexes on purpose. The read endpoint pages newest-first by
    // id, which the rowid primary key already serves optimally, and this table is
    // on the write path of every moderation action — an index that no query uses
    // is pure write cost. Add one alongside the filter that needs it, not before.
    // (v16 does exactly that, when actor/target/action filters arrived. This step
    // is left alone: an already-migrated deployment has run it.)

    exec(db, R"(
        CREATE TRIGGER IF NOT EXISTS audit_log_is_append_only_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
        END
    )");
    exec(db, R"(
        CREATE TRIGGER IF NOT EXISTS audit_log_is_append_only_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
        END
    )");

    // No backfill, and none is possible. Everything this table records happened
    // before there was anywhere to record it: the m.room.member events from past
    // kicks and bans do not say who was acting under which permission, past role
    // edits left only their end state in server_state, and past channel deletions
    // erased their own evidence. Inventing plausible history for an audit log
    // would be strictly worse than an honest empty one, so an upgraded deployment
    // starts recording from the moment it restarts.
}

// v14: per-server nickname.
//
// CHANGE_NICKNAME (bit 11) and MANAGE_NICKNAMES (bit 12) had existed as
// permission flags since roles were introduced, and CHANGE_NICKNAME has always
// been part of kEveryoneDefault, so the bit is set in stored role bitfields on
// every deployment — but nothing anywhere read either flag, because there was no
// nickname to change. This column is what makes them mean something.
//
// Why a column and not the m.room.member `displayname` it will be mirrored into:
// that field is already REWRITTEN from the global profile by four independent
// code paths (ProfileHandler::broadcastMemberUpdate, the creator join in
// handle_create_room, the self-membership branch of handle_set_state, and
// AutoJoin's force-join). Room state is therefore a cache of the profile, not a
// place to keep authority — a nickname stored only there would be silently
// reverted the next time the user changed their avatar or a new channel
// force-joined them. One authoritative row per user, mirrored outward, is the
// shape that survives all four.
//
// NULL means "no nickname" and is distinct from '': the API accepts an empty
// string as the instruction to CLEAR a nickname, so the two must not collide.
void migrate_v14(sqlite3* db, bool /*fresh_database*/) {
    // ALTER TABLE ADD COLUMN is the whole migration; existing rows get NULL,
    // which is exactly "this user has no nickname". No backfill: a nickname
    // nobody has ever set has no prior value to recover.
    if (!column_exists(db, "users", "nickname")) {
        exec(db, "ALTER TABLE users ADD COLUMN nickname TEXT");
    }
}

// v15: the server-wide ban list.
//
// "Ban from server" had no server-side representation at all. It was a CLIENT
// loop over the rooms its sync happened to have surfaced, calling
// POST /rooms/{id}/ban once per room, with a comment conceding that rooms the
// client had not synced "fall through the cracks". So a banned user stayed a
// joined member of every channel the moderator's client had not seen, and
// auto-join could put them back into the ones it had.
//
// Why its OWN table and not the `server_state` (event_type, state_key) blob that
// server-wide roles use:
//   * server_state holds one JSON document per key. A ban list kept there is
//     read-modify-written on every ban, so two moderators banning at the same
//     moment lose one of the two bans — the exact lost-update shape that
//     set_server_state's read-inside-the-write exists to avoid for roles, and
//     roles get away with it only because the client always submits the WHOLE
//     list. A ban is a single-row fact and belongs in a row.
//   * "is this user banned" is on the hot path of /join, every auto-join and
//     every /sync. That must be an indexed primary-key lookup, not a JSON parse
//     of an unbounded document.
// It is a table rather than room state for the reason server-wide roles stopped
// being room state earlier: delete_room hard-deletes a room's events, so a ban
// kept in room state is lifted by whoever deletes the channel it was recorded
// in. Nothing here references rooms(room_id) or users(user_id) by foreign key —
// a ban must outlive the channel it was placed from, and must survive an account
// row being removed, or deletion becomes a way to launder a ban.
void migrate_v15(sqlite3* db, bool /*fresh_database*/) {
    exec(db, R"(
        CREATE TABLE IF NOT EXISTS server_bans (
            user_id    TEXT PRIMARY KEY,
            actor      TEXT NOT NULL DEFAULT '',
            reason     TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        )
    )");

    // Backfill from room_members. Every existing membership='ban' row was placed
    // by POST /rooms/{id}/ban, and the only thing that has ever called it is the
    // client's "ban from server" loop — so each of those rows is the surviving
    // fragment of an intended SERVER ban, and dropping them on the floor would
    // silently un-ban everybody the moment this migration ran.
    //
    // `actor` is left empty because room_members does not record one: the table
    // has (room_id, user_id, membership, updated_at) and nothing else. An honest
    // blank is better than naming a plausible moderator that the database never
    // stored. created_at takes the newest updated_at across that user's ban rows,
    // which is the closest thing to "when they were banned" that exists.
    exec(db, R"(
        INSERT OR IGNORE INTO server_bans (user_id, actor, reason, created_at)
        SELECT user_id, '', '', MAX(updated_at)
        FROM room_members
        WHERE membership = 'ban'
        GROUP BY user_id
    )");
}

// v16: the indexes the audit-log filters need, and nothing more.
//
// v13 deliberately created NO secondary index on audit_log: the only query was
// "newest first by id", which the rowid primary key already serves optimally, and
// this table sits on the write path of every moderation action. That comment ended
// "add one alongside the filter that needs it, not before". This is that moment —
// GET /audit_log now filters by actor, target user, target room and action.
//
// One index per exposed filter, no composite indexes. A composite would only pay
// off for one particular AND-combination and cost a write on every insert
// regardless; with four single-column indexes SQLite picks the most selective one
// and evaluates the rest as a residual test over the (already tiny) matching run,
// which is the right trade for a table measured in tens of rows a day.
//
// WRITE COST, per appended audit record (measured against the shape of the
// queries in SqliteStore::list_audit_records):
//   * idx_audit_log_actor   — one b-tree insert on EVERY record. `actor` is never
//                             empty (an audited action always has an authenticated
//                             performer), so this index is as tall as the table.
//   * idx_audit_log_action  — one b-tree insert on EVERY record, same reasoning.
//                             Low cardinality (~13 action names), so the index is
//                             a handful of long key runs; still worth it, because
//                             "show me every ban" otherwise scans the whole table
//                             to fill one page.
//   * idx_audit_log_target_user — PARTIAL (WHERE target_user <> ''). Records with
//                             no user target — channel/category deletions, role
//                             definition edits — are not indexed at all and pay
//                             nothing on insert.
//   * idx_audit_log_target_room — PARTIAL (WHERE target_room <> ''). Likewise:
//                             nickname changes and role writes are server-wide and
//                             stay out of this index.
// So the worst case is 4 extra b-tree inserts on one row of a few hundred bytes,
// for an action that already performed a permission check, a state write and a
// sync broadcast. The table's volume is bounded by privilege rather than by
// traffic (see SqliteStore::append_audit_record), so this is not a hot path in
// the sense that `events` is.
//
// Why the target indexes are PARTIAL: '' is the "not applicable" sentinel and is
// by far the most common value in both columns, so a full index would be mostly
// one enormous key run that no query ever probes. The consequence is that the
// planner only uses them when the statement itself proves the row is in the index
// — a bound `target_user = ?` cannot prove `? <> ''` — so list_audit_records emits
// the matching `AND target_user <> ''` guard alongside the equality. Dropping that
// guard does not break correctness, it silently degrades to a full scan.
//
// No explicit `id` column in any of these. For a rowid table with
// `id INTEGER PRIMARY KEY`, the rowid IS `id` and is already the implicit last
// column of every index, so `WHERE actor = ? AND id < ? ORDER BY id DESC` is
// served as a range seek inside the actor's key run with no sort step. Naming
// `id` explicitly would store it twice per entry and buy nothing. Verified with
// EXPLAIN QUERY PLAN: SEARCH ... USING COVERING INDEX (actor=? AND rowid<?), and
// no "USE TEMP B-TREE FOR ORDER BY".
//
// Indexes do NOT weaken the append-only guarantee. The v13 triggers fire BEFORE
// UPDATE and BEFORE DELETE on audit_log; index maintenance happens in the b-tree
// layer under an INSERT and issues no UPDATE or DELETE statement, and CREATE INDEX
// only reads rows. Both triggers are left exactly as v13 wrote them.
void migrate_v16(sqlite3* db, bool /*fresh_database*/) {
    exec(db, "CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor)");
    exec(db, "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)");
    exec(db, "CREATE INDEX IF NOT EXISTS idx_audit_log_target_user "
             "ON audit_log(target_user) WHERE target_user <> ''");
    exec(db, "CREATE INDEX IF NOT EXISTS idx_audit_log_target_room "
             "ON audit_log(target_room) WHERE target_room <> ''");
}

// v17: call signalling stops being a permanent public record of everyone's IP.
//
// See store/CallSignalling.h for what the leak was and why these five event
// types are singled out. This step does two things, in this order:
//
//   1. Adds `signal_to` to `events` and backfills it. It is the ADDRESSEE of an
//      addressed signalling event and NULL for everything else — every message,
//      every state event, and any signalling from a client too old to address
//      it. Every read path keys off "signal_to IS NULL" meaning "ordinary
//      event, behave exactly as before", so the column has to be NULL-by-
//      default and the backfill has to be conservative: anything it cannot
//      confidently parse stays NULL and stays visible, because the failure mode
//      in that direction is the status quo while the other direction is a call
//      that silently never connects.
//
//   2. Deletes the addressed signalling already on disk that is older than the
//      TTL. This is the part that matters for a deployment that has been
//      running: the column alone would stop NEW addresses being published, and
//      leave the existing archive — 4,518 events back to April on production —
//      sitting in the timeline for the next person to join and page back
//      through. A privacy fix that only applies going forward is not one.
//
// The delete is safe to do here in bulk. Nothing references events(event_id)
// except event_mentions (ON DELETE CASCADE, and signalling never carries a
// mention) and event_search (populated only for m.room.message, so no
// signalling event has ever had a row in it). Stream positions are not
// disturbed either: the head lives in server_meta and is never re-derived from
// MAX(stream_position), so removing rows cannot rewind a client's sync token.
//
// Counted and logged, because "it deleted something" is not a claim worth
// making without a number next to it.
void migrate_v17(sqlite3* db, bool /*fresh_database*/) {
    if (!column_exists(db, "events", "signal_to")) {
        exec(db, "ALTER TABLE events ADD COLUMN signal_to TEXT");
    }

    // Partial: only addressed signalling is ever in it, which on a normal
    // deployment is a couple of minutes' worth of rows rather than the whole
    // events table. It serves the sweep's `WHERE signal_to IS NOT NULL AND
    // origin_server_ts < ?` directly, and it costs an insert only on the events
    // that go into it — a chat message pays nothing.
    exec(db, "CREATE INDEX IF NOT EXISTS idx_events_signal_expiry "
             "ON events(origin_server_ts) WHERE signal_to IS NOT NULL");

    // Backfill. Only the five types can match, so this reads a bounded slice of
    // the table rather than all of it.
    std::string type_list;
    for (auto t : {event_type::kCallInvite, event_type::kCallAnswer,
                   event_type::kCallCandidates, event_type::kCallHangup,
                   event_type::kCallNegotiate}) {
        if (!type_list.empty()) type_list += ", ";
        type_list += "'" + std::string(t) + "'";
    }

    std::vector<std::pair<std::string, std::string>> addressed; // event_id -> to
    {
        auto sel = prepare(db, "SELECT event_id, event_type, content FROM events "
                               "WHERE event_type IN (" + type_list + ")");
        while (sqlite3_step(sel.get()) == SQLITE_ROW) {
            const std::string id = text_or_empty(sel.get(), 0);
            const std::string type = text_or_empty(sel.get(), 1);
            const std::string content = text_or_empty(sel.get(), 2);
            if (auto to = call_signal_addressee(type, content)) {
                addressed.emplace_back(id, *to);
            }
        }
    }

    {
        auto upd = prepare(db, "UPDATE events SET signal_to = ? WHERE event_id = ?");
        for (const auto& [id, to] : addressed) {
            sqlite3_reset(upd.get());
            sqlite3_bind_text(upd.get(), 1, to.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(upd.get(), 2, id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(upd.get()) != SQLITE_DONE) {
                throw std::runtime_error(std::string("v17 backfill failed: ") +
                                         sqlite3_errmsg(db));
            }
        }
    }

    // The purge. Everything already on disk is by definition older than a
    // 2-minute TTL by the time a server that has been down long enough to
    // upgrade comes back, but the cutoff is computed rather than assumed so
    // this step cannot delete a live call's signalling on a fast restart.
    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    const int64_t cutoff = now_ms - limits::kCallSignallingTtlMs;

    const int before = scalar_int(db, "SELECT COUNT(*) FROM events WHERE signal_to IS NOT NULL");
    {
        auto del = prepare(db, "DELETE FROM events "
                               "WHERE signal_to IS NOT NULL AND origin_server_ts < ?");
        sqlite3_bind_int64(del.get(), 1, cutoff);
        if (sqlite3_step(del.get()) != SQLITE_DONE) {
            throw std::runtime_error(std::string("v17 purge failed: ") + sqlite3_errmsg(db));
        }
    }
    const int purged = before - scalar_int(db,
        "SELECT COUNT(*) FROM events WHERE signal_to IS NOT NULL");

    get_logger()->info(
        "Schema v17: purged {} stored call-signalling events older than {}s "
        "(they carried participants' LAN and public IP addresses); {} retained "
        "as still within the delivery window",
        purged, limits::kCallSignallingTtlMs / 1000, before - purged);
}

// v18: existing DMs say so in their own room state, like new ones do.
//
// RoomHandler now stamps `is_direct: true` onto both participants' m.room.member
// content when a DM is created, so the room itself tells every client what it
// is. Rooms created before that have `rooms.is_direct = 1` and membership events
// with nothing in them — and those are precisely the DMs a running deployment
// has. This backfills them so the two kinds are indistinguishable from here on.
//
// Strictly additive and idempotent: it sets one key on rows that lack it, adds
// no rows, deletes none, and emits no events — a re-run matches nothing.
//
// Safe against the event store's shape:
//   - `content` is plain TEXT holding the JSON a handler dumped. There is no
//     hash, signature or content-derived id over it (no federation), so nothing
//     is invalidated by rewriting it.
//   - `events` carries no triggers, and `event_search` is populated only for
//     m.room.message, so no FTS row can drift out of step with a member event.
//   - Only the CURRENT state row per (room, state_key) is touched, matched the
//     same way get_state_events() resolves current state. History keeps saying
//     what it said at the time, and stream positions are untouched, so no
//     client's sync token moves.
//   - json_valid() guards the rewrite: a row whose content somehow is not JSON
//     is skipped rather than being set to NULL by json_set().
//
// This is belt to the braces of restating m.direct in /sync — a client that has
// both needs neither — but it is what makes an existing DM classifiable from
// room state alone, which is the property new DMs get for free.
void migrate_v18(sqlite3* db, bool fresh_database) {
    // A fresh database has no rooms at all, let alone legacy ones.
    if (fresh_database) return;

    const int before = scalar_int(db,
        "SELECT COUNT(*) FROM events "
        "WHERE event_type = 'm.room.member' "
        "  AND json_valid(content) AND json_extract(content, '$.is_direct') IS NOT NULL");

    exec(db, R"(
        UPDATE events
           SET content = json_set(content, '$.is_direct', json('true'))
         WHERE event_type = 'm.room.member'
           AND state_key IS NOT NULL
           AND json_valid(content)
           AND json_extract(content, '$.is_direct') IS NULL
           AND room_id IN (SELECT room_id FROM rooms WHERE is_direct = 1)
           AND stream_position = (
                 SELECT MAX(prev.stream_position) FROM events prev
                  WHERE prev.room_id = events.room_id
                    AND prev.event_type = 'm.room.member'
                    AND prev.state_key = events.state_key)
    )");

    const int after = scalar_int(db,
        "SELECT COUNT(*) FROM events "
        "WHERE event_type = 'm.room.member' "
        "  AND json_valid(content) AND json_extract(content, '$.is_direct') IS NOT NULL");

    get_logger()->info(
        "Schema v18: marked {} membership event(s) in pre-existing direct rooms as "
        "is_direct, so clients can tell a DM from a channel without m.direct",
        after - before);
}

using Step = void (*)(sqlite3*, bool);

const std::vector<Step>& steps() {
    static const std::vector<Step> kMigrations = {
        migrate_v1,
        migrate_v2,
        migrate_v3,
        migrate_v4,
        migrate_v5,
        migrate_v6,
        migrate_v7,
        migrate_v8,
        migrate_v9,
        migrate_v10,
        migrate_v11,
        migrate_v12,
        migrate_v13,
        migrate_v14,
        migrate_v15,
        migrate_v16,
        migrate_v17,
        migrate_v18,
    };
    return kMigrations;
}

} // namespace

int get_schema_version(sqlite3* db) {
    return scalar_int(db, "PRAGMA user_version");
}

void run_migrations(sqlite3* db, bool fresh_database) {
    const auto& all = steps();
    if (static_cast<int>(all.size()) != kTargetSchemaVersion) {
        throw std::runtime_error("migration table size does not match kTargetSchemaVersion");
    }

    int current = get_schema_version(db);
    if (current > kTargetSchemaVersion) {
        throw std::runtime_error(
            "database schema version " + std::to_string(current) +
            " is newer than this build supports (" + std::to_string(kTargetSchemaVersion) +
            "); refusing to start against a database written by a newer server");
    }
    if (current == kTargetSchemaVersion) return;

    get_logger()->info("Applying schema migrations {} -> {}", current, kTargetSchemaVersion);

    for (int v = current; v < kTargetSchemaVersion; ++v) {
        exec(db, "BEGIN IMMEDIATE");
        try {
            all[static_cast<size_t>(v)](db, fresh_database);
            // PRAGMA user_version doesn't accept a bound parameter.
            exec(db, "PRAGMA user_version = " + std::to_string(v + 1));
            exec(db, "COMMIT");
        } catch (...) {
            exec(db, "ROLLBACK");
            throw;
        }
        get_logger()->info("Schema migration {} applied", v + 1);
    }
}

} // namespace bsfchat
