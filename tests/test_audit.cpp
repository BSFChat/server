// Moderation audit log (schema v13).
//
// The properties under test, in the order they appear below:
//   1. v13 applies to a real, populated v12 database and loses nothing.
//   2. Each audited action writes EXACTLY ONE record, with the right actor and
//      target — and an action that was refused writes none.
//   3. A channel-deletion record outlives the channel, which is the whole reason
//      the log is not stored as room events.
//   4. The read endpoint is gated at SERVER scope: a per-channel override that
//      grants the flag inside a channel must NOT unlock the server-wide log.
//   5. Pagination is stable while inserts are landing concurrently.
//   6. No path mutates or deletes a record — enforced by the database, not by
//      convention.
//   7. Audit content never reaches the FTS5 message-search index.

#include <gtest/gtest.h>

#include "api/AuditHandler.h"
#include "api/RoomHandler.h"
#include "audit/AuditLog.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "store/Migrations.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <sqlite3.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-audit-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

// httplib leaves status at -1 until the response is actually written, so a
// handler that succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

template <typename Handler, typename Method>
httplib::Response call(Handler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
}

// A request whose query parameters matter (the audit endpoint's limit/from).
httplib::Response call_with_params(AuditHandler& handler, const std::string& token,
                                   const httplib::Params& params) {
    auto req = make_request(std::string(api_path::kAuditLog), token);
    req.params = params;
    httplib::Response res;
    handler.handle_get_audit_log(req, res);
    return res;
}

// Runs arbitrary SQL on a SEPARATE connection to the same database file. Used to
// prove what the DATABASE permits, not merely what SqliteStore chooses to do —
// append-only has to hold against any writer, including a future one.
int raw_exec(const std::string& path, const std::string& sql, std::string* error = nullptr) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return SQLITE_ERROR;
    sqlite3_busy_timeout(db, 5000);
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    if (error) *error = err ? err : "";
    if (err) sqlite3_free(err);
    sqlite3_close(db);
    return rc;
}

std::string raw_text(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return {};
    sqlite3_stmt* stmt = nullptr;
    std::string out;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            out = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

// The query plan SQLite chooses for a statement, as the concatenated `detail`
// column of EXPLAIN QUERY PLAN. Whether an index is USED is invisible in a
// result set — an unindexed scan returns byte-identical rows — so this is the
// only way to assert it.
std::string explain_plan(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return {};
    sqlite3_stmt* stmt = nullptr;
    std::string out;
    const std::string explained = "EXPLAIN QUERY PLAN " + sql;
    if (sqlite3_prepare_v2(db, explained.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            // Column 3 is `detail`.
            auto* text = sqlite3_column_text(stmt, 3);
            if (text) out += std::string(reinterpret_cast<const char*>(text)) + "\n";
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

int schema_version_of(const std::string& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return -1;
    int v = get_schema_version(db);
    sqlite3_close(db);
    return v;
}

// A role with only the flags a test needs, so gating can be checked without
// ADMINISTRATOR papering over it.
ServerRole role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

struct Fixture {
    std::string db_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;

    // A file-backed database (not ":memory:") so raw_exec can attack the same
    // data through a second connection.
    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    // Seeds roles by writing server_state DIRECTLY rather than through
    // write_server_scoped_state, so fixture setup does not itself land audit
    // records and every test starts from an empty log.
    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kModerator, 10,
                                     permission::kEveryoneDefault | permission::kKickMembers |
                                         permission::kBanMembers |
                                         permission::kManageChannels |
                                         permission::kManageRoles));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        // Server management without ADMINISTRATOR, so the audit gate is exercised
        // on its own flag rather than on the god-mode short-circuit.
        content.roles.push_back(role("serveradmin", 90,
                                     permission::kEveryoneDefault | permission::kManageServer));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev");

        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    std::string add_channel(const std::string& creator, const std::string& name,
                            const std::string& type = "text") {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", type}}.dump(), 1001);
        return room_id;
    }

    // Writes a per-channel allow/deny override the way handle_set_state does.
    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target, j.dump(), 1002);
    }

    std::vector<SqliteStore::AuditRecord> records() {
        return store->list_audit_records(limits::kMaxAuditLimit, std::nullopt).records;
    }

    int64_t record_count() {
        return store->list_audit_records(1, std::nullopt).total;
    }
};

const std::string kRoomsPrefix = "/_matrix/client/v3/rooms/";

std::string kick_path(const std::string& room) { return kRoomsPrefix + room + "/kick"; }
std::string ban_path(const std::string& room) { return kRoomsPrefix + room + "/ban"; }
std::string unban_path(const std::string& room) { return kRoomsPrefix + room + "/unban"; }
std::string state_path(const std::string& room, const std::string& type,
                       const std::string& key) {
    return kRoomsPrefix + room + "/state/" + type + "/" + key;
}

// ── A real v12 database, populated ────────────────────────────────────────
//
// Exactly the shape migrations v1–v12 leave behind, with user_version pinned to
// 12 and data in every table v13 could plausibly disturb — including a live FTS5
// search index, since the audit log must not end up entangled with it.
void create_v12_database(const std::string& path) {
    remove_db(path);
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);

    const char* schema = R"SQL(
        CREATE TABLE users (user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
            display_name TEXT, avatar_url TEXT,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));
        CREATE TABLE access_tokens (token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id), device_id TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            expires_at INTEGER NOT NULL, last_used_at INTEGER,
            lifetime_ms INTEGER NOT NULL, refresh_hash TEXT UNIQUE);
        CREATE INDEX idx_access_tokens_user ON access_tokens(user_id);
        CREATE TABLE rooms (room_id TEXT PRIMARY KEY, creator TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            is_direct INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE room_members (room_id TEXT NOT NULL REFERENCES rooms(room_id),
            user_id TEXT NOT NULL, membership TEXT NOT NULL DEFAULT 'join',
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (room_id, user_id));
        CREATE TABLE events (event_id TEXT PRIMARY KEY,
            room_id TEXT NOT NULL REFERENCES rooms(room_id), sender TEXT NOT NULL,
            event_type TEXT NOT NULL, state_key TEXT, content TEXT NOT NULL,
            origin_server_ts INTEGER NOT NULL, stream_position INTEGER NOT NULL UNIQUE,
            redacted_by TEXT, edited_by TEXT, replaces TEXT);
        CREATE INDEX idx_events_room_stream ON events(room_id, stream_position);
        CREATE TABLE read_markers (user_id TEXT NOT NULL, room_id TEXT NOT NULL,
            last_read_pos INTEGER NOT NULL, PRIMARY KEY (user_id, room_id));
        CREATE TABLE media (media_id TEXT PRIMARY KEY, uploader TEXT NOT NULL,
            content_type TEXT NOT NULL, filename TEXT, file_size INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));
        CREATE TABLE server_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE server_state (event_type TEXT NOT NULL, state_key TEXT NOT NULL,
            sender TEXT NOT NULL, content TEXT NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (event_type, state_key));
        CREATE TABLE event_transactions (user_id TEXT NOT NULL, txn_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (user_id, txn_id));
        CREATE TABLE event_mentions (
            event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
            room_id TEXT NOT NULL, user_id TEXT NOT NULL, sender TEXT NOT NULL,
            stream_position INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (event_id, user_id));
        CREATE INDEX idx_event_mentions_target
            ON event_mentions(user_id, room_id, stream_position);
        CREATE INDEX idx_event_mentions_room ON event_mentions(room_id);
        CREATE TABLE pushers (user_id TEXT NOT NULL, app_id TEXT NOT NULL,
            pushkey TEXT NOT NULL, device_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
            app_display_name TEXT NOT NULL DEFAULT '',
            device_display_name TEXT NOT NULL DEFAULT '',
            profile_tag TEXT NOT NULL DEFAULT '', lang TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '', format TEXT NOT NULL DEFAULT '',
            data TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (user_id, app_id, pushkey));
        CREATE INDEX idx_pushers_user ON pushers(user_id);
        CREATE INDEX idx_pushers_pushkey ON pushers(pushkey);
        CREATE TABLE push_queue (id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL, app_id TEXT NOT NULL, pushkey TEXT NOT NULL,
            url TEXT NOT NULL, payload TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));
        CREATE INDEX idx_push_queue_due ON push_queue(next_attempt_at);
        CREATE TABLE room_notify_settings (user_id TEXT NOT NULL, room_id TEXT NOT NULL,
            level TEXT NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (user_id, room_id));
        CREATE INDEX idx_room_notify_room ON room_notify_settings(room_id);
        CREATE TABLE event_search (rowid INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
            room_id TEXT NOT NULL, sender TEXT NOT NULL, stream_position INTEGER NOT NULL,
            body TEXT NOT NULL);
        CREATE INDEX idx_event_search_room ON event_search(room_id, stream_position);
        CREATE VIRTUAL TABLE event_search_fts USING fts5(
            body, content='event_search', content_rowid='rowid');

        INSERT INTO users (user_id, password_hash, display_name) VALUES
            ('@alice:test','hash-a','Alice'),
            ('@bob:test','hash-b','Bob');
        INSERT INTO access_tokens (token_hash, user_id, device_id, expires_at, lifetime_ms)
            VALUES ('deadbeef','@alice:test','dev-a', 99999999999999, 7776000000);
        INSERT INTO rooms (room_id, creator, is_direct) VALUES
            ('!general:test','@alice:test',0),
            ('!dm:test','@alice:test',1);
        INSERT INTO room_members (room_id,user_id,membership) VALUES
            ('!general:test','@alice:test','join'),
            ('!general:test','@bob:test','join'),
            ('!dm:test','@alice:test','join');
        INSERT INTO events VALUES ('$m1','!general:test','@alice:test','m.room.message',
            NULL,'{"msgtype":"m.text","body":"hello pineapple"}',1000,1,NULL,NULL,NULL);
        INSERT INTO events VALUES ('$s1','!general:test','@alice:test','m.room.name',
            '','{"name":"general"}',1001,2,NULL,NULL,NULL);
        INSERT INTO read_markers VALUES ('@bob:test','!general:test',1);
        INSERT INTO server_meta (key,value) VALUES ('next_stream_position','3');
        INSERT INTO server_state (event_type,state_key,sender,content) VALUES
            ('bsfchat.server.roles','','@server:test',
             '{"roles":[{"id":"everyone","name":"@everyone","position":0,"permissions":"0x1f"}]}');
        INSERT INTO event_transactions (user_id,txn_id,event_id) VALUES
            ('@alice:test','txn-1','$m1');
        INSERT INTO event_mentions (event_id,room_id,user_id,sender,stream_position)
            VALUES ('$m1','!general:test','@bob:test','@alice:test',1);
        INSERT INTO pushers (user_id,app_id,pushkey,kind,url) VALUES
            ('@bob:test','com.bsfchat.app','key-1','http','https://gw.example/notify');
        INSERT INTO room_notify_settings (user_id,room_id,level) VALUES
            ('@bob:test','!general:test','all');
        INSERT INTO event_search (event_id,room_id,sender,stream_position,body)
            VALUES ('$m1','!general:test','@alice:test',1,'hello pineapple');
        INSERT INTO event_search_fts (rowid, body)
            SELECT rowid, body FROM event_search;

        PRAGMA user_version = 12;
    )SQL";

    char* err = nullptr;
    ASSERT_EQ(sqlite3_exec(db, schema, nullptr, nullptr, &err), SQLITE_OK) << (err ? err : "?");
    sqlite3_close(db);
}


// ── A real v15 database, populated, WITH audit history ────────────────────
//
// The state an existing deployment is actually in the moment before v16 runs:
// the v12 fixture above plus v13's audit_log and its two append-only triggers,
// v14's users.nickname column and v15's server_bans table — applied as raw DDL
// rather than by letting a v16-aware SqliteStore build it, so the "before" really
// is the shape the earlier migrations left behind.
//
// The audit rows are deliberately varied: different actors, some with a user
// target, some with a room target, some with neither. v16 adds PARTIAL indexes
// keyed on `<> ''`, and a fixture where every row had every field populated would
// not exercise the rows those indexes deliberately exclude.
void create_v15_database_with_audit_history(const std::string& path) {
    create_v12_database(path);

    const char* upgrade = R"SQL(
        -- v13
        CREATE TABLE audit_log (
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
        );
        CREATE TRIGGER audit_log_is_append_only_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
        END;
        CREATE TRIGGER audit_log_is_append_only_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
        END;

        -- v14
        ALTER TABLE users ADD COLUMN nickname TEXT;

        -- v15
        CREATE TABLE server_bans (
            user_id    TEXT PRIMARY KEY,
            actor      TEXT NOT NULL DEFAULT '',
            reason     TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );

        -- History recorded by the running v13-v15 deployment.
        INSERT INTO audit_log (created_at, actor, action, target_user, target_room, reason)
        VALUES
          (1000, '@mallory:test', 'member.kick', '@bob:test',   '!general:test', 'spam'),
          (1001, '@mallory:test', 'member.ban',  '@bob:test',   '!general:test', 'again'),
          (1002, '@alice:test',   'member.ban',  '@carol:test', '!general:test', ''),
          (1003, '@alice:test',   'channel.delete', '',         '!gone:test',    ''),
          (1004, '@mallory:test', 'role.update', '',            '',              '');

        PRAGMA user_version = 15;
    )SQL";

    std::string err;
    ASSERT_EQ(raw_exec(path, upgrade, &err), SQLITE_OK) << err;
}

} // namespace

// ══ 1. Migration ══════════════════════════════════════════════════════════

TEST(AuditMigration, FreshDatabaseGetsV13WithAnAppendOnlySchema) {
    Fixture f("fresh-v13");
    EXPECT_EQ(schema_version_of(f.db_path), kTargetSchemaVersion);
    // v13 is the audit log; the pin tracks the latest schema, now 19 (v14
    // users.nickname, v15 server_bans, v16 the audit_log filter indexes, v17
    // events.signal_to and the call-signalling sweep, v18 the is_direct
    // backfill onto pre-existing DMs' membership state, v19 refresh-token
    // families). This test's subject remains the v13 audit_log shape below.
    EXPECT_EQ(kTargetSchemaVersion, 19);

    // AUTOINCREMENT, not a bare INTEGER PRIMARY KEY. Without it SQLite reuses
    // max(rowid) + 1, which is exactly the position-reuse defect v4 fixed for
    // events.stream_position — and here it would silently corrupt pagination
    // cursors.
    auto sql = raw_text(f.db_path,
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_log'");
    EXPECT_NE(sql.find("AUTOINCREMENT"), std::string::npos) << sql;

    // Append-only is a schema guarantee, not a code convention.
    EXPECT_EQ(raw_text(f.db_path,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
        "AND name IN ('audit_log_is_append_only_update','audit_log_is_append_only_delete')"),
        "2");
}

TEST(AuditMigration, PreExistingV12DatabaseUpgradesAndKeepsItsData) {
    auto path = temp_db_path("v12-upgrade");
    create_v12_database(path);
    ASSERT_EQ(schema_version_of(path), 12);

    {
        SqliteStore store(path);
        store.initialize();

        // Every pre-existing row survived the upgrade.
        EXPECT_EQ(store.list_all_users().size(), 2u);
        EXPECT_TRUE(store.room_exists("!general:test"));
        EXPECT_TRUE(store.is_direct_room("!dm:test"));
        EXPECT_EQ(store.get_room_members("!general:test").size(), 2u);
        EXPECT_EQ(store.get_display_name("@alice:test").value_or(""), "Alice");
        EXPECT_EQ(store.get_read_marker("@bob:test", "!general:test"), 1);
        EXPECT_EQ(store.get_transaction_event("@alice:test", "txn-1").value_or(""), "$m1");
        EXPECT_EQ(store.get_server_roles().size(), 1u);
        EXPECT_EQ(store.get_pushers("@bob:test").size(), 1u);
        EXPECT_EQ(store.get_room_notify_level("@bob:test", "!general:test").value_or(""), "all");
        ASSERT_TRUE(store.get_event_by_id("$m1").has_value());

        // The v12 search index still works against the pre-existing data.
        ASSERT_TRUE(store.search_index_available());
        EXPECT_EQ(store.count_search_index_rows(), 1);
        EXPECT_EQ(store.search_messages({"!general:test"}, {"pineapple"}, {}, 10, 0, false)
                      .hits.size(), 1u);

        // The new table exists, starts empty (no fabricated history), and works.
        auto page = store.list_audit_records(10, std::nullopt);
        EXPECT_TRUE(page.records.empty());
        EXPECT_EQ(page.total, 0);

        SqliteStore::AuditRecord r;
        r.actor = "@alice:test";
        r.action = audit_action::kMemberBan;
        r.target_user = "@bob:test";
        r.target_room = "!general:test";
        EXPECT_GT(store.append_audit_record(r), 0);
        EXPECT_EQ(store.list_audit_records(10, std::nullopt).total, 1);
    }

    EXPECT_EQ(schema_version_of(path), kTargetSchemaVersion);
    remove_db(path);
}

TEST(AuditMigration, UpgradeFromV12IsIdempotent) {
    auto path = temp_db_path("v12-idempotent");
    create_v12_database(path);
    {
        SqliteStore store(path);
        store.initialize();
        store.initialize(); // re-running must be a no-op
        SqliteStore::AuditRecord r;
        r.actor = "@alice:test";
        r.action = audit_action::kChannelDelete;
        store.append_audit_record(r);
    }
    {
        // Reopening must not re-run v13 in a way that disturbs existing records.
        SqliteStore store(path);
        store.initialize();
        EXPECT_EQ(store.list_audit_records(10, std::nullopt).total, 1);
    }
    EXPECT_EQ(schema_version_of(path), kTargetSchemaVersion);
    remove_db(path);
}

// ══ 2. Write sites: exactly one record, correct actor and target ═══════════

TEST(AuditWrites, KickWritesExactlyOneRecord) {
    Fixture f("kick");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_kick, kick_path(room), "token-mod",
                    json{{"user_id", bob}, {"reason", "spam"}}.dump());
    ASSERT_TRUE(IsOk(res));

    auto all = f.records();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].action, audit_action::kMemberKick);
    EXPECT_EQ(all[0].actor, mod);
    EXPECT_EQ(all[0].target_user, bob);
    EXPECT_EQ(all[0].target_room, room);
    EXPECT_EQ(all[0].reason, "spam");
    EXPECT_GT(all[0].created_at, 0);
    // The transition, not just the end state.
    EXPECT_EQ(json::parse(all[0].before_json).value("membership", ""), "join");
    EXPECT_EQ(json::parse(all[0].after_json).value("membership", ""), "leave");
}

TEST(AuditWrites, BanWritesExactlyOneRecord) {
    Fixture f("ban");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          json{{"user_id", bob}, {"reason", "raiding"}}.dump())));

    auto all = f.records();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].action, audit_action::kMemberBan);
    EXPECT_EQ(all[0].actor, mod);
    EXPECT_EQ(all[0].target_user, bob);
    EXPECT_EQ(all[0].reason, "raiding");
    EXPECT_EQ(json::parse(all[0].after_json).value("membership", ""), "ban");
}

TEST(AuditWrites, UnbanWorksAndWritesExactlyOneRecord) {
    Fixture f("unban");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kBan));

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_unban, unban_path(room), "token-mod",
                          json{{"user_id", bob}}.dump())));

    // The ban is actually lifted (this endpoint did not exist before).
    EXPECT_EQ(f.store->get_membership(room, bob), "leave");

    auto all = f.records();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].action, audit_action::kMemberUnban);
    EXPECT_EQ(all[0].actor, mod);
    EXPECT_EQ(all[0].target_user, bob);
    EXPECT_EQ(json::parse(all[0].before_json).value("membership", ""), "ban");
    EXPECT_EQ(json::parse(all[0].after_json).value("membership", ""), "leave");
}

TEST(AuditWrites, UnbanningSomebodyWhoIsNotBannedIsRefusedAndRecordsNothing) {
    Fixture f("unban-notbanned");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_unban, unban_path(room), "token-mod",
                    json{{"user_id", bob}}.dump());
    EXPECT_EQ(res.status, 403);
    EXPECT_EQ(f.store->get_membership(room, bob), "join");
    EXPECT_EQ(f.record_count(), 0);
}

TEST(AuditWrites, ARefusedKickRecordsNothing) {
    Fixture f("kick-refused");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");   // @everyone only: no KICK_MEMBERS
    auto carol = f.add_user("carol");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));
    f.store->set_membership(room, carol, std::string(membership::kJoin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_kick, kick_path(room), "token-bob",
                    json{{"user_id", carol}}.dump());
    EXPECT_EQ(res.status, 403);
    // The log records what HAPPENED. A rejected attempt changed nothing, and
    // logging refusals here would let any user write to the audit log at will.
    EXPECT_EQ(f.record_count(), 0);
    EXPECT_EQ(f.store->get_membership(room, carol), "join");
}

TEST(AuditWrites, ChannelDeletionIsRecordedAndOutlivesTheChannel) {
    Fixture f("delete-channel");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "announcements");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_delete_room,
                          "/_matrix/client/v3/rooms/" + room, "token-mod")));
    ASSERT_FALSE(f.store->room_exists(room));

    // THE point of not storing the log as room events: delete_room hard-deletes
    // every event in the room, so a record kept there would have deleted itself
    // along with the thing it documents.
    auto all = f.records();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].action, audit_action::kChannelDelete);
    EXPECT_EQ(all[0].actor, mod);
    EXPECT_EQ(all[0].target_room, room);
    // And it still knows what the channel WAS, which nothing else in the
    // database can say any more.
    auto before = json::parse(all[0].before_json);
    EXPECT_EQ(before.value("name", ""), "announcements");
    EXPECT_EQ(before.value("type", ""), "text");
    EXPECT_EQ(before.value("members", 0), 2);
    EXPECT_TRUE(all[0].after_json.empty()) << "a deleted room has no after-state";
}

TEST(AuditWrites, CategoryDeletionUsesTheCategoryAction) {
    Fixture f("delete-category");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto room = f.add_channel(mod, "Text Channels", "category");

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_delete_room,
                          "/_matrix/client/v3/rooms/" + room, "token-mod")));

    auto all = f.records();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].action, audit_action::kCategoryDelete);
    EXPECT_EQ(json::parse(all[0].before_json).value("name", ""), "Text Channels");
}

TEST(AuditWrites, RoleCreationUpdateAndDeletionRecordPermissionBitfields) {
    Fixture f("roles");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(admin, "general");

    RoomHandler handler(*f.store, *f.sync, f.config);
    const auto path = state_path(room, std::string(event_type::kServerRoles), "");

    // One write that creates a role ("helper"), deletes another ("serveradmin")
    // and modifies a third (BAN_MEMBERS taken off the moderator).
    ServerRolesContent next;
    next.roles.push_back(role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
    next.roles.push_back(role(permission::role_id::kModerator, 10,
                              permission::kEveryoneDefault | permission::kKickMembers |
                                  permission::kManageChannels | permission::kManageRoles));
    next.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
    next.roles.push_back(role("helper", 5, permission::kEveryoneDefault));
    json body;
    to_json(body, next);

    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state, path, "token-admin",
                          body.dump())));

    auto all = f.records();
    ASSERT_EQ(all.size(), 3u) << "expected one record per role actually changed";

    std::map<std::string, SqliteStore::AuditRecord> by_action;
    for (const auto& r : all) by_action[r.action] = r;
    ASSERT_EQ(by_action.size(), 3u);

    const auto& created = by_action.at(audit_action::kRoleCreate);
    EXPECT_EQ(created.actor, admin);
    EXPECT_EQ(created.target_key, "helper");
    EXPECT_TRUE(created.before_json.empty()) << "a new role has no before-state";
    EXPECT_EQ(json::parse(created.after_json).value("permissions", ""),
              permission::flags_to_hex(permission::kEveryoneDefault));

    const auto& deleted = by_action.at(audit_action::kRoleDelete);
    EXPECT_EQ(deleted.target_key, "serveradmin");
    EXPECT_TRUE(deleted.after_json.empty()) << "a deleted role has no after-state";
    EXPECT_EQ(json::parse(deleted.before_json).value("permissions", ""),
              permission::flags_to_hex(permission::kEveryoneDefault |
                                       permission::kManageServer));

    const auto& updated = by_action.at(audit_action::kRoleUpdate);
    EXPECT_EQ(updated.target_key, permission::role_id::kModerator);
    // The bitfield either side of the change, which is what makes "who took away
    // BAN_MEMBERS" answerable.
    auto before_flags = permission::flags_from_hex(
        json::parse(updated.before_json).value("permissions", ""));
    auto after_flags = permission::flags_from_hex(
        json::parse(updated.after_json).value("permissions", ""));
    EXPECT_TRUE(permission::has(before_flags, permission::kBanMembers));
    EXPECT_FALSE(permission::has(after_flags, permission::kBanMembers));
}

TEST(AuditWrites, ARoleWriteThatChangesNothingRecordsNothing) {
    Fixture f("roles-noop");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(admin, "general");

    // Resubmit exactly what is already stored.
    auto current = f.store->get_server_state(std::string(event_type::kServerRoles), "");
    ASSERT_TRUE(current.has_value());

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kServerRoles), ""),
                          "token-admin", *current)));

    // Role writes carry the entire list. Without a diff, one edit would log a
    // no-op for every other role, and the idempotent startup bootstrap would log
    // the whole list on every restart.
    EXPECT_EQ(f.record_count(), 0);
}

TEST(AuditWrites, RoleAssignmentChangeRecordsWhatWasAddedAndRemoved) {
    Fixture f("role-assign");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin, "general");

    MemberRolesContent next;
    next.role_ids = {std::string(permission::role_id::kEveryone),
                     std::string(permission::role_id::kAdmin)};
    json body;
    to_json(body, next);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kMemberRoles), bob),
                          "token-admin", body.dump())));

    auto all = f.records();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].action, audit_action::kRoleAssign);
    EXPECT_EQ(all[0].actor, admin);
    EXPECT_EQ(all[0].target_user, bob);
    auto after = json::parse(all[0].after_json);
    ASSERT_EQ(after.at("added").size(), 1u);
    EXPECT_EQ(after.at("added")[0], permission::role_id::kAdmin);
    EXPECT_TRUE(after.at("removed").empty());
    EXPECT_EQ(json::parse(all[0].before_json).at("role_ids").size(), 1u);
}

TEST(AuditWrites, ReorderingTheSameRoleIdsRecordsNothing) {
    Fixture f("role-assign-noop");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob", {std::string(permission::role_id::kModerator)});
    auto room = f.add_channel(admin, "general");

    MemberRolesContent same;
    same.role_ids = {std::string(permission::role_id::kModerator),
                     std::string(permission::role_id::kEveryone)}; // reversed order
    json body;
    to_json(body, same);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kMemberRoles), bob),
                          "token-admin", body.dump())));
    // Order is not a change in what the user can do.
    EXPECT_EQ(f.record_count(), 0);
}

TEST(AuditWrites, ChannelOverrideChangeRecordsAllowAndDeny) {
    Fixture f("override");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));
    f.set_override(room, "user:" + bob, permission::kViewChannel, 0);

    ChannelPermissionOverride next;
    next.allow = 0;
    next.deny = permission::kSendMessages;
    json body;
    to_json(body, next);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + bob),
                          "token-admin", body.dump())));

    auto all = f.records();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].action, audit_action::kChannelPermissionsSet);
    EXPECT_EQ(all[0].actor, admin);
    EXPECT_EQ(all[0].target_room, room);
    EXPECT_EQ(all[0].target_key, "user:" + bob);
    // A "user:" override is also filed under that user, so "what was done to Bob"
    // does not miss permission changes aimed squarely at him.
    EXPECT_EQ(all[0].target_user, bob);
    EXPECT_EQ(json::parse(all[0].before_json).value("allow", ""),
              permission::flags_to_hex(permission::kViewChannel));
    EXPECT_EQ(json::parse(all[0].after_json).value("deny", ""),
              permission::flags_to_hex(permission::kSendMessages));
}

TEST(AuditWrites, AnUnchangedOverrideWriteRecordsNothing) {
    Fixture f("override-noop");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(admin, "general");
    f.set_override(room, "role:mod", permission::kManageMessages, 0);

    ChannelPermissionOverride same;
    same.allow = permission::kManageMessages;
    json body;
    to_json(body, same);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "role:mod"),
                          "token-admin", body.dump())));
    EXPECT_EQ(f.record_count(), 0);
}

TEST(AuditWrites, BanThroughTheGenericStateEndpointIsAlsoRecorded) {
    Fixture f("state-ban");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    // PUT /rooms/{id}/state/m.room.member/{user} is a SECOND route to a ban. If
    // only POST /rooms/{id}/ban were audited, a ban placed here would be
    // invisible — and it is gated on the same KICK_MEMBERS permission.
    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kRoomMember), bob),
                          "token-mod",
                          json{{"membership", "ban"}, {"reason", "via state"}}.dump())));

    auto all = f.records();
    ASSERT_EQ(all.size(), 1u);
    // Recorded under the SAME action name as the dedicated endpoint, so "show me
    // every ban" cannot silently miss half of them.
    EXPECT_EQ(all[0].action, audit_action::kMemberBan);
    EXPECT_EQ(all[0].actor, mod);
    EXPECT_EQ(all[0].target_user, bob);
    EXPECT_EQ(all[0].reason, "via state");
}

TEST(AuditWrites, LeavingAChannelYourselfIsNotAModerationAction) {
    Fixture f("self-leave");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kRoomMember), bob),
                          "token-bob", json{{"membership", "leave"}}.dump())));
    EXPECT_EQ(f.record_count(), 0);
}

TEST(AuditWrites, MembershipActionNameFollowsTheTransition) {
    // The mapping, unit-tested directly: the same "leave" is a kick or an unban
    // depending on where the user was coming from.
    EXPECT_EQ(membership_audit_action("join", "leave"), audit_action::kMemberKick);
    EXPECT_EQ(membership_audit_action("ban", "leave"), audit_action::kMemberUnban);
    EXPECT_EQ(membership_audit_action("join", "ban"), audit_action::kMemberBan);
    EXPECT_EQ(membership_audit_action("", "ban"), audit_action::kMemberBan);
    EXPECT_EQ(membership_audit_action("join", "invite"), audit_action::kMemberMembershipSet);
}

TEST(AuditWrites, BootstrapRoleAssignmentIsAttributedToTheServer) {
    Fixture f("bootstrap");
    // No seed_roles() here: let the real bootstrap seed them, which is the only
    // way an owner can ever answer "how did the first account get Admin?".
    f.store->create_user("@owner:test", hash_password("password", 10));
    bootstrap_roles(*f.store, *f.sync, f.config);

    auto all = f.records();
    ASSERT_FALSE(all.empty());
    for (const auto& r : all) {
        EXPECT_EQ(r.actor, "@server:test");
    }
    bool granted_admin = false;
    for (const auto& r : all) {
        if (r.action != audit_action::kRoleAssign || r.target_user != "@owner:test") continue;
        auto added = json::parse(r.after_json).at("added");
        granted_admin = std::find(added.begin(), added.end(),
                                  json(permission::role_id::kAdmin)) != added.end();
    }
    EXPECT_TRUE(granted_admin) << "the owner's admin grant must be in the log";
}

// ══ 3. Read endpoint: permission gating ═══════════════════════════════════

TEST(AuditEndpoint, RejectsAnUnauthenticatedCaller) {
    Fixture f("endpoint-401");
    f.seed_roles();
    AuditHandler handler(*f.store, f.config);
    auto res = call(handler, &AuditHandler::handle_get_audit_log,
                    std::string(api_path::kAuditLog), "bogus-token");
    EXPECT_EQ(res.status, 401);
}

TEST(AuditEndpoint, PlainMemberIsRefused) {
    Fixture f("endpoint-403");
    f.seed_roles();
    f.add_user("bob");
    AuditHandler handler(*f.store, f.config);
    auto res = call(handler, &AuditHandler::handle_get_audit_log,
                    std::string(api_path::kAuditLog), "token-bob");
    ASSERT_EQ(res.status, 403);
    EXPECT_EQ(json::parse(res.body).value("errcode", ""), "M_FORBIDDEN");
}

TEST(AuditEndpoint, ModeratorWithoutManageServerIsRefused) {
    Fixture f("endpoint-mod");
    f.seed_roles();
    f.add_user("mod", {std::string(permission::role_id::kModerator)});
    // MANAGE_ROLES and BAN_MEMBERS are not permission to read the whole server's
    // moderation history.
    AuditHandler handler(*f.store, f.config);
    EXPECT_EQ(call(handler, &AuditHandler::handle_get_audit_log,
                   std::string(api_path::kAuditLog), "token-mod").status, 403);
}

TEST(AuditEndpoint, ManageServerRoleCanRead) {
    Fixture f("endpoint-manageserver");
    f.seed_roles();
    auto ops = f.add_user("ops", {"serveradmin"}); // MANAGE_SERVER, not ADMINISTRATOR
    SqliteStore::AuditRecord r;
    r.actor = ops;
    r.action = audit_action::kMemberBan;
    r.target_user = "@bob:test";
    f.store->append_audit_record(r);

    AuditHandler handler(*f.store, f.config);
    auto res = call(handler, &AuditHandler::handle_get_audit_log,
                    std::string(api_path::kAuditLog), "token-ops");
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    ASSERT_EQ(body.at("records").size(), 1u);
    EXPECT_EQ(body.at("records")[0].at("action"), audit_action::kMemberBan);
    EXPECT_EQ(body.at("records")[0].at("target_user"), "@bob:test");
    EXPECT_EQ(body.at("total"), 1);
    EXPECT_FALSE(body.contains("next_from")) << "there is no further page";
}

TEST(AuditEndpoint, AdministratorCanRead) {
    Fixture f("endpoint-admin");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    AuditHandler handler(*f.store, f.config);
    EXPECT_TRUE(IsOk(call(handler, &AuditHandler::handle_get_audit_log,
                          std::string(api_path::kAuditLog), "token-admin")));
}

// The escalation shape that was a real bug in the role-write path: a per-channel
// override granting a flag inside one channel must not unlock a server-wide
// capability.
TEST(AuditEndpoint, PerChannelOverrideDoesNotGrantAccess) {
    Fixture f("endpoint-override-escalation");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin, "bobs-corner");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    // Bob is handed MANAGE_SERVER — and ADMINISTRATOR for good measure — inside
    // this one channel.
    f.set_override(room, "user:" + bob,
                   permission::kManageServer | permission::kAdministrator, 0);

    // Positive control: the override really is in effect at CHANNEL scope. Without
    // this the test would still pass if the override had silently failed to apply,
    // which would make the assertion below vacuous.
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.can(bob, room, permission::kManageServer))
            << "override did not apply; the rest of this test would prove nothing";
    }
    // And it does NOT leak to server scope.
    {
        PermissionsEngine perms(*f.store, f.config);
        EXPECT_FALSE(perms.can(bob, "", permission::kManageServer));
    }

    AuditHandler handler(*f.store, f.config);
    auto res = call(handler, &AuditHandler::handle_get_audit_log,
                    std::string(api_path::kAuditLog), "token-bob");
    ASSERT_EQ(res.status, 403) << res.body;
    EXPECT_EQ(res.body.find("records"), std::string::npos) << "no records may leak in a 403";
}

TEST(AuditEndpoint, RejectsAMalformedCursor) {
    Fixture f("endpoint-cursor");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    AuditHandler handler(*f.store, f.config);

    // Silently treating a bad cursor as "start from the newest" would hand a
    // paginating reader page one forever while looking like progress.
    auto res = call_with_params(handler, "token-admin", {{"from", "not-a-number"}});
    ASSERT_EQ(res.status, 400);
    EXPECT_EQ(json::parse(res.body).value("errcode", ""), "M_INVALID_PARAM");

    EXPECT_EQ(call_with_params(handler, "token-admin", {{"from", "-5"}}).status, 400);
    EXPECT_EQ(call_with_params(handler, "token-admin", {{"limit", "lots"}}).status, 400);
}

TEST(AuditEndpoint, ClampsAnOversizedLimit) {
    Fixture f("endpoint-limit");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    for (int i = 0; i < limits::kMaxAuditLimit + 20; ++i) {
        SqliteStore::AuditRecord r;
        r.actor = "@admin:test";
        r.action = audit_action::kMemberKick;
        f.store->append_audit_record(r);
    }

    AuditHandler handler(*f.store, f.config);
    auto res = call_with_params(handler, "token-admin", {{"limit", "100000"}});
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    EXPECT_EQ(body.at("records").size(), static_cast<size_t>(limits::kMaxAuditLimit));
    EXPECT_TRUE(body.contains("next_from"));
}

// ══ 4. Pagination ═════════════════════════════════════════════════════════

TEST(AuditPagination, IsStableWhenNewRecordsLandBetweenPages) {
    Fixture f("page-stable");
    std::vector<int64_t> original;
    for (int i = 0; i < 10; ++i) {
        SqliteStore::AuditRecord r;
        r.actor = "@admin:test";
        r.action = audit_action::kMemberKick;
        r.target_user = "@u" + std::to_string(i) + ":test";
        original.push_back(f.store->append_audit_record(r));
    }

    std::vector<int64_t> seen;
    auto page = f.store->list_audit_records(4, std::nullopt);
    for (const auto& r : page.records) seen.push_back(r.id);
    ASSERT_TRUE(page.next_from.has_value());

    // Five more actions happen while the reader is mid-pagination.
    for (int i = 0; i < 5; ++i) {
        SqliteStore::AuditRecord r;
        r.actor = "@admin:test";
        r.action = audit_action::kMemberBan;
        f.store->append_audit_record(r);
    }

    while (page.next_from) {
        page = f.store->list_audit_records(4, page.next_from);
        for (const auto& r : page.records) seen.push_back(r.id);
    }

    // Ids are strictly monotonic, so the interleaved inserts landed ABOVE the
    // cursor and cannot appear in a later page, duplicate a record, or push one
    // out of the window unseen.
    std::vector<int64_t> expected(original.rbegin(), original.rend());
    EXPECT_EQ(seen, expected);
    EXPECT_EQ(std::set<int64_t>(seen.begin(), seen.end()).size(), seen.size())
        << "a record was served twice";
}

TEST(AuditPagination, IsStableUnderConcurrentWriters) {
    Fixture f("page-concurrent");
    constexpr int kPreexisting = 40;
    for (int i = 0; i < kPreexisting; ++i) {
        SqliteStore::AuditRecord r;
        r.actor = "@admin:test";
        r.action = audit_action::kMemberKick;
        f.store->append_audit_record(r);
    }

    std::atomic<bool> stop{false};
    std::vector<std::thread> writers;
    for (int t = 0; t < 3; ++t) {
        writers.emplace_back([&, t] {
            for (int i = 0; i < 100 && !stop.load(); ++i) {
                SqliteStore::AuditRecord r;
                r.actor = "@admin:test";
                r.action = audit_action::kMemberBan;
                r.target_user = "@t" + std::to_string(t) + ":test";
                f.store->append_audit_record(r);
            }
        });
    }

    // Page through while the writers hammer the table.
    std::vector<int64_t> seen;
    auto page = f.store->list_audit_records(7, std::nullopt);
    for (const auto& r : page.records) seen.push_back(r.id);
    while (page.next_from) {
        page = f.store->list_audit_records(7, page.next_from);
        for (const auto& r : page.records) seen.push_back(r.id);
    }
    stop.store(true);
    for (auto& w : writers) w.join();

    // Strictly decreasing: no duplicates and no going backwards.
    for (size_t i = 1; i < seen.size(); ++i) {
        ASSERT_LT(seen[i], seen[i - 1]) << "pagination repeated or reordered a record";
    }
    // Nothing that existed when pagination started was skipped.
    std::set<int64_t> seen_set(seen.begin(), seen.end());
    for (int64_t id = 1; id <= kPreexisting; ++id) {
        EXPECT_TRUE(seen_set.count(id)) << "record " << id << " was skipped";
    }
}

TEST(AuditPagination, IdsAreNeverReusedEvenAfterARowIsForciblyRemoved) {
    Fixture f("page-noreuse");
    int64_t last = 0;
    for (int i = 0; i < 3; ++i) {
        SqliteStore::AuditRecord r;
        r.actor = "@admin:test";
        r.action = audit_action::kMemberKick;
        last = f.store->append_audit_record(r);
    }
    ASSERT_EQ(last, 3);

    // Simulate the one way a row can ever leave this table: an operator taking the
    // trigger off deliberately (documented in the example config). Even then the id
    // must not come back — a stale pagination cursor pointing at 3 must never start
    // matching a DIFFERENT record. That reuse is exactly the defect migration v4
    // fixed for events.stream_position.
    std::string err;
    ASSERT_EQ(raw_exec(f.db_path,
        "DROP TRIGGER audit_log_is_append_only_delete;"
        "DELETE FROM audit_log WHERE id = 3;", &err), SQLITE_OK) << err;

    SqliteStore::AuditRecord fresh;
    fresh.actor = "@admin:test";
    fresh.action = audit_action::kMemberBan;
    EXPECT_GT(f.store->append_audit_record(fresh), last)
        << "id was reused after a row was removed";
}

// ══ 5. Immutability ═══════════════════════════════════════════════════════

TEST(AuditImmutability, TheDatabaseItselfRejectsAnUpdate) {
    Fixture f("immutable-update");
    SqliteStore::AuditRecord r;
    r.actor = "@mod:test";
    r.action = audit_action::kMemberBan;
    r.target_user = "@bob:test";
    f.store->append_audit_record(r);

    // Append-only cannot rest on code review for a tamper-evidence feature: it has
    // to hold against ANY writer, including one added later.
    std::string err;
    EXPECT_NE(raw_exec(f.db_path, "UPDATE audit_log SET actor = '@nobody:test'", &err),
              SQLITE_OK);
    EXPECT_NE(err.find("append-only"), std::string::npos) << err;
    EXPECT_EQ(f.records().at(0).actor, "@mod:test") << "the record was altered";
}

TEST(AuditImmutability, TheDatabaseItselfRejectsADelete) {
    Fixture f("immutable-delete");
    SqliteStore::AuditRecord r;
    r.actor = "@mod:test";
    r.action = audit_action::kMemberBan;
    f.store->append_audit_record(r);

    std::string err;
    EXPECT_NE(raw_exec(f.db_path, "DELETE FROM audit_log", &err), SQLITE_OK);
    EXPECT_NE(err.find("append-only"), std::string::npos) << err;
    EXPECT_EQ(f.record_count(), 1) << "the record was deleted";
}

TEST(AuditImmutability, DeletingARoomDoesNotDisturbItsAuditRecords) {
    Fixture f("immutable-deleteroom");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          json{{"user_id", bob}}.dump())));
    ASSERT_EQ(f.record_count(), 1);

    // delete_room sweeps events, members, read markers, mentions and search rows.
    // The audit log is deliberately outside all of that — no foreign key, no
    // cascade — so the record of the ban survives the channel it happened in.
    f.store->delete_room(room);
    auto all = f.records();
    ASSERT_EQ(all.size(), 1u) << "the ban record must still be there, unchanged";
    EXPECT_EQ(all[0].action, audit_action::kMemberBan);
    EXPECT_EQ(all[0].target_room, room);
    EXPECT_EQ(all[0].target_user, bob);
}

// ══ 6. Search isolation ═══════════════════════════════════════════════════

TEST(AuditSearch, RecordsNeverEnterTheMessageSearchIndex) {
    Fixture f("search-isolation");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(mod, "general");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    // A real message, so the index is demonstrably working and this test can tell
    // "not indexed" apart from "search is broken".
    f.store->insert_event(generate_event_id("test"), room, mod,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", "ordinary pineapple"}}.dump(),
                          2000);
    ASSERT_TRUE(f.store->search_index_available());
    const int indexed_before = f.store->count_search_index_rows();
    ASSERT_EQ(f.store->search_messages({room}, {"pineapple"}, {}, 10, 0, false).hits.size(), 1u);

    // Now a ban whose reason contains a distinctive word.
    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          json{{"user_id", bob}, {"reason", "zqxwv unforgettable"}}.dump())));
    ASSERT_EQ(f.record_count(), 1);
    ASSERT_EQ(f.records().at(0).reason, "zqxwv unforgettable");

    // A moderation reason is not message content: it must not be searchable by
    // anyone, including the admin who wrote it.
    EXPECT_EQ(f.store->count_search_index_rows(), indexed_before)
        << "the audit write changed the search index";
    EXPECT_EQ(f.store->search_messages({room}, {"zqxwv"}, {}, 10, 0, false).hits.size(), 0u);
    EXPECT_EQ(f.store->search_messages({room}, {"unforgettable"}, {}, 10, 0, false).total, 0);

    // Structurally, too: the FTS5 index reads from event_search and nothing else,
    // so there is no path by which audit_log could be indexed.
    auto fts_sql = raw_text(f.db_path,
        "SELECT sql FROM sqlite_master WHERE name = 'event_search_fts'");
    EXPECT_NE(fts_sql.find("content='event_search'"), std::string::npos) << fts_sql;
    EXPECT_EQ(fts_sql.find("audit"), std::string::npos) << fts_sql;
}

// ══ 8. Filtering (schema v16) ═════════════════════════════════════════════
//
// The properties, in order:
//   a. v16 applies to a real, populated, pre-existing v15 database: history
//      intact, both append-only triggers untouched and still aborting.
//   b. Every exposed filter is actually SERVED BY ITS INDEX. This is invisible in
//      the results (a full scan returns the same rows), so it is asserted on the
//      query plan of the REAL statement the store builds.
//   c. Filters select correctly, AND together, and a filter that matches nothing
//      returns nothing rather than degrading to "everything".
//   d. Pagination stays stable under a filter while inserts land concurrently.
//   e. The endpoint's SERVER-scope gate still holds on the filtered path — a
//      per-channel MANAGE_SERVER override must not unlock it.

// ── a. Migration against a populated pre-existing v15 database ─────────────

TEST(AuditFilterMigration, PreExistingV15DatabaseGainsTheIndexesAndKeepsEverythingElse) {
    auto path = temp_db_path("v15-to-v16");
    create_v15_database_with_audit_history(path);
    ASSERT_EQ(schema_version_of(path), 15) << "the fixture must start BELOW the target";

    // The pre-migration facts, so "nothing was lost" is measured rather than
    // assumed.
    ASSERT_EQ(raw_text(path, "SELECT COUNT(*) FROM audit_log"), "5");
    // Ordered in a SUBQUERY, not with a trailing ORDER BY on the aggregate: the
    // latter orders the one-row result and leaves group_concat at the mercy of
    // whatever scan the planner picks — which v16 changes, by design.
    const auto kOrderedIds =
        "SELECT group_concat(id) FROM (SELECT id FROM audit_log ORDER BY id)";
    const auto ids_before = raw_text(path, kOrderedIds);
    const auto events_before = raw_text(path, "SELECT COUNT(*) FROM events");

    {
        SqliteStore store(path);
        store.initialize();
        EXPECT_EQ(schema_version_of(path), kTargetSchemaVersion);

        // Nothing lost: the audit history, its ids (cursors handed to clients
        // before the upgrade must still resolve), and the unrelated tables.
        EXPECT_EQ(raw_text(path, "SELECT COUNT(*) FROM audit_log"), "5");
        EXPECT_EQ(raw_text(path, kOrderedIds), ids_before);
        EXPECT_EQ(raw_text(path, "SELECT COUNT(*) FROM events"), events_before);
        EXPECT_EQ(raw_text(path, "SELECT COUNT(*) FROM event_search"), "1");

        // The AUTOINCREMENT high-water mark survives, which is what keeps a
        // pre-upgrade cursor meaningful.
        EXPECT_EQ(raw_text(path, "SELECT seq FROM sqlite_sequence WHERE name = 'audit_log'"),
                  "5");

        // And the filters work on rows written long before the filters existed.
        SqliteStore::AuditFilter by_mallory;
        by_mallory.actor = "@mallory:test";
        auto page = store.list_audit_records(50, std::nullopt, by_mallory);
        EXPECT_EQ(page.records.size(), 3u);
        ASSERT_TRUE(page.matching.has_value());
        EXPECT_EQ(*page.matching, 3);
        EXPECT_EQ(page.total, 5) << "total stays whole-table under a filter";
    }

    // All four indexes exist, and the two target ones are PARTIAL. The partial
    // predicate is load-bearing, not decoration: without it the index covers every
    // '' sentinel row, and list_audit_records' matching `<> ''` guard would exclude
    // the index rather than enable it.
    EXPECT_NE(raw_text(path, "SELECT sql FROM sqlite_master WHERE name='idx_audit_log_actor'")
                  .find("audit_log(actor)"), std::string::npos);
    EXPECT_NE(raw_text(path, "SELECT sql FROM sqlite_master WHERE name='idx_audit_log_action'")
                  .find("audit_log(action)"), std::string::npos);
    EXPECT_NE(raw_text(path,
                       "SELECT sql FROM sqlite_master WHERE name='idx_audit_log_target_user'")
                  .find("WHERE target_user <> ''"), std::string::npos);
    EXPECT_NE(raw_text(path,
                       "SELECT sql FROM sqlite_master WHERE name='idx_audit_log_target_room'")
                  .find("WHERE target_room <> ''"), std::string::npos);

    // The append-only triggers are UNTOUCHED — still there, still by name.
    EXPECT_EQ(raw_text(path, "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                             "AND tbl_name='audit_log'"), "2");

    // ...and still ABORT. Presence in sqlite_master is not the property; refusal
    // is. Asserted against a second connection, so this is what the DATABASE
    // permits and not what SqliteStore declines to offer.
    std::string update_err;
    EXPECT_NE(raw_exec(path, "UPDATE audit_log SET reason = 'tampered' WHERE id = 1",
                       &update_err), SQLITE_OK);
    EXPECT_NE(update_err.find("append-only"), std::string::npos)
        << "refused for the wrong reason: " << update_err;
    std::string delete_err;
    EXPECT_NE(raw_exec(path, "DELETE FROM audit_log WHERE id = 1", &delete_err), SQLITE_OK);
    EXPECT_NE(delete_err.find("append-only"), std::string::npos)
        << "refused for the wrong reason: " << delete_err;
    EXPECT_EQ(raw_text(path, "SELECT reason FROM audit_log WHERE id = 1"), "spam");

    remove_db(path);
}

TEST(AuditFilterMigration, UpgradeToV16IsIdempotent) {
    auto path = temp_db_path("v16-idempotent");
    create_v15_database_with_audit_history(path);
    for (int i = 0; i < 3; ++i) {
        SqliteStore store(path);
        store.initialize();
        EXPECT_EQ(schema_version_of(path), kTargetSchemaVersion);
    }
    EXPECT_EQ(raw_text(path, "SELECT COUNT(*) FROM audit_log"), "5");
    EXPECT_EQ(raw_text(path, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' "
                             "AND name LIKE 'idx_audit_log_%'"), "4");
    remove_db(path);
}

// ── b. Every filter is served by its index ────────────────────────────────

TEST(AuditFilterPlan, EveryFilterIsServedByItsOwnIndex) {
    Fixture f("filter-plan");
    // A populated table, so the planner is choosing rather than shrugging at an
    // empty one.
    for (int i = 0; i < 500; ++i) {
        SqliteStore::AuditRecord r;
        r.actor = "@a" + std::to_string(i % 7) + ":test";
        r.action = i % 5 == 0 ? audit_action::kMemberBan : audit_action::kRoleUpdate;
        if (i % 3 == 0) r.target_user = "@v" + std::to_string(i % 11) + ":test";
        if (i % 4 == 0) r.target_room = "!r" + std::to_string(i % 13) + ":test";
        f.store->append_audit_record(r);
    }
    ASSERT_EQ(raw_exec(f.db_path, "ANALYZE"), SQLITE_OK);

    struct Case {
        const char* name;
        SqliteStore::AuditFilter filter;
        const char* index;
    };
    std::vector<Case> cases;
    {
        SqliteStore::AuditFilter x; x.actor = "@a3:test";
        cases.push_back({"actor", x, "idx_audit_log_actor"});
    }
    {
        SqliteStore::AuditFilter x; x.action = audit_action::kMemberBan;
        cases.push_back({"action", x, "idx_audit_log_action"});
    }
    {
        SqliteStore::AuditFilter x; x.target_user = "@v5:test";
        cases.push_back({"target_user", x, "idx_audit_log_target_user"});
    }
    {
        SqliteStore::AuditFilter x; x.target_room = "!r7:test";
        cases.push_back({"target_room", x, "idx_audit_log_target_room"});
    }

    for (const auto& c : cases) {
        // The REAL statement the store runs, not a hand-copied lookalike — the
        // partial-index guards live in audit_page_query and nowhere else, so a
        // test that rebuilt the SQL itself would assert nothing about production.
        for (bool with_cursor : {false, true}) {
            const auto query = SqliteStore::audit_page_query(c.filter, with_cursor);
            const auto plan = explain_plan(f.db_path, query.sql);
            EXPECT_NE(plan.find(c.index), std::string::npos)
                << c.name << " (cursor=" << with_cursor << ") is not using " << c.index
                << "\nsql:  " << query.sql << "\nplan: " << plan;
            // A residual sort would mean the index served the lookup but not the
            // newest-first ordering, which is where the cost actually is on a big
            // log: SQLite would have to materialise every match to return 50.
            EXPECT_EQ(plan.find("TEMP B-TREE"), std::string::npos)
                << c.name << " needs a sort pass:\n" << plan;
        }
        // The matching-count query rides the same index.
        const auto count_query = SqliteStore::audit_match_count_query(c.filter);
        EXPECT_NE(explain_plan(f.db_path, count_query.sql).find(c.index), std::string::npos)
            << c.name << " count query is not using " << c.index;
    }

    // The unfiltered page is unchanged by v16: still a plain reverse walk of the
    // rowid, with no index and no sort. If this ever starts naming an index, an
    // index is being consulted for a query that never needed one.
    const auto plain = SqliteStore::audit_page_query({}, false);
    const auto plain_plan = explain_plan(f.db_path, plain.sql);
    EXPECT_EQ(plain_plan.find("idx_audit_log_"), std::string::npos) << plain_plan;
    EXPECT_EQ(plain_plan.find("TEMP B-TREE"), std::string::npos) << plain_plan;
}

// ── c. Filters select correctly ───────────────────────────────────────────

namespace {

// Ten records covering every combination the filters have to separate.
void seed_filterable_history(Fixture& f) {
    const auto add = [&](const char* actor, const char* action, const char* target_user,
                         const char* target_room) {
        SqliteStore::AuditRecord r;
        r.actor = actor;
        r.action = action;
        r.target_user = target_user;
        r.target_room = target_room;
        f.store->append_audit_record(r);
    };
    add("@mallory:test", audit_action::kMemberKick, "@bob:test",   "!general:test");
    add("@mallory:test", audit_action::kMemberBan,  "@bob:test",   "!general:test");
    add("@mallory:test", audit_action::kMemberBan,  "@carol:test", "!lounge:test");
    add("@alice:test",   audit_action::kMemberBan,  "@bob:test",   "!lounge:test");
    add("@alice:test",   audit_action::kMemberKick, "@dave:test",  "!general:test");
    add("@alice:test",   audit_action::kChannelDelete, "",         "!gone:test");
    add("@alice:test",   audit_action::kRoleUpdate, "",            "");
    add("@bob:test",     audit_action::kRoleAssign, "@mallory:test", "");
    add("@bob:test",     audit_action::kMemberNicknameSet, "@carol:test", "");
    add("@bob:test",     audit_action::kChannelPermissionsSet, "@dave:test", "!general:test");
}

std::vector<std::string> actors_of(const SqliteStore::AuditPage& page) {
    std::vector<std::string> out;
    for (const auto& r : page.records) out.push_back(r.actor);
    return out;
}

} // namespace

TEST(AuditFilter, ByActorReturnsOnlyThatActorsRecords) {
    Fixture f("filter-actor");
    seed_filterable_history(f);

    SqliteStore::AuditFilter filter;
    filter.actor = "@mallory:test";
    auto page = f.store->list_audit_records(50, std::nullopt, filter);

    ASSERT_EQ(page.records.size(), 3u) << "expected exactly Mallory's three records";
    for (const auto& r : page.records) EXPECT_EQ(r.actor, "@mallory:test");
    // Newest first, unchanged by filtering.
    EXPECT_GT(page.records.front().id, page.records.back().id);
    ASSERT_TRUE(page.matching.has_value());
    EXPECT_EQ(*page.matching, 3);
    EXPECT_EQ(page.total, 10) << "total is the whole table, not the filtered subset";
}

TEST(AuditFilter, ByTargetUserFindsEveryActionAimedAtThem) {
    Fixture f("filter-target-user");
    seed_filterable_history(f);

    SqliteStore::AuditFilter filter;
    filter.target_user = "@bob:test";
    auto page = f.store->list_audit_records(50, std::nullopt, filter);

    ASSERT_EQ(page.records.size(), 3u);
    for (const auto& r : page.records) EXPECT_EQ(r.target_user, "@bob:test");
    // Two actors did things to Bob; a filter that quietly also matched on actor
    // would miss one of them.
    const auto actors = actors_of(page);
    EXPECT_EQ(std::set<std::string>(actors.begin(), actors.end()),
              (std::set<std::string>{"@mallory:test", "@alice:test"}));
    EXPECT_EQ(*page.matching, 3);
}

TEST(AuditFilter, ByTargetRoomFindsEveryActionInThatChannel) {
    Fixture f("filter-target-room");
    seed_filterable_history(f);

    SqliteStore::AuditFilter filter;
    filter.target_room = "!general:test";
    auto page = f.store->list_audit_records(50, std::nullopt, filter);

    ASSERT_EQ(page.records.size(), 4u);
    for (const auto& r : page.records) EXPECT_EQ(r.target_room, "!general:test");
    EXPECT_EQ(*page.matching, 4);
}

TEST(AuditFilter, ByActionSeparatesTheVocabulary) {
    Fixture f("filter-action");
    seed_filterable_history(f);

    SqliteStore::AuditFilter bans;
    bans.action = audit_action::kMemberBan;
    auto page = f.store->list_audit_records(50, std::nullopt, bans);
    ASSERT_EQ(page.records.size(), 3u);
    for (const auto& r : page.records) EXPECT_EQ(r.action, audit_action::kMemberBan);

    // Kicks and bans are distinct action names, so a ban filter must not sweep up
    // kicks — that distinction is the whole reason membership_audit_action exists.
    SqliteStore::AuditFilter kicks;
    kicks.action = audit_action::kMemberKick;
    EXPECT_EQ(f.store->list_audit_records(50, std::nullopt, kicks).records.size(), 2u);
}

TEST(AuditFilter, FiltersAreAndedNotOred) {
    Fixture f("filter-combined");
    seed_filterable_history(f);

    SqliteStore::AuditFilter filter;
    filter.actor = "@mallory:test";
    filter.action = audit_action::kMemberBan;
    auto page = f.store->list_audit_records(50, std::nullopt, filter);
    ASSERT_EQ(page.records.size(), 2u) << "Mallory's bans, not her bans plus everyone's";
    for (const auto& r : page.records) {
        EXPECT_EQ(r.actor, "@mallory:test");
        EXPECT_EQ(r.action, audit_action::kMemberBan);
    }

    // All four at once, narrowing to a single record.
    SqliteStore::AuditFilter all_four;
    all_four.actor = "@mallory:test";
    all_four.action = audit_action::kMemberBan;
    all_four.target_user = "@bob:test";
    all_four.target_room = "!general:test";
    auto one = f.store->list_audit_records(50, std::nullopt, all_four);
    ASSERT_EQ(one.records.size(), 1u);
    EXPECT_EQ(*one.matching, 1);
}

TEST(AuditFilter, AFilterThatMatchesNothingReturnsNothing) {
    Fixture f("filter-empty-result");
    seed_filterable_history(f);

    // The failure mode worth naming: a filter that is silently dropped returns the
    // WHOLE log, and the reader believes they have looked and found nothing.
    SqliteStore::AuditFilter nobody;
    nobody.actor = "@nobody:test";
    auto page = f.store->list_audit_records(50, std::nullopt, nobody);
    EXPECT_TRUE(page.records.empty());
    ASSERT_TRUE(page.matching.has_value());
    EXPECT_EQ(*page.matching, 0);
    EXPECT_EQ(page.total, 10) << "the log is still ten records; the filter matched none";
    EXPECT_FALSE(page.next_from.has_value());

    // A combination where each half matches on its own but the pair does not.
    SqliteStore::AuditFilter impossible;
    impossible.actor = "@bob:test";
    impossible.target_room = "!lounge:test";
    EXPECT_TRUE(f.store->list_audit_records(50, std::nullopt, impossible).records.empty());
}

TEST(AuditFilter, TargetFiltersNeverMatchTheNotApplicableSentinel) {
    Fixture f("filter-sentinel");
    seed_filterable_history(f);

    // '' is "this action has no user target" (role edits, channel deletions), and
    // the v16 indexes deliberately exclude those rows. Asking for '' must return
    // nothing rather than every unrelated record — and must not silently become an
    // unfiltered query.
    SqliteStore::AuditFilter empty_user;
    empty_user.target_user = "";
    auto page = f.store->list_audit_records(50, std::nullopt, empty_user);
    EXPECT_TRUE(page.records.empty()) << "'' matched " << page.records.size() << " records";
    EXPECT_EQ(*page.matching, 0);
}

// ── d. Pagination under a filter ──────────────────────────────────────────

TEST(AuditFilterPagination, CursorStaysStableWhileMatchingAndNonMatchingRecordsLand) {
    Fixture f("filter-page-stable");
    const auto append = [&](const char* actor) {
        SqliteStore::AuditRecord r;
        r.actor = actor;
        r.action = audit_action::kMemberKick;
        return f.store->append_audit_record(r);
    };

    std::set<int64_t> expected;
    for (int i = 0; i < 9; ++i) {
        expected.insert(append("@mallory:test"));
        append("@alice:test"); // noise the filter must not surface
    }

    SqliteStore::AuditFilter filter;
    filter.actor = "@mallory:test";

    std::vector<int64_t> seen;
    std::optional<int64_t> cursor;
    for (int page_no = 0; page_no < 10; ++page_no) {
        auto page = f.store->list_audit_records(2, cursor, filter);
        for (const auto& r : page.records) {
            EXPECT_EQ(r.actor, "@mallory:test");
            seen.push_back(r.id);
        }
        if (!page.next_from) break;
        cursor = page.next_from;
        // Writes land BETWEEN pages, both matching and not. Ids are AUTOINCREMENT,
        // so every new row is above the cursor and cannot disturb the walk.
        append("@alice:test");
        append("@mallory:test");
    }

    // Every record that existed when the walk began was returned exactly once, and
    // nothing that arrived mid-walk was injected into an earlier page.
    std::set<int64_t> unique_seen(seen.begin(), seen.end());
    EXPECT_EQ(unique_seen.size(), seen.size()) << "a record was returned twice";
    for (int64_t id : expected) {
        EXPECT_TRUE(unique_seen.count(id)) << "record " << id << " was skipped";
    }
}

// ── e. The endpoint ───────────────────────────────────────────────────────

TEST(AuditEndpoint, FilterParametersReachTheQuery) {
    Fixture f("endpoint-filters");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    seed_filterable_history(f);
    AuditHandler handler(*f.store, f.config);

    auto by_actor = call_with_params(handler, "token-admin", {{"actor", "@mallory:test"}});
    ASSERT_TRUE(IsOk(by_actor));
    auto body = json::parse(by_actor.body);
    ASSERT_EQ(body.at("records").size(), 3u);
    for (const auto& r : body.at("records")) EXPECT_EQ(r.at("actor"), "@mallory:test");
    EXPECT_EQ(body.at("matching"), 3);
    EXPECT_EQ(body.at("total"), 10);

    auto by_room = call_with_params(handler, "token-admin", {{"target_room", "!general:test"}});
    ASSERT_TRUE(IsOk(by_room));
    EXPECT_EQ(json::parse(by_room.body).at("records").size(), 4u);

    auto by_user = call_with_params(handler, "token-admin", {{"target_user", "@bob:test"}});
    ASSERT_TRUE(IsOk(by_user));
    EXPECT_EQ(json::parse(by_user.body).at("records").size(), 3u);

    auto by_action = call_with_params(handler, "token-admin",
                                      {{"action", audit_action::kMemberBan}});
    ASSERT_TRUE(IsOk(by_action));
    EXPECT_EQ(json::parse(by_action.body).at("records").size(), 3u);

    auto combined = call_with_params(
        handler, "token-admin",
        {{"actor", "@mallory:test"}, {"action", audit_action::kMemberBan}});
    ASSERT_TRUE(IsOk(combined));
    EXPECT_EQ(json::parse(combined.body).at("records").size(), 2u);

    // Unfiltered responses must not sprout a `matching` field that just repeats
    // `total`.
    auto unfiltered = call_with_params(handler, "token-admin", {});
    ASSERT_TRUE(IsOk(unfiltered));
    EXPECT_FALSE(json::parse(unfiltered.body).contains("matching"));
}

TEST(AuditEndpoint, FilteredPaginationWalksTheWholeMatchingSet) {
    Fixture f("endpoint-filter-pages");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    for (int i = 0; i < 7; ++i) {
        SqliteStore::AuditRecord r;
        r.actor = "@mallory:test";
        r.action = audit_action::kMemberBan;
        f.store->append_audit_record(r);
        SqliteStore::AuditRecord noise;
        noise.actor = "@alice:test";
        noise.action = audit_action::kMemberBan;
        f.store->append_audit_record(noise);
    }
    AuditHandler handler(*f.store, f.config);

    std::set<int64_t> seen;
    httplib::Params params{{"actor", "@mallory:test"}, {"limit", "3"}};
    for (int page_no = 0; page_no < 10; ++page_no) {
        auto res = call_with_params(handler, "token-admin", params);
        ASSERT_TRUE(IsOk(res));
        auto body = json::parse(res.body);
        EXPECT_EQ(body.at("matching"), 7) << "matching describes the whole set, not the page";
        for (const auto& r : body.at("records")) {
            EXPECT_EQ(r.at("actor"), "@mallory:test");
            EXPECT_TRUE(seen.insert(r.at("id").get<int64_t>()).second) << "duplicate record";
        }
        if (!body.contains("next_from")) break;
        params = {{"actor", "@mallory:test"},
                  {"limit", "3"},
                  {"from", std::to_string(body.at("next_from").get<int64_t>())}};
    }
    EXPECT_EQ(seen.size(), 7u) << "the filtered walk did not reach every matching record";
}

TEST(AuditEndpoint, RejectsAnEmptyFilterValueRatherThanIgnoringIt) {
    Fixture f("endpoint-empty-filter");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    seed_filterable_history(f);
    AuditHandler handler(*f.store, f.config);

    // Silently dropping an empty filter would hand the reader the WHOLE log while
    // they believed they had narrowed it — the same class of quiet lie as a
    // malformed cursor being treated as "start from the newest".
    for (const char* name : {"actor", "target_user", "target_room", "action"}) {
        auto res = call_with_params(handler, "token-admin", {{name, ""}});
        ASSERT_EQ(res.status, 400) << name << " -> " << res.body;
        auto body = json::parse(res.body);
        EXPECT_EQ(body.value("errcode", ""), "M_INVALID_PARAM") << name;
        // Assert on the REASON, not merely that it was refused: a 400 produced by
        // some unrelated guard would prove nothing about this one.
        EXPECT_NE(body.value("error", "").find(name), std::string::npos)
            << name << " was refused for a different reason: " << res.body;
        EXPECT_EQ(res.body.find("records"), std::string::npos);
    }
}

// The escalation shape that was a real bug in the role-write path, re-asserted on
// the FILTERED path: a per-channel override granting MANAGE_SERVER inside one
// channel must not unlock the server-wide log, and adding query parameters must
// not route around the gate.
TEST(AuditEndpoint, PerChannelOverrideDoesNotGrantFilteredAccessEither) {
    Fixture f("endpoint-filter-override-escalation");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin, "bobs-corner");
    f.store->set_membership(room, bob, std::string(membership::kJoin));

    // A record that Bob's filters WOULD match if he were allowed to read at all.
    // Without this the 403 below could pass simply because the log is empty.
    {
        SqliteStore::AuditRecord r;
        r.actor = admin;
        r.action = audit_action::kMemberBan;
        r.target_user = bob;
        r.target_room = room;
        f.store->append_audit_record(r);
    }

    f.set_override(room, "user:" + bob,
                   permission::kManageServer | permission::kAdministrator, 0);

    // Positive controls. Without these the test would still pass if the override
    // had silently failed to apply, or if the seeded record were unmatchable.
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.can(bob, room, permission::kManageServer))
            << "override did not apply; the rest of this test would prove nothing";
        ASSERT_FALSE(perms.can(bob, "", permission::kManageServer));
    }
    {
        SqliteStore::AuditFilter filter;
        filter.target_user = bob;
        ASSERT_EQ(f.store->list_audit_records(50, std::nullopt, filter).records.size(), 1u)
            << "the record Bob must not be shown is not actually matchable";
    }

    AuditHandler handler(*f.store, f.config);
    // Every filter shape, including the one aimed squarely at himself and at the
    // very channel his override covers.
    const std::vector<httplib::Params> attempts = {
        {{"actor", admin}},
        {{"target_user", bob}},
        {{"target_room", room}},
        {{"action", std::string(audit_action::kMemberBan)}},
        {{"target_room", room}, {"target_user", bob}},
        {{"target_room", room}, {"limit", "1"}},
    };
    for (const auto& params : attempts) {
        auto res = call_with_params(handler, "token-bob", params);
        ASSERT_EQ(res.status, 403) << res.body;
        auto body = json::parse(res.body);
        // Refused by the PERMISSION gate, not by parameter validation — a 403 is
        // only the right answer if it came from the server-scope check.
        EXPECT_EQ(body.value("errcode", ""), "M_FORBIDDEN");
        EXPECT_NE(body.value("error", "").find("audit log"), std::string::npos)
            << "refused for the wrong reason: " << res.body;
        EXPECT_EQ(res.body.find("records"), std::string::npos)
            << "no records may leak in a 403";
        EXPECT_EQ(res.body.find(admin), std::string::npos)
            << "no record content may leak in a 403";
    }

    // And the same filters DO work for someone with the flag at server scope, so
    // the refusal above is about Bob and not about the filters being broken.
    auto ok = call_with_params(handler, "token-admin", {{"target_user", bob}});
    ASSERT_TRUE(IsOk(ok));
    EXPECT_EQ(json::parse(ok.body).at("records").size(), 1u);
}
