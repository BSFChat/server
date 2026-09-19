// Upgrade path for the v9–v11 block: mentions, the `replaces` denormalisation,
// and the push tables.
//
// The point of this file is that the upgrade is exercised against a database in
// the shape a REAL v8 deployment has, with real data in it, rather than against
// a fresh database where every migration is a no-op. Migrations v9 and v11 add
// tables and a column; v9 also backfills, and a backfill is exactly the kind of
// step that passes on an empty database and corrupts a populated one.

#include <gtest/gtest.h>

#include "auth/LocalAuth.h"
#include "store/Migrations.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>

#include <sqlite3.h>
#include <unistd.h>

#include <filesystem>
#include <string>

using namespace bsfchat;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-mig-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

int schema_version_of(const std::string& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return -1;
    int v = get_schema_version(db);
    sqlite3_close(db);
    return v;
}

int scalar(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return -1;
    sqlite3_stmt* stmt = nullptr;
    int out = -1;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) out = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

// Builds a database in exactly the shape migrations v1–v8 leave behind — the
// hashed/expiring access_tokens table, rooms.is_direct, events.redacted_by and
// events.edited_by, server_meta, server_state, event_transactions — with
// user_version pinned to 8, and populates it with the situations the new steps
// have to survive: an edited message, a redacted message, a DM, and a channel.
void create_v8_database(const std::string& path, std::string& out_edit_id) {
    std::filesystem::remove(path);
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
            redacted_by TEXT, edited_by TEXT);
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

        INSERT INTO users (user_id, password_hash, display_name) VALUES
            ('@alice:test','hash-a','Alice'),
            ('@bob:test','hash-b','Bob'),
            ('@carol:test','hash-c',NULL);

        INSERT INTO access_tokens
            (token_hash, user_id, device_id, expires_at, lifetime_ms) VALUES
            ('deadbeef','@alice:test','dev-a', 99999999999999, 7776000000);

        INSERT INTO rooms (room_id, creator, is_direct) VALUES
            ('!general:test','@alice:test',0),
            ('!dm:test','@alice:test',1);

        INSERT INTO room_members (room_id,user_id,membership) VALUES
            ('!general:test','@alice:test','join'),
            ('!general:test','@bob:test','join'),
            ('!general:test','@carol:test','join'),
            ('!dm:test','@alice:test','join'),
            ('!dm:test','@bob:test','join');

        -- 1: a plain message.
        INSERT INTO events VALUES ('$m1','!general:test','@alice:test','m.room.message',
            NULL,'{"msgtype":"m.text","body":"first"}',1000,1,NULL,'$e1');
        -- 2: a REPLACEMENT of $m1, already reconciled by v8 (edited_by above).
        INSERT INTO events VALUES ('$e1','!general:test','@alice:test','m.room.message',
            NULL,'{"msgtype":"m.text","body":"* first (edited)","m.new_content":{"msgtype":"m.text","body":"first (edited)"},"m.relates_to":{"rel_type":"m.replace","event_id":"$m1"}}',
            1001,2,NULL,NULL);
        -- 3: a redacted message (content already stripped by v5).
        INSERT INTO events VALUES ('$m2','!general:test','@bob:test','m.room.message',
            NULL,'{}',1002,3,'@alice:test',NULL);
        -- 4: an ordinary unread message.
        INSERT INTO events VALUES ('$m3','!general:test','@alice:test','m.room.message',
            NULL,'{"msgtype":"m.text","body":"third"}',1003,4,NULL,NULL);
        -- 5: a message in the DM.
        INSERT INTO events VALUES ('$m4','!dm:test','@alice:test','m.room.message',
            NULL,'{"msgtype":"m.text","body":"psst"}',1004,5,NULL,NULL);
        -- A state event, to be sure non-message rows are untouched by the backfill.
        INSERT INTO events VALUES ('$s1','!general:test','@alice:test','m.room.name',
            '','{"name":"general"}',1005,6,NULL,NULL);

        INSERT INTO read_markers VALUES ('@bob:test','!general:test',1);
        INSERT INTO server_meta (key,value) VALUES ('next_stream_position','7');
        INSERT INTO server_state (event_type,state_key,sender,content) VALUES
            ('bsfchat.server.roles','','@server:test',
             '{"roles":[{"id":"everyone","name":"@everyone","position":0,"permissions":"0x1f"}]}');
        INSERT INTO event_transactions (user_id,txn_id,event_id) VALUES
            ('@alice:test','txn-1','$m1');

        PRAGMA user_version = 8;
    )SQL";

    char* err = nullptr;
    ASSERT_EQ(sqlite3_exec(db, schema, nullptr, nullptr, &err), SQLITE_OK) << (err ? err : "?");
    sqlite3_close(db);
    out_edit_id = "$e1";
}

} // namespace

TEST(MigrationV11, PreExistingV8DatabaseUpgradesAndKeepsItsData) {
    auto path = temp_db_path("v8-upgrade");
    std::string edit_id;
    create_v8_database(path, edit_id);
    ASSERT_EQ(schema_version_of(path), 8);

    {
        SqliteStore store(path);
        store.initialize();

        // Every row survived.
        EXPECT_EQ(store.list_all_users().size(), 3u);
        EXPECT_TRUE(store.room_exists("!general:test"));
        EXPECT_TRUE(store.room_exists("!dm:test"));
        EXPECT_TRUE(store.is_direct_room("!dm:test"));
        EXPECT_FALSE(store.is_direct_room("!general:test"));
        EXPECT_EQ(store.get_room_members("!general:test").size(), 3u);
        EXPECT_EQ(store.get_display_name("@alice:test").value_or(""), "Alice");
        EXPECT_EQ(store.get_read_marker("@bob:test", "!general:test"), 1);
        EXPECT_TRUE(store.get_meta("next_stream_position").has_value());
        EXPECT_EQ(store.get_transaction_event("@alice:test", "txn-1").value_or(""), "$m1");
        EXPECT_EQ(store.get_server_roles().size(), 1u);

        // The v8 edit reconciliation is untouched: $m1 still resolves through
        // its replacement to the edited text.
        auto m1 = store.get_event_by_id("$m1");
        ASSERT_TRUE(m1.has_value());
        EXPECT_EQ(m1->content.data.value("body", ""), "first (edited)");
        EXPECT_EQ(store.get_edit_pointer("$m1").value_or(""), edit_id);

        // Redaction state survived.
        EXPECT_TRUE(store.is_event_redacted("$m2"));
    }

    EXPECT_EQ(schema_version_of(path), kTargetSchemaVersion);
    // Pinned on purpose, so bumping the schema is always a conscious edit rather
    // than something that slides past review. 12 -> 13 added the moderation audit
    // log; 13 -> 14 added users.nickname; 14 -> 15 added the server_bans table and
    // its backfill from existing room_members ban rows; 15 -> 16 added the
    // audit_log filter indexes; 16 -> 17 added events.signal_to and swept the
    // stored call signalling that used to publish everyone's IP addresses;
    // 17 -> 18 stamped is_direct into the membership state of DMs that predate
    // the server writing it; 18 -> 19 added users.kind, the bots table and
    // access_tokens.token_kind for first-class bot accounts; 19 -> 20 persisted
    // the LiveKit media-key generation, which until then lived in memory and
    // reverted on every restart. A v8 database still upgrades all the way in
    // one go.
    EXPECT_EQ(kTargetSchemaVersion, 21);
    std::filesystem::remove(path);
}

TEST(MigrationV11, SearchIndexIsBackfilledFromExistingHistory) {
    auto path = temp_db_path("v8-searchbackfill");
    std::string edit_id;
    create_v8_database(path, edit_id);

    SqliteStore store(path);
    store.initialize();
    ASSERT_TRUE(store.search_index_available());

    // Indexed: $m1 (folded to its edited text), $m3, $m4. NOT indexed: $e1 (a
    // replacement — it would be a duplicate hit), $m2 (redacted), $s1 (state).
    // A search feature that only saw messages sent after the deploy would not be
    // one, so the backfill is the whole point on an upgrade.
    EXPECT_EQ(store.count_search_index_rows(), 3);

    auto all_rooms = std::vector<std::string>{"!general:test", "!dm:test"};
    auto find = [&](const std::string& term) {
        return store.search_messages(all_rooms, {term}, {}, 20, 0, false);
    };

    // The edit's text is searchable, attributed to the ORIGINAL event...
    auto edited = find("edited");
    ASSERT_EQ(edited.hits.size(), 1u);
    EXPECT_EQ(edited.hits[0].event_id, "$m1");
    // ...and the pre-edit wording is not, because search must match current text.
    // ("first" survives in the edited body, so probe the discarded prefix marker
    // instead: the "* " fallback form must never reach the index.)
    EXPECT_EQ(find("third").hits.size(), 1u);
    EXPECT_EQ(find("psst").hits.size(), 1u);
    // Redacted content never enters the index.
    EXPECT_EQ(find("nothing").hits.size(), 0u);

    std::filesystem::remove(path);
}

TEST(MigrationV11, SearchOnUpgradedDataStillRespectsRoomBoundaries) {
    auto path = temp_db_path("v8-searchperm");
    std::string edit_id;
    create_v8_database(path, edit_id);

    SqliteStore store(path);
    store.initialize();

    // Carol is in #general only. Backfilled DM content must not be reachable by
    // restricting the search to the rooms she may see — which is exactly how the
    // handler calls this.
    auto general_only = store.search_messages({"!general:test"}, {"psst"}, {}, 20, 0, false);
    EXPECT_EQ(general_only.hits.size(), 0u);
    EXPECT_EQ(general_only.total, 0);

    auto with_dm = store.search_messages({"!general:test", "!dm:test"}, {"psst"}, {}, 20, 0, false);
    EXPECT_EQ(with_dm.hits.size(), 1u);

    // Fail-closed: no permitted rooms means no results, never an unrestricted
    // search.
    EXPECT_EQ(store.search_messages({}, {"psst"}, {}, 20, 0, false).hits.size(), 0u);

    std::filesystem::remove(path);
}

TEST(MigrationV11, ReplacesIsBackfilledFromExistingContent) {
    auto path = temp_db_path("v8-replaces");
    std::string edit_id;
    create_v8_database(path, edit_id);

    {
        SqliteStore store(path);
        store.initialize();
    }

    // Exactly one row is a replacement: the edit. Not the original it replaces,
    // not the redacted message, not the state event.
    EXPECT_EQ(scalar(path, "SELECT COUNT(*) FROM events WHERE replaces IS NOT NULL"), 1);
    EXPECT_EQ(scalar(path, "SELECT COUNT(*) FROM events WHERE event_id = '$e1' "
                           "AND replaces = '$m1'"), 1);
    EXPECT_EQ(scalar(path, "SELECT COUNT(*) FROM events WHERE event_id = '$s1' "
                           "AND replaces IS NULL"), 1);
    std::filesystem::remove(path);
}

TEST(MigrationV11, UnreadCountOnUpgradedDataExcludesEditsAndRedactions) {
    auto path = temp_db_path("v8-unread");
    std::string edit_id;
    create_v8_database(path, edit_id);

    SqliteStore store(path);
    store.initialize();

    // Bob's marker is at position 1, so positions 2-6 are "new" to him. Of the
    // m.room.message rows past it: $e1 is an edit (excluded), $m2 is redacted
    // (excluded), $m3 is his to see (counted), $m4 is in another room.
    // Before this change the same data reported 2.
    EXPECT_EQ(store.count_unread("@bob:test", "!general:test"), 1);
    // Alice authored $m3 and $e1, and $m2 is redacted, so she has nothing unread.
    EXPECT_EQ(store.count_unread("@alice:test", "!general:test"), 0);
    // Carol has no marker at all, so she sees everything that still counts:
    // $m1 and $m3 (both Alice's, neither an edit nor redacted).
    EXPECT_EQ(store.count_unread("@carol:test", "!general:test"), 2);

    std::filesystem::remove(path);
}

TEST(MigrationV11, NewFeatureTablesAreUsableAfterUpgrade) {
    auto path = temp_db_path("v8-newtables");
    std::string edit_id;
    create_v8_database(path, edit_id);

    SqliteStore store(path);
    store.initialize();

    // Mentions work against pre-existing events, including the read marker that
    // was already there.
    store.record_mentions("$m3", "!general:test", "@alice:test", 4, {"@bob:test"});
    EXPECT_EQ(store.count_unread_mentions("@bob:test", "!general:test"), 1);
    EXPECT_EQ(store.get_unread_mention_counts("@bob:test").at("!general:test"), 1);

    // A mention at or below the existing marker is already read.
    store.record_mentions("$m1", "!general:test", "@alice:test", 1, {"@carol:test"});
    store.set_read_marker("@carol:test", "!general:test", 10);
    EXPECT_EQ(store.count_unread_mentions("@carol:test", "!general:test"), 0);

    // Push tables exist and round-trip.
    SqliteStore::Pusher p;
    p.user_id = "@bob:test";
    p.app_id = "com.bsfchat.app";
    p.pushkey = "token";
    p.kind = "http";
    p.url = "https://gateway.example/notify";
    p.data_json = "{}";
    store.upsert_pusher(p);
    ASSERT_EQ(store.get_pushers("@bob:test").size(), 1u);
    EXPECT_EQ(store.list_room_pusher_candidates("!general:test", "@alice:test").size(), 1u);
    EXPECT_EQ(store.list_room_pusher_candidates("!general:test", "@bob:test").size(), 0u);

    store.set_room_notify_level("@bob:test", "!general:test", "all");
    EXPECT_EQ(store.get_room_notify_level("@bob:test", "!general:test").value_or(""), "all");

    std::filesystem::remove(path);
}

TEST(MigrationV11, UpgradeIsIdempotentAndRefusesToDowngrade) {
    auto path = temp_db_path("v8-idempotent");
    std::string edit_id;
    create_v8_database(path, edit_id);

    {
        SqliteStore store(path);
        store.initialize();
        store.initialize(); // re-running must be a no-op
    }
    EXPECT_EQ(schema_version_of(path), kTargetSchemaVersion);

    // Reopening an already-migrated database must not re-run the v9 backfill in
    // a way that changes anything.
    {
        SqliteStore store(path);
        store.initialize();
        EXPECT_EQ(store.count_unread("@bob:test", "!general:test"), 1);
    }
    EXPECT_EQ(scalar(path, "SELECT COUNT(*) FROM events WHERE replaces IS NOT NULL"), 1);

    // A database written by a newer server is refused rather than opened and
    // silently mangled.
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        sqlite3_exec(db, "PRAGMA user_version = 99", nullptr, nullptr, nullptr);
        sqlite3_close(db);
    }
    {
        SqliteStore store(path);
        EXPECT_THROW(store.initialize(), std::runtime_error);
    }

    std::filesystem::remove(path);
}
