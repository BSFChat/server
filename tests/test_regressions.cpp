// Regression tests for the correctness/security defects fixed in this pass.
// Each test names the behaviour that used to be wrong.

#include <gtest/gtest.h>

#include "api/AuthHandler.h"
#include "api/EventHandler.h"
#include "api/ProfileHandler.h"
#include "api/RoomHandler.h"
#include "auth/AutoJoin.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "http/Middleware.h"
#include "store/Migrations.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/JwtUtils.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <sqlite3.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Builds a request the handlers can consume: they parse parameters out of
// req.path via match_route, and read the bearer token from the header.
httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

// httplib initialises Response::status to -1 and only substitutes 200 when
// the response is actually written to the socket, so a handler that succeeds
// typically never touches it. Treat "untouched" as success.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure()
           << "status " << res.status << ", body: " << res.body;
}

struct Fixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;

    Fixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
    }

    std::string add_user(const std::string& localpart) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        std::string token = "token-" + localpart;
        store->store_access_token(token, uid, "dev");
        return uid;
    }

    void grant(const std::string& user_id, const std::string& role_id) {
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone), role_id};
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), user_id,
                                "@server:test", j.dump());
    }
};

// Appends one extra server-wide role carrying exactly `perms` to whatever role
// set is currently defined, and returns its id. Used to build a NON-ADMIN role
// that holds a single capability, which is the whole point of the role system:
// "users with the appropriate permission can do so" has to be true for a role
// that is not Admin, or the permission is decorative.
std::string define_role(Fixture& f, const std::string& id, permission::Flags perms,
                        int position = 5) {
    ServerRolesContent c;
    c.roles = f.store->get_server_roles();
    ServerRole r;
    r.id = id;
    r.name = id;
    r.color = "#36d6c7";
    r.position = position;
    r.permissions = perms;
    c.roles.push_back(r);
    json j;
    to_json(j, c);
    f.store->set_server_state(std::string(event_type::kServerRoles), "",
                              "@server:test", j.dump());
    return id;
}

// Grants `perms` to `user_id` as a per-channel override inside `room` only.
void allow_in_channel(Fixture& f, const std::string& room, const std::string& actor,
                      const std::string& user_id, permission::Flags perms) {
    ChannelPermissionOverride ov;
    ov.allow = perms;
    ov.deny = 0;
    json ov_json;
    to_json(ov_json, ov);
    f.store->insert_event(generate_event_id("test"), room, actor,
                          std::string(event_type::kChannelPermissions),
                          "user:" + user_id, ov_json.dump(), now_ms());
}

} // namespace

// ── S11: migrations ───────────────────────────────────────────────────────

TEST(Migrations, InitializeReachesTargetVersionAndIsIdempotent) {
    SqliteStore store(":memory:");
    store.initialize();
    // Re-running initialize() must be a no-op, not an error.
    store.initialize();
    SUCCEED();
}

TEST(Migrations, FreshDatabaseSkipsTheOneTimePublicizeMigration) {
    Fixture f;
    // A brand-new database has no legacy channels, so the historical
    // publicize migration is pre-marked as applied and can never run.
    EXPECT_TRUE(f.store->get_meta("migration.publicize_legacy_channels").has_value());
}

namespace {

// Builds a database with the ORIGINAL schema (no is_direct, no server_meta,
// no server_state, user_version 0) so the upgrade path can be exercised for
// real rather than assumed.
void create_legacy_database(const std::string& path) {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
    const char* schema = R"(
        CREATE TABLE users (user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
            display_name TEXT, avatar_url TEXT,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));
        CREATE TABLE access_tokens (token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));
        CREATE TABLE rooms (room_id TEXT PRIMARY KEY, creator TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));
        CREATE TABLE room_members (room_id TEXT NOT NULL, user_id TEXT NOT NULL,
            membership TEXT NOT NULL DEFAULT 'join',
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (room_id, user_id));
        CREATE TABLE events (event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL,
            sender TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT,
            content TEXT NOT NULL, origin_server_ts INTEGER NOT NULL,
            stream_position INTEGER NOT NULL UNIQUE);
        CREATE TABLE read_markers (user_id TEXT NOT NULL, room_id TEXT NOT NULL,
            last_read_pos INTEGER NOT NULL, PRIMARY KEY (user_id, room_id));
        CREATE TABLE media (media_id TEXT PRIMARY KEY, uploader TEXT NOT NULL,
            content_type TEXT NOT NULL, filename TEXT, file_size INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));

        INSERT INTO users (user_id, password_hash) VALUES
            ('@alice:test',''), ('@bob:test',''), ('@carol:test','');

        -- A DM alice opened with bob, which the old boot-time backfill had
        -- already publicized and force-joined carol into.
        INSERT INTO rooms (room_id, creator) VALUES ('!dm:test','@alice:test');
        INSERT INTO room_members (room_id,user_id,membership) VALUES
            ('!dm:test','@alice:test','join'),
            ('!dm:test','@bob:test','join'),
            ('!dm:test','@carol:test','join');
        INSERT INTO events VALUES
            ('$1','!dm:test','@alice:test','m.room.member','@bob:test',
             '{"membership":"invite"}',1,1),
            ('$2','!dm:test','@alice:test','m.room.join_rules','',
             '{"join_rule":"public"}',2,2),
            ('$3','!dm:test','@alice:test','m.room.message',NULL,
             '{"body":"private"}',3,3);

        -- A genuinely legacy channel: private, and with no bsfchat.room.type.
        INSERT INTO rooms (room_id, creator) VALUES ('!legacy:test','@alice:test');
        INSERT INTO room_members (room_id,user_id,membership) VALUES
            ('!legacy:test','@alice:test','join');
        INSERT INTO events VALUES
            ('$4','!legacy:test','@alice:test','m.room.join_rules','',
             '{"join_rule":"invite"}',4,4),
            ('$5','!legacy:test','@alice:test','m.room.name','',
             '{"name":"general"}',5,5);

        -- Server roles living inside a deletable channel, the old arrangement.
        INSERT INTO events VALUES
            ('$6','!legacy:test','@server:test','bsfchat.server.roles','',
             '{"roles":[{"id":"everyone","name":"@everyone","position":0,"permissions":"0x1f"}]}',6,6),
            ('$7','!legacy:test','@server:test','bsfchat.member.roles','@alice:test',
             '{"role_ids":["everyone","admin"]}',7,7);
    )";
    char* err = nullptr;
    ASSERT_EQ(sqlite3_exec(db, schema, nullptr, nullptr, &err), SQLITE_OK)
        << (err ? err : "unknown");
    sqlite3_close(db);
}

int get_schema_version_for_test(const std::string& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return -1;
    int v = get_schema_version(db);
    sqlite3_close(db);
    return v;
}

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-test-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

} // namespace

TEST(LegacyUpgrade, ExistingDatabaseMigratesWithoutLeakingDms) {
    auto path = temp_db_path("legacy");
    std::filesystem::remove(path);
    create_legacy_database(path);

    Config config = Config::defaults();
    config.server_name = "test";

    {
        SqliteStore store(path);
        store.initialize();
        SyncEngine sync(store, config);

        // The DM is retro-detected: no name, not a category, exactly one
        // explicit invite, at most two participants.
        EXPECT_TRUE(store.is_direct_room("!dm:test"));
        EXPECT_FALSE(store.is_direct_room("!legacy:test"));

        // Carol's force-join into the DM is undone; the two real
        // participants stay.
        EXPECT_FALSE(store.is_room_member("!dm:test", "@carol:test"));
        EXPECT_TRUE(store.is_room_member("!dm:test", "@alice:test"));
        EXPECT_TRUE(store.is_room_member("!dm:test", "@bob:test"));

        // v18: the DM's membership state now says so on its own, exactly as a
        // DM created by this server does — so a client that never receives
        // m.direct can still tell this room from a channel.
        auto dm_member = store.get_state_event("!dm:test", "m.room.member", "@bob:test");
        ASSERT_TRUE(dm_member.has_value());
        EXPECT_TRUE(dm_member->content.data.value("is_direct", false));
        // And nothing else about it moved.
        EXPECT_EQ(dm_member->content.data.value("membership", ""), "invite");

        // The channel is left alone — the client must not start hiding real
        // channels because a migration was too eager.
        auto chan_name = store.get_state_event("!legacy:test", "m.room.name", "");
        ASSERT_TRUE(chan_name.has_value());
        EXPECT_FALSE(chan_name->content.data.contains("is_direct"));

        // Roles were carried into server_state, so they no longer depend on
        // the channel they happened to be written into.
        EXPECT_FALSE(store.get_server_roles().empty());
        EXPECT_FALSE(store.get_member_role_ids("@alice:test").empty());

        // The legitimate historical intent is preserved exactly once: the
        // untyped legacy channel becomes public.
        backfill_auto_join(store, sync, config);
        auto jr = store.get_state_event("!legacy:test", "m.room.join_rules", "");
        ASSERT_TRUE(jr.has_value());
        EXPECT_EQ(jr->content.data.value("join_rule", ""), "public");
        EXPECT_TRUE(store.is_room_member("!legacy:test", "@carol:test"));

        // ...and the DM is untouched by it.
        EXPECT_FALSE(store.is_room_member("!dm:test", "@carol:test"));
        auto dm_rooms = store.list_public_rooms();
        EXPECT_EQ(std::find(dm_rooms.begin(), dm_rooms.end(), "!dm:test"), dm_rooms.end());
    }

    // Reopen (i.e. restart): migrations must not re-run, and the one-time
    // publicize must not fire again.
    {
        SqliteStore store(path);
        store.initialize();
        SyncEngine sync(store, config);
        EXPECT_EQ(get_schema_version_for_test(path), kTargetSchemaVersion);
        backfill_auto_join(store, sync, config);
        EXPECT_FALSE(store.is_room_member("!dm:test", "@carol:test"));
        EXPECT_TRUE(store.is_direct_room("!dm:test"));
    }

    std::filesystem::remove(path);
}

// v18 rewrites event content in place, which is the one thing in this codebase
// that edits history rather than appending to it. Two properties keep that
// honest: it touches only the CURRENT state row per (room, state_key), and a
// second run changes nothing.
TEST(LegacyUpgrade, DirectMarkerBackfillTouchesOnlyCurrentStateAndIsIdempotent) {
    auto path = temp_db_path("v18");
    std::filesystem::remove(path);

    auto set_user_version = [&](int v) {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, ("PRAGMA user_version = " + std::to_string(v)).c_str(),
                               nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    };
    auto content_of = [&](const std::string& event_id) {
        sqlite3* db = nullptr;
        EXPECT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        std::string out;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT content FROM events WHERE event_id = ?", -1,
                               &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                out = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
        return out;
    };

    // A DM as an older server left it: two membership events for bob, neither
    // marked, the newer one current.
    {
        SqliteStore store(path);
        store.initialize();
        store.create_user("@alice:test", hash_password("p", 10));
        store.create_user("@bob:test", hash_password("p", 10));
        store.create_room("!dm:test", "@alice:test", /*is_direct=*/true);
        store.set_membership("!dm:test", "@bob:test", "join");
        store.insert_event("$old", "!dm:test", "@alice:test", "m.room.member", "@bob:test",
                           json{{"membership", "invite"}}.dump(), now_ms());
        store.insert_event("$new", "!dm:test", "@alice:test", "m.room.member", "@bob:test",
                           json{{"membership", "join"}, {"displayname", "Bob"}}.dump(),
                           now_ms());
        // A channel alongside it, to prove the WHERE clause is doing work.
        store.create_room("!chan:test", "@alice:test");
        store.insert_event("$chan", "!chan:test", "@alice:test", "m.room.member", "@bob:test",
                           json{{"membership", "join"}}.dump(), now_ms());
    }

    set_user_version(kTargetSchemaVersion - 1);
    { SqliteStore store(path); store.initialize(); }

    EXPECT_EQ(json::parse(content_of("$new")).value("is_direct", false), true);
    EXPECT_EQ(json::parse(content_of("$new")).value("displayname", ""), "Bob");
    // Superseded state keeps saying what it said at the time.
    EXPECT_FALSE(json::parse(content_of("$old")).contains("is_direct"));
    // A channel's membership is not a DM marker.
    EXPECT_FALSE(json::parse(content_of("$chan")).contains("is_direct"));

    // Re-running it is a no-op, not a second rewrite.
    const auto after_first = content_of("$new");
    set_user_version(kTargetSchemaVersion - 1);
    { SqliteStore store(path); store.initialize(); }
    EXPECT_EQ(content_of("$new"), after_first);

    EXPECT_EQ(get_schema_version_for_test(path), kTargetSchemaVersion);
    std::filesystem::remove(path);
}

// ── S1: the backfill must never publicize a DM ────────────────────────────

TEST(AutoJoinBackfill, DirectRoomStaysPrivateAndUnjoinedAcrossRestarts) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");

    // A DM between alice and bob.
    auto dm = generate_room_id("test");
    f.store->create_room(dm, alice, /*is_direct=*/true);
    f.store->set_membership(dm, alice, "join");
    f.store->set_membership(dm, bob, "join");
    f.store->insert_event(generate_event_id("test"), dm, alice,
                          std::string(event_type::kRoomJoinRules), std::string(""),
                          json{{"join_rule", "invite"}}.dump(), now_ms());
    f.store->insert_event(generate_event_id("test"), dm, alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", "secret"}}.dump(), now_ms());

    // Simulate several server restarts.
    for (int i = 0; i < 3; ++i) {
        backfill_auto_join(*f.store, *f.sync, f.config);
    }

    // Still private...
    auto jr = f.store->get_state_event(dm, std::string(event_type::kRoomJoinRules), "");
    ASSERT_TRUE(jr.has_value());
    EXPECT_EQ(jr->content.data.value("join_rule", ""), "invite");

    // ...never listed as a public room...
    auto public_rooms = f.store->list_public_rooms();
    EXPECT_EQ(std::find(public_rooms.begin(), public_rooms.end(), dm), public_rooms.end());

    // ...and carol was never dragged in.
    EXPECT_FALSE(f.store->is_room_member(dm, carol));
    EXPECT_TRUE(f.store->is_room_member(dm, alice));
    EXPECT_TRUE(f.store->is_room_member(dm, bob));
}

TEST(AutoJoinBackfill, DeliberatelyPrivateChannelSurvivesRestarts) {
    Fixture f;
    auto alice = f.add_user("alice");
    f.add_user("bob");

    // A private channel created by the current code path: it carries a
    // bsfchat.room.type event, which is what marks it as "not legacy".
    auto chan = generate_room_id("test");
    f.store->create_room(chan, alice);
    f.store->set_membership(chan, alice, "join");
    f.store->insert_event(generate_event_id("test"), chan, alice,
                          std::string(event_type::kRoomJoinRules), std::string(""),
                          json{{"join_rule", "invite"}}.dump(), now_ms());
    f.store->insert_event(generate_event_id("test"), chan, alice,
                          std::string(event_type::kRoomType), std::string(""),
                          json{{"type", "text"}}.dump(), now_ms());

    for (int i = 0; i < 3; ++i) {
        backfill_auto_join(*f.store, *f.sync, f.config);
    }

    auto jr = f.store->get_state_event(chan, std::string(event_type::kRoomJoinRules), "");
    ASSERT_TRUE(jr.has_value());
    EXPECT_EQ(jr->content.data.value("join_rule", ""), "invite")
        << "a channel deliberately created private was re-publicized";
    EXPECT_FALSE(f.store->is_room_member(chan, "@bob:test"));
}

TEST(AutoJoinBackfill, PublicChannelStillAutoJoinsEveryone) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto chan = generate_room_id("test");
    f.store->create_room(chan, alice);
    f.store->set_membership(chan, alice, "join");
    f.store->insert_event(generate_event_id("test"), chan, alice,
                          std::string(event_type::kRoomJoinRules), std::string(""),
                          json{{"join_rule", "public"}}.dump(), now_ms());

    backfill_auto_join(*f.store, *f.sync, f.config);
    EXPECT_TRUE(f.store->is_room_member(chan, bob));
}

// A kick is a moderator decision. backfill_auto_join runs unconditionally at
// every boot, and it used to test is_room_member() — `membership = 'join'`
// only — so the `leave` row a kick writes read as "not joined yet" and the
// user was force-joined straight back in. The moderator's action was undone
// by the next restart or deploy, silently, with nothing in the log.
TEST(AutoJoinBackfill, AKickSurvivesARestart) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto chan = generate_room_id("test");
    f.store->create_room(chan, alice);
    f.store->set_membership(chan, alice, "join");
    f.store->insert_event(generate_event_id("test"), chan, alice,
                          std::string(event_type::kRoomJoinRules), std::string(""),
                          json{{"join_rule", "public"}}.dump(), now_ms());

    backfill_auto_join(*f.store, *f.sync, f.config);
    ASSERT_TRUE(f.store->is_room_member(chan, bob));

    // Alice kicks bob — this is what handle_kick writes.
    f.store->set_membership(chan, bob, "leave");
    ASSERT_FALSE(f.store->is_room_member(chan, bob));

    for (int i = 0; i < 3; ++i) {
        backfill_auto_join(*f.store, *f.sync, f.config);
    }
    EXPECT_FALSE(f.store->is_room_member(chan, bob))
        << "the kick was undone by a restart";
}

// Same mechanism, from the user's side: leaving a channel you do not want to
// be in has to stick.
TEST(AutoJoinBackfill, LeavingAChannelSticksAcrossRestarts) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto chan = generate_room_id("test");
    f.store->create_room(chan, alice);
    f.store->set_membership(chan, alice, "join");
    f.store->insert_event(generate_event_id("test"), chan, alice,
                          std::string(event_type::kRoomJoinRules), std::string(""),
                          json{{"join_rule", "public"}}.dump(), now_ms());
    backfill_auto_join(*f.store, *f.sync, f.config);
    ASSERT_TRUE(f.store->is_room_member(chan, bob));

    f.store->set_membership(chan, bob, "leave");
    backfill_auto_join(*f.store, *f.sync, f.config);
    EXPECT_FALSE(f.store->is_room_member(chan, bob));

    // But a user who has never been considered still gets auto-joined — the
    // thing backfill is actually for.
    auto dave = f.add_user("dave");
    backfill_auto_join(*f.store, *f.sync, f.config);
    EXPECT_TRUE(f.store->is_room_member(chan, dave));
}

// find_membership must distinguish "no row" from "leave"; get_membership
// cannot, which is what made the bug above possible.
TEST(AutoJoinBackfill, FindMembershipSeparatesNeverJoinedFromLeft) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto chan = generate_room_id("test");
    f.store->create_room(chan, alice);

    EXPECT_FALSE(f.store->find_membership(chan, bob).has_value());
    EXPECT_EQ(f.store->get_membership(chan, bob), "leave");

    f.store->set_membership(chan, bob, "leave");
    ASSERT_TRUE(f.store->find_membership(chan, bob).has_value());
    EXPECT_EQ(*f.store->find_membership(chan, bob), "leave");
}

TEST(RoomHandlerCreate, DirectRoomIsPersistedPrivateAndPeerJoined) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    f.add_user("carol");

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/createRoom", "token-alice",
                            json{{"is_direct", true},
                                 {"visibility", "private"},
                                 {"invite", json::array({bob})}}.dump());
    handler.handle_create_room(req, res);

    ASSERT_TRUE(IsOk(res));
    auto room_id = json::parse(res.body).at("room_id").get<std::string>();

    // is_direct must actually be persisted — the client has always sent the
    // flag and the server never read it.
    EXPECT_TRUE(f.store->is_direct_room(room_id));
    EXPECT_TRUE(f.store->is_room_member(room_id, bob));
    EXPECT_FALSE(f.store->is_room_member(room_id, "@carol:test"));

    // And a restart must not change any of that.
    backfill_auto_join(*f.store, *f.sync, f.config);
    EXPECT_FALSE(f.store->is_room_member(room_id, "@carol:test"));
}

// ── DMs: one room per pair, and both sides can tell it is a DM ─────────────

// /sync used to carry nothing that marked a room as direct. The creator's
// client knew because it made the room; the invited side filed it under
// channels and then opened a SECOND DM with the same person.
TEST(DirectRooms, SyncReportsMDirectToBothSidesAndNobodyElse) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");

    // Bob is already syncing when alice opens the DM.
    auto bob_since = f.sync->handle_sync(bob, "", 0).next_batch;

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/createRoom", "token-alice",
                            json{{"is_direct", true}, {"invite", json::array({bob})}}.dump());
    handler.handle_create_room(req, res);
    ASSERT_TRUE(IsOk(res));
    auto room_id = json::parse(res.body).at("room_id").get<std::string>();

    // Incremental: the sync that delivers the room also says what it is.
    auto bob_inc = f.sync->handle_sync(bob, bob_since, 0);
    ASSERT_EQ(bob_inc.rooms.join.count(room_id), 1u);
    ASSERT_TRUE(bob_inc.direct_rooms.has_value());
    EXPECT_EQ(bob_inc.direct_rooms->at(alice), std::vector<std::string>{room_id});

    // Initial: a fresh login on either side sees it too.
    auto bob_init = f.sync->handle_sync(bob, "", 0);
    ASSERT_TRUE(bob_init.direct_rooms.has_value());
    EXPECT_EQ(bob_init.direct_rooms->at(alice), std::vector<std::string>{room_id});
    auto alice_init = f.sync->handle_sync(alice, "", 0);
    ASSERT_TRUE(alice_init.direct_rooms.has_value());
    EXPECT_EQ(alice_init.direct_rooms->at(bob), std::vector<std::string>{room_id});

    EXPECT_FALSE(f.sync->handle_sync(carol, "", 0).direct_rooms.has_value());

    // Every delivered incremental sync restates it. It used to be attached
    // only where the room was NEW to the user, which is exactly the case a DM
    // that already exists is not — see DmsThatPredateThisServerAreStillLearned
    // below for why that left the upgrade path broken.
    f.store->insert_event(generate_event_id("test"), room_id, alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", "hi"}}.dump(), now_ms());
    auto bob_quiet = f.sync->handle_sync(bob, bob_inc.next_batch, 0);
    EXPECT_EQ(bob_quiet.rooms.join.count(room_id), 1u);
    ASSERT_TRUE(bob_quiet.direct_rooms.has_value());
    EXPECT_EQ(bob_quiet.direct_rooms->at(alice), std::vector<std::string>{room_id});
}

// A client can only de-duplicate against what it has synced. A second device,
// a double click, or both people opening the DM at once all get past that.
TEST(DirectRooms, CreatingADmThatAlreadyExistsReturnsTheExistingRoom) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    RoomHandler handler(*f.store, *f.sync, f.config);

    auto open_dm = [&](const std::string& token, const std::string& peer) {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/createRoom", token,
                                json{{"is_direct", true}, {"invite", json::array({peer})}}.dump());
        handler.handle_create_room(req, res);
        EXPECT_TRUE(IsOk(res));
        return json::parse(res.body).at("room_id").get<std::string>();
    };

    auto first = open_dm("token-alice", bob);
    EXPECT_EQ(open_dm("token-alice", bob), first);
    // From the other side too — bob must not mint a twin.
    EXPECT_EQ(open_dm("token-bob", alice), first);
    // A different peer is a different room.
    EXPECT_NE(open_dm("token-alice", carol), first);

    // Once a side has left, the old room is no longer a usable answer.
    f.store->set_membership(first, alice, "leave");
    EXPECT_NE(open_dm("token-alice", bob), first);
}

// ── The upgrade path: DMs that already existed ────────────────────────────

namespace {

// A DM exactly as a server that predates this work left it on disk: the room
// is flagged, both sides are joined, and the membership events carry NO
// `is_direct` marker, because nothing wrote one. This is what production's
// database actually holds.
std::string legacy_dm(Fixture& f, const std::string& a, const std::string& b) {
    auto room_id = generate_room_id("test");
    f.store->create_room(room_id, a, /*is_direct=*/true);
    for (const auto& u : {a, b}) {
        f.store->set_membership(room_id, u, "join");
        f.store->insert_event(generate_event_id("test"), room_id, a,
                              std::string(event_type::kRoomMember), u,
                              json{{"membership", "join"}}.dump(), now_ms());
    }
    return room_id;
}

} // namespace

// The half of this fix that reaches the rooms the complaint is about.
//
// Stamping `is_direct` on new DMs' membership events does nothing for a DM
// that already exists, and neither did m.direct as it was attached: on an
// initial sync, and on the one incremental sync where the user NEWLY JOINS a
// direct room. A running client resumes from a persisted sync token, so it
// never asks for an initial sync again, and it joined its existing DMs long
// ago — so upgrading the server left every existing DM sitting in the channel
// list exactly as before, until the client was reinstalled.
TEST(DirectRoomUpgradePath, DmsThatPredateThisServerAreStillLearned) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto chan = generate_room_id("test");
    f.store->create_room(chan, alice);
    for (const auto& u : {alice, bob}) f.store->set_membership(chan, u, "join");

    const auto room_id = legacy_dm(f, alice, bob);

    // Nothing in the room's own state says it is direct — this is the case the
    // membership marker cannot cover.
    auto member = f.store->get_state_event(room_id, std::string(event_type::kRoomMember), bob);
    ASSERT_TRUE(member.has_value());
    EXPECT_FALSE(member->content.data.value("is_direct", false));

    // Bob has been running since before the upgrade: he holds a sync token and
    // will never ask for an initial sync again.
    const auto old_token = "s" + std::to_string(f.store->get_current_stream_position());

    // His next incremental sync with something in it — a message in an
    // ORDINARY channel, nothing to do with the DM — tells him anyway.
    f.store->insert_event(generate_event_id("test"), chan, alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", "hi"}}.dump(), now_ms());
    auto bob_inc = f.sync->handle_sync(bob, old_token, 0);
    ASSERT_EQ(bob_inc.rooms.join.count(chan), 1u);
    EXPECT_EQ(bob_inc.rooms.join.count(room_id), 0u) << "the DM itself had no new events";
    ASSERT_TRUE(bob_inc.direct_rooms.has_value());
    EXPECT_EQ(bob_inc.direct_rooms->at(alice), std::vector<std::string>{room_id});

    // And on a completely quiet server, where no incremental sync ever has
    // anything in it, the empty reply carries it too — otherwise a client with
    // nobody talking to it would never find out.
    auto bob_quiet = f.sync->handle_sync(bob, bob_inc.next_batch, 0);
    EXPECT_TRUE(bob_quiet.rooms.join.empty());
    ASSERT_TRUE(bob_quiet.direct_rooms.has_value());
    EXPECT_EQ(bob_quiet.direct_rooms->at(alice), std::vector<std::string>{room_id});

    // Alice, who created it, learns the same way.
    auto alice_inc = f.sync->handle_sync(alice, old_token, 0);
    ASSERT_TRUE(alice_inc.direct_rooms.has_value());
    EXPECT_EQ(alice_inc.direct_rooms->at(bob), std::vector<std::string>{room_id});
}

// The thing that would make restating m.direct dangerous: if it counted as
// content, every long poll would return instantly and every client would spin.
// It cannot, because the "keep waiting" decision is taken on rooms.join before
// m.direct is ever attached — but that is a claim worth holding a test against,
// since the two live in the same function.
TEST(DirectRoomUpgradePath, AnIdleLongPollStillBlocksDespiteAlwaysCarryingMDirect) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    const auto room_id = legacy_dm(f, alice, bob);

    const auto since = f.sync->handle_sync(bob, "", 0).next_batch;

    constexpr int kTimeoutMs = 400;
    const auto started = std::chrono::steady_clock::now();
    auto resp = f.sync->handle_sync(bob, since, kTimeoutMs);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    // It waited out the timeout rather than returning at once on its own
    // m.direct. A little slack below the nominal figure for timer coarseness.
    EXPECT_GE(elapsed, kTimeoutMs - 50) << "the long poll returned early";
    EXPECT_TRUE(resp.rooms.join.empty());
    EXPECT_EQ(resp.next_batch, since) << "an idle reply must not look like progress";
    // And it still carries m.direct, which is the whole point.
    ASSERT_TRUE(resp.direct_rooms.has_value());

    // A poll that IS woken still returns promptly.
    std::thread waiter;
    SyncResponse woken;
    const auto wake_started = std::chrono::steady_clock::now();
    waiter = std::thread([&] { woken = f.sync->handle_sync(bob, since, 5000); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    f.store->insert_event(generate_event_id("test"), room_id, alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", "hi"}}.dump(), now_ms());
    f.sync->notify_new_event();
    waiter.join();
    const auto wake_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - wake_started).count();
    EXPECT_LT(wake_elapsed, 4000);
    EXPECT_EQ(woken.rooms.join.count(room_id), 1u);
}

// ── DM isolation: a DM is not a channel, and only its two people are in it ──

namespace {

// Alice and bob's DM, with carol standing by as the third party. Carol is the
// FIRST registered user, so role bootstrap makes her the server's Admin: every
// "carol cannot" below is therefore a statement about the most privileged
// account on the server, not about an ordinary one.
struct DmFixture : Fixture {
    std::string carol = add_user("carol");
    std::string alice = add_user("alice");
    std::string bob = add_user("bob");
    RoomHandler rooms{*store, *sync, config};
    std::string room_id;

    DmFixture() {
        bootstrap_roles(*store, *sync, config);
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/createRoom", "token-alice",
                                json{{"is_direct", true},
                                     {"invite", json::array({bob})}}.dump());
        rooms.handle_create_room(req, res);
        EXPECT_TRUE(IsOk(res));
        room_id = json::parse(res.body).at("room_id").get<std::string>();
    }
};

// The `is_direct` flag on a user's m.room.member content, or nullopt when there
// is no such member event.
std::optional<bool> member_is_direct(SqliteStore& store, const std::string& room_id,
                                     const std::string& user_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kRoomMember), user_id);
    if (!ev) return std::nullopt;
    return ev->content.data.value("is_direct", false);
}

} // namespace

// m.direct is account data: it rides in exactly one /sync response, and a
// client that never sees that one response has nothing in the room itself to
// classify it by — so it files somebody's DM under the server's channels. The
// room's own membership state says what the room is, for BOTH sides, and every
// client gets it on every initial sync.
TEST(DirectRoomIsolation, BothParticipantsMembershipEventSaysItIsDirect) {
    DmFixture f;

    EXPECT_EQ(member_is_direct(*f.store, f.room_id, f.alice), std::optional<bool>(true));
    EXPECT_EQ(member_is_direct(*f.store, f.room_id, f.bob), std::optional<bool>(true));

    // An ordinary channel carries no such marker — the client must not start
    // hiding real channels.
    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/createRoom", "token-carol",
                            json{{"name", "general"}}.dump());
    f.rooms.handle_create_room(req, res);
    ASSERT_TRUE(IsOk(res));
    auto chan = json::parse(res.body).at("room_id").get<std::string>();
    EXPECT_EQ(member_is_direct(*f.store, chan, f.carol), std::optional<bool>(false));
}

// broadcastMemberUpdate REPLACES the member event in every joined room, so
// anything it does not rebuild is erased. Renaming yourself must not turn both
// sides' DM back into a channel.
TEST(DirectRoomIsolation, AProfileChangeDoesNotEraseTheDirectMarker) {
    DmFixture f;
    ProfileHandler profiles(*f.store, *f.sync, f.config);

    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/profile/" + f.alice + "/displayname",
                            "token-alice", json{{"displayname", "Alice B"}}.dump());
    profiles.handle_put_displayname(req, res);
    ASSERT_TRUE(IsOk(res));

    EXPECT_EQ(member_is_direct(*f.store, f.room_id, f.alice), std::optional<bool>(true));
    EXPECT_EQ(member_is_direct(*f.store, f.room_id, f.bob), std::optional<bool>(true));
}

// Read. Every read path on a room is membership-gated, and a DM has exactly two
// members — so the server's Admin is as much an outsider here as anyone.
TEST(DirectRoomIsolation, ANonParticipantCannotReadADm) {
    DmFixture f;
    EventHandler events(*f.store, *f.sync, f.config);

    f.store->insert_event(generate_event_id("test"), f.room_id, f.alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", "secret"}}.dump(), now_ms());

    auto expect_forbidden = [&](const char* what, httplib::Response& res) {
        EXPECT_EQ(res.status, 403) << what << ": " << res.body;
        EXPECT_EQ(json::parse(res.body).value("errcode", ""), "M_FORBIDDEN") << what;
    };

    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + f.room_id + "/messages",
                                "token-carol");
        events.handle_room_messages(req, res);
        expect_forbidden("/messages", res);
    }
    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + f.room_id + "/state",
                                "token-carol");
        f.rooms.handle_room_state(req, res);
        expect_forbidden("/state", res);
    }
    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + f.room_id + "/members",
                                "token-carol");
        f.rooms.handle_room_members(req, res);
        expect_forbidden("/members", res);
    }
    // ...and /sync, the path that would otherwise put it in her sidebar.
    auto carol_sync = f.sync->handle_sync(f.carol, "", 0);
    EXPECT_EQ(carol_sync.rooms.join.count(f.room_id), 0u);
    EXPECT_FALSE(carol_sync.direct_rooms.has_value());
}

// Send.
TEST(DirectRoomIsolation, ANonParticipantCannotSendIntoADm) {
    DmFixture f;
    EventHandler events(*f.store, *f.sync, f.config);

    httplib::Response res;
    auto req = make_request(
        "/_matrix/client/v3/rooms/" + f.room_id + "/send/m.room.message/txn1",
        "token-carol", json{{"msgtype", "m.text"}, {"body", "hello"}}.dump());
    events.handle_send_event(req, res);

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_EQ(json::parse(res.body).value("errcode", ""), "M_FORBIDDEN");

    // And nothing landed: bob's timeline is exactly what alice and bob put there.
    for (const auto& ev : f.store->get_room_events(f.room_id, 50)) {
        EXPECT_NE(ev.sender, f.carol);
    }
}

// Enumeration. A DM must not appear in any sweep that answers "what channels
// does this server have" — those feed auto-join, the public room directory and
// the historical publicize migration.
TEST(DirectRoomIsolation, ADmIsNotInAnyServerChannelEnumeration) {
    DmFixture f;

    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/createRoom", "token-carol",
                            json{{"name", "general"}}.dump());
    f.rooms.handle_create_room(req, res);
    ASSERT_TRUE(IsOk(res));
    auto chan = json::parse(res.body).at("room_id").get<std::string>();

    auto lacks = [&](const std::vector<std::string>& v, const std::string& id) {
        return std::find(v.begin(), v.end(), id) == v.end();
    };

    auto all = f.store->list_all_non_category_rooms();
    EXPECT_TRUE(lacks(all, f.room_id));
    EXPECT_FALSE(lacks(all, chan)) << "the real channel must still be listed";

    EXPECT_TRUE(lacks(f.store->list_public_rooms(), f.room_id));
    EXPECT_TRUE(lacks(f.store->list_legacy_untyped_rooms(), f.room_id));

    // The auto-join sweep a new channel triggers must not drag carol into the
    // DM on its way past.
    EXPECT_FALSE(f.store->is_room_member(f.room_id, f.carol));
    backfill_auto_join(*f.store, *f.sync, f.config);
    EXPECT_FALSE(f.store->is_room_member(f.room_id, f.carol));
}

// A DM is a conversation between exactly two people. Nothing may add a third,
// and nothing may file it under the server's channel tree — not the dedicated
// endpoints and not the generic state route behind them.
TEST(DirectRoomIsolation, ADmCannotBeWidenedOrTurnedIntoAChannel) {
    DmFixture f;

    auto expect_forbidden = [&](const char* what, const httplib::Response& res) {
        EXPECT_EQ(res.status, 403) << what << ": " << res.body;
        EXPECT_EQ(json::parse(res.body).value("errcode", ""), "M_FORBIDDEN") << what;
    };

    // A category to aim at, and alice as an Admin so the refusals below are
    // about the room being a DM rather than about her permissions.
    f.grant(f.alice, std::string(permission::role_id::kAdmin));
    std::string category;
    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/createRoom", "token-carol",
                                json{{"name", "Text"}, {"is_category", true}}.dump());
        f.rooms.handle_create_room(req, res);
        ASSERT_TRUE(IsOk(res));
        category = json::parse(res.body).at("room_id").get<std::string>();
    }

    {   // Alice is a participant AND an admin. She still cannot add carol.
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + f.room_id + "/invite",
                                "token-alice", json{{"user_id", f.carol}}.dump());
        f.rooms.handle_invite(req, res);
        expect_forbidden("/invite", res);
        EXPECT_FALSE(f.store->is_room_member(f.room_id, f.carol));
    }
    {   // Nor give it a place in the sidebar.
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + f.room_id + "/category",
                                "token-alice", json{{"parent_id", category}}.dump());
        f.rooms.handle_move_channel(req, res);
        expect_forbidden("/category", res);
    }
    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + f.room_id + "/order",
                                "token-alice", json{{"order", 3}}.dump());
        f.rooms.handle_set_order(req, res);
        expect_forbidden("/order", res);
    }
    {   // The generic state route is the back door to both of the above.
        httplib::Response res;
        auto req = make_request(
            "/_matrix/client/v3/rooms/" + f.room_id + "/state/bsfchat.room.category",
            "token-alice", json{{"parent_id", category}, {"order", 0}}.dump());
        f.rooms.handle_set_state(req, res);
        expect_forbidden("state/bsfchat.room.category", res);
    }
    {   // Reopening the join rules would make it joinable by anyone.
        httplib::Response res;
        auto req = make_request(
            "/_matrix/client/v3/rooms/" + f.room_id + "/state/m.room.join_rules",
            "token-alice", json{{"join_rule", "public"}}.dump());
        f.rooms.handle_set_state(req, res);
        expect_forbidden("state/m.room.join_rules", res);
    }

    EXPECT_FALSE(f.store->get_state_event(
        f.room_id, std::string(event_type::kRoomCategory), "").has_value());
}

// Deleting a channel is a moderator act performed from OUTSIDE it, so
// handle_delete_room has no membership check — which made every DM on the
// server destroyable by whoever holds MANAGE_CHANNELS, with the member list
// captured into the audit log on the way out.
TEST(DirectRoomIsolation, AnAdminOutsideADmCannotDeleteIt) {
    DmFixture f;

    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/rooms/" + f.room_id, "token-carol");
    f.rooms.handle_delete_room(req, res);

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(f.store->room_exists(f.room_id));
    EXPECT_TRUE(f.store->is_room_member(f.room_id, f.bob));
}

// ── S2: room creation authorization ───────────────────────────────────────

TEST(RoomHandlerCreate, PlainUserCannotCreateChannels) {
    Fixture f;
    f.add_user("owner");
    auto mallory = f.add_user("mallory");
    bootstrap_roles(*f.store, *f.sync, f.config);
    ASSERT_FALSE(f.store->get_member_role_ids(mallory).empty());

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/createRoom", "token-mallory",
                            json{{"name", "spam"}}.dump());
    handler.handle_create_room(req, res);

    EXPECT_EQ(res.status, 403) << res.body;
}

TEST(RoomHandlerCreate, AdminCanCreateChannelsAndAnyoneCanOpenADm) {
    Fixture f;
    auto owner = f.add_user("owner");
    auto mallory = f.add_user("mallory");
    bootstrap_roles(*f.store, *f.sync, f.config);

    RoomHandler handler(*f.store, *f.sync, f.config);
    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/createRoom", "token-owner",
                                json{{"name", "general"}}.dump());
        handler.handle_create_room(req, res);
        EXPECT_TRUE(IsOk(res));
    }
    {
        // A DM is a per-user capability, not channel management.
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/createRoom", "token-mallory",
                                json{{"is_direct", true},
                                     {"invite", json::array({owner})}}.dump());
        handler.handle_create_room(req, res);
        EXPECT_TRUE(IsOk(res));
    }
}

// The positive half of the same gate: closing the hole is only half the
// requirement, the permission also has to actually WORK for a role that is not
// Admin. Bob holds a custom role whose only power beyond the @everyone default
// is MANAGE_CHANNELS.
TEST(RoomHandlerCreate, RoleGrantedManageChannelsLetsANonAdminCreate) {
    Fixture f;
    f.add_user("owner"); // first-registered → Admin at bootstrap
    auto bob = f.add_user("bob");
    bootstrap_roles(*f.store, *f.sync, f.config);
    define_role(f, "builder", permission::kEveryoneDefault | permission::kManageChannels);
    f.grant(bob, "builder");

    {
        PermissionsEngine check(*f.store, f.config);
        ASSERT_FALSE(check.can(bob, "", permission::kAdministrator))
            << "precondition: this test is about a NON-admin role";
        ASSERT_TRUE(check.can(bob, "", permission::kManageChannels));
    }

    RoomHandler handler(*f.store, *f.sync, f.config);

    std::string channel_id;
    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/createRoom", "token-bob",
                                json{{"name", "builds"}}.dump());
        handler.handle_create_room(req, res);
        ASSERT_TRUE(IsOk(res));
        channel_id = json::parse(res.body).at("room_id").get<std::string>();
    }
    EXPECT_TRUE(f.store->room_exists(channel_id));
    EXPECT_TRUE(f.store->is_room_member(channel_id, bob));

    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/createRoom", "token-bob",
                                json{{"name", "Projects"}, {"is_category", true}}.dump());
        handler.handle_create_room(req, res);
        ASSERT_TRUE(IsOk(res));
        auto category_id = json::parse(res.body).at("room_id").get<std::string>();
        auto type = f.store->get_state_event(
            category_id, std::string(event_type::kRoomType), "");
        ASSERT_TRUE(type.has_value());
        EXPECT_EQ(type->content.data.value("type", ""), "category");
    }
}

// A user with no channel-management role must be refused for categories too,
// not only for text channels: a category is server structure just the same, and
// the is_category branch of the handler runs after the gate.
TEST(RoomHandlerCreate, PlainUserCannotCreateCategories) {
    Fixture f;
    f.add_user("owner");
    f.add_user("mallory");
    bootstrap_roles(*f.store, *f.sync, f.config);

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/createRoom", "token-mallory",
                            json{{"name", "spam"}, {"is_category", true}}.dump());
    handler.handle_create_room(req, res);

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(f.store->list_all_non_category_rooms().empty());
}

// Creation is server structure, so the gate is evaluated at SERVER scope. A
// per-channel MANAGE_CHANNELS override — which legitimately lets someone rename
// or configure that one channel — must not become a licence to add channels to
// the server, the same shape of escalation that
// ServerRoles.PerChannelManageRolesCannotRewriteServerRoles guards against.
TEST(RoomHandlerCreate, PerChannelOverrideDoesNotConferServerWideCreation) {
    Fixture f;
    auto owner = f.add_user("owner");
    auto mallory = f.add_user("mallory");

    auto room = generate_room_id("test");
    f.store->create_room(room, owner);
    f.store->set_membership(room, owner, "join");
    f.store->set_membership(room, mallory, "join");
    bootstrap_roles(*f.store, *f.sync, f.config);

    allow_in_channel(f, room, owner, mallory, permission::kManageChannels);

    {
        PermissionsEngine check(*f.store, f.config);
        ASSERT_TRUE(check.can(mallory, room, permission::kManageChannels))
            << "precondition: the override should grant MANAGE_CHANNELS in this room";
        EXPECT_FALSE(check.can(mallory, "", permission::kManageChannels))
            << "a channel override must not contribute to the server-scope answer";
    }

    RoomHandler handler(*f.store, *f.sync, f.config);
    for (const bool is_category : {false, true}) {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/createRoom", "token-mallory",
                                json{{"name", "mallory-was-here"},
                                     {"is_category", is_category}}.dump());
        handler.handle_create_room(req, res);
        EXPECT_EQ(res.status, 403) << "is_category=" << is_category << " body: " << res.body;
    }
}

// ── S5: sync must not silently drop events ────────────────────────────────

TEST(SyncEngineIncremental, DeliversEveryEventAcrossMoreThanOneBatch) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = generate_room_id("test");
    f.store->create_room(room, alice);
    f.store->set_membership(room, alice, "join");

    // get_events_since caps at 1000 rows per call; the old code then set
    // next_batch to the GLOBAL stream head, so everything past the cap was
    // skipped forever.
    constexpr int kTotal = 2500;
    for (int i = 0; i < kTotal; ++i) {
        f.store->insert_event(generate_event_id("test"), room, alice,
                              std::string(event_type::kRoomMessage), std::nullopt,
                              json{{"msgtype", "m.text"}, {"body", std::to_string(i)}}.dump(),
                              now_ms());
    }

    std::set<std::string> seen_bodies;
    std::string since = "s0";
    for (int page = 0; page < 20; ++page) {
        auto resp = f.sync->handle_sync(alice, since, 0);
        auto it = resp.rooms.join.find(room);
        if (it == resp.rooms.join.end()) break;
        for (const auto& ev : it->second.timeline.events) {
            if (ev.type == std::string(event_type::kRoomMessage)) {
                seen_bodies.insert(ev.content.data.value("body", ""));
            }
        }
        ASSERT_NE(resp.next_batch, since) << "sync token failed to advance";
        since = resp.next_batch;
    }

    EXPECT_EQ(seen_bodies.size(), static_cast<size_t>(kTotal))
        << "incremental sync lost events past the fetch limit";
}

TEST(SyncEngineIncremental, NextBatchNeverSkipsPastUndeliveredEvents) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto visible = generate_room_id("test");
    auto other = generate_room_id("test");
    f.store->create_room(visible, alice);
    f.store->create_room(other, alice);
    f.store->set_membership(visible, alice, "join");

    f.store->insert_event(generate_event_id("test"), visible, alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"body", "one"}}.dump(), now_ms());

    auto resp = f.sync->handle_sync(alice, "s0", 0);
    ASSERT_EQ(resp.rooms.join.count(visible), 1u);

    // The token must be the position actually delivered, so a later event in
    // a room alice isn't in can't push it past undelivered data.
    f.store->insert_event(generate_event_id("test"), other, alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"body", "unrelated"}}.dump(), now_ms());
    f.store->insert_event(generate_event_id("test"), visible, alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"body", "two"}}.dump(), now_ms());

    auto resp2 = f.sync->handle_sync(alice, resp.next_batch, 0);
    ASSERT_EQ(resp2.rooms.join.count(visible), 1u);
    bool saw_two = false;
    for (const auto& ev : resp2.rooms.join[visible].timeline.events) {
        if (ev.content.data.value("body", "") == "two") saw_two = true;
    }
    EXPECT_TRUE(saw_two);
}

TEST(SyncEngine, MalformedSinceTokenDoesNotThrow) {
    Fixture f;
    auto alice = f.add_user("alice");
    EXPECT_NO_THROW(f.sync->handle_sync(alice, "snot-a-number", 0));
    EXPECT_NO_THROW(f.sync->handle_sync(alice, "s99999999999999999999999", 0));
    EXPECT_NO_THROW(f.sync->handle_sync(alice, "garbage", 0));
}

TEST(SqliteStoreStream, PositionsAreMonotonicAcrossRoomDeletion) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto keep = generate_room_id("test");
    auto doomed = generate_room_id("test");
    f.store->create_room(keep, alice);
    f.store->create_room(doomed, alice);

    f.store->insert_event(generate_event_id("test"), keep, alice, "m.room.message",
                          std::nullopt, "{}", now_ms());
    int64_t high = 0;
    for (int i = 0; i < 5; ++i) {
        high = f.store->insert_event(generate_event_id("test"), doomed, alice,
                                     "m.room.message", std::nullopt, "{}", now_ms());
    }

    f.store->delete_room(doomed);

    // Deleting the newest events must not rewind the head; reusing positions
    // stranded any client holding a token at or above a reused value.
    EXPECT_GE(f.store->get_current_stream_position(), high);
    int64_t next = f.store->insert_event(generate_event_id("test"), keep, alice,
                                         "m.room.message", std::nullopt, "{}", now_ms());
    EXPECT_GT(next, high) << "stream position was reused after delete_room";
}

// ── S4: typing/presence must wake the long poll ───────────────────────────

TEST(SyncEngineWait, EphemeralNotifyWakesALongPoll) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = generate_room_id("test");
    f.store->create_room(room, alice);
    f.store->set_membership(room, alice, "join");

    auto since = f.sync->handle_sync(alice, "s0", 0).next_batch;

    auto start = std::chrono::steady_clock::now();
    std::thread waker([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        f.sync->notify_ephemeral();
    });
    f.sync->handle_sync(alice, since, 5000);
    waker.join();
    auto elapsed = std::chrono::steady_clock::now() - start;

    // notify_new_event() re-reads an unchanged stream position for an EDU, so
    // the waiter's predicate stayed false and the poll ran to its full
    // timeout — typing/presence were invisible until then.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 2000);
}

// ── S7: server-wide roles ─────────────────────────────────────────────────

TEST(ServerRoles, SurviveDeletionOfEveryRoom) {
    Fixture f;
    auto owner = f.add_user("owner");
    auto room = generate_room_id("test");
    f.store->create_room(room, owner);
    f.store->set_membership(room, owner, "join");

    bootstrap_roles(*f.store, *f.sync, f.config);
    ASSERT_FALSE(f.store->get_server_roles().empty());
    ASSERT_FALSE(f.store->get_member_role_ids(owner).empty());

    // Roles used to live as events inside whichever room came back first from
    // an unordered query; deleting it destroyed every role server-wide.
    f.store->delete_room(room);

    EXPECT_FALSE(f.store->get_server_roles().empty())
        << "deleting a channel wiped the server role definitions";
    EXPECT_FALSE(f.store->get_member_role_ids(owner).empty())
        << "deleting a channel wiped role assignments";

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_TRUE(perms.can(owner, "", permission::kAdministrator));
}

TEST(ServerRoles, PerChannelManageRolesCannotRewriteServerRoles) {
    Fixture f;
    auto owner = f.add_user("owner");
    auto mallory = f.add_user("mallory");

    auto room = generate_room_id("test");
    f.store->create_room(room, owner);
    f.store->set_membership(room, owner, "join");
    f.store->set_membership(room, mallory, "join");
    bootstrap_roles(*f.store, *f.sync, f.config);

    // Mallory is granted MANAGE_ROLES in ONE unimportant channel.
    ChannelPermissionOverride ov;
    ov.allow = permission::kManageRoles;
    ov.deny = 0;
    json ov_json;
    to_json(ov_json, ov);
    f.store->insert_event(generate_event_id("test"), room, owner,
                          std::string(event_type::kChannelPermissions),
                          "user:" + mallory, ov_json.dump(), now_ms());

    PermissionsEngine check(*f.store, f.config);
    ASSERT_TRUE(check.can(mallory, room, permission::kManageRoles))
        << "precondition: the channel override should grant MANAGE_ROLES here";

    // She now tries to rewrite the SERVER-wide roles, making @everyone an
    // administrator. The old code evaluated MANAGE_ROLES per-channel while the
    // role reader ignored room_id, so this succeeded server-wide.
    ServerRolesContent evil;
    ServerRole everyone;
    everyone.id = permission::role_id::kEveryone;
    everyone.name = "@everyone";
    everyone.position = 0;
    everyone.permissions = permission::kAllFlags;
    evil.roles.push_back(everyone);
    json evil_json;
    to_json(evil_json, evil);

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        "/_matrix/client/v3/rooms/" + room + "/state/" +
            std::string(event_type::kServerRoles) + "/",
        "token-mallory", evil_json.dump());
    handler.handle_set_state(req, res);

    EXPECT_EQ(res.status, 403) << res.body;

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_FALSE(perms.can(mallory, "", permission::kAdministrator))
        << "privilege escalation: a per-channel override granted server-wide admin";
}

// ── S9: VIEW_CHANNEL on read endpoints, and self-membership forgery ───────

TEST(RoomReads, DeniedViewChannelBlocksStateAndMemberList) {
    Fixture f;
    auto owner = f.add_user("owner");
    auto bob = f.add_user("bob");
    auto room = generate_room_id("test");
    f.store->create_room(room, owner);
    f.store->set_membership(room, owner, "join");
    f.store->set_membership(room, bob, "join");
    bootstrap_roles(*f.store, *f.sync, f.config);

    f.store->insert_event(generate_event_id("test"), room, owner,
                          std::string(event_type::kRoomName), std::string(""),
                          json{{"name", "secret-channel"}}.dump(), now_ms());

    ChannelPermissionOverride ov;
    ov.allow = 0;
    ov.deny = permission::kViewChannel;
    json ov_json;
    to_json(ov_json, ov);
    f.store->insert_event(generate_event_id("test"), room, owner,
                          std::string(event_type::kChannelPermissions),
                          "user:" + bob, ov_json.dump(), now_ms());

    RoomHandler handler(*f.store, *f.sync, f.config);

    // Everyone is force-joined to every public room, so membership alone was
    // never authorization: bob could still read the name, topic and roster.
    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + room + "/state", "token-bob");
        handler.handle_room_state(req, res);
        EXPECT_EQ(res.status, 403) << res.body;
    }
    {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + room + "/members", "token-bob");
        handler.handle_room_members(req, res);
        EXPECT_EQ(res.status, 403) << res.body;
    }
}

TEST(RoomSetState, SelfMembershipCannotForgeADisplayName) {
    Fixture f;
    auto owner = f.add_user("owner");
    auto mallory = f.add_user("mallory");
    f.store->set_display_name(mallory, "mallory");

    auto room = generate_room_id("test");
    f.store->create_room(room, owner);
    f.store->set_membership(room, mallory, "join");
    bootstrap_roles(*f.store, *f.sync, f.config);

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        "/_matrix/client/v3/rooms/" + room + "/state/m.room.member/" + mallory,
        "token-mallory",
        json{{"membership", "join"}, {"displayname", "owner"}}.dump());
    handler.handle_set_state(req, res);

    ASSERT_TRUE(IsOk(res));
    auto stored = f.store->get_state_event(room, std::string(event_type::kRoomMember), mallory);
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->content.data.value("displayname", ""), "mallory")
        << "client-supplied displayname was written verbatim";

    // The response must name an event that actually exists.
    auto echoed = json::parse(res.body).value("event_id", "");
    EXPECT_EQ(echoed, stored->event_id);
    EXPECT_TRUE(f.store->get_event_by_id(echoed).has_value());
}

// ── S8: redaction and transaction idempotency ─────────────────────────────

TEST(Redaction, TargetContentIsActuallyRemoved) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = generate_room_id("test");
    f.store->create_room(room, alice);
    f.store->set_membership(room, alice, "join");

    auto target = generate_event_id("test");
    f.store->insert_event(target, room, alice, std::string(event_type::kRoomMessage),
                          std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", "please delete me"}}.dump(),
                          now_ms());

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        "/_matrix/client/v3/rooms/" + room + "/redact/" + target + "/txn1",
        "token-alice", json{{"reason", "oops"}}.dump());
    handler.handle_redact(req, res);
    ASSERT_TRUE(IsOk(res));

    // Redaction used to append a tombstone and leave the original readable
    // through /rooms/{id}/messages.
    auto stored = f.store->get_event_by_id(target);
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->content.data.value("body", ""), "");

    auto [events, _] = f.store->get_room_events_paginated(room, 50, "b");
    for (const auto& ev : events) {
        EXPECT_NE(ev.content.data.value("body", ""), "please delete me")
            << "redacted content still retrievable via /messages";
    }
}

TEST(SendEvent, RetryWithSameTransactionIdDoesNotDuplicate) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = generate_room_id("test");
    f.store->create_room(room, alice);
    f.store->set_membership(room, alice, "join");

    EventHandler handler(*f.store, *f.sync, f.config);
    const std::string path =
        "/_matrix/client/v3/rooms/" + room + "/send/m.room.message/txn-42";
    const std::string body = json{{"msgtype", "m.text"}, {"body", "hi"}}.dump();

    httplib::Response res1;
    auto req1 = make_request(path, "token-alice", body);
    handler.handle_send_event(req1, res1);
    ASSERT_TRUE(IsOk(res1));

    httplib::Response res2;
    auto req2 = make_request(path, "token-alice", body);
    handler.handle_send_event(req2, res2);
    ASSERT_TRUE(IsOk(res2));

    EXPECT_EQ(json::parse(res1.body).at("event_id"), json::parse(res2.body).at("event_id"));

    auto [events, _] = f.store->get_room_events_paginated(room, 50, "b");
    int messages = 0;
    for (const auto& ev : events) {
        if (ev.type == std::string(event_type::kRoomMessage)) ++messages;
    }
    EXPECT_EQ(messages, 1) << "a client retry duplicated the message";
}

// ── S10: auth hardening ───────────────────────────────────────────────────

TEST(PasswordHashing, OldLowCostHashesStillVerify) {
    // Raising the default cost must not lock out existing accounts: the cost
    // travels with the stored hash.
    auto legacy = hash_password("correct horse", 12);
    EXPECT_TRUE(verify_password("correct horse", legacy));
    EXPECT_FALSE(verify_password("wrong", legacy));
    ASSERT_TRUE(password_hash_cost(legacy).has_value());
    EXPECT_EQ(*password_hash_cost(legacy), 12);
}

TEST(PasswordHashing, RejectsMalformedAndAbsurdCostValues) {
    EXPECT_FALSE(verify_password("x", ""));
    EXPECT_FALSE(verify_password("x", "$pbkdf2$"));
    EXPECT_FALSE(verify_password("x", "$pbkdf2$notanumber$aa$bb"));
    // A cost of 60 would be 2^60 iterations, and shifting by 60 into an int
    // is undefined behaviour.
    EXPECT_FALSE(verify_password("x", "$pbkdf2$60$aa$bb"));
}

// Lives here rather than in protocol/tests so this pass stays confined to
// server/ plus the one JwtUtils change it was asked to make.
TEST(JwtAudience, TokenMintedForAnotherClientIsRejected) {
    auto [priv, pub] = generate_rsa_keypair();

    JwtClaims claims;
    claims.iss = "https://id.example.com";
    claims.sub = "user-123";
    claims.aud = "some-other-app";   // NOT this chat server
    claims.iat = std::time(nullptr);
    claims.exp = claims.iat + 3600;
    auto token = jwt_sign(claims, priv, "kid1");

    // Signature, issuer and expiry are all fine — only the audience is wrong.
    // Without an audience check this verified, so an ID token minted for any
    // other client of the same identity provider was a valid chat login.
    EXPECT_FALSE(jwt_verify(token, pub, claims.iss, "bsfchat-desktop").has_value());
    EXPECT_TRUE(jwt_verify(token, pub, claims.iss, "some-other-app").has_value());
    // Empty expected audience preserves the old unchecked behaviour.
    EXPECT_TRUE(jwt_verify(token, pub, claims.iss).has_value());
}

TEST(JwtAudience, TokenWithNoAudienceIsRejectedWhenOneIsRequired) {
    auto [priv, pub] = generate_rsa_keypair();

    JwtClaims claims;
    claims.iss = "https://id.example.com";
    claims.sub = "user-123";
    claims.aud = "";
    claims.iat = std::time(nullptr);
    claims.exp = claims.iat + 3600;
    auto token = jwt_sign(claims, priv, "kid1");

    EXPECT_FALSE(jwt_verify(token, pub, claims.iss, "bsfchat-desktop").has_value());
}

TEST(ConfigValidation, VoiceEnabledWithRelayOnlyAndNoTurnFallsBackToP2p) {
    Config cfg = Config::defaults();
    cfg.voice.enabled = true;
    cfg.voice.allow_peer_to_peer = false;
    cfg.voice.turn_uris.clear();
    Config::validate(cfg);
    // Relay-only with zero relays means 100% call failure.
    EXPECT_TRUE(cfg.voice.allow_peer_to_peer);
}

TEST(ConfigValidation, ClampsDangerouslyLowPasswordCost) {
    Config cfg = Config::defaults();
    cfg.password_hash_cost = 4;
    Config::validate(cfg);
    EXPECT_GE(cfg.password_hash_cost, 12);
}

// ── S12: password change, access-token lifecycle, edit reconciliation ──────

namespace {

// Sends a request through a handler and returns the response, mirroring how
// Server::register_routes wires them up.
template <typename Handler, typename Method>
httplib::Response call(Handler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
}

json password_change_body(const std::string& current, const std::string& next,
                          std::optional<bool> logout_devices = std::nullopt) {
    json body = {
        {"auth", {{"type", "m.login.password"}, {"password", current}}},
        {"new_password", next},
    };
    if (logout_devices) body["logout_devices"] = *logout_devices;
    return body;
}

// Reads a single text value straight out of the database file, bypassing
// SqliteStore — used to prove what is actually persisted.
std::optional<std::string> raw_query_text(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return std::nullopt;
    sqlite3_stmt* stmt = nullptr;
    std::optional<std::string> out;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            out = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

const char* kPasswordPath = "/_matrix/client/v3/account/password";

} // namespace

// There was no password-change endpoint on the chat server at all: a local-auth
// user could never change their password, and access-token invalidation
// consequently had nowhere to hook.
TEST(PasswordChange, RotatesTheHashAndRevokesOtherSessions) {
    Fixture f;
    f.config.password_hash_cost = 12; // keep the test fast
    auto alice = f.add_user("alice");
    f.store->store_access_token("alice-phone", alice, "PHONE");
    f.store->store_access_token("alice-laptop", alice, "LAPTOP");

    auto before = f.store->get_password_hash(alice);
    ASSERT_TRUE(before.has_value());

    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_password_change, kPasswordPath,
                    "alice-phone", password_change_body("password", "brand-new-password").dump());
    ASSERT_TRUE(IsOk(res));

    // The stored hash actually rotated, and to the currently configured cost.
    auto after = f.store->get_password_hash(alice);
    ASSERT_TRUE(after.has_value());
    EXPECT_NE(*after, *before);
    EXPECT_FALSE(verify_password("password", *after));
    EXPECT_TRUE(verify_password("brand-new-password", *after));
    ASSERT_TRUE(password_hash_cost(*after).has_value());
    EXPECT_EQ(*password_hash_cost(*after), f.config.password_hash_cost);

    // Other sessions are gone; the one that re-authenticated survives, so the
    // user isn't kicked out of the client they just used.
    EXPECT_FALSE(f.store->get_user_by_token("alice-laptop").has_value());
    EXPECT_FALSE(f.store->get_user_by_token("token-alice").has_value());
    EXPECT_TRUE(f.store->get_user_by_token("alice-phone").has_value());
}

// A valid access token proves only that a client holds a token. Without
// re-authentication, a leaked token could be used to lock the owner out.
TEST(PasswordChange, RequiresTheCurrentPassword) {
    Fixture f;
    f.config.password_hash_cost = 12;
    auto alice = f.add_user("alice");
    auto before = f.store->get_password_hash(alice);

    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_password_change, kPasswordPath, "token-alice",
                    password_change_body("not-my-password", "brand-new-password").dump());
    EXPECT_EQ(res.status, 403);
    EXPECT_EQ(json::parse(res.body).value("errcode", ""), "M_FORBIDDEN");
    EXPECT_EQ(f.store->get_password_hash(alice), before) << "hash changed on a failed attempt";
    EXPECT_TRUE(f.store->get_user_by_token("token-alice").has_value());
}

TEST(PasswordChange, WithoutReauthReturnsAnAuthChallenge) {
    Fixture f;
    f.add_user("alice");
    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_password_change, kPasswordPath, "token-alice",
                    json{{"new_password", "brand-new-password"}}.dump());
    ASSERT_EQ(res.status, 401);
    auto body = json::parse(res.body);
    ASSERT_TRUE(body.contains("flows"));
    EXPECT_EQ(body["flows"][0]["stages"][0], "m.login.password");
}

TEST(PasswordChange, RejectsAnUnauthenticatedCaller) {
    Fixture f;
    f.add_user("alice");
    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_password_change, kPasswordPath, "bogus-token",
                    password_change_body("password", "brand-new-password").dump());
    EXPECT_EQ(res.status, 401);
}

TEST(PasswordChange, RejectsAShortNewPassword) {
    Fixture f;
    f.config.password_hash_cost = 12;
    auto alice = f.add_user("alice");
    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_password_change, kPasswordPath, "token-alice",
                    password_change_body("password", "short").dump());
    EXPECT_EQ(res.status, 400);
    EXPECT_TRUE(verify_password("password", *f.store->get_password_hash(alice)));
}

// OIDC accounts are created with an empty hash so password login can never work
// for them. They must get a comprehensible error, not a wrong-password one.
TEST(PasswordChange, OidcBackedAccountGetsAClearError) {
    Fixture f;
    f.config.password_hash_cost = 12;
    const std::string oidc_user = "@oidc_sub123:test";
    f.store->create_user(oidc_user, ""); // exactly how handle_login creates them
    f.store->store_access_token("oidc-token", oidc_user, "DEV");

    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_password_change, kPasswordPath, "oidc-token",
                    password_change_body("", "brand-new-password").dump());
    ASSERT_EQ(res.status, 403);
    auto err = json::parse(res.body).value("error", "");
    EXPECT_NE(err.find("identity provider"), std::string::npos) << "unclear error: " << err;
    // And no password was set behind the scenes.
    EXPECT_EQ(*f.store->get_password_hash(oidc_user), "");
    EXPECT_TRUE(f.store->get_user_by_token("oidc-token").has_value());
}

TEST(PasswordChange, LogoutDevicesFalseKeepsOtherSessions) {
    Fixture f;
    f.config.password_hash_cost = 12;
    auto alice = f.add_user("alice");
    f.store->store_access_token("alice-laptop", alice, "LAPTOP");

    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_password_change, kPasswordPath, "token-alice",
                    password_change_body("password", "brand-new-password", false).dump());
    ASSERT_TRUE(IsOk(res));
    EXPECT_TRUE(f.store->get_user_by_token("alice-laptop").has_value());
    EXPECT_TRUE(verify_password("brand-new-password", *f.store->get_password_hash(alice)));
}

// A token must not be usable to re-authenticate as a different account.
TEST(PasswordChange, IdentifierMustMatchTheAuthenticatedUser) {
    Fixture f;
    f.config.password_hash_cost = 12;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    json body = password_change_body("password", "brand-new-password");
    body["auth"]["identifier"] = {{"type", "m.id.user"}, {"user", "bob"}};

    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_password_change, kPasswordPath, "token-alice",
                    body.dump());
    EXPECT_EQ(res.status, 403);
    EXPECT_TRUE(verify_password("password", *f.store->get_password_hash(bob)));
}

// Tokens used to be stored in the clear, so a database dump was a live session
// for every logged-in user.
TEST(AccessTokens, AreNeverStoredInTheClear) {
    auto path = temp_db_path("tokenhash");
    std::filesystem::remove(path);
    {
        SqliteStore store(path);
        store.initialize();
        store.create_user("@alice:test", hash_password("password", 10));
        store.store_access_token("super-secret-token", "@alice:test", "DEV");
        EXPECT_TRUE(store.get_user_by_token("super-secret-token").has_value());
    }

    // The plaintext appears nowhere in the table...
    auto leaked = raw_query_text(path,
        "SELECT token_hash FROM access_tokens WHERE token_hash = 'super-secret-token'");
    EXPECT_FALSE(leaked.has_value()) << "access token is still readable at rest";
    // ...but the digest is there, and it is the digest we expect.
    auto stored = raw_query_text(path, "SELECT token_hash FROM access_tokens");
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(*stored, hash_access_token("super-secret-token"));
    EXPECT_NE(*stored, "super-secret-token");

    std::filesystem::remove(path);
}

// Tokens never expired: a leaked one was permanent.
TEST(AccessTokens, ExpiredTokenIsRejectedAndReaped) {
    Fixture f;
    f.store->create_user("@alice:test", hash_password("password", 10));
    // 1ms lifetime, i.e. expired by the time we look it up.
    f.store->store_access_token("short-lived", "@alice:test", "DEV", 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    EXPECT_FALSE(f.store->get_user_by_token("short-lived").has_value());
    // Both the direct store lookup and the middleware used by every handler
    // must refuse it.
    EXPECT_FALSE(authenticate(*f.store, "Bearer short-lived").has_value());
    EXPECT_FALSE(f.store->get_token_expiry("short-lived").has_value())
        << "expired row was not reaped";

    // A token issued with the normal lifetime still works.
    f.store->store_access_token("fresh", "@alice:test", "DEV");
    EXPECT_TRUE(f.store->get_user_by_token("fresh").has_value());
}

// The desktop client holds one token and polls /sync; a finite lifetime must
// not log an active user out mid-session.
TEST(AccessTokens, ActiveSessionSlidesItsExpiryForward) {
    Fixture f;
    f.store->create_user("@alice:test", hash_password("password", 10));
    f.store->store_access_token("sliding", "@alice:test", "DEV", 400);

    auto first = f.store->get_token_expiry("sliding");
    ASSERT_TRUE(first.has_value());

    // Past the halfway point: the next authentication renews.
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    ASSERT_TRUE(f.store->get_user_by_token("sliding").has_value());
    auto renewed = f.store->get_token_expiry("sliding");
    ASSERT_TRUE(renewed.has_value());
    EXPECT_GT(*renewed, *first);

    // Past the ORIGINAL expiry, but still valid because it was in use.
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    EXPECT_TRUE(f.store->get_user_by_token("sliding").has_value())
        << "an actively-used session was logged out";
}

TEST(AccessTokens, LogoutAllRevokesEverySession) {
    Fixture f;
    auto alice = f.add_user("alice");
    f.store->store_access_token("alice-phone", alice, "PHONE");
    auto bob = f.add_user("bob");

    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_logout_all,
                    "/_matrix/client/v3/logout/all", "token-alice");
    ASSERT_TRUE(IsOk(res));

    EXPECT_FALSE(f.store->get_user_by_token("token-alice").has_value());
    EXPECT_FALSE(f.store->get_user_by_token("alice-phone").has_value());
    // Another user's sessions are untouched.
    EXPECT_TRUE(f.store->get_user_by_token("token-bob").has_value());
}

TEST(AccessTokens, LogoutRevokesOnlyTheCallingSession) {
    Fixture f;
    auto alice = f.add_user("alice");
    f.store->store_access_token("alice-phone", alice, "PHONE");

    AuthHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AuthHandler::handle_logout, "/_matrix/client/v3/logout",
                    "token-alice");
    ASSERT_TRUE(IsOk(res));
    EXPECT_FALSE(f.store->get_user_by_token("token-alice").has_value());
    EXPECT_TRUE(f.store->get_user_by_token("alice-phone").has_value());
}

TEST(AccessTokens, RefreshRotatesBothSecrets) {
    Fixture f;
    f.config.password_hash_cost = 10;
    f.store->create_user("@alice:test", hash_password("password", 10));

    AuthHandler handler(*f.store, *f.sync, f.config);

    // Log in asking for a refresh token.
    httplib::Request login_req;
    login_req.body = json{
        {"type", "m.login.password"},
        {"identifier", {{"type", "m.id.user"}, {"user", "alice"}}},
        {"password", "password"},
        {"refresh_token", true},
    }.dump();
    httplib::Response login_res;
    handler.handle_login(login_req, login_res);
    ASSERT_TRUE(IsOk(login_res));
    auto login_body = json::parse(login_res.body);
    ASSERT_TRUE(login_body.contains("refresh_token"));
    EXPECT_GT(login_body.value("expires_in_ms", int64_t{0}), 0);
    const auto old_access = login_body.value("access_token", "");
    const auto old_refresh = login_body.value("refresh_token", "");
    ASSERT_TRUE(f.store->get_user_by_token(old_access).has_value());

    auto res = call(handler, &AuthHandler::handle_refresh, "/_matrix/client/v3/refresh", "",
                    json{{"refresh_token", old_refresh}}.dump());
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    const auto new_access = body.value("access_token", "");
    const auto new_refresh = body.value("refresh_token", "");
    EXPECT_NE(new_access, old_access);
    EXPECT_NE(new_refresh, old_refresh);

    EXPECT_TRUE(f.store->get_user_by_token(new_access).has_value());
    // Rotation: the old pair dies with the refresh.
    EXPECT_FALSE(f.store->get_user_by_token(old_access).has_value());
    auto reused = call(handler, &AuthHandler::handle_refresh, "/_matrix/client/v3/refresh", "",
                       json{{"refresh_token", old_refresh}}.dump());
    EXPECT_EQ(reused.status, 401);
}

TEST(AccessTokens, LoginWithoutAskingForRefreshGetsNoRefreshToken) {
    Fixture f;
    f.config.password_hash_cost = 10;
    f.store->create_user("@alice:test", hash_password("password", 10));

    AuthHandler handler(*f.store, *f.sync, f.config);
    httplib::Request req;
    req.body = json{
        {"type", "m.login.password"},
        {"identifier", {{"type", "m.id.user"}, {"user", "alice"}}},
        {"password", "password"},
    }.dump();
    httplib::Response res;
    handler.handle_login(req, res);
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    // Pre-refresh clients must keep working unchanged.
    EXPECT_FALSE(body.contains("refresh_token"));
    EXPECT_TRUE(f.store->get_user_by_token(body.value("access_token", "")).has_value());
}

// ── Message edits are reconciled server-side, not left to client goodwill ──

namespace {

struct EditFixture : Fixture {
    std::string alice;
    std::string room;
    std::unique_ptr<EventHandler> events;

    EditFixture() {
        alice = add_user("alice");
        room = generate_room_id("test");
        store->create_room(room, alice);
        store->set_membership(room, alice, "join");
        events = std::make_unique<EventHandler>(*store, *sync, config);
    }

    std::string send(const std::string& body, const std::string& txn) {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + room + "/send/m.room.message/" + txn,
                                "token-alice",
                                json{{"msgtype", "m.text"}, {"body", body}}.dump());
        events->handle_send_event(req, res);
        EXPECT_TRUE(IsOk(res)) << res.body;
        return json::parse(res.body).value("event_id", "");
    }

    // Exactly the payload the desktop client sends (MatrixClient::editMessage):
    // "* " fallback body plus the authoritative m.new_content.
    httplib::Response edit(const std::string& target, const std::string& new_body,
                           const std::string& txn, const std::string& token = "token-alice") {
        json content = {
            {"msgtype", "m.text"},
            {"body", "* " + new_body},
            {"m.new_content", {{"msgtype", "m.text"}, {"body", new_body}}},
            {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}},
        };
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + room + "/send/m.room.message/" + txn,
                                token, content.dump());
        events->handle_send_event(req, res);
        return res;
    }

    std::optional<RoomEvent> from_messages(const std::string& event_id) {
        auto [chunk, _] = store->get_room_events_paginated(room, 100, "b");
        for (const auto& ev : chunk) {
            if (ev.event_id == event_id) return ev;
        }
        return std::nullopt;
    }
};

} // namespace

// The server validated authorship, stored the edit as a sibling event, and then
// never reconciled: /messages kept returning the pre-edit text forever, so edits
// were real only for clients that chose to apply them.
TEST(MessageEdits, MessagesReturnsTheEditedContent) {
    EditFixture f;
    auto original = f.send("first draft", "t1");
    auto res = f.edit(original, "corrected text", "t2");
    ASSERT_TRUE(IsOk(res)) << res.body;
    auto replacement = json::parse(res.body).value("event_id", "");

    auto seen = f.from_messages(original);
    ASSERT_TRUE(seen.has_value());
    EXPECT_EQ(seen->content.data.value("body", ""), "corrected text")
        << "/messages still serves the pre-edit text";
    // The original keeps its identity: same event id, same sender, same type.
    EXPECT_EQ(seen->event_id, original);
    EXPECT_EQ(seen->sender, f.alice);

    // The replacement stays discoverable, spec-shaped, and the pristine text is
    // still available for rendering edit history.
    ASSERT_TRUE(seen->unsigned_data.has_value());
    const auto& u = seen->unsigned_data->data;
    ASSERT_TRUE(u.contains("m.relations"));
    EXPECT_EQ(u["m.relations"]["m.replace"].value("event_id", ""), replacement);
    EXPECT_EQ(u["m.relations"]["m.replace"].value("sender", ""), f.alice);
    EXPECT_EQ(u["bsfchat.original_content"].value("body", ""), "first draft");

    // And it is also still an ordinary timeline event.
    EXPECT_TRUE(f.from_messages(replacement).has_value());
    // Direct single-event reads agree with the paginated ones.
    auto by_id = f.store->get_event_by_id(original);
    ASSERT_TRUE(by_id.has_value());
    EXPECT_EQ(by_id->content.data.value("body", ""), "corrected text");
}

TEST(MessageEdits, LatestEditWinsAndPaginationStaysConsistent) {
    EditFixture f;
    auto original = f.send("v1", "t1");
    ASSERT_TRUE(IsOk(f.edit(original, "v2", "t2")));
    ASSERT_TRUE(IsOk(f.edit(original, "v3", "t3")));

    auto seen = f.from_messages(original);
    ASSERT_TRUE(seen.has_value());
    EXPECT_EQ(seen->content.data.value("body", ""), "v3");
    EXPECT_EQ(seen->unsigned_data->data["bsfchat.original_content"].value("body", ""), "v1");

    // Reconciliation must not depend on which page the event lands on: walk the
    // room one event per page and check every page agrees.
    std::optional<std::string> from;
    bool found = false;
    for (int page = 0; page < 10; ++page) {
        auto [chunk, next] = f.store->get_room_events_paginated(f.room, 1, "b", from);
        for (const auto& ev : chunk) {
            if (ev.event_id != original) continue;
            found = true;
            EXPECT_EQ(ev.content.data.value("body", ""), "v3") << "page " << page;
        }
        if (!next) break;
        from = "s" + std::to_string(*next);
    }
    EXPECT_TRUE(found);
}

// An edit aimed at a previous edit must still land on the original, or the
// second edit would be invisible.
TEST(MessageEdits, EditOfAnEditResolvesToTheOriginal) {
    EditFixture f;
    auto original = f.send("v1", "t1");
    auto first_res = f.edit(original, "v2", "t2");
    ASSERT_TRUE(IsOk(first_res));
    auto first_edit = json::parse(first_res.body).value("event_id", "");

    ASSERT_TRUE(IsOk(f.edit(first_edit, "v3", "t3")));

    auto seen = f.from_messages(original);
    ASSERT_TRUE(seen.has_value());
    EXPECT_EQ(seen->content.data.value("body", ""), "v3");
}

TEST(MessageEdits, SyncDeliversEditedContentForAnOldMessage) {
    EditFixture f;
    auto original = f.send("original wording", "t1");

    // A client that has been offline: its position predates nothing relevant,
    // it just does an initial sync.
    int64_t before_edit = f.store->get_current_stream_position();
    ASSERT_TRUE(IsOk(f.edit(original, "edited wording", "t2")));

    auto initial = f.sync->handle_sync(f.alice, "", 0);
    ASSERT_TRUE(initial.rooms.join.count(f.room));
    bool saw_original = false;
    for (const auto& ev : initial.rooms.join[f.room].timeline.events) {
        if (ev.event_id != original) continue;
        saw_original = true;
        EXPECT_EQ(ev.content.data.value("body", ""), "edited wording")
            << "/sync served the pre-edit text";
        EXPECT_TRUE(ev.unsigned_data.has_value());
    }
    EXPECT_TRUE(saw_original);

    // An incremental sync from before the edit delivers the replacement event,
    // which is what lets a connected client update a message it already holds.
    auto incremental = f.sync->handle_sync(f.alice, "s" + std::to_string(before_edit), 0);
    ASSERT_TRUE(incremental.rooms.join.count(f.room));
    bool saw_replacement = false;
    for (const auto& ev : incremental.rooms.join[f.room].timeline.events) {
        const auto& rel = ev.content.data.value("m.relates_to", json::object());
        if (rel.value("rel_type", "") == "m.replace" &&
            rel.value("event_id", "") == original) {
            saw_replacement = true;
            EXPECT_EQ(ev.content.data["m.new_content"].value("body", ""), "edited wording");
        }
    }
    EXPECT_TRUE(saw_replacement);
}

// An edit is an ordinary send, so the txnId idempotency added earlier applies:
// a retry must not produce a second replacement.
TEST(MessageEdits, RetriedEditIsIdempotent) {
    EditFixture f;
    auto original = f.send("v1", "t1");
    auto first = f.edit(original, "v2", "edit-txn");
    ASSERT_TRUE(IsOk(first));
    auto retry = f.edit(original, "v2", "edit-txn");
    ASSERT_TRUE(IsOk(retry));
    EXPECT_EQ(json::parse(first.body).at("event_id"), json::parse(retry.body).at("event_id"));

    auto [chunk, _] = f.store->get_room_events_paginated(f.room, 100, "b");
    int replacements = 0;
    for (const auto& ev : chunk) {
        const auto& rel = ev.content.data.value("m.relates_to", json::object());
        if (rel.value("rel_type", "") == "m.replace") ++replacements;
    }
    EXPECT_EQ(replacements, 1);
    EXPECT_EQ(f.from_messages(original)->content.data.value("body", ""), "v2");
}

TEST(MessageEdits, OnlyTheAuthorCanEdit) {
    EditFixture f;
    f.add_user("bob");
    f.store->set_membership(f.room, "@bob:test", "join");
    auto original = f.send("mine", "t1");

    auto res = f.edit(original, "hijacked", "t2", "token-bob");
    EXPECT_EQ(res.status, 403);
    EXPECT_EQ(f.from_messages(original)->content.data.value("body", ""), "mine");
}

// Consistency with the redaction fix: deleting a message must not leave an edit
// behind that resolves the content back into view.
TEST(MessageEdits, RedactedMessageStaysRedactedAndCannotBeEdited) {
    EditFixture f;
    auto original = f.send("secret", "t1");
    ASSERT_TRUE(IsOk(f.edit(original, "still secret", "t2")));

    httplib::Response redact_res;
    auto redact_req = make_request(
        "/_matrix/client/v3/rooms/" + f.room + "/redact/" + original + "/rtxn", "token-alice", "{}");
    f.events->handle_redact(redact_req, redact_res);
    ASSERT_TRUE(IsOk(redact_res));

    auto seen = f.from_messages(original);
    ASSERT_TRUE(seen.has_value());
    EXPECT_EQ(seen->content.data.value("body", ""), "")
        << "an edit resurrected redacted content";
    EXPECT_FALSE(f.store->get_edit_pointer(original).has_value());

    // And a new edit cannot bring it back either.
    auto res = f.edit(original, "resurrected", "t3");
    EXPECT_EQ(res.status, 404);
    EXPECT_EQ(f.from_messages(original)->content.data.value("body", ""), "");
}

// Redacting the edit itself rolls the message back to the newest surviving
// version rather than leaving a dangling pointer.
TEST(MessageEdits, RedactingAnEditRollsBackToThePreviousVersion) {
    EditFixture f;
    auto original = f.send("v1", "t1");
    auto e2 = json::parse(f.edit(original, "v2", "t2").body).value("event_id", "");
    auto e3 = json::parse(f.edit(original, "v3", "t3").body).value("event_id", "");
    ASSERT_EQ(f.from_messages(original)->content.data.value("body", ""), "v3");

    httplib::Response res3;
    auto req3 = make_request(
        "/_matrix/client/v3/rooms/" + f.room + "/redact/" + e3 + "/r1", "token-alice", "{}");
    f.events->handle_redact(req3, res3);
    ASSERT_TRUE(IsOk(res3));
    EXPECT_EQ(f.from_messages(original)->content.data.value("body", ""), "v2");

    httplib::Response res2;
    auto req2 = make_request(
        "/_matrix/client/v3/rooms/" + f.room + "/redact/" + e2 + "/r2", "token-alice", "{}");
    f.events->handle_redact(req2, res2);
    ASSERT_TRUE(IsOk(res2));
    auto rolled_back = f.from_messages(original);
    EXPECT_EQ(rolled_back->content.data.value("body", ""), "v1");
    EXPECT_FALSE(rolled_back->unsigned_data.has_value());
}

// An edited reply must not lose what it was replying to: m.new_content carries
// no relation of its own, so the original's has to survive reconciliation.
TEST(MessageEdits, EditingAReplyKeepsTheReplyPointer) {
    EditFixture f;
    auto parent = f.send("question", "t1");

    json reply = {
        {"msgtype", "m.text"},
        {"body", "answer"},
        {"m.relates_to", {{"m.in_reply_to", {{"event_id", parent}}}}},
    };
    httplib::Response send_res;
    auto send_req = make_request(
        "/_matrix/client/v3/rooms/" + f.room + "/send/m.room.message/t2", "token-alice",
        reply.dump());
    f.events->handle_send_event(send_req, send_res);
    ASSERT_TRUE(IsOk(send_res));
    auto reply_id = json::parse(send_res.body).value("event_id", "");

    ASSERT_TRUE(IsOk(f.edit(reply_id, "better answer", "t3")));

    auto seen = f.from_messages(reply_id);
    ASSERT_TRUE(seen.has_value());
    EXPECT_EQ(seen->content.data.value("body", ""), "better answer");
    ASSERT_TRUE(seen->content.data.contains("m.relates_to"));
    EXPECT_EQ(seen->content.data["m.relates_to"]["m.in_reply_to"].value("event_id", ""), parent);
}

// ── Migrating a PRE-EXISTING database (v6 -> v8) ───────────────────────────

namespace {

// A database at schema v6 — i.e. one written by yesterday's build: plaintext
// access tokens with no expiry, and an m.replace edit that the server accepted
// but never reconciled.
void create_v6_database(const std::string& path) {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
    const char* schema = R"(
        CREATE TABLE users (user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
            display_name TEXT, avatar_url TEXT,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));
        CREATE TABLE access_tokens (token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000));
        CREATE TABLE rooms (room_id TEXT PRIMARY KEY, creator TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            is_direct INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE room_members (room_id TEXT NOT NULL, user_id TEXT NOT NULL,
            membership TEXT NOT NULL DEFAULT 'join',
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (room_id, user_id));
        CREATE TABLE events (event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL,
            sender TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT,
            content TEXT NOT NULL, origin_server_ts INTEGER NOT NULL,
            stream_position INTEGER NOT NULL UNIQUE, redacted_by TEXT);
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
        PRAGMA user_version = 6;

        INSERT INTO users (user_id, password_hash) VALUES
            ('@alice:test','$pbkdf2$12$aa$bb'), ('@bob:test','');

        -- Two live sessions, plus one belonging to a user that no longer exists.
        INSERT INTO access_tokens (token, user_id, device_id) VALUES
            ('alice-plaintext-token','@alice:test','PHONE'),
            ('bob-plaintext-token','@bob:test','LAPTOP'),
            ('orphan-token','@ghost:test','GONE');

        INSERT INTO rooms (room_id, creator) VALUES ('!chan:test','@alice:test');
        INSERT INTO room_members (room_id,user_id,membership) VALUES
            ('!chan:test','@alice:test','join'),
            ('!chan:test','@bob:test','join');
        INSERT INTO events VALUES
            ('$name','!chan:test','@alice:test','m.room.name','',
             '{"name":"general"}',1,1,NULL),
            ('$orig','!chan:test','@alice:test','m.room.message',NULL,
             '{"msgtype":"m.text","body":"typo heer"}',2,2,NULL),
            ('$edit1','!chan:test','@alice:test','m.room.message',NULL,
             '{"msgtype":"m.text","body":"* typo here","m.new_content":{"msgtype":"m.text","body":"typo here"},"m.relates_to":{"rel_type":"m.replace","event_id":"$orig"}}',3,3,NULL),
            ('$edit2','!chan:test','@alice:test','m.room.message',NULL,
             '{"msgtype":"m.text","body":"* no typo now","m.new_content":{"msgtype":"m.text","body":"no typo now"},"m.relates_to":{"rel_type":"m.replace","event_id":"$orig"}}',4,4,NULL),
            ('$plain','!chan:test','@bob:test','m.room.message',NULL,
             '{"msgtype":"m.text","body":"never edited"}',5,5,NULL);
        INSERT INTO server_meta (key,value) VALUES ('next_stream_position','6');
    )";
    char* err = nullptr;
    ASSERT_EQ(sqlite3_exec(db, schema, nullptr, nullptr, &err), SQLITE_OK)
        << (err ? err : "unknown");
    sqlite3_close(db);
}

} // namespace

// Hashing tokens at rest must not log the whole instance out: we still hold the
// plaintext at migration time, so each existing session is hashed in place.
TEST(V6Upgrade, PlaintextTokensAreHashedWithoutLoggingAnyoneOut) {
    auto path = temp_db_path("v6tokens");
    std::filesystem::remove(path);
    create_v6_database(path);
    ASSERT_EQ(get_schema_version_for_test(path), 6);

    {
        SqliteStore store(path);
        store.initialize();
        EXPECT_EQ(get_schema_version_for_test(path), kTargetSchemaVersion);

        // Sessions that existed before the upgrade still authenticate.
        auto alice = store.get_user_by_token("alice-plaintext-token");
        ASSERT_TRUE(alice.has_value()) << "existing session was invalidated by the migration";
        EXPECT_EQ(*alice, "@alice:test");
        EXPECT_TRUE(store.get_user_by_token("bob-plaintext-token").has_value());
        // A token whose user is gone is dropped rather than aborting the run.
        EXPECT_FALSE(store.get_user_by_token("orphan-token").has_value());

        // They now have an expiry, and they are no longer readable at rest.
        auto expiry = store.get_token_expiry("alice-plaintext-token");
        ASSERT_TRUE(expiry.has_value());
        EXPECT_GT(*expiry, now_ms());

        // Everything else survived.
        EXPECT_TRUE(store.is_room_member("!chan:test", "@bob:test"));
        EXPECT_EQ(*store.get_password_hash("@alice:test"), "$pbkdf2$12$aa$bb");
        EXPECT_TRUE(store.get_event_by_id("$plain").has_value());
    }

    EXPECT_FALSE(raw_query_text(path,
        "SELECT token_hash FROM access_tokens WHERE token_hash = 'alice-plaintext-token'")
            .has_value())
        << "plaintext token survived the migration";
    EXPECT_TRUE(raw_query_text(path,
        "SELECT user_id FROM access_tokens WHERE token_hash = '" +
        hash_access_token("alice-plaintext-token") + "'").has_value());

    // Reopening must not re-run anything.
    {
        SqliteStore store(path);
        store.initialize();
        EXPECT_TRUE(store.get_user_by_token("alice-plaintext-token").has_value());
        EXPECT_EQ(get_schema_version_for_test(path), kTargetSchemaVersion);
    }

    std::filesystem::remove(path);
}

// Edits accepted before this release were advisory only. The migration
// backfills them, newest winning, so history stops lying.
TEST(V6Upgrade, PreExistingEditsBecomeEffective) {
    auto path = temp_db_path("v6edits");
    std::filesystem::remove(path);
    create_v6_database(path);

    {
        SqliteStore store(path);
        store.initialize();

        auto edited = store.get_event_by_id("$orig");
        ASSERT_TRUE(edited.has_value());
        EXPECT_EQ(edited->content.data.value("body", ""), "no typo now")
            << "historical edit is still invisible through the API";
        ASSERT_TRUE(edited->unsigned_data.has_value());
        EXPECT_EQ(edited->unsigned_data->data["m.relations"]["m.replace"].value("event_id", ""),
                  "$edit2");
        EXPECT_EQ(edited->unsigned_data->data["bsfchat.original_content"].value("body", ""),
                  "typo heer");

        // An unedited message is untouched and carries no bundle.
        auto plain = store.get_event_by_id("$plain");
        ASSERT_TRUE(plain.has_value());
        EXPECT_EQ(plain->content.data.value("body", ""), "never edited");
        EXPECT_FALSE(plain->unsigned_data.has_value());

        // The replacements themselves are still first-class events.
        EXPECT_TRUE(store.get_event_by_id("$edit1").has_value());
        EXPECT_TRUE(store.get_event_by_id("$edit2").has_value());
    }

    std::filesystem::remove(path);
}

// Now that tokens expire and can be revoked, a client has to be able to tell
// "you sent no token" from "your token is dead" — the latter is the only one it
// can fix by re-authenticating. Every handler used to answer M_MISSING_TOKEN
// for both.
TEST(AccessTokens, MissingAndInvalidTokensAreDistinguishable) {
    Fixture f;
    f.add_user("alice");
    AuthHandler handler(*f.store, *f.sync, f.config);

    httplib::Request no_header;
    httplib::Response no_header_res;
    handler.handle_whoami(no_header, no_header_res);
    EXPECT_EQ(no_header_res.status, 401);
    EXPECT_EQ(json::parse(no_header_res.body).value("errcode", ""), "M_MISSING_TOKEN");

    auto dead = call(handler, &AuthHandler::handle_whoami, "/_matrix/client/v3/account/whoami",
                     "revoked-or-expired");
    EXPECT_EQ(dead.status, 401);
    EXPECT_EQ(json::parse(dead.body).value("errcode", ""), "M_UNKNOWN_TOKEN");

    EXPECT_EQ(auth_error("").errcode, "M_MISSING_TOKEN");
    EXPECT_EQ(auth_error("Bearer something").errcode, "M_UNKNOWN_TOKEN");
}

// ── P6 / audit-data B5, B8, B15: data at rest ─────────────────────────────
//
// The findings behind these: the database file was created at the process
// umask (0644 in the shipped container) and never chmod'ed by anything in the
// server, the image or deploy/setup.sh; and SQLite was left at its default
// `secure_delete=off` with no VACUUM anywhere, so deletes that exist
// specifically to destroy secrets — migration v7's plaintext access-token
// table, redaction of message bodies, the call-signalling prune that exists to
// remove participants' IP addresses — only unlinked those bytes from the
// b-tree and left them in the file.

namespace {

// A unique temp directory per test, removed on scope exit. The store is opened
// on a real path rather than ":memory:" because both behaviours under test are
// properties of the FILE.
struct TempDb {
    std::filesystem::path dir;
    std::filesystem::path db;

    TempDb() {
        dir = std::filesystem::temp_directory_path() /
              ("bsfchat-p6-" + std::to_string(::getpid()) + "-" +
               std::to_string(reinterpret_cast<uintptr_t>(this)));
        std::filesystem::create_directories(dir);
        db = dir / "bsfchat.db";
    }
    ~TempDb() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

// The whole file as bytes. This is the attacker's view — `strings bsfchat.db`
// on a stolen volume or in a backup — not a query, which is the point: a
// logically deleted row is invisible to SQL and perfectly visible here.
std::string read_file_bytes(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::optional<std::string> read_meta(const std::filesystem::path& db, const std::string& key) {
    sqlite3* raw = nullptr;
    if (sqlite3_open(db.c_str(), &raw) != SQLITE_OK) return std::nullopt;
    std::optional<std::string> out;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(raw, "SELECT value FROM server_meta WHERE key = ?", -1, &stmt,
                           nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            out = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(raw);
    return out;
}

} // namespace

TEST(DataAtRest, DatabaseFileIsNotReadableByOtherLocalUsers) {
    TempDb t;
    {
        SqliteStore store(t.db.string());
        store.initialize();
    }

    // -wal and -shm are removed by the clean close above, so only the main
    // file is asserted on here; the open path tightens all three.
    ASSERT_TRUE(std::filesystem::exists(t.db));
    // Before the fix this was 0644 under the default umask: every message
    // body, the second copy of each body in the search index, queued push
    // payloads and the audit log, readable by any local account.
    const auto mode = std::filesystem::status(t.db).permissions();
    EXPECT_EQ(mode & (std::filesystem::perms::group_all | std::filesystem::perms::others_all),
              std::filesystem::perms::none);
}

TEST(DataAtRest, DeletedContentIsOverwrittenNotJustUnlinked) {
    TempDb t;
    // Distinctive enough that a match cannot be anything but our own row.
    const std::string canary = "CANARY-8f31d2a7-secure-delete-regression";

    {
        SqliteStore store(t.db.string());
        store.initialize();
        store.create_user("@alice:test", "hash");
        store.create_room("!room:test", "@alice:test");
        for (int i = 0; i < 64; ++i) {
            json content{{"msgtype", "m.text"}, {"body", canary + "-" + std::to_string(i)}};
            store.insert_event("$ev" + std::to_string(i), "!room:test", "@alice:test",
                               "m.room.message", std::nullopt, content.dump(), now_ms());
        }
        // Deleting the room is the same class of operation as the signalling
        // prune and the v7 token-table drop: rows go away, pages go to the
        // freelist.
        store.delete_room("!room:test");
    }

    const std::string bytes = read_file_bytes(t.db);
    EXPECT_EQ(bytes.find(canary), std::string::npos)
        << "deleted message bodies are still recoverable from the database file";
}

TEST(DataAtRest, FreshDatabaseRecordsTheVacuumMarkerWithoutVacuuming) {
    TempDb t;
    {
        SqliteStore store(t.db.string());
        store.initialize();
    }
    // A database this build created has never held pre-hardening deletes, so
    // the one-time VACUUM is pointless work. It must still be marked done, or
    // it is reconsidered on every single start.
    EXPECT_EQ(read_meta(t.db, "maintenance.freelist_vacuumed"), std::optional<std::string>("1"));
}

TEST(DataAtRest, ExistingDatabaseIsVacuumedOnceAndOnlyOnce) {
    TempDb t;

    // Build a database, put content in it, then delete the content and clear
    // the marker — i.e. exactly the state of a deployment upgrading to this
    // build: a populated file with a fat freelist full of deleted secrets.
    {
        SqliteStore store(t.db.string());
        store.initialize();
        store.create_user("@alice:test", "hash");
        store.create_room("!room:test", "@alice:test");
        for (int i = 0; i < 400; ++i) {
            json content{{"msgtype", "m.text"}, {"body", std::string(400, 'x')}};
            store.insert_event("$ev" + std::to_string(i), "!room:test", "@alice:test",
                               "m.room.message", std::nullopt, content.dump(), now_ms());
        }
        store.delete_room("!room:test");
    }
    {
        sqlite3* raw = nullptr;
        ASSERT_EQ(sqlite3_open(t.db.c_str(), &raw), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(raw,
                               "DELETE FROM server_meta WHERE key = 'maintenance.freelist_vacuumed'",
                               nullptr, nullptr, nullptr),
                  SQLITE_OK);
        sqlite3_close(raw);
    }

    const auto size_before = std::filesystem::file_size(t.db);
    {
        SqliteStore store(t.db.string());
        store.initialize();
    }
    EXPECT_EQ(read_meta(t.db, "maintenance.freelist_vacuumed"), std::optional<std::string>("1"));
    // VACUUM rewrites the file from the live pages only, so the freelist those
    // 400 deleted rows left behind is returned to the filesystem.
    EXPECT_LT(std::filesystem::file_size(t.db), size_before);

    // And the mode survives the rewrite: VACUUM creates a new file and moves
    // it into place, which is the obvious way to silently undo the chmod.
    EXPECT_EQ(std::filesystem::status(t.db).permissions() &
                  (std::filesystem::perms::group_all | std::filesystem::perms::others_all),
              std::filesystem::perms::none);

    // Second start must not VACUUM again — the marker is the whole mechanism.
    const auto size_after_first = std::filesystem::file_size(t.db);
    {
        SqliteStore store(t.db.string());
        store.initialize();
        store.create_user("@bob:test", "hash");
    }
    EXPECT_GE(std::filesystem::file_size(t.db), size_after_first);
}

TEST(ConfigValidation, HonoursButWarnsAboutADeployTemplateCostOf12) {
    // deploy/config/server.toml.template shipped `password_hash_cost = 12`
    // (4,096 PBKDF2 iterations) and the only startup warning fired BELOW 12,
    // so the weakest value anyone would actually deploy passed silently by
    // exactly one step. 12 is still honoured — the login CPU bill is the
    // operator's to spend — but it is no longer endorsed.
    Config cfg = Config::defaults();
    cfg.password_hash_cost = 12;
    Config::validate(cfg);
    EXPECT_EQ(cfg.password_hash_cost, 12);
    EXPECT_LT(cfg.password_hash_cost, kRecommendedPasswordHashCost);
}

TEST(ConfigValidation, DefaultPasswordCostIsTheRecommendedOne) {
    EXPECT_EQ(Config::defaults().password_hash_cost, kRecommendedPasswordHashCost);
    EXPECT_EQ(kRecommendedPasswordHashCost, 19);
}
