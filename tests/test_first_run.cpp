// What a brand-new deployment hands its first user, and — at least as
// important — what it must never hand a deployment that is already in use.
//
// THE INCIDENT. A freshly installed server on uat.bsfchat.com reported
// users = 1, rooms = 0, events = 0 after its first account signed in
// successfully. The startup log said "Seeded default server roles" and "Running
// auto-join backfill...", so the first-run machinery ran; it just had nothing to
// act on. backfill_auto_join walks list_public_rooms() × list_all_users() and
// returns immediately when either is empty, and nothing anywhere on the server
// creates the first room. The only room-creating code is an HTTP handler.
//
// That left the first user in an empty shell, AND unable to leave it — the part
// that makes this a deadlock rather than a blank page. Server-side they hold
// Admin (bootstrap_roles assigns it to the oldest account), so POST /createRoom
// would have been allowed. But a client learns roles from bsfchat.server.roles
// state events in /sync, write_server_scoped_state can only mirror those into a
// room, and pick_server_state_mirror_room correctly answers "" when there are
// no rooms. So the event was never delivered, the client computed its own
// permissions as zero, and every create-channel affordance stayed hidden.
//
// The properties under test:
//   1. A server with an empty `rooms` table creates #general and General Voice,
//      each carrying the state a channel made through the API carries.
//   2. It happens once. A second boot creates nothing further.
//   3. A server with ANY room — a channel, a category, or a single DM — creates
//      nothing, and is marked so that deleting every channel later does not
//      resurrect them. This is the production guard.
//   4. The config switch suppresses creation and is likewise recorded, so
//      enabling it later on a server that has since been emptied still creates
//      nothing.
//   5. The deadlock is closed end-to-end: after the real Server::start()
//      sequence, a role document reaches a room, which is the only channel by
//      which a client can be told it is an admin.
//   6. A deployment that is already empty-but-deployed (the UAT shape: one
//      account, no rooms) gets the channels on upgrade and its existing user is
//      joined to them.

#include <gtest/gtest.h>

#include "auth/AutoJoin.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "core/FirstRun.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

constexpr const char* kMarker = "bootstrap.default_channels";

struct Fixture {
    std::string db_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;

    explicit Fixture(const std::string& name) {
        db_path = (std::filesystem::temp_directory_path() /
                   ("bsfchat-firstrun-" + name + "-" + std::to_string(::getpid()) + ".db"))
                      .string();
        remove_db();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db();
    }

    void remove_db() {
        std::filesystem::remove(db_path);
        std::filesystem::remove(db_path + "-wal");
        std::filesystem::remove(db_path + "-shm");
    }

    // The three calls Server::start() makes, in the order it makes them.
    void boot() {
        bootstrap_default_channels(*store, *sync, config);
        backfill_auto_join(*store, *sync, config);
        bootstrap_roles(*store, *sync, config);
    }

    std::string add_room(const std::string& type, bool is_direct = false) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, "@owner:test", is_direct);
        store->insert_event(generate_event_id("test"), room_id, "@owner:test",
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", type}}.dump(), 1000);
        return room_id;
    }

    std::string name_of(const std::string& room_id) {
        auto ev = store->get_state_event(room_id, std::string(event_type::kRoomName), "");
        return ev ? ev->content.data.value("name", "") : std::string();
    }

    std::string type_of(const std::string& room_id) {
        auto ev = store->get_state_event(room_id, std::string(event_type::kRoomType), "");
        return ev ? ev->content.data.value("type", "") : std::string();
    }
};

} // namespace

// Property 1. The channels exist, and they are real channels rather than rows
// in the rooms table: public join rules is what puts them in
// list_public_rooms(), which is what every auto-join sweep walks, and
// bsfchat.room.type is what makes the client draw one as a channel at all.
TEST(FirstRun, ANewServerCreatesAGeneralTextChannelAndAVoiceChannel) {
    Fixture f("creates");
    ASSERT_FALSE(f.store->has_any_room());

    bootstrap_default_channels(*f.store, *f.sync, f.config);

    auto rooms = f.store->list_public_rooms();
    ASSERT_EQ(rooms.size(), 2u);

    std::string text_room, voice_room;
    for (const auto& id : rooms) {
        if (f.type_of(id) == room_type::kText) text_room = id;
        if (f.type_of(id) == room_type::kVoice) voice_room = id;
    }
    ASSERT_FALSE(text_room.empty()) << "no text channel was created";
    ASSERT_FALSE(voice_room.empty()) << "no voice channel was created";

    EXPECT_EQ(f.name_of(text_room), "general");
    EXPECT_FALSE(f.name_of(voice_room).empty());

    // The text channel says something, because its topic is the only prose the
    // first user is handed.
    auto topic = f.store->get_state_event(text_room, std::string(event_type::kRoomTopic), "");
    ASSERT_TRUE(topic.has_value());
    EXPECT_FALSE(topic->content.data.value("topic", "").empty());

    // The voice channel is actually voice-capable. Without m.room.voice the
    // client draws a speaker icon on a room nobody can call in.
    auto voice = f.store->get_state_event(voice_room, std::string(event_type::kRoomVoice), "");
    ASSERT_TRUE(voice.has_value());
    EXPECT_TRUE(voice->content.data.value("enabled", false));

    // Both are public and neither is a DM — list_public_rooms() enforces both,
    // and it returned them, so state this as the reason rather than re-deriving
    // it.
    for (const auto& id : rooms) {
        auto jr = f.store->get_state_event(id, std::string(event_type::kRoomJoinRules), "");
        ASSERT_TRUE(jr.has_value());
        EXPECT_EQ(jr->content.data.value("join_rule", ""), join_rule::kPublic);
    }

    // No permission overrides. A default channel must get its visibility from
    // @everyone like any other channel — writing an override here would make
    // "is a member" and "may see it" diverge on the very first room on the
    // server (see auth/RoomVisibility.h).
    for (const auto& id : rooms) {
        EXPECT_FALSE(
            f.store->get_state_event(id, std::string(event_type::kChannelPermissions), "everyone")
                .has_value());
    }
}

// Property 2. Boot is not a channel factory.
TEST(FirstRun, ASecondBootCreatesNothingFurther) {
    Fixture f("once");
    bootstrap_default_channels(*f.store, *f.sync, f.config);
    ASSERT_EQ(f.store->list_public_rooms().size(), 2u);

    bootstrap_default_channels(*f.store, *f.sync, f.config);
    bootstrap_default_channels(*f.store, *f.sync, f.config);
    EXPECT_EQ(f.store->list_public_rooms().size(), 2u);
    EXPECT_EQ(f.store->get_meta(kMarker).value_or(""), "created");
}

// Property 3, and the reason this file exists. Production is live, has real
// users, and receives this build like any other.
TEST(FirstRun, AServerThatAlreadyHasAChannelGetsNothing) {
    Fixture f("established");
    auto existing = f.add_room(std::string(room_type::kText));

    bootstrap_default_channels(*f.store, *f.sync, f.config);

    auto rooms = f.store->list_all_non_category_rooms();
    ASSERT_EQ(rooms.size(), 1u);
    EXPECT_EQ(rooms.front(), existing);
}

// A category is a room an admin arranged a sidebar with, so it is evidence of
// use even though it is not a channel. list_public_rooms() excludes categories,
// so a narrower guard would have read this server as new.
TEST(FirstRun, AServerWhoseOnlyRoomIsACategoryGetsNothing) {
    Fixture f("category-only");
    f.add_room(std::string(room_type::kCategory));
    ASSERT_TRUE(f.store->list_public_rooms().empty())
        << "this test is pointless unless the narrower predicate would have been fooled";

    bootstrap_default_channels(*f.store, *f.sync, f.config);

    EXPECT_TRUE(f.store->list_public_rooms().empty());
    EXPECT_EQ(f.store->get_meta(kMarker).value_or(""), "skipped-existing-rooms");
}

// Two people talking is a used server. list_public_rooms() excludes direct
// rooms for good reasons of its own, which is exactly why it is the wrong
// question to ask here.
TEST(FirstRun, AServerWhoseOnlyRoomIsADirectMessageGetsNothing) {
    Fixture f("dm-only");
    f.add_room(std::string(room_type::kText), /*is_direct=*/true);
    ASSERT_TRUE(f.store->list_public_rooms().empty());

    bootstrap_default_channels(*f.store, *f.sync, f.config);

    EXPECT_TRUE(f.store->list_public_rooms().empty());
}

// The half of the guard a room count alone cannot give. An admin who deletes
// every channel on an established server has made a decision, and the next
// restart must not overrule it — which means the "is this server new?" question
// has to be asked once, when this build first runs, and never again.
TEST(FirstRun, AnEstablishedServerEmptiedLaterDoesNotGetChannelsBack) {
    Fixture f("emptied");
    auto existing = f.add_room(std::string(room_type::kText));
    bootstrap_default_channels(*f.store, *f.sync, f.config);
    ASSERT_EQ(f.store->get_meta(kMarker).value_or(""), "skipped-existing-rooms");

    f.store->delete_room(existing);
    ASSERT_FALSE(f.store->has_any_room()) << "the server is now indistinguishable from a new one";

    bootstrap_default_channels(*f.store, *f.sync, f.config);

    EXPECT_TRUE(f.store->list_public_rooms().empty())
        << "a deliberate deletion was undone by a restart";
}

// Property 4. Off means off — and the decision is still recorded, so switching
// it on later is not a way to get channels invented on an old server.
TEST(FirstRun, TheConfigSwitchSuppressesCreationAndTheDecisionSticks) {
    Fixture f("disabled");
    f.config.create_default_channels = false;

    bootstrap_default_channels(*f.store, *f.sync, f.config);
    EXPECT_TRUE(f.store->list_public_rooms().empty());
    EXPECT_EQ(f.store->get_meta(kMarker).value_or(""), "disabled");

    f.config.create_default_channels = true;
    bootstrap_default_channels(*f.store, *f.sync, f.config);
    EXPECT_TRUE(f.store->list_public_rooms().empty());
}

// Property 5. The deadlock, stated as the thing the client actually needs.
//
// A role document that exists only in the server_state table is invisible to
// every client on the instance: the client reads bsfchat.server.roles from
// /sync and from nowhere else. So "the first user is an admin" is only true in
// a way that matters once that event has been mirrored into a room the user is
// in — which is why creating the channels is ordered ahead of bootstrap_roles.
TEST(FirstRun, TheFirstAdminsRoleDocumentReachesARoomTheyAreIn) {
    Fixture f("deadlock");
    f.store->create_user("@first:test", "hash");

    f.boot();

    // Server-side truth, unchanged by this work: the oldest account is Admin.
    auto role_ids = f.store->get_member_role_ids("@first:test");
    ASSERT_FALSE(role_ids.empty());
    EXPECT_NE(std::find(role_ids.begin(), role_ids.end(),
                        std::string(permission::role_id::kAdmin)),
              role_ids.end());

    // The part that was missing. There is a mirror room, the role document is
    // in it as a state event, and the user is a member of that room — all three
    // are required for the event to arrive in their /sync.
    const auto mirror = pick_server_state_mirror_room(*f.store);
    ASSERT_FALSE(mirror.empty()) << "no room to deliver roles through";
    EXPECT_TRUE(
        f.store->get_state_event(mirror, std::string(event_type::kServerRoles), "").has_value());
    EXPECT_TRUE(
        f.store->get_state_event(mirror, std::string(event_type::kMemberRoles), "@first:test")
            .has_value());
    EXPECT_TRUE(f.store->is_room_member(mirror, "@first:test"));
}

// Property 6. The shape the UAT server was actually in: deployed, one account,
// zero rooms. It must be carried across the upgrade by a restart alone, without
// anybody re-registering — which is what ordering the creation before
// backfill_auto_join buys.
TEST(FirstRun, AnAlreadyDeployedButEmptyServerJoinsItsExistingUserOnUpgrade) {
    Fixture f("uat");
    f.store->create_user("@demo:test", "hash");
    ASSERT_TRUE(f.store->get_joined_rooms("@demo:test").empty());

    f.boot();

    auto joined = f.store->get_joined_rooms("@demo:test");
    EXPECT_EQ(joined.size(), 2u) << "the existing account was left outside the new channels";
}
