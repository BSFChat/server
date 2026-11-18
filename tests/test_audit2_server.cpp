// Server findings from docs/../AUDIT-2-2026-11-18 that are about what the
// server does on the user's behalf when access goes away:
//
//   V2-7  a kicked, banned or locked-out user stayed in the call 30-40 s
//         (nothing retracted their m.call.member row; only the reaper did).
//   S2-5  deleting a private channel named its room id to every member through
//         the 'deleted' departure, viewers or not.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "api/VoiceHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <memory>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

const std::string kRooms = "/_matrix/client/v3/rooms/";

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

struct Fixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<RoomHandler> rooms;
    std::unique_ptr<VoiceHandler> voice;
    std::string admin, mod, alice, bob, room;

    Fixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        seed_roles();
        rooms = std::make_unique<RoomHandler>(*store, *sync, config);
        voice = std::make_unique<VoiceHandler>(*store, *sync, config);

        admin = add_user("admin", std::string(permission::role_id::kAdmin));
        mod = add_user("mod", std::string(permission::role_id::kModerator));
        alice = add_user("alice");
        bob = add_user("bob");
        room = add_voice_channel(admin);
        for (const auto& u : {mod, alice, bob}) join(room, u);
    }

    void seed_roles() {
        ServerRolesContent c;
        const auto add = [&](std::string_view id, int position, permission::Flags flags) {
            ServerRole r;
            r.id = std::string(id);
            r.name = r.id;
            r.position = position;
            r.permissions = flags;
            c.roles.push_back(r);
        };
        add(permission::role_id::kEveryone, 0, permission::kEveryoneDefault);
        add(permission::role_id::kModerator, 10,
            permission::kEveryoneDefault | permission::kKickMembers | permission::kBanMembers |
                permission::kManageChannels);
        add(permission::role_id::kAdmin, 100, permission::kAllFlags);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart, const std::string& extra_role = "") {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        if (!extra_role.empty()) c.role_ids.push_back(extra_role);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    void join(const std::string& room_id, const std::string& user) {
        store->set_membership(room_id, user, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, user,
                            std::string(event_type::kRoomMember), user,
                            json{{"membership", membership::kJoin}}.dump(), 1001);
    }

    std::string add_voice_channel(const std::string& creator) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        join(room_id, creator);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "voice"}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomVoice), std::string(""),
                            json{{"enabled", true}, {"max_participants", 0}}.dump(), 1000);
        return room_id;
    }

    void override_directly(const std::string& room_id, const std::string& target,
                           permission::Flags deny) {
        ChannelPermissionOverride ov;
        ov.allow = 0;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target, j.dump(), 1002);
    }

    httplib::Response voice_join(const std::string& room_id, const std::string& who) {
        httplib::Request req;
        req.path = kRooms + room_id + "/voice/join";
        req.set_header("Authorization", "Bearer token-" + who);
        httplib::Response res;
        voice->handle_voice_join(req, res);
        return res;
    }

    template <typename Method>
    httplib::Response call(Method method, const std::string& path, const std::string& who,
                           const std::string& body = "") {
        httplib::Request req;
        req.path = path;
        req.body = body;
        req.set_header("Authorization", "Bearer token-" + who);
        httplib::Response res;
        ((*rooms).*method)(req, res);
        return res;
    }

    bool in_call(const std::string& room_id, const std::string& user) {
        auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), user);
        return ev && ev->content.data.value("active", false);
    }
};

} // namespace

// ── V2-7: retraction on removal ───────────────────────────────────────────

TEST(CallRetraction, AKickEndsTheKickedUsersCallAndNobodyElses) {
    Fixture f;
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "alice")));
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "bob")));

    ASSERT_TRUE(IsOk(f.call(&RoomHandler::handle_kick, kRooms + f.room + "/kick", "mod",
                            json{{"user_id", f.alice}}.dump())));
    EXPECT_FALSE(f.in_call(f.room, f.alice)) << "the kicked user is still listed in the call";
    EXPECT_TRUE(f.in_call(f.room, f.bob));
}

TEST(CallRetraction, ABanEndsTheCall) {
    Fixture f;
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "alice")));
    ASSERT_TRUE(IsOk(f.call(&RoomHandler::handle_ban, kRooms + f.room + "/ban", "mod",
                            json{{"user_id", f.alice}}.dump())));
    EXPECT_FALSE(f.in_call(f.room, f.alice));
}

TEST(CallRetraction, LeavingTheRoomEndsTheCall) {
    Fixture f;
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "alice")));
    ASSERT_TRUE(IsOk(f.call(&RoomHandler::handle_leave, kRooms + f.room + "/leave", "alice")));
    EXPECT_FALSE(f.in_call(f.room, f.alice));
}

TEST(CallRetraction, AnOverrideThatTakesViewChannelEndsTheCallOfWhoItHides) {
    Fixture f;
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "alice")));
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "bob")));

    ChannelPermissionOverride ov;
    ov.allow = 0;
    ov.deny = permission::kViewChannel;
    json body;
    to_json(body, ov);
    ASSERT_TRUE(IsOk(f.call(&RoomHandler::handle_set_state,
                            kRooms + f.room + "/state/" +
                                std::string(event_type::kChannelPermissions) + "/user:" + f.alice,
                            "admin", body.dump())));
    EXPECT_FALSE(f.in_call(f.room, f.alice));
    EXPECT_TRUE(f.in_call(f.room, f.bob));
}

TEST(CallRetraction, TheSweepHelpersOnlyRetractWhoLostAccess) {
    Fixture f;
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "alice")));
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "bob")));
    // Written behind the handler's back, so nothing has reacted yet.
    f.override_directly(f.room, "user:" + f.alice, permission::kViewChannel);
    ASSERT_TRUE(f.in_call(f.room, f.alice));

    EXPECT_EQ(retract_user_calls_without_view(*f.store, *f.sync, f.config, f.bob), 0u);
    EXPECT_EQ(retract_user_calls_without_view(*f.store, *f.sync, f.config, f.alice), 1u);
    EXPECT_FALSE(f.in_call(f.room, f.alice));
    EXPECT_TRUE(f.in_call(f.room, f.bob));

    // Idempotent: nothing left to retract, no event written.
    const auto head = f.store->get_current_stream_position();
    EXPECT_FALSE(retract_call_member(*f.store, *f.sync, f.config.server_name, f.room, f.alice,
                                     "test"));
    EXPECT_EQ(f.store->get_current_stream_position(), head);

    f.override_directly(f.room, "user:" + f.bob, permission::kViewChannel);
    EXPECT_EQ(retract_call_members_without_view(*f.store, *f.sync, f.config, f.room), 1u);
    EXPECT_FALSE(f.in_call(f.room, f.bob));
}

// ── S2-5: deletion departures only reach viewers ──────────────────────────

TEST(DeleteRoomDepartures, OnlyMembersWhoCouldSeeTheRoomAreToldItsId) {
    Fixture f;
    f.override_directly(f.room, "user:" + f.alice, permission::kViewChannel);
    const auto since = f.store->get_current_stream_position();

    ASSERT_TRUE(IsOk(f.call(&RoomHandler::handle_delete_room, kRooms + f.room, "admin")));
    ASSERT_FALSE(f.store->room_exists(f.room));
    const auto head = f.store->get_current_stream_position();

    auto bobs = f.store->get_room_departures(f.bob, since, head);
    ASSERT_EQ(bobs.size(), 1u);
    EXPECT_EQ(bobs[0].room_id, f.room);
    EXPECT_EQ(bobs[0].reason, SqliteStore::kDepartureDeleted);
    EXPECT_TRUE(f.store->get_room_departures(f.alice, since, head).empty())
        << "a member denied VIEW_CHANNEL was told the deleted channel's id";
}

TEST(DeleteRoomDepartures, TheStoreDefaultStillReachesEveryJoinedMember) {
    Fixture f;
    const auto since = f.store->get_current_stream_position();
    f.store->delete_room(f.room);
    const auto head = f.store->get_current_stream_position();
    EXPECT_EQ(f.store->get_room_departures(f.alice, since, head).size(), 1u);
    EXPECT_EQ(f.store->get_room_departures(f.bob, since, head).size(), 1u);
}

TEST(DeleteRoomDepartures, DeletingAChannelEndsItsCallFirst) {
    Fixture f;
    ASSERT_TRUE(IsOk(f.voice_join(f.room, "bob")));
    const auto since = f.store->get_current_stream_position();
    ASSERT_TRUE(IsOk(f.call(&RoomHandler::handle_delete_room, kRooms + f.room, "admin")));
    // The room's events are gone; what survives is bob's departure.
    EXPECT_EQ(f.store->get_room_departures(f.bob, since,
                                           f.store->get_current_stream_position()).size(),
              1u);
}

// ── S2-10: one server process per database ─────────────────────────────────

#include "core/DatabaseLock.h"

#include <filesystem>
#include <unistd.h>

TEST(DatabaseLockTest, ASecondHolderIsRefusedUntilTheFirstLetsGo) {
    const auto db = (std::filesystem::temp_directory_path() /
                     ("bsfchat-dblock-" + std::to_string(::getpid()) + ".db"))
                        .string();
    std::filesystem::remove(DatabaseLock::lock_path_for(db));

    EXPECT_FALSE(DatabaseLock::held_elsewhere(db));
    auto first = DatabaseLock::acquire(db);
    ASSERT_TRUE(first);
    EXPECT_TRUE(DatabaseLock::held_elsewhere(db));

    try {
        auto second = DatabaseLock::acquire(db);
        FAIL() << "a second server was allowed onto the same database";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("already using"), std::string::npos) << e.what();
        EXPECT_NE(std::string(e.what()).find(std::to_string(::getpid())), std::string::npos)
            << "the message should name the holder's pid: " << e.what();
    }
    // The probe did not steal it.
    EXPECT_TRUE(DatabaseLock::held_elsewhere(db));

    first.reset();
    EXPECT_FALSE(DatabaseLock::held_elsewhere(db));
    EXPECT_TRUE(DatabaseLock::acquire(db));
    std::filesystem::remove(DatabaseLock::lock_path_for(db));
}

TEST(DatabaseLockTest, AnInMemoryDatabaseNeedsNoLock) {
    EXPECT_EQ(DatabaseLock::acquire(":memory:"), nullptr);
    EXPECT_FALSE(DatabaseLock::held_elsewhere(":memory:"));
}
