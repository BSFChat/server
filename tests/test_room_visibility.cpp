// Membership is not visibility.
//
// A private channel on this server is a PUBLIC room that everyone is
// force-joined into, with VIEW_CHANNEL denied to @everyone on top. So every
// user holds a membership row for every private channel, and backfill_auto_join
// re-creates those rows on each boot. Membership therefore says nothing about
// what a user may be told, and any response built from it discloses the
// complete list of the server's private channels.
//
// GET /_matrix/client/v3/joined_rooms did exactly that. The properties below,
// in order:
//   1. A user denied VIEW_CHANNEL does not get the room id from /joined_rooms,
//      while a user who holds it does. This is the leak.
//   2. The denial is a real permission evaluation, not a blanket hide: a
//      user-specific ALLOW override reinstates the room for that one user,
//      which is the precedence chain the endpoint has to honour rather than
//      short-circuit.
//   3. Categories stay visible when denied, matching SyncEngine — the sidebar
//      renders the container even when its children are hidden.
//   4. DMs, which are the one room kind where membership IS the privacy
//      boundary, are unaffected.
//   5. /sync does not put the id back. SyncEngine filters response.rooms.join
//      by VIEW_CHANNEL, and then SyncHandler's typing pass adds rooms into that
//      same map from the caller's joined-room list — so the leak reappeared
//      there, through a different endpoint, whenever anyone typed in a private
//      channel.
//   6. One PermissionsEngine services the whole list, and caching role data
//      across rooms does not leak one user's answers into another's.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "api/SyncHandler.h"
#include "api/TypingHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "auth/RoomVisibility.h"
#include "core/Config.h"
#include "identity/Nickname.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <regex>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-vis-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

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

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);

        ServerRolesContent content;
        content.roles.push_back(
            role(std::string(permission::role_id::kEveryone), 0, permission::kEveryoneDefault));
        content.roles.push_back(
            role(std::string(permission::role_id::kAdmin), 100, permission::kAllFlags));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
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

    // A channel as the client actually creates one: public join rules, so
    // auto-join force-joins everybody, and a bsfchat.room.type. `type` is
    // "text" for a channel and "category" for a sidebar container.
    std::string add_channel(const std::string& creator, const std::string& name,
                            const char* type = "text") {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", type}}.dump(), 1001);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomJoinRules), std::string(""),
                            json{{"join_rule", "public"}}.dump(), 1002);
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, user_id,
                            std::string(event_type::kRoomMember), user_id,
                            member_event_content(*store, user_id,
                                                 std::string(membership::kJoin)).dump(),
                            1003);
    }

    // The override the client writes for "make this channel private": deny
    // VIEW_CHANNEL to @everyone. ChannelSettings.qml defines isPrivate as
    // exactly this bit — there is no other marker to test against.
    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny = 0) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target, j.dump(), 1004);
    }

    void make_private(const std::string& room_id) {
        set_override(room_id, std::string("role:") + permission::role_id::kEveryone, 0,
                     permission::kViewChannel);
    }
};

httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

const std::string kJoinedRoomsPath = "/_matrix/client/v3/joined_rooms";

std::vector<std::string> joined_rooms(RoomHandler& handler, const std::string& token) {
    auto req = make_request(kJoinedRoomsPath, token);
    httplib::Response res;
    handler.handle_joined_rooms(req, res);
    EXPECT_TRUE(res.status == -1 || res.status == 200) << "status " << res.status;
    auto body = json::parse(res.body);
    return body.at("joined_rooms").get<std::vector<std::string>>();
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

// handle_typing reads the room and user from the regex captures httplib fills
// in, not from req.path, so a hand-built request has to fill them the same way.
// req.matches holds iterators into req.path, which outlives the call.
void set_typing(TypingHandler& handler, const std::string& room_id, const std::string& user_id,
                const std::string& token) {
    static const std::regex re(R"(/_matrix/client/v3/rooms/([^/]+)/typing/(.+))");
    auto req = make_request("/_matrix/client/v3/rooms/" + room_id + "/typing/" + user_id, token,
                            json{{"typing", true}, {"timeout", 30000}}.dump());
    ASSERT_TRUE(std::regex_match(req.path, req.matches, re));
    httplib::Response res;
    handler.handle_typing(req, res);
    ASSERT_TRUE(res.status == -1 || res.status == 200) << "status " << res.status;
}

// The room ids /sync would hand the client: the keys of rooms.join, which is
// what a client turns into its channel list.
std::vector<std::string> sync_room_ids(SyncHandler& handler, const std::string& token) {
    auto req = make_request("/_matrix/client/v3/sync", token);
    req.params.emplace("timeout", "0");
    httplib::Response res;
    handler.handle_sync(req, res);
    EXPECT_TRUE(res.status == -1 || res.status == 200) << "status " << res.status;
    auto body = json::parse(res.body);
    std::vector<std::string> ids;
    if (auto rooms = body.find("rooms"); rooms != body.end()) {
        if (auto joined = rooms->find("join"); joined != rooms->end()) {
            for (auto it = joined->begin(); it != joined->end(); ++it) ids.push_back(it.key());
        }
    }
    return ids;
}

} // namespace

// The leak. `bob` is a joined member of the private channel — he has to be,
// that is how the channel works — and must still not be told it exists.
TEST(RoomVisibility, DeniedUserDoesNotSeeRoomIdInJoinedRooms) {
    Fixture f("denied");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto public_room = f.add_channel(alice, "general");
    auto private_room = f.add_channel(alice, "staff-only");
    f.join(public_room, bob);
    f.join(private_room, bob);
    f.make_private(private_room);

    // The precondition the whole bug rests on: bob really is joined.
    ASSERT_TRUE(f.store->is_room_member(private_room, bob));

    RoomHandler handler(*f.store, *f.sync, f.config);

    auto bobs = joined_rooms(handler, "token-bob");
    EXPECT_TRUE(contains(bobs, public_room));
    EXPECT_FALSE(contains(bobs, private_room))
        << "private channel id disclosed to a user denied VIEW_CHANNEL";

    // Same list, from someone who may see it: proves the endpoint still works
    // and that the room was hidden by the permission, not by being absent.
    auto alices = joined_rooms(handler, "token-alice");
    EXPECT_TRUE(contains(alices, public_room));
    EXPECT_TRUE(contains(alices, private_room));
}

// An @everyone DENY with a per-user ALLOW on top is how one person is let into
// a private channel. If the endpoint hid rooms by testing for the deny bit
// instead of evaluating the chain, this is the case it would get wrong.
TEST(RoomVisibility, UserOverrideReinstatesTheRoom) {
    Fixture f("override");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");

    auto private_room = f.add_channel(alice, "staff-only");
    f.join(private_room, bob);
    f.join(private_room, carol);
    f.make_private(private_room);
    f.set_override(private_room, "user:" + carol, permission::kViewChannel, 0);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_FALSE(contains(joined_rooms(handler, "token-bob"), private_room));
    EXPECT_TRUE(contains(joined_rooms(handler, "token-carol"), private_room));
}

// Categories are the documented exemption. Hiding them here would empty the
// sidebar of its structure for anyone whose channels are individually hidden.
TEST(RoomVisibility, CategoriesSurviveTheFilter) {
    Fixture f("category");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto category = f.add_channel(alice, "Staff", "category");
    f.join(category, bob);
    f.make_private(category);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(contains(joined_rooms(handler, "token-bob"), category));
}

// A DM is the one room where membership is the privacy boundary — it is not
// public, nobody is force-joined into it, and it carries no override. The
// filter must not cost a user their conversations.
TEST(RoomVisibility, DirectRoomsAreUnaffected) {
    Fixture f("dm");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto dm = generate_room_id("test");
    f.store->create_room(dm, alice, /*is_direct=*/true);
    f.store->set_membership(dm, alice, std::string(membership::kJoin));
    f.store->set_membership(dm, bob, std::string(membership::kJoin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(contains(joined_rooms(handler, "token-alice"), dm));
    EXPECT_TRUE(contains(joined_rooms(handler, "token-bob"), dm));
}

// The same disclosure through /sync. SyncEngine filters rooms.join correctly;
// SyncHandler then walked the caller's RAW joined-room list to attach typing
// indicators, and created a rooms.join entry for any room with a typist in it.
// One person typing in a private channel put its id back in front of everyone
// the channel is hidden from.
TEST(RoomVisibility, TypingDoesNotResurrectAHiddenRoomInSync) {
    Fixture f("typing");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto private_room = f.add_channel(alice, "staff-only");
    f.join(private_room, bob);
    f.make_private(private_room);

    TypingHandler typing(*f.store, *f.sync, f.config);
    SyncHandler sync_handler(*f.store, *f.sync, f.config);
    sync_handler.set_typing_handler(&typing);

    set_typing(typing, private_room, alice, "token-alice");
    ASSERT_FALSE(typing.get_typing_users(private_room).empty())
        << "fixture failed to register a typist, so the test proves nothing";

    EXPECT_FALSE(contains(sync_room_ids(sync_handler, "token-bob"), private_room))
        << "private channel id disclosed through the /sync typing pass";
    EXPECT_TRUE(contains(sync_room_ids(sync_handler, "token-alice"), private_room));
}

// Cost, and the correctness risk the cost fix introduces.
//
// The filter runs a permission check per joined room, and the role data behind
// every one of those checks is identical — so a PermissionsEngine constructed
// per room re-reads the server roles once per channel, all of it serialised
// behind the store's single mutex. visible_joined_rooms takes the engine by
// reference precisely so that the expensive shape cannot be written inside it.
//
// What that buys has to be paid for once: an engine now carries cached role
// data across rooms AND across users, so the cache must be keyed properly. An
// engine that answered for the first user it saw would silently hand every
// caller somebody else's channel list, which is a far worse bug than the one
// being fixed. Both users are served here from one engine.
TEST(RoomVisibility, OneEngineServesManyRoomsAndManyUsers) {
    Fixture f("cost");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    constexpr int kChannels = 12;
    std::vector<std::string> private_rooms;
    for (int i = 0; i < kChannels; ++i) {
        auto room = f.add_channel(alice, "channel-" + std::to_string(i));
        f.join(room, bob);
        // Half private, so the loop covers both outcomes rather than taking
        // one branch twelve times.
        if (i % 2 == 0) {
            f.make_private(room);
            private_rooms.push_back(room);
        }
    }

    PermissionsEngine perms(*f.store, f.config);
    auto bobs = visible_joined_rooms(*f.store, perms, bob);
    auto alices = visible_joined_rooms(*f.store, perms, alice);

    EXPECT_EQ(bobs.size(), static_cast<size_t>(kChannels / 2));
    EXPECT_EQ(alices.size(), static_cast<size_t>(kChannels));
    for (const auto& room : private_rooms) {
        EXPECT_FALSE(contains(bobs, room));
        EXPECT_TRUE(contains(alices, room)) << "the engine reused bob's cached roles for alice";
    }
}
