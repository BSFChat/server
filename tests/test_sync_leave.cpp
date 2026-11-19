// rooms.leave: telling a client to drop a room (audit 2026-11-15, R-1).
//
// An incremental /sync scans events in rooms the reader is CURRENTLY joined to,
// and every departure is precisely the thing that ends that. So none of these
// ever reached the device that had to act on it:
//   * the reader's own leave (from another device), kick or ban — their own
//     member event sat in a room the scan no longer looked at;
//   * a deleted channel — delete_room wrote no event and claimed no position,
//     so there was nothing on any stream at all.
// Channels stayed in sidebars and answered 403 when opened.
//
// The properties under test:
//   1. leave, kick and ban each reach the reader in rooms.leave, with the
//      right bsfchat.reason and their own member event, and the room is not
//      also in rooms.join.
//   2. Deleting a channel reaches every joined member, and wakes a parked poll.
//   3. Once delivered, a departure is below next_batch and is not repeated.
//   4. A room re-joined since is not listed.
//   5. no_access is reported only for a room the reader is known to have seen.
//   6. The exact wire format attach_leave_section writes.
//   7. The store's bookkeeping: what records a departure, what clears one, and
//      the retention prune.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-leave-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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
    std::unique_ptr<RoomHandler> rooms;
    int64_t ts = 1000;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        rooms = std::make_unique<RoomHandler>(*store, *sync, config);

        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    ~Fixture() {
        rooms.reset();
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

    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomCreate, "", json{{"creator", creator}});
        state(room_id, creator, event_type::kRoomMember, creator, json{{"membership", "join"}});
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        state(room_id, creator, event_type::kRoomType, "", json{{"type", "text"}});
        state(room_id, creator, event_type::kRoomJoinRules, "",
              json{{"join_rule", join_rule::kPublic}});
        return room_id;
    }

    void state(const std::string& room_id, const std::string& sender,
               std::string_view type, const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ts++);
        sync->notify_new_event();
    }

    void join_member(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        state(room_id, user_id, event_type::kRoomMember, user_id, json{{"membership", "join"}});
    }

    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny = 0) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        state(room_id, "@server:test", event_type::kChannelPermissions, target, j);
    }

    httplib::Response call(void (RoomHandler::*method)(const httplib::Request&,
                                                       httplib::Response&),
                           const std::string& path, const std::string& token,
                           const std::string& body = "") {
        httplib::Request req;
        req.path = path;
        req.body = body;
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        ((*rooms).*method)(req, res);
        return res;
    }

    httplib::Response leave(const std::string& room_id, const std::string& token) {
        return call(&RoomHandler::handle_leave,
                    "/_matrix/client/v3/rooms/" + room_id + "/leave", token, "{}");
    }

    httplib::Response kick(const std::string& room_id, const std::string& token,
                           const std::string& target) {
        return call(&RoomHandler::handle_kick, "/_matrix/client/v3/rooms/" + room_id + "/kick",
                    token, json{{"user_id", target}}.dump());
    }

    httplib::Response delete_room(const std::string& room_id, const std::string& token) {
        return call(&RoomHandler::handle_delete_room, "/_matrix/client/v3/rooms/" + room_id,
                    token);
    }

    // A token at the current head, minted the way the client gets one.
    std::string token_now(const std::string& user_id) {
        return sync->handle_sync(user_id, "", 0).next_batch;
    }
};

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

} // namespace

// ── 1. leave, kick and ban ───────────────────────────────────────────────────

TEST(SyncLeave, OwnLeaveIsDeliveredWithTheMemberEvent) {
    Fixture f("own-leave");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);

    // Bob's OTHER device holds this token; the leave happens on this one.
    auto since = f.token_now(bob);
    ASSERT_TRUE(IsOk(f.leave(room, "token-bob")));

    auto result = f.sync->handle_sync_full(bob, since, 0);
    ASSERT_EQ(result.leave.count(room), 1u) << "the leave never reached the other device";
    const auto& left = result.leave.at(room);
    EXPECT_EQ(left.reason, "leave");
    ASSERT_EQ(left.timeline.size(), 1u);
    EXPECT_EQ(left.timeline[0].type, std::string(event_type::kRoomMember));
    EXPECT_EQ(left.timeline[0].state_key.value_or(""), bob);
    EXPECT_EQ(left.timeline[0].content.data.value("membership", ""), "leave");
    EXPECT_EQ(result.response.rooms.join.count(room), 0u);
}

TEST(SyncLeave, KickIsReportedAsAKick) {
    Fixture f("kick");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);

    auto since = f.token_now(bob);
    ASSERT_TRUE(IsOk(f.kick(room, "token-alice", bob)));

    auto result = f.sync->handle_sync_full(bob, since, 0);
    ASSERT_EQ(result.leave.count(room), 1u);
    EXPECT_EQ(result.leave.at(room).reason, "kick");
    ASSERT_EQ(result.leave.at(room).timeline.size(), 1u);
    EXPECT_EQ(result.leave.at(room).timeline[0].sender, alice);
}

TEST(SyncLeave, RoomBanIsReportedAsABan) {
    // Through the store rather than POST /ban, which is a SERVER ban on this
    // deployment and blanks the banned account's /sync entirely. A per-room ban
    // row is still what the state route and future paths write.
    Fixture f("ban");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);

    auto since = f.token_now(bob);
    f.store->set_membership(room, bob, std::string(membership::kBan));
    f.state(room, alice, event_type::kRoomMember, bob, json{{"membership", "ban"}});

    auto result = f.sync->handle_sync_full(bob, since, 0);
    ASSERT_EQ(result.leave.count(room), 1u);
    EXPECT_EQ(result.leave.at(room).reason, "ban");
    ASSERT_EQ(result.leave.at(room).timeline.size(), 1u);
}

TEST(SyncLeave, OtherMembersAreNotToldAboutSomeoneElsesLeave) {
    Fixture f("others");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);

    auto since = f.token_now(alice);
    ASSERT_TRUE(IsOk(f.leave(room, "token-bob")));

    auto result = f.sync->handle_sync_full(alice, since, 0);
    EXPECT_TRUE(result.leave.empty());
    // Alice sees bob's leave the ordinary way: as a member event in the room.
    EXPECT_EQ(result.response.rooms.join.count(room), 1u);
}

// ── 2. deletion ─────────────────────────────────────────────────────────────

TEST(SyncLeave, DeletedRoomReachesEveryJoinedMember) {
    Fixture f("deleted");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "doomed");
    f.join_member(room, bob);

    auto alice_since = f.token_now(alice);
    auto bob_since = f.token_now(bob);
    ASSERT_TRUE(IsOk(f.delete_room(room, "token-alice")));
    ASSERT_FALSE(f.store->room_exists(room));

    for (const auto& [uid, since] : {std::pair{alice, alice_since}, std::pair{bob, bob_since}}) {
        auto result = f.sync->handle_sync_full(uid, since, 0);
        ASSERT_EQ(result.leave.count(room), 1u) << uid << " was never told";
        EXPECT_EQ(result.leave.at(room).reason, "deleted");
        EXPECT_TRUE(result.leave.at(room).timeline.empty());
        EXPECT_EQ(result.response.rooms.join.count(room), 0u);
    }
}

TEST(SyncLeave, DeletingARoomWakesAParkedPoll) {
    Fixture f("deleted-parked");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "doomed");
    f.join_member(room, bob);
    auto since = f.token_now(bob);

    std::thread deleter([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        f.delete_room(room, "token-alice");
    });
    const auto start = std::chrono::steady_clock::now();
    auto result = f.sync->handle_sync_full(bob, since, 10000);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    deleter.join();

    ASSERT_EQ(result.leave.count(room), 1u);
    EXPECT_LT(elapsed, 3000) << "a departure must count as payload, not wait out the poll";
}

// ── 3. delivered once ───────────────────────────────────────────────────────

TEST(SyncLeave, ADeliveredDepartureIsNotRepeated) {
    Fixture f("once");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);

    auto since = f.token_now(bob);
    ASSERT_TRUE(IsOk(f.leave(room, "token-bob")));
    auto first = f.sync->handle_sync_full(bob, since, 0);
    ASSERT_EQ(first.leave.count(room), 1u);

    auto second = f.sync->handle_sync_full(bob, first.response.next_batch, 0);
    EXPECT_TRUE(second.leave.empty());
}

// ── 4. re-joined ────────────────────────────────────────────────────────────

TEST(SyncLeave, ARoomRejoinedSinceIsNotListed) {
    Fixture f("rejoin");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);

    auto since = f.token_now(bob);
    ASSERT_TRUE(IsOk(f.leave(room, "token-bob")));
    f.join_member(room, bob);

    auto result = f.sync->handle_sync_full(bob, since, 0);
    EXPECT_EQ(result.leave.count(room), 0u) << "told to drop a room they are in";
    ASSERT_EQ(result.response.rooms.join.count(room), 1u);
    EXPECT_FALSE(result.response.rooms.join.at(room).state.events.empty())
        << "the re-join carries the room's state";
    EXPECT_TRUE(f.store->get_room_departures(bob, 0, f.store->get_current_stream_position())
                    .empty())
        << "re-joining clears the departure row";
}

// ── 5. no_access ────────────────────────────────────────────────────────────

TEST(SyncLeave, LosingViewChannelIsReportedForARoomTheReaderHadRead) {
    Fixture f("no-access");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto seen = f.add_channel(alice, "seen");
    auto unseen = f.add_channel(alice, "unseen");
    auto never = f.add_channel(alice, "never");
    f.join_member(seen, bob);
    f.join_member(unseen, bob);
    f.join_member(never, bob);
    f.set_override(never, "user:" + bob, 0, permission::kViewChannel);
    ASSERT_TRUE(f.store->set_read_marker(bob, seen, f.store->get_current_stream_position()));

    auto since = f.token_now(bob);
    f.set_override(seen, "user:" + bob, 0, permission::kViewChannel);
    f.set_override(unseen, "user:" + bob, 0, permission::kViewChannel);
    f.set_override(never, "user:" + bob, 0, permission::kViewChannel | permission::kSendMessages);

    auto result = f.sync->handle_sync_full(bob, since, 0);
    ASSERT_EQ(result.leave.count(seen), 1u);
    EXPECT_EQ(result.leave.at(seen).reason, "no_access");
    EXPECT_TRUE(result.leave.at(seen).timeline.empty());
    EXPECT_EQ(result.response.rooms.join.count(seen), 0u);
    // Unread, but listed in the response that minted bob's token (audit 3:
    // the engine records what each token's response showed), so dropping it
    // tells bob nothing he was not already told.
    ASSERT_EQ(result.leave.count(unseen), 1u);
    EXPECT_EQ(result.leave.at(unseen).reason, "no_access");
    EXPECT_EQ(result.response.rooms.join.count(unseen), 0u);
    // Never shown at all, so naming the room now would be the only thing that
    // ever told bob it exists.
    EXPECT_EQ(result.leave.count(never), 0u);
    EXPECT_EQ(result.response.rooms.join.count(never), 0u);
}

// ── 6. the wire format ──────────────────────────────────────────────────────

TEST(SyncLeave, WireFormatIsTheAgreedShape) {
    RoomEvent ev;
    ev.event_id = "$e";
    ev.room_id = "!r:test";
    ev.sender = "@a:test";
    ev.type = std::string(event_type::kRoomMember);
    ev.state_key = "@b:test";
    ev.content.data = {{"membership", "leave"}};
    ev.origin_server_ts = 5;

    LeftRooms leave;
    leave["!r:test"] = LeftRoom{"kick", {ev}};
    leave["!gone:test"] = LeftRoom{"deleted", {}};

    json resp = {{"next_batch", "t_x"}, {"rooms", {{"join", json::object()}}}};
    attach_leave_section(resp, leave);

    ASSERT_TRUE(resp["rooms"].contains("leave"));
    const auto& section = resp["rooms"]["leave"];
    EXPECT_EQ(section["!r:test"]["bsfchat.reason"], "kick");
    ASSERT_EQ(section["!r:test"]["timeline"]["events"].size(), 1u);
    EXPECT_EQ(section["!r:test"]["timeline"]["events"][0]["event_id"], "$e");
    EXPECT_EQ(section["!r:test"]["timeline"]["events"][0]["content"]["membership"], "leave");
    EXPECT_EQ(section["!gone:test"]["bsfchat.reason"], "deleted");
    EXPECT_TRUE(section["!gone:test"]["timeline"]["events"].is_array());
    EXPECT_TRUE(section["!gone:test"]["timeline"]["events"].empty());
    EXPECT_TRUE(resp["rooms"].contains("join")) << "the rest of rooms is untouched";

    json untouched = {{"rooms", {{"join", json::object()}}}};
    attach_leave_section(untouched, {});
    EXPECT_FALSE(untouched["rooms"].contains("leave")) << "absent when there is nothing to drop";
}

// ── 7. store bookkeeping ────────────────────────────────────────────────────

TEST(SyncLeave, OnlyJoinToLeaveOrBanRecordsADeparture) {
    Fixture f("store");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");

    auto head = [&] { return f.store->get_current_stream_position(); };
    // Invite then decline: the invite restatement already covers it.
    f.store->set_membership(room, bob, std::string(membership::kInvite));
    f.store->set_membership(room, bob, std::string(membership::kLeave));
    EXPECT_TRUE(f.store->get_room_departures(bob, 0, head()).empty());

    f.store->set_membership(room, bob, std::string(membership::kJoin));
    const auto before = head();
    f.store->set_membership(room, bob, std::string(membership::kLeave));
    auto rows = f.store->get_room_departures(bob, 0, head());
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].room_id, room);
    EXPECT_EQ(rows[0].reason, "leave");
    EXPECT_GT(rows[0].stream_pos, before) << "a departure claims a fresh stream position";

    // leave -> ban is not a second departure: nothing the sidebar shows changed.
    f.store->set_membership(room, bob, std::string(membership::kBan));
    rows = f.store->get_room_departures(bob, 0, head());
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].reason, "leave");
}

TEST(SyncLeave, RetentionPrunesOldRows) {
    Fixture f("prune");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    f.store->set_membership(room, bob, std::string(membership::kLeave));
    ASSERT_EQ(f.store->get_room_departures(bob, 0, f.store->get_current_stream_position()).size(),
              1u);

    EXPECT_EQ(f.store->prune_room_departures(0), 0) << "nothing is older than the epoch";
    const int64_t far_future = 4102444800000;  // 2100-01-01
    EXPECT_EQ(f.store->prune_room_departures(far_future), 1);
    EXPECT_TRUE(
        f.store->get_room_departures(bob, 0, f.store->get_current_stream_position()).empty());
}
