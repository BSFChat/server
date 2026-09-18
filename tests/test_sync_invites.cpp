// A human account learning, through the API, that it has been invited.
//
// POST /rooms/{id}/invite wrote the membership row and the m.room.member event
// and stopped there. SyncResponse had only rooms.join, and get_events_since
// joined room_members on membership = 'join', so the invitee's own invite
// matched no row on any stream they polled: the only way to find out you had
// been invited was to be told out of band and then guess the room id.
//
// (Bots were never affected — inviting a bot joins it outright, so it sees an
// ordinary join. This is the human path, which keeps plain invite semantics.)
//
// The properties under test, in the order they appear below:
//   1. An invite reaches the invitee's /sync, in rooms.invite, and the room
//      does NOT appear in rooms.join.
//   2. invite_state is stripped: the room's identity plus the invitee's and
//      the inviter's member events. No timeline, no power levels, no other
//      members — and nothing new leaks as the room goes on living.
//   3. An invite that predates the client's sync token is still delivered,
//      because every delivered response restates the pending set.
//   4. That restatement does not make a long poll return instantly, which
//      would spin a client at full speed for as long as an invite is pending.
//   5. POST /rooms/{id}/join works off the back of it, and afterwards the room
//      is in rooms.join with its full state and gone from rooms.invite.
//   6. Declining (leave) clears it the same way, with no rooms.leave section.
//   7. A parked long poll gets the invite promptly, not at timeout.
//   8. VIEW_CHANNEL still decides: an invite into a channel the account's
//      roles cannot see is not surfaced.

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
            ("bsfchat-invites-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

// The invite and join endpoints are exercised through RoomHandler rather than
// by writing membership rows directly: the point of the exercise is that a real
// POST /invite becomes something a real /sync shows, and a store-level shortcut
// would prove nothing about the path an owner's client actually takes.
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

    // A private channel: the invite-only case is the one invites are for.
    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomCreate, "", json{{"creator", creator}});
        state(room_id, creator, event_type::kRoomMember, creator,
              json{{"membership", "join"}, {"displayname", "Alice A"}});
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        state(room_id, creator, event_type::kRoomType, "", json{{"type", "text"}});
        state(room_id, creator, event_type::kRoomJoinRules, "",
              json{{"join_rule", join_rule::kInvite}});
        state(room_id, creator, event_type::kRoomPowerLevels, "",
              json{{"users", {{creator, 100}}}});
        return room_id;
    }

    void state(const std::string& room_id, const std::string& sender,
               std::string_view type, const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ts++);
    }

    void say(const std::string& room_id, const std::string& sender, const std::string& body) {
        store->insert_event(generate_event_id("test"), room_id, sender,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", body}}.dump(), ts++);
        sync->notify_new_event();
    }

    void join_member(const std::string& room_id, const std::string& user_id,
                     const std::string& display) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        state(room_id, user_id, event_type::kRoomMember, user_id,
              json{{"membership", "join"}, {"displayname", display}});
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

    httplib::Response post(void (RoomHandler::*method)(const httplib::Request&,
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

    httplib::Response invite(const std::string& room_id, const std::string& actor_token,
                             const std::string& target) {
        return post(&RoomHandler::handle_invite,
                    "/_matrix/client/v3/rooms/" + room_id + "/invite", actor_token,
                    json{{"user_id", target}}.dump());
    }

    httplib::Response accept(const std::string& room_id, const std::string& token) {
        return post(&RoomHandler::handle_join,
                    "/_matrix/client/v3/rooms/" + room_id + "/join", token, "{}");
    }

    httplib::Response decline(const std::string& room_id, const std::string& token) {
        return post(&RoomHandler::handle_leave,
                    "/_matrix/client/v3/rooms/" + room_id + "/leave", token, "{}");
    }
};

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

// The (type, state_key) pairs in an invite_state, for asserting on the SET of
// events rather than on their order.
std::vector<std::pair<std::string, std::string>> keys_of(const InvitedRoom& room) {
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& ev : room.invite_state.events) {
        out.emplace_back(ev.type, ev.state_key.value_or("<none>"));
    }
    return out;
}

bool has_key(const InvitedRoom& room, std::string_view type, const std::string& state_key) {
    for (const auto& [t, k] : keys_of(room)) {
        if (t == type && k == state_key) return true;
    }
    return false;
}

} // namespace

// ── 1. the invite arrives at all ─────────────────────────────────────────────

TEST(SyncInvites, InviteReachesTheInviteeAndNotAsAJoinedRoom) {
    Fixture f("arrives");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");

    auto since = f.sync->handle_sync(bob, "", 0).next_batch;
    ASSERT_EQ(f.sync->handle_sync(bob, since, 0).rooms.invite.count(room), 0u)
        << "nothing pending yet";

    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    auto resp = f.sync->handle_sync(bob, since, 0);
    ASSERT_EQ(resp.rooms.invite.count(room), 1u) << "the invite never reached /sync";
    // The room is NOT joined. Putting it in rooms.join would hand a client a
    // room it is not in and, with it, that room's state and timeline.
    EXPECT_EQ(resp.rooms.join.count(room), 0u);
}

TEST(SyncInvites, InitialSyncCarriesPendingInvites) {
    // A fresh install, or a client whose cache was cleared, gets the invite in
    // the one sync it does without a token.
    Fixture f("initial");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    auto resp = f.sync->handle_sync(bob, "", 0);
    ASSERT_EQ(resp.rooms.invite.count(room), 1u);
    EXPECT_EQ(resp.rooms.join.count(room), 0u);
}

// ── 2. stripped state, and it stays stripped ─────────────────────────────────

TEST(SyncInvites, InviteStateIdentifiesTheRoomAndTheInviterAndNothingElse) {
    Fixture f("stripped");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto room = f.add_channel(alice, "planning");
    f.join_member(room, carol, "Carol C");
    f.say(room, alice, "the merger closes friday");
    f.say(room, carol, "does legal know");

    auto since = f.sync->handle_sync(bob, "", 0).next_batch;
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    auto resp = f.sync->handle_sync(bob, since, 0);
    ASSERT_EQ(resp.rooms.invite.count(room), 1u);
    const auto& invited = resp.rooms.invite[room];

    // What a client needs to render "Alice invited you to #planning".
    EXPECT_TRUE(has_key(invited, event_type::kRoomName, ""));
    EXPECT_TRUE(has_key(invited, event_type::kRoomCreate, ""));
    EXPECT_TRUE(has_key(invited, event_type::kRoomType, ""));
    EXPECT_TRUE(has_key(invited, event_type::kRoomJoinRules, ""));
    EXPECT_TRUE(has_key(invited, event_type::kRoomMember, bob)) << "the invite itself";
    EXPECT_TRUE(has_key(invited, event_type::kRoomMember, alice)) << "who invited them";

    // And nothing else. Power levels are the room's authority structure, and
    // Carol's membership is not Bob's to read until he is in the room.
    EXPECT_FALSE(has_key(invited, event_type::kRoomPowerLevels, ""));
    EXPECT_FALSE(has_key(invited, event_type::kRoomMember, carol));

    // No timeline anywhere: InvitedRoom has nowhere to put one, so the check
    // that matters is that none of the room's messages came through on any
    // other route either.
    for (const auto& ev : invited.invite_state.events) {
        EXPECT_NE(ev.type, std::string(event_type::kRoomMessage)) << ev.event_id;
    }
    EXPECT_EQ(resp.rooms.join.count(room), 0u);
}

TEST(SyncInvites, MessagesSentWhileTheInviteIsPendingDoNotReachTheInvitee) {
    // The membership filter in get_events_since is what stops this, and it has
    // to keep stopping it for every event type, not just the ones we thought
    // of: an invitee who has not accepted is not a member yet.
    Fixture f("no-leak");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    auto since = f.sync->handle_sync(bob, "", 0).next_batch;
    f.say(room, alice, "secret");
    f.state(room, alice, event_type::kRoomTopic, "", json{{"topic", "also secret"}});
    f.join_member(room, f.add_user("dave"), "Dave D");
    f.sync->notify_new_event();

    auto resp = f.sync->handle_sync(bob, since, 0);
    EXPECT_EQ(resp.rooms.join.count(room), 0u) << "a room Bob has not joined";
    // Still pending, so still stated — but with no more in it than before.
    ASSERT_EQ(resp.rooms.invite.count(room), 1u);
    for (const auto& ev : resp.rooms.invite[room].invite_state.events) {
        EXPECT_NE(ev.type, std::string(event_type::kRoomMessage));
        EXPECT_FALSE(ev.type == std::string(event_type::kRoomMember)
                     && ev.state_key == "@dave:test");
    }
}

// ── 3. an invite older than the client's token ───────────────────────────────

TEST(SyncInvites, AnInviteOlderThanTheSyncTokenIsStillDelivered) {
    // The upgrade case, and the one a delta alone cannot serve: a client
    // resumes from a persisted token and never asks for an initial sync again,
    // so an invite whose member event sits below that token would otherwise be
    // invisible forever.
    Fixture f("restated");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    // Bob's client walks its token past the invite without ever having been
    // shown it — exactly what an old server left behind.
    auto token = "s" + std::to_string(f.store->get_current_stream_position());

    auto resp = f.sync->handle_sync(bob, token, 0);
    ASSERT_EQ(resp.rooms.invite.count(room), 1u)
        << "a pending invite must be restated, not only announced once";
    EXPECT_TRUE(has_key(resp.rooms.invite[room], event_type::kRoomName, ""));
}

// ── 4. the restatement must not spin the client ──────────────────────────────

TEST(SyncInvites, APendingInviteDoesNotShortCircuitTheLongPoll) {
    // If a restated invite counted as payload, every poll would return
    // instantly for as long as the invite stayed unanswered: return, advance
    // the token, find the same invite, return again — a client at full speed
    // against an idle server, for hours, over one unanswered invite.
    //
    // The restatement therefore happens in deliver(), after the decision to
    // park has already been taken on the built response.
    Fixture f("no-spin");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    auto token = "s" + std::to_string(f.store->get_current_stream_position());

    const auto start = std::chrono::steady_clock::now();
    auto resp = f.sync->handle_sync(bob, token, 400);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    EXPECT_GE(elapsed, 350) << "the poll returned early on a restated invite";
    // And the idle-timeout reply still carries it, which is what makes one
    // poll enough to learn about an invite that predates the token.
    EXPECT_EQ(resp.rooms.invite.count(room), 1u);
}

// ── 5. accepting ─────────────────────────────────────────────────────────────

TEST(SyncInvites, JoiningOffTheBackOfTheInviteMovesTheRoomToJoin) {
    Fixture f("accept");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    f.say(room, alice, "before bob");

    auto since = f.sync->handle_sync(bob, "", 0).next_batch;
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));
    ASSERT_EQ(f.sync->handle_sync(bob, since, 0).rooms.invite.count(room), 1u);

    // The room is invite-only, so this 200 is itself the assertion that the
    // invite is what let Bob in.
    ASSERT_TRUE(IsOk(f.accept(room, "token-bob")));
    EXPECT_EQ(f.store->get_membership(room, bob), "join");

    auto resp = f.sync->handle_sync(bob, since, 0);
    ASSERT_EQ(resp.rooms.join.count(room), 1u) << "the accepted room must be joined";
    // newly_joined_rooms gives a fresh joiner the room's full state, including
    // the things invite_state withheld.
    bool saw_power_levels = false;
    for (const auto& ev : resp.rooms.join[room].state.events) {
        if (ev.type == std::string(event_type::kRoomPowerLevels)) saw_power_levels = true;
    }
    EXPECT_TRUE(saw_power_levels);
    // And it is no longer an invite. A client that kept showing the prompt
    // after the user accepted would be showing it forever.
    EXPECT_EQ(resp.rooms.invite.count(room), 0u);
}

TEST(SyncInvites, AJoinedRoomIsNeverAlsoAnInvite) {
    // Belt and braces on the section split: whatever the delta contains, a
    // room must never be in both maps, or a client has to guess which wins.
    Fixture f("disjoint");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));
    ASSERT_TRUE(IsOk(f.accept(room, "token-bob")));
    f.say(room, alice, "welcome");

    for (const auto& token : {std::string(""), std::string("s0")}) {
        auto resp = f.sync->handle_sync(bob, token, 0);
        EXPECT_EQ(resp.rooms.join.count(room), 1u) << "token=" << token;
        EXPECT_EQ(resp.rooms.invite.count(room), 0u) << "token=" << token;
    }
}

// ── 6. declining ─────────────────────────────────────────────────────────────

TEST(SyncInvites, DecliningClearsTheInviteWithoutARoomsLeaveSection) {
    // There is no rooms.leave. What retracts the prompt is that the pending
    // set is restated in full on every delivered response, so an invite the
    // user answered anywhere simply stops appearing.
    Fixture f("decline");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    auto token = "s" + std::to_string(f.store->get_current_stream_position());
    ASSERT_EQ(f.sync->handle_sync(bob, token, 0).rooms.invite.count(room), 1u);

    // /leave is the decline. It was join-only until this change, so an invitee
    // could accept and not refuse.
    ASSERT_TRUE(IsOk(f.decline(room, "token-bob")));
    EXPECT_EQ(f.store->get_membership(room, bob), "leave");

    auto resp = f.sync->handle_sync(bob, token, 0);
    EXPECT_EQ(resp.rooms.invite.count(room), 0u);
    EXPECT_EQ(resp.rooms.join.count(room), 0u);
}

TEST(SyncInvites, DecliningTwiceOrLeavingSomewhereYouWereNeverInvitedIsRefused) {
    // The widening above is exactly two memberships wide. In particular a
    // 'ban' row must not pass: writing 'leave' over it would lift the ban.
    Fixture f("decline-guard");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");

    EXPECT_EQ(f.decline(room, "token-bob").status, 403) << "never invited";

    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));
    ASSERT_TRUE(IsOk(f.decline(room, "token-bob")));
    EXPECT_EQ(f.decline(room, "token-bob").status, 403) << "already declined";

    f.store->set_membership(room, bob, std::string(membership::kBan));
    EXPECT_EQ(f.decline(room, "token-bob").status, 403) << "a ban is not a leave";
    EXPECT_EQ(f.store->get_membership(room, bob), "ban");
}

TEST(SyncInvites, AWithdrawnInviteStopsBeingStated) {
    // A moderator kicking someone who was invited but never joined is the
    // retraction path from the other side.
    Fixture f("withdrawn");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    auto token = "s" + std::to_string(f.store->get_current_stream_position());
    ASSERT_EQ(f.sync->handle_sync(bob, token, 0).rooms.invite.count(room), 1u);

    ASSERT_TRUE(IsOk(f.post(&RoomHandler::handle_kick,
                            "/_matrix/client/v3/rooms/" + room + "/kick", "token-alice",
                            json{{"user_id", bob}}.dump())));

    EXPECT_EQ(f.sync->handle_sync(bob, token, 0).rooms.invite.count(room), 0u);
}

// ── 7. a parked poll, not a timeout ──────────────────────────────────────────

TEST(SyncInvites, AnInviteWakesAParkedLongPollPromptly) {
    // The invitee is not in the room, so anything that routes wakeups by room
    // membership cannot reach them from the room side — it has to reach them
    // because the member event names them. Without that, an invite is
    // delivered when the poll times out instead of when it is sent: up to
    // thirty seconds, intermittent, and it looks like this change is broken.
    Fixture f("parked");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");

    auto since = f.sync->handle_sync(bob, "", 0).next_batch;

    std::thread inviter([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        f.invite(room, "token-alice", bob);
    });

    const auto start = std::chrono::steady_clock::now();
    auto resp = f.sync->handle_sync(bob, since, 10000);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    inviter.join();

    ASSERT_EQ(resp.rooms.invite.count(room), 1u) << "parked poll returned without the invite";
    EXPECT_LT(elapsed, 3000) << "the invite waited out the poll instead of waking it";
}

// ── 8. VIEW_CHANNEL still decides ────────────────────────────────────────────

TEST(SyncInvites, AnInviteIntoAChannelTheAccountCannotViewIsNotSurfaced) {
    // Every other room in a /sync response passes VIEW_CHANNEL, and an invite
    // is not a way around it: accepting would land the account in a channel it
    // still could not read, and listing it would name a channel the server has
    // decided this account cannot see.
    Fixture f("hidden");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    f.set_override(room, "user:" + bob, 0, permission::kViewChannel);

    auto since = f.sync->handle_sync(bob, "", 0).next_batch;
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    EXPECT_EQ(f.sync->handle_sync(bob, since, 0).rooms.invite.count(room), 0u);
    EXPECT_EQ(f.sync->handle_sync(bob, "", 0).rooms.invite.count(room), 0u);

    // And once the denial is lifted it shows up, so the assertion above is
    // about the override and not about some other reason nothing appeared.
    f.set_override(room, "user:" + bob, 0, 0);
    f.sync->notify_new_event();
    EXPECT_EQ(f.sync->handle_sync(bob, since, 0).rooms.invite.count(room), 1u);
}

TEST(SyncInvites, AnInviteeWhoIsServerBannedSeesNothing) {
    Fixture f("banned");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "planning");
    ASSERT_TRUE(IsOk(f.invite(room, "token-alice", bob)));

    auto token = "s" + std::to_string(f.store->get_current_stream_position());
    ASSERT_EQ(f.sync->handle_sync(bob, token, 0).rooms.invite.count(room), 1u);

    f.store->set_server_ban(bob, alice, "spam", 0);
    auto resp = f.sync->handle_sync(bob, token, 0);
    EXPECT_TRUE(resp.rooms.invite.empty());
    EXPECT_TRUE(resp.rooms.join.empty());
}
