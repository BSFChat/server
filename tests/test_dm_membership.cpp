// A direct message stays a conversation between exactly two people, whichever
// door a membership write arrives at.
//
// ── The gap ──────────────────────────────────────────────────────────────
//
// POST /rooms/{id}/invite has refused to widen a DM since the DM work landed:
// refuse_on_direct_room, with the reason written next to it — "only the two of
// us" is the whole guarantee of a direct room, and a third member would also be
// handed the entire backlog, because a DM has no history-visibility story of
// its own.
//
// The generic state route had no equivalent. PUT
// /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey} carries a
// deny-list of state types that a direct room refuses — bsfchat.room.category,
// bsfchat.room.type, m.room.join_rules and bsfchat.channel.permissions — and
// m.room.member was not on it. A member write whose state key is somebody other
// than the caller is handed to apply_membership_moderation, classify_transition
// folds both `{"membership":"invite"}` and `{"membership":"join"}` into
// invite_intent(), and invite_intent() asked for room-scoped MANAGE_CHANNELS
// and nothing else. So a participant in a DM holding that flag could add a
// third account to somebody's private conversation, and the `join` spelling
// force-joined them outright rather than leaving an invite.
//
// It is the same defect the phantom-membership work found in the same place and
// for the same reason (test_phantom_membership.cpp: "the same decision through
// the generic state route ... this one FORCE-JOINS, so it is strictly worse
// than the reported bug"), one rule further along.
//
// ── Where the rule now lives, and why these tests are shaped this way ────
//
// Not on the state route, and not a second copy of refuse_on_direct_room: on
// MembershipIntent, as `direct_room_refusal`. That is the struct every
// membership write is classified into before anything is checked, and it exists
// precisely so that the dedicated endpoints and the generic route cannot
// disagree about what an act requires. The DM rule was the last rule about a
// membership write that was not on it, which is why it could differ between the
// two doors — so the tests below always exercise BOTH doors for an act that has
// both, and compare the refusals to each other.
//
// ── What must keep working in a DM, which is most of this file ───────────
//
// A blanket "refuse every member write on a direct room" would pass every
// refusal test here and be wrong three ways, so each is pinned:
//
//   * LEAVING. Self-membership never reaches apply_membership_moderation at
//     all — the state route returns on `state_key == *user_id` well above the
//     moderation delegation, and POST /rooms/{id}/leave is its own handler —
//     but "leaving a DM still works" is the property, not the code path, and a
//     guard put at the top of the state route instead would have broken it.
//
//   * BANNING, including from inside the DM window. A ban is not an act on this
//     room; it is an act on the ACCOUNT, projected across every room the target
//     has a row in. Refusing it on a direct room would leave a banned account
//     joined to every DM it was in, still holding the backlog — the blind spot
//     the server-wide ban list was added to close, reopened for one room type.
//     And `room_id` is only the room the request came through: the person you
//     need to ban is usually the person in the DM you are looking at.
//
//   * UNBANNING. The mirror. A ban that reaches a DM and an unban that does not
//     is a ban nobody can lift there.
//
// KICKING is refused, and that is a decision rather than a consequence. A kick
// touches one room, so in a DM it means ejecting the other participant from a
// two-person conversation — leaving a one-member direct room they cannot return
// to, since invites into a DM are refused and handle_join refuses a non-member
// of one. It is gated on KICK_MEMBERS at SERVER scope, so it is exactly the
// case refuse_on_direct_room's comment names: a role that lets someone run the
// server must not let them run somebody's private conversation. Nothing is
// lost, because wanting out of a DM is leaving it and wanting the other person
// gone from the server is a ban.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-dmmember-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

// A role that is NOT administrator. ADMINISTRATOR short-circuits every flag
// inside PermissionsEngine::compute, so a suite that only ever acts as an admin
// cannot tell "the DM rule refuses this" from "the permission check refuses
// this" — and the bug being closed here was reachable by an ordinary moderator.
// One test acts as an admin on purpose, to pin that the rule is above the
// permission system rather than part of it.
constexpr const char* kModeratorRole = "moderator";
constexpr permission::Flags kModeratorFlags =
    permission::kViewChannel | permission::kSendMessages | permission::kManageChannels |
    permission::kKickMembers | permission::kBanMembers;

// Everything goes through RoomHandler, for the reason test_phantom_membership
// .cpp gives: the subject is what a real request writes, and a store-level
// shortcut would prove nothing about the path a client takes.
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
        content.roles.push_back(role(kModeratorRole, 50, kModeratorFlags));
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

    // A DM, built the way handle_create_room builds one: is_direct on the room
    // row, invite-only join rules, and both participants JOINED outright (there
    // is no invite delivery channel in /sync, so a DM never has an invite
    // stage). The `is_direct` flag on the room row is what is_direct_room reads.
    std::string add_dm(const std::string& a, const std::string& b) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, a, /*is_direct=*/true);
        store->set_membership(room_id, a, std::string(membership::kJoin));
        store->set_membership(room_id, b, std::string(membership::kJoin));
        state(room_id, a, event_type::kRoomCreate, "", json{{"creator", a}});
        state(room_id, a, event_type::kRoomJoinRules, "",
              json{{"join_rule", join_rule::kInvite}});
        state(room_id, a, event_type::kRoomMember, a,
              json{{"membership", membership::kJoin}, {"is_direct", true}});
        state(room_id, a, event_type::kRoomMember, b,
              json{{"membership", membership::kJoin}, {"is_direct", true}});
        // The backlog. A third member arriving would be handed all of it, which
        // is half the reason the rule exists.
        store->insert_event(generate_event_id("test"), room_id, a,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", "between us"}}.dump(), ts++);
        return room_id;
    }

    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomCreate, "", json{{"creator", creator}});
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        state(room_id, creator, event_type::kRoomType, "", json{{"type", "text"}});
        state(room_id, creator, event_type::kRoomJoinRules, "",
              json{{"join_rule", join_rule::kInvite}});
        return room_id;
    }

    void state(const std::string& room_id, const std::string& sender,
               std::string_view type, const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ts++);
    }

    httplib::Response call(void (RoomHandler::*method)(const httplib::Request&,
                                                       httplib::Response&),
                           const std::string& path, const std::string& token,
                           const std::string& body) {
        httplib::Request req;
        req.path = path;
        req.body = body;
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        ((*rooms).*method)(req, res);
        return res;
    }

    // ── the two doors ────────────────────────────────────────────────────

    httplib::Response invite(const std::string& room_id, const std::string& token,
                             const std::string& target) {
        return call(&RoomHandler::handle_invite,
                    "/_matrix/client/v3/rooms/" + room_id + "/invite", token,
                    json{{"user_id", target}}.dump());
    }

    // The generic state route: the door that had no DM rule.
    httplib::Response set_member_state(const std::string& room_id, const std::string& token,
                                       const std::string& target,
                                       const std::string& membership_value) {
        return call(&RoomHandler::handle_set_state,
                    "/_matrix/client/v3/rooms/" + room_id + "/state/" +
                        std::string(event_type::kRoomMember) + "/" + target,
                    token, json{{"membership", membership_value}}.dump());
    }

    httplib::Response kick(const std::string& room_id, const std::string& token,
                           const std::string& target) {
        return call(&RoomHandler::handle_kick,
                    "/_matrix/client/v3/rooms/" + room_id + "/kick", token,
                    json{{"user_id", target}}.dump());
    }

    httplib::Response ban(const std::string& room_id, const std::string& token,
                          const std::string& target) {
        return call(&RoomHandler::handle_ban,
                    "/_matrix/client/v3/rooms/" + room_id + "/ban", token,
                    json{{"user_id", target}}.dump());
    }

    httplib::Response unban(const std::string& room_id, const std::string& token,
                            const std::string& target) {
        return call(&RoomHandler::handle_unban,
                    "/_matrix/client/v3/rooms/" + room_id + "/unban", token,
                    json{{"user_id", target}}.dump());
    }

    httplib::Response leave(const std::string& room_id, const std::string& token) {
        return call(&RoomHandler::handle_leave,
                    "/_matrix/client/v3/rooms/" + room_id + "/leave", token, "{}");
    }

    // ── what actually landed ─────────────────────────────────────────────

    bool has_membership_row(const std::string& room_id, const std::string& target) {
        for (const auto& [uid, state_value] : store->get_room_members(room_id)) {
            if (uid == target) return true;
        }
        return false;
    }

    int member_events_for(const std::string& room_id, const std::string& target) {
        int n = 0;
        for (const auto& ev : store->get_room_events(room_id, 1000)) {
            if (ev.type == event_type::kRoomMember && ev.state_key && *ev.state_key == target) {
                ++n;
            }
        }
        return n;
    }
};

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

bool mentions_direct_message(const httplib::Response& res) {
    return res.body.find("direct message") != std::string::npos;
}

} // namespace

// ── 1. the gap: the state route could widen a DM ─────────────────────────

TEST(DirectRoomMembership, TheStateRouteCannotInviteAThirdPersonIntoADm) {
    // The reported shape. Alice is a participant AND holds MANAGE_CHANNELS,
    // which is all invite_intent() asked for, so nothing but the DM rule stands
    // between her and a third member.
    Fixture f("state-invite");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto dm = f.add_dm(alice, bob);

    auto res = f.set_member_state(dm, "token-alice", carol,
                                  std::string(membership::kInvite));

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_direct_message(res)) << res.body;
    // Both halves, separately: the status is the visible symptom, the row and
    // the event are what outlive the request.
    EXPECT_FALSE(f.has_membership_row(dm, carol));
    EXPECT_EQ(f.member_events_for(dm, carol), 0);
    EXPECT_EQ(f.store->get_membership(dm, carol), std::string(membership::kLeave));
}

TEST(DirectRoomMembership, TheStateRouteCannotForceJoinAThirdPersonIntoADm) {
    // The worse spelling, and the one that makes this more than a tidiness
    // fix. classify_transition sends `join` to the same invite_intent(), and
    // the write is a JOIN — no invite to notice and decline, no stage in
    // between. The third account is simply in the room, and every message
    // already in it is theirs to read.
    Fixture f("state-join");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto dm = f.add_dm(alice, bob);

    auto res = f.set_member_state(dm, "token-alice", carol, std::string(membership::kJoin));

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_direct_message(res)) << res.body;
    EXPECT_FALSE(f.has_membership_row(dm, carol));
    EXPECT_EQ(f.member_events_for(dm, carol), 0);

    // The backlog is the reason the rule exists, so assert the backlog. A DM
    // has no history-visibility setting to hide behind: membership IS access.
    EXPECT_FALSE(f.store->is_room_member(dm, carol));
}

TEST(DirectRoomMembership, AnAdministratorIsRefusedTheSameWay) {
    // The rule is ABOVE the permission system, not part of it. ADMINISTRATOR
    // short-circuits every flag in PermissionsEngine::compute, so a guard
    // expressed as "requires some permission nobody has in a DM" would let an
    // owner straight through — and an owner is exactly who
    // refuse_on_direct_room's comment is about: "a role that lets someone run
    // the SERVER must not let them run somebody's private conversation."
    Fixture f("state-admin");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto dm = f.add_dm(alice, bob);

    auto res = f.set_member_state(dm, "token-alice", carol, std::string(membership::kJoin));
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_FALSE(f.has_membership_row(dm, carol));
}

TEST(DirectRoomMembership, BothDoorsRefuseAnInviteWithTheSameSentence) {
    // The drift test, and the reason the rule sits on MembershipIntent rather
    // than being written out at each door. These are two different handlers
    // reaching the same refusal, and a future reword that reaches one and not
    // the other is precisely the failure that produced this gap — the client
    // matches on this text (ChannelInviteModel::explainFailure) as well as on
    // the errcode.
    Fixture f("two-doors");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto dm = f.add_dm(alice, bob);

    auto dedicated = f.invite(dm, "token-alice", carol);
    auto generic = f.set_member_state(dm, "token-alice", carol,
                                      std::string(membership::kInvite));

    EXPECT_EQ(dedicated.status, 403) << dedicated.body;
    EXPECT_EQ(generic.status, 403) << generic.body;
    EXPECT_NE(dedicated.body.find("Cannot invite someone into a direct message"),
              std::string::npos)
        << dedicated.body;
    EXPECT_NE(generic.body.find("Cannot invite someone into a direct message"),
              std::string::npos)
        << generic.body;
}

TEST(DirectRoomMembership, AParticipantWithNoPermissionsIsToldItIsADirectMessage) {
    // ORDERING, at both doors. The DM rule sits ABOVE the permission check —
    // no permission makes it false, so testing permissions first would be
    // asking a question whose answer cannot matter. The dedicated endpoint has
    // always been ordered that way; the state route now is too, and the two
    // therefore give a plain participant the same answer instead of one saying
    // "not in a DM" and the other "not allowed" for the same request.
    //
    // Nothing is disclosed by the ordering: every door into a membership write
    // checks is_room_member first, so whoever reaches this is a participant and
    // already knows the room is a DM.
    Fixture f("ordering");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");        // @everyone only: no MANAGE_CHANNELS
    auto carol = f.add_user("carol");
    auto dm = f.add_dm(alice, bob);

    auto generic = f.set_member_state(dm, "token-bob", carol,
                                      std::string(membership::kInvite));
    auto dedicated = f.invite(dm, "token-bob", carol);

    EXPECT_EQ(generic.status, 403) << generic.body;
    EXPECT_TRUE(mentions_direct_message(generic)) << generic.body;
    EXPECT_EQ(generic.body.find("Insufficient permissions"), std::string::npos)
        << generic.body;
    EXPECT_TRUE(mentions_direct_message(dedicated)) << dedicated.body;
}

TEST(DirectRoomMembership, TheDedicatedInviteEndpointStillCarriesItsErrcode) {
    // The half of the dedicated endpoint the shared rule must NOT flatten. It
    // answers seven situations behind one M_FORBIDDEN, and the client tells
    // them apart by `bsfchat.errcode`; the state route has no such contract and
    // no errcode field on its refusals. Keying the guard off the intent had to
    // leave this intact, so it is asserted rather than assumed.
    Fixture f("errcode");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto dm = f.add_dm(alice, bob);

    auto res = f.invite(dm, "token-alice", carol);
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_NE(res.body.find(std::string(refusal::kInviteDirectRoom)), std::string::npos)
        << res.body;
}

// ── 2. removal: refused, and the decision behind that ────────────────────

TEST(DirectRoomMembership, TheStateRouteCannotRemoveTheOtherParticipant) {
    // `{"membership":"leave"}` for the peer classifies as a kick (the target is
    // not banned). Refused: it would leave a one-member direct room the other
    // person cannot return to, on a SERVER moderation permission. Leaving is
    // the gesture for "I want out", and it is pinned below.
    Fixture f("state-kick");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto dm = f.add_dm(alice, bob);

    auto res = f.set_member_state(dm, "token-alice", bob, std::string(membership::kLeave));

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_direct_message(res)) << res.body;
    EXPECT_EQ(f.store->get_membership(dm, bob), std::string(membership::kJoin));
    // Two member events from add_dm and no third: nothing was written.
    EXPECT_EQ(f.member_events_for(dm, bob), 1);
}

TEST(DirectRoomMembership, TheDedicatedKickEndpointIsRefusedToo) {
    // Same act, other door. POST /rooms/{id}/kick routes through
    // apply_membership_moderation, so it picks the rule up from the same field
    // — which is the arrangement being tested as much as the refusal is.
    Fixture f("kick-endpoint");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto dm = f.add_dm(alice, bob);

    auto res = f.kick(dm, "token-alice", bob);
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_direct_message(res)) << res.body;
    EXPECT_EQ(f.store->get_membership(dm, bob), std::string(membership::kJoin));
}

// ── 3. what a DM must NOT stop: leaving ──────────────────────────────────

TEST(DirectRoomMembership, LeavingADirectMessageStillWorks) {
    // The control that a guard placed one level up — at the top of the state
    // route, or on "any m.room.member write in a direct room" — would break.
    // Wanting out of a conversation is the one membership change a participant
    // must always be able to make.
    Fixture f("leave-endpoint");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto dm = f.add_dm(alice, bob);

    EXPECT_TRUE(IsOk(f.leave(dm, "token-alice")));
    EXPECT_EQ(f.store->get_membership(dm, alice), std::string(membership::kLeave));
    EXPECT_EQ(f.store->get_membership(dm, bob), std::string(membership::kJoin));
}

TEST(DirectRoomMembership, LeavingADirectMessageThroughTheStateRouteStillWorks) {
    // The same act at the door this change touched. Self-membership returns
    // above the moderation delegation, so the rule must never see it — asserted
    // rather than reasoned about, because "it returns earlier" is a property of
    // today's control flow and this is a property of the product.
    Fixture f("leave-state");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto dm = f.add_dm(alice, bob);

    EXPECT_TRUE(IsOk(f.set_member_state(dm, "token-bob", bob,
                                        std::string(membership::kLeave))));
    EXPECT_EQ(f.store->get_membership(dm, bob), std::string(membership::kLeave));
}

// ── 4. what a DM must NOT stop: server-wide moderation ───────────────────

TEST(DirectRoomMembership, BanningFromInsideADirectMessageStillWorks) {
    // The gesture this has to keep: the person you need to ban is the person in
    // the DM window you are looking at. `room_id` is only the room the request
    // arrived through — the act is on the account — so a rule that read the
    // room and stopped there would take away the one place the button is.
    Fixture f("ban-from-dm");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto dm = f.add_dm(alice, bob);

    EXPECT_TRUE(IsOk(f.ban(dm, "token-alice", bob)));
    EXPECT_TRUE(f.store->is_server_banned(bob));
    EXPECT_EQ(f.store->get_membership(dm, bob), std::string(membership::kBan));
}

TEST(DirectRoomMembership, UnbanningFromInsideADirectMessageStillWorks) {
    // The mirror, and not a formality: a ban that reaches a DM together with an
    // unban that does not is a ban nobody can lift there, which is the state
    // handle_unban exists to stop.
    Fixture f("unban-from-dm");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto dm = f.add_dm(alice, bob);

    ASSERT_TRUE(IsOk(f.ban(dm, "token-alice", bob)));
    EXPECT_TRUE(IsOk(f.unban(dm, "token-alice", bob)));
    EXPECT_FALSE(f.store->is_server_banned(bob));
    // "leave", not "join": lifting a ban restores the ability to come back, it
    // does not decide for them that they have.
    EXPECT_EQ(f.store->get_membership(dm, bob), std::string(membership::kLeave));
}

TEST(DirectRoomMembership, AServerBanPlacedInAChannelStillReachesEveryDirectMessage) {
    // The projection, from the other side. The ban is placed in an ordinary
    // channel, so the DM rule is never even consulted for it — what is pinned
    // here is that the ban still rewrites the membership row in an unrelated
    // DM. A banned account left joined to its DMs would keep the backlog and
    // keep reading it, which is the exact blind spot the server-wide ban list
    // was added to close.
    Fixture f("ban-projection");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto channel = f.add_channel(alice, "general");
    f.store->set_membership(channel, bob, std::string(membership::kJoin));
    auto dm = f.add_dm(bob, carol);   // alice is not in it and never sees it

    EXPECT_TRUE(IsOk(f.ban(channel, "token-alice", bob)));
    EXPECT_EQ(f.store->get_membership(dm, bob), std::string(membership::kBan));
    EXPECT_EQ(f.store->get_membership(channel, bob), std::string(membership::kBan));
}

// ── 5. ordinary channels are untouched ───────────────────────────────────

TEST(DirectRoomMembership, InvitingIntoAnOrdinaryChannelStillWorksAtBothDoors) {
    // The control that says the rule is about direct rooms and not about member
    // writes. If this goes red, whatever was added is broader than the property
    // and proves nothing about it.
    Fixture f("channel-control");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto channel = f.add_channel(alice, "general");

    EXPECT_TRUE(IsOk(f.invite(channel, "token-alice", bob)));
    EXPECT_EQ(f.store->get_membership(channel, bob), std::string(membership::kInvite));

    EXPECT_TRUE(IsOk(f.set_member_state(channel, "token-alice", carol,
                                        std::string(membership::kInvite))));
    EXPECT_EQ(f.store->get_membership(channel, carol), std::string(membership::kInvite));
}

TEST(DirectRoomMembership, KickingFromAnOrdinaryChannelStillWorksAtBothDoors) {
    Fixture f("channel-kick-control");
    auto alice = f.add_user("alice", {kModeratorRole});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto channel = f.add_channel(alice, "general");
    f.store->set_membership(channel, bob, std::string(membership::kJoin));
    f.store->set_membership(channel, carol, std::string(membership::kJoin));

    EXPECT_TRUE(IsOk(f.kick(channel, "token-alice", bob)));
    EXPECT_EQ(f.store->get_membership(channel, bob), std::string(membership::kLeave));

    EXPECT_TRUE(IsOk(f.set_member_state(channel, "token-alice", carol,
                                        std::string(membership::kLeave))));
    EXPECT_EQ(f.store->get_membership(channel, carol), std::string(membership::kLeave));
}
