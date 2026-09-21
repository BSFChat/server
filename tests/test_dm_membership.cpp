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

    // `room_create_limit` is a ctor parameter rather than a poke at `config`
    // after the fact, because RoomHandler builds its SendLimiter FROM the
    // config in its own constructor — a later assignment would not reach it.
    // The rate-limit tests pass a small number so they exercise the MECHANISM
    // and not the configured default: at the shipped 30 they would have to
    // register 33 accounts and bcrypt each one, and they would silently stop
    // testing anything the day somebody tuned the number.
    explicit Fixture(const std::string& name, int room_create_limit = 0) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        if (room_create_limit > 0) config.send_limits.room_create_limit = room_create_limit;
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

    // ── the door a DM is BORN through ────────────────────────────────────
    //
    // Everything above acts on a DM the fixture built directly in the store.
    // These go through POST /createRoom, because that is the only place on the
    // server that decides what a direct room IS — and, before
    // fix/direct-room-guard, the only place it could be decided wrongly.
    httplib::Response create(const std::string& token, const json& body) {
        return call(&RoomHandler::handle_create_room,
                    "/_matrix/client/v3/createRoom", token, body.dump());
    }

    httplib::Response create_dm(const std::string& token, const std::string& peer) {
        return create(token, json{{"is_direct", true}, {"invite", json::array({peer})}});
    }

    httplib::Response destroy(const std::string& room_id, const std::string& token) {
        return call(&RoomHandler::handle_delete_room,
                    "/_matrix/client/v3/rooms/" + room_id, token, "");
    }

    static std::string room_id_of(const httplib::Response& res) {
        if (res.body.empty()) return "";
        return json::parse(res.body).value("room_id", "");
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


// ─────────────────────────────────────────────────────────────────────────
// 6. THE SHAPE OF A DM IS DECIDED WHERE IT IS CREATED
//
// Everything above this line enforces "a DM stays two people" against a DM
// that already exists. None of it could say anything about one that was born
// with five, and POST /createRoom would make you one: `is_direct` came
// straight out of the request body and skipping the MANAGE_CHANNELS check was
// the only thing it did, so `{"is_direct": true, "invite": [a, b, c]}` from an
// account holding nothing but @everyone produced a room that
//
//   * force-JOINED all three (this file's invite loop, `is_direct` => kJoin),
//   * could not be hidden from them (compute() clears overrides on a DM),
//   * no administrator could find (the directory excludes DMs in SQL),
//   * no administrator could delete (participants only), and
//   * nobody could be kicked from (the rule at the top of this file).
//
// That is finding F3 of docs/audit-permissions-2026-09.md and the only finding
// in it reachable from a default account. Its proofs are in
// tests/test_permission_audit_2026_09.cpp; what is below is the rest of the
// property, including the controls that say the fix is not broader than it.
//
// WHY EXACTLY TWO, established rather than assumed — this is the question the
// audit deliberately left for an owner, because capping `invite` at one breaks
// any client that opens a group DM. There is no such client. The desktop
// client's only DM path is ServerConnection::createDirectMessage(QString), a
// single scalar user id, reached from four UI affordances that each pass one
// person (the New DM dialog's single text field, the profile card's Message
// button, the member-list context menu, and /dm); MatrixClient::
// createDirectMessageRoom does one push_back onto `invite`; DirectRooms keeps
// QMap<roomId, peer> — one peer per room — and every DM header renders that
// one peer. The server never modelled anything else either: get_direct_rooms()
// returns (room, peer) PAIRS and /sync turns them into an m.direct keyed by
// peer, so a three-person direct room lists itself under two different people.
// "Group DM" appears nowhere in the client, the protocol or this repo outside
// the audit's own note. Nothing is being taken away.
// ─────────────────────────────────────────────────────────────────────────

TEST(DirectRoomMembership, AnOrdinaryMemberCanStillOpenAOneToOneDm) {
    // THE CONTROL, and it is first on purpose. Everything else in this section
    // is a refusal, and a suite of refusals cannot tell a fix from a blanket
    // ban on the feature — which is the failure mode mutate_dm_membership.py's
    // M4 exists to provoke. Opening a DM must go on costing NO permission at
    // all: that is what `is_direct` is for and the reason it was ungated.
    Fixture f("create-dm-control");
    auto alice = f.add_user("alice");   // @everyone only. No moderator role.
    auto bob = f.add_user("bob");

    auto res = f.create_dm("token-alice", bob);
    ASSERT_TRUE(IsOk(res)) << res.body;
    const auto dm = Fixture::room_id_of(res);
    ASSERT_FALSE(dm.empty());

    EXPECT_TRUE(f.store->is_direct_room(dm));
    EXPECT_EQ(f.store->get_membership(dm, alice), std::string(membership::kJoin));
    // The peer is JOINED, not invited: there is no invite delivery channel in
    // /sync, so this is how a DM reaches the other side at all.
    EXPECT_EQ(f.store->get_membership(dm, bob), std::string(membership::kJoin));
}

TEST(DirectRoomMembership, AMemberStillCannotCreateAChannel) {
    // The check `is_direct` used to walk around, pinned here so that a fix
    // which accidentally made createRoom permissive for everyone is visible in
    // this file rather than only in the audit's.
    Fixture f("create-channel-control");
    f.add_user("alice");
    auto res = f.create("token-alice", json{{"name", "general"}});
    EXPECT_EQ(res.status, 403) << res.body;
}

TEST(DirectRoomMembership, IsDirectWithMoreThanOneInviteeIsRefused) {
    // F3 itself. Mallory holds @everyone and nothing else.
    Fixture f("create-dm-three");
    f.add_user("mallory");
    auto v1 = f.add_user("victim1");
    auto v2 = f.add_user("victim2");
    auto v3 = f.add_user("victim3");

    auto res = f.create("token-mallory",
                        json{{"is_direct", true},
                             {"invite", json::array({v1, v2, v3})}});

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_direct_message(res)) << res.body;
    // The status is the symptom; what matters is that nothing was written. No
    // room, so no membership row, no m.room.member event and no sync wake for
    // three people who never asked for any of it.
    EXPECT_TRUE(f.store->get_direct_rooms(v1).empty());
    EXPECT_TRUE(f.store->get_direct_rooms(v2).empty());
    EXPECT_TRUE(f.store->get_direct_rooms(v3).empty());
}

TEST(DirectRoomMembership, IsDirectIsRefusedForAModeratorToo) {
    // The rule is STRUCTURAL, not a permission the right role gets to skip —
    // the same shape as the refusals at the top of this file. A room that no
    // directory lists, no override can hide and no kick can empty is
    // unmanageable whoever made it, so MANAGE_CHANNELS is not a licence to
    // manufacture one. Without this, the fix would only have moved F3 from
    // "@everyone can do it" to "a channel moderator can do it".
    Fixture f("create-dm-three-mod");
    f.add_user("alice", {kModeratorRole});
    auto b = f.add_user("bob");
    auto c = f.add_user("carol");

    auto res = f.create("token-alice",
                        json{{"is_direct", true}, {"invite", json::array({b, c})}});
    EXPECT_EQ(res.status, 403) << res.body;
}

TEST(DirectRoomMembership, IsDirectWithNoInviteesIsRefused) {
    // The empty list is the same room by another spelling: one member, no
    // directory entry, no remedy. Nothing in the client can open one, so
    // nothing is lost by refusing it.
    Fixture f("create-dm-empty");
    f.add_user("alice");
    EXPECT_EQ(f.create("token-alice", json{{"is_direct", true}}).status, 403);
    EXPECT_EQ(f.create("token-alice",
                       json{{"is_direct", true}, {"invite", json::array()}}).status, 403);
}

TEST(DirectRoomMembership, IsDirectWithOnlySelfIsRefused) {
    // And this one would also defeat the dedup in handle_create_room — the pair
    // (me, me) can never match an existing direct room, so every request would
    // mint a fresh one. An unbounded supply of undeletable rooms, one request
    // each, with a single user id needed to ask.
    Fixture f("create-dm-self");
    auto alice = f.add_user("alice");
    EXPECT_EQ(f.create("token-alice",
                       json{{"is_direct", true}, {"invite", json::array({alice})}}).status,
              403);
}

TEST(DirectRoomMembership, ADuplicatedInviteeIsNotAWayAroundTheCap) {
    // `{"invite": [bob, bob]}` is two entries naming one person, and the loop
    // that consumes it would have skipped the second as a no-op — so a cap
    // written as "the list must name at most two DISTINCT accounts" would let
    // this through and then have to decide what it meant. The rule is about the
    // LIST, not about who survives it, which is the version a reader can check.
    Fixture f("create-dm-dupe");
    f.add_user("alice");
    auto bob = f.add_user("bob");
    EXPECT_EQ(f.create("token-alice",
                       json{{"is_direct", true}, {"invite", json::array({bob, bob})}}).status,
              403);
}

TEST(DirectRoomMembership, ADirectRoomCannotBeCreatedAsServerStructure) {
    // A DM is not part of the channel tree, and handle_set_state already
    // refuses bsfchat.room.category, bsfchat.room.type, m.room.join_rules and
    // bsfchat.channel.permissions on one. Creation was the hole in that rule:
    // every field below could be written into a direct room, at creation, by a
    // caller who would have needed MANAGE_CHANNELS to write it one request
    // later. Doing the ungated thing first is not a different act.
    Fixture f("create-dm-structure");
    f.add_user("alice");
    auto bob = f.add_user("bob");
    auto parent = f.add_channel("@alice:test", "category");

    auto with = [&](const json& extra) {
        json body{{"is_direct", true}, {"invite", json::array({bob})}};
        body.update(extra);
        return f.create("token-alice", body).status;
    };

    EXPECT_EQ(with(json{{"name", "not a dm"}}), 403);
    EXPECT_EQ(with(json{{"topic", "not a dm"}}), 403);
    EXPECT_EQ(with(json{{"is_category", true}}), 403);
    EXPECT_EQ(with(json{{"voice", true}}), 403);
    EXPECT_EQ(with(json{{"parent_id", parent}}), 403);
}

TEST(DirectRoomMembership, RefusingTheShapeSaysNothingAboutWhoExists) {
    // The shape rules sit ABOVE the permission check, which everywhere else in
    // RoomHandler.cpp is only safe once the caller has proven membership. It is
    // safe here for a different reason, and the reason is worth pinning: every
    // sentence the rule can return is a statement about the body the caller
    // just wrote, and none of them reads the store. So a well-formed DM request
    // naming an account that does not exist must NOT be refused — createRoom
    // needs no permission, so a refusal there would answer "does @x exist?" for
    // anyone who asked.
    Fixture f("create-dm-oracle");
    f.add_user("alice");
    auto real = f.add_user("bob");

    auto ghost = f.create_dm("token-alice", "@nobody:test");
    auto present = f.create_dm("token-alice", real);
    EXPECT_TRUE(IsOk(ghost)) << ghost.body;
    EXPECT_TRUE(IsOk(present)) << present.body;
    // Same answer either way, which is the property. The cost is a one-member
    // room; the alternative cost is a user directory nobody published.
    EXPECT_EQ(ghost.status, present.status);
}

TEST(DirectRoomMembership, CreatingRoomsIsRateLimited) {
    // The fan-out half of F3, and it is separate from the cap. The cap bounds
    // one request; this bounds the requests. createRoom is the most expensive
    // write the server has — a room row, half a dozen state events, a
    // membership row plus a member event plus a sync wake per participant — and
    // it is the ONLY such route every authenticated account can reach, because
    // opening a DM is deliberately ungated. Before this it had no limiter at
    // all: SendLimiter had buckets for send, redact, media upload and profile,
    // and RoomHandler held none.
    Fixture f("create-rate", /*room_create_limit=*/3);
    f.add_user("alice");
    std::vector<std::string> peers;
    for (int i = 0; i < f.config.send_limits.room_create_limit + 3; ++i) {
        peers.push_back(f.add_user("peer" + std::to_string(i)));
    }

    int refused = 0;
    for (const auto& peer : peers) {
        if (f.create_dm("token-alice", peer).status == 429) ++refused;
    }
    EXPECT_GT(refused, 0) << "POST /createRoom has no rate limit";
}

TEST(DirectRoomMembership, TheRateLimitIsChargedBelowTheRefusals) {
    // Ordering, and it is the same one EventHandler::handle_send uses. A budget
    // spent above a refusal is an oracle: a caller could probe which bodies are
    // accepted by watching where the 429 boundary falls instead of reading the
    // 403s. A budget spent below one only meters work the server was going to
    // do. So a wall of refused requests must not exhaust the bucket.
    Fixture f("create-rate-order", /*room_create_limit=*/3);
    f.add_user("alice");
    auto bob = f.add_user("bob");

    for (int i = 0; i < f.config.send_limits.room_create_limit * 4; ++i) {
        ASSERT_EQ(f.create("token-alice", json{{"is_direct", true}}).status, 403);
    }
    // The first request that describes a real DM still gets one.
    EXPECT_TRUE(IsOk(f.create_dm("token-alice", bob)));
}

// ─────────────────────────────────────────────────────────────────────────
// 7. THE OTHER SIDE OF THE PAIR RULE: find_direct_room
// ─────────────────────────────────────────────────────────────────────────

TEST(DirectRoomMembership, AManufacturedMultiPartyRoomIsNotHandedBackAsSomebodysDm) {
    // THE CONFUSED DEPUTY, and the reason the pair rule is enforced where a DM
    // is READ as well as where it is written.
    //
    // find_direct_room() answers "the oldest direct room these two are both
    // joined to", which stopped being the same question as "their DM" the
    // moment a direct room could hold three people. Given a room holding
    // {mallory, alice, bob} — which any account could manufacture before the
    // cap landed — the next time alice opened a DM with bob, handle_create_room
    // deduped against it and handed back MALLORY'S room, and the two of them
    // held a private conversation in front of him. Oldest-first ordering means
    // the manufactured room beats a real one created later.
    //
    // Refusing the write stops NEW ones and does nothing for a database that
    // already carries one, exactly as PermissionsEngine::compute() argues for
    // clearing channel overrides on a direct room rather than trusting the
    // route that refuses to write them. So the room simply stops matching, and
    // alice and bob get a clean two-person room minted instead: the repair
    // happens by itself, on the next attempt, with nothing to migrate.
    Fixture f("dedup-poisoned");
    auto mallory = f.add_user("mallory");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    // Built in the store, because the handler will no longer make one.
    auto poisoned = f.add_dm(mallory, alice);
    f.store->set_membership(poisoned, bob, std::string(membership::kJoin));
    ASSERT_TRUE(f.store->is_direct_room(poisoned));

    auto res = f.create_dm("token-alice", bob);
    ASSERT_TRUE(IsOk(res)) << res.body;
    const auto dm = Fixture::room_id_of(res);
    ASSERT_FALSE(dm.empty());
    EXPECT_NE(dm, poisoned) << "alice and bob were handed a room mallory is sitting in";
    EXPECT_EQ(f.store->get_membership(dm, mallory), std::string(membership::kLeave));
}

TEST(DirectRoomMembership, OpeningTheSameDmTwiceStillReturnsTheSameRoom) {
    // The control for the one above. The dedup exists because a client can only
    // de-duplicate against what it has already synced, which loses to a second
    // device and to both people clicking at once; a member-count rule that
    // broke it would replace one bug with another.
    Fixture f("dedup-control");
    f.add_user("alice");
    auto bob = f.add_user("bob");

    auto first = f.create_dm("token-alice", bob);
    ASSERT_TRUE(IsOk(first));
    auto second = f.create_dm("token-alice", bob);
    ASSERT_TRUE(IsOk(second));
    EXPECT_EQ(Fixture::room_id_of(first), Fixture::room_id_of(second));
    // And from the other side, which is the case a per-client dedup cannot see.
    auto third = f.create_dm("token-bob", "@alice:test");
    ASSERT_TRUE(IsOk(third));
    EXPECT_EQ(Fixture::room_id_of(first), Fixture::room_id_of(third));
}

// ─────────────────────────────────────────────────────────────────────────
// 8. THE ADMINISTRATION REMEDY, AND WHY IT IS NARROWER THAN THE AUDIT ASKED
//
// F3's other half: with the four DM predicates composed, a room marked
// `is_direct` had no moderation remedy at all — invisible to the channel
// directory, unhideable by an override, unkickable, and undeletable by anyone
// outside it. An unprivileged account could manufacture one.
//
// The audit's proof for this (F3b, tests/test_permission_audit_2026_09.cpp)
// asserts that an ADMINISTRATOR can delete the room such an account made. It
// is left DISABLED, and this is the argument, recorded here because the next
// person to read that test will ask.
//
// F3b builds its room with ONE invitee. Before the creation rule that was
// still a bypass — `is_direct` skipped the permission check whatever the list
// looked like — so the room was an artefact of the hole and deleting it was
// obviously right. After the creation rule it is an ordinary two-person DM,
// indistinguishable from any other, and no predicate exists that could tell
// them apart. So satisfying F3b now means "an administrator can delete
// anybody's DM", which
//
//   * is not what the audit argued for anywhere in its text,
//   * reverses DirectRoomIsolation.AnAdminOutsideADmCannotDeleteIt in
//     test_regressions.cpp — an enabled test with a prior incident behind it,
//     and the two cannot both be green, and
//   * changes what m.direct is derived against. A DM's privacy is its
//     membership; an operator who can destroy one at will is a different
//     promise, and reopening a closed privacy finding to close an abuse
//     finding is a bad trade even when both are real.
//
// What ships instead is scoped to the SHAPE rather than to the actor: a direct
// room whose joined membership is not exactly two people is not a direct
// message, and MANAGE_CHANNELS at SERVER scope may remove it. That closes the
// gap completely, because after the creation rule a room in that state cannot
// be made — every one that exists is manufactured by the hole or left over
// from a database that ran the vulnerable code. A genuine DM keeps exactly the
// protection it had, and the residual case for one has remedies that already
// exist and are correctly scoped: ban the sender (a ban is an act on the
// ACCOUNT and deliberately reaches a DM), or leave.
//
// Enumeration is untouched either way, and that is the limit that matters
// most — it is pinned last in this section.
// ─────────────────────────────────────────────────────────────────────────

TEST(DirectRoomMembership, AnAdministratorCanDeleteAManufacturedMultiPartyDirectRoom) {
    // The remedy, aimed at the thing that needed one. This room cannot be
    // created any more; a database that ran the vulnerable code still has them.
    Fixture f("dm-delete-manufactured");
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");
    auto v1 = f.add_user("victim1");
    auto v2 = f.add_user("victim2");
    auto fake = f.add_dm(mallory, v1);
    f.store->set_membership(fake, v2, std::string(membership::kJoin));

    EXPECT_TRUE(IsOk(f.destroy(fake, "token-admin"))) << "no remedy for a reported room";
    EXPECT_FALSE(f.store->room_exists(fake));
}

TEST(DirectRoomMembership, AnAdministratorStillCannotDeleteAGenuineTwoPersonDm) {
    // THE LINE, and the assertion that says the remedy above is scoped to a
    // broken shape rather than handed to a role. Same actor, same route, same
    // is_direct flag; the only difference is that this room is what it claims
    // to be. DirectRoomIsolation.AnAdminOutsideADmCannotDeleteIt pins the same
    // property from the regression suite — it is restated here because this is
    // the file where somebody will come looking for it after reading F3b.
    Fixture f("dm-delete-genuine");
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto dm = f.add_dm(alice, bob);

    EXPECT_EQ(f.destroy(dm, "token-admin").status, 403);
    EXPECT_TRUE(f.store->room_exists(dm));
    EXPECT_TRUE(f.store->is_room_member(dm, bob));
}

TEST(DirectRoomMembership, AParticipantOfAManufacturedRoomDoesNotNeedTheException) {
    // The exception is about people OUTSIDE the room; the participant path is
    // untouched, and a participant without MANAGE_CHANNELS is refused by the
    // ordinary permission check below it exactly as before.
    Fixture f("dm-delete-participant");
    auto mallory = f.add_user("mallory");
    auto v1 = f.add_user("victim1");
    auto v2 = f.add_user("victim2");
    auto fake = f.add_dm(mallory, v1);
    f.store->set_membership(fake, v2, std::string(membership::kJoin));

    EXPECT_EQ(f.destroy(fake, "token-victim2").status, 403);
    EXPECT_TRUE(f.store->room_exists(fake));
}

TEST(DirectRoomMembership, AnOrdinaryMemberCannotDeleteAnyDirectRoom) {
    // The floor, both shapes. MANAGE_CHANNELS at server scope is the gate for
    // the exception, so @everyone is exactly where it was.
    Fixture f("dm-delete-member");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    f.add_user("mallory");
    auto dm = f.add_dm(alice, bob);
    auto fake = f.add_dm(alice, carol);
    f.store->set_membership(fake, bob, std::string(membership::kJoin));

    EXPECT_EQ(f.destroy(dm, "token-mallory").status, 403);
    EXPECT_EQ(f.destroy(fake, "token-mallory").status, 403);
    EXPECT_TRUE(f.store->room_exists(dm));
    EXPECT_TRUE(f.store->room_exists(fake));
}

TEST(DirectRoomMembership, DeletingAManufacturedRoomIsAuditedAndNamesNobody) {
    // The remedy has to leave a trace — that is most of what makes it a
    // guardrail rather than a hole. And the record must stay a record: it names
    // the room, the actor and a member COUNT, never a member list and never a
    // line of content, which is what keeps a delete from being a read.
    Fixture f("dm-delete-audit");
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");
    auto v1 = f.add_user("victim1");
    auto v2 = f.add_user("victim2");
    auto fake = f.add_dm(mallory, v1);
    f.store->set_membership(fake, v2, std::string(membership::kJoin));

    ASSERT_TRUE(IsOk(f.destroy(fake, "token-admin")));
    SqliteStore::AuditFilter only_this_room;
    only_this_room.target_room = fake;
    auto page = f.store->list_audit_records(100, std::nullopt, only_this_room);
    bool found = false;
    for (const auto& rec : page.records) {
        found = true;
        EXPECT_EQ(rec.actor, "@admin:test");
        for (const auto& participant : {mallory, v1, v2}) {
            EXPECT_EQ(rec.before_json.find(participant), std::string::npos)
                << "the audit record names a participant: " << rec.before_json;
        }
    }
    EXPECT_TRUE(found) << "deleting a direct room left no audit record";
}

TEST(DirectRoomMembership, NothingLetsAnAdministratorDiscoverDirectRoomsToDelete) {
    // THE LIMIT that matters most, and the assertion that keeps the judgement
    // above honest. The remedy is report-driven: it acts on an id somebody
    // handed over. Nothing added here hands ids over. If this test ever goes
    // red, the product changed, and this comment is the place that said so.
    Fixture f("dm-delete-no-enumeration");
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto dm = f.add_dm(alice, bob);
    auto fake = f.add_dm(alice, carol);
    f.store->set_membership(fake, bob, std::string(membership::kJoin));
    auto channel = f.add_channel("@admin:test", "general");

    auto res = f.call(&RoomHandler::handle_channel_directory,
                      "/_matrix/client/v3/bsfchat/channels", "token-admin", "");
    ASSERT_TRUE(IsOk(res)) << res.body;
    EXPECT_EQ(res.body.find(dm), std::string::npos)
        << "the channel directory is listing a direct room to an administrator";
    // Including the broken-shaped one. Being deletable once reported must not
    // become being listed.
    EXPECT_EQ(res.body.find(fake), std::string::npos)
        << "the channel directory is listing a manufactured direct room";
    EXPECT_NE(res.body.find(channel), std::string::npos) << "control: the channel is listed";

    // And the administrator's own m.direct is their own DMs only.
    EXPECT_TRUE(f.store->get_direct_rooms("@admin:test").empty());
}
