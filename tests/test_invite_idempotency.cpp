// An invite never demotes somebody who is already in the channel.
//
// THE BUG. handle_invite's human branch ended in an unconditional
// set_membership(room_id, target, 'invite'). set_membership is a blind upsert,
// so inviting a member who was already JOINED rewrote their row back to
// 'invite' — a moderator clicking "add member" on somebody already in the
// channel silently removed them from it. The bot branch twenty lines above had
// had the guard from the day it was written, with a comment explaining that a
// second invite must not produce a duplicate join event or a second audit
// record; nothing equivalent existed for a person.
//
// WHY IT MATTERED, which is not obvious from the row. Nearly every membership
// projection on this server is join-only, so one 'invite' write took away:
//
//   * the channel itself — get_joined_rooms filters on 'join', so it left the
//     demoted member's /sync rooms.join, and get_invited_rooms then put it back
//     as a bare invite card with no timeline and no state;
//   * reading — can_read_room starts with is_room_member (join-only), so
//     GET /rooms/{id}/state, /state/{type} and /members all began answering 403;
//   * posting and voice — EventHandler and VoiceHandler gate on the same
//     helper, so sending a message answered "Not a member of this room";
//   * presence and counts — SyncHandler's presence sweep and
//     AuditLog::joined_member_count both skip anything that is not 'join'.
//
// And none of it was audited: the human invite path writes no audit record, so
// the only trace of the removal was an m.room.member event saying 'invite',
// sent by the moderator who thought they were adding somebody.
//
// THE SUBTLE PART, and the reason the guard is join-only rather than "has a
// row". POST /rooms/{id}/invite is also the documented — and only — way to
// re-admit a user a moderator kicked (see test_kick_enforcement.cpp). That
// user's row says 'leave', and the thing that actually lets them back in is
// the invite REWRITING their m.room.member event, because was_removed_by_
// moderator reads the current event and the fresh invite content carries no
// bsfchat.removed_by marker. So a guard that skipped the write for anyone with
// an existing membership row would have made every kick permanent while the
// endpoint went on answering 200. ReAdmissionAfterAKickStillWrites is that
// interaction, pinned here as well as in test_kick_enforcement.cpp so a change
// to the invite path fails in the file it was made in.
//
// The generic state route carried the same defect by a different road:
// classify_transition folds "invite" and "join" into one intent that asserts
// nothing about the target's current membership, so
// PUT /rooms/{id}/state/m.room.member/{user} with {"membership":"invite"}
// reached apply_membership_moderation's unconditional write. Both doors are
// tested here; fixing one alone would have left the bug reachable by any
// Matrix client that writes member state directly.

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

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

ServerRole role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

// Everything goes through RoomHandler, not through the store: the subject is
// what a real request writes, and a store-level shortcut would prove nothing
// about the path a client takes.
struct Fixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<RoomHandler> rooms;
    int64_t ts = 1000;

    Fixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
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

    // A channel exactly as the client creates one: join_rule "public". Privacy
    // on this deployment is an @everyone DENY VIEW_CHANNEL override, not a join
    // rule, so a fixture that used "invite" here would not be reproducing
    // anything that exists on a real server.
    std::string add_channel(const std::string& creator) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomCreate, "", json{{"creator", creator}});
        state(room_id, creator, event_type::kRoomType, "", json{{"type", "text"}});
        state(room_id, creator, event_type::kRoomJoinRules, "",
              json{{"join_rule", join_rule::kPublic}});
        return room_id;
    }

    void state(const std::string& room_id, const std::string& sender, std::string_view type,
               const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ts++);
    }

    // A member who arrived the ordinary way: a row and the event that goes with
    // it. Writing only the row would leave the two sources disagreeing, which
    // is the one thing was_removed_by_moderator cannot survive.
    void join_directly(const std::string& room_id, const std::string& user) {
        store->set_membership(room_id, user, std::string(membership::kJoin));
        state(room_id, user, event_type::kRoomMember, user,
              json{{"membership", membership::kJoin}});
    }

    httplib::Response post(void (RoomHandler::*method)(const httplib::Request&,
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

    httplib::Response invite(const std::string& room_id, const std::string& who,
                             const std::string& target) {
        return post(&RoomHandler::handle_invite,
                    "/_matrix/client/v3/rooms/" + room_id + "/invite", "token-" + who,
                    json{{"user_id", target}}.dump());
    }

    httplib::Response kick(const std::string& room_id, const std::string& who,
                           const std::string& target) {
        return post(&RoomHandler::handle_kick,
                    "/_matrix/client/v3/rooms/" + room_id + "/kick", "token-" + who,
                    json{{"user_id", target}}.dump());
    }

    httplib::Response join_as(const std::string& room_id, const std::string& who) {
        return post(&RoomHandler::handle_join,
                    "/_matrix/client/v3/rooms/" + room_id + "/join", "token-" + who, "");
    }

    httplib::Response leave_as(const std::string& room_id, const std::string& who) {
        return post(&RoomHandler::handle_leave,
                    "/_matrix/client/v3/rooms/" + room_id + "/leave", "token-" + who, "");
    }

    // The SECOND way to write somebody else's membership, and the one a plain
    // Matrix client reaches for.
    httplib::Response set_member_state(const std::string& room_id, const std::string& who,
                                       const std::string& target,
                                       std::string_view membership_value) {
        return post(&RoomHandler::handle_set_state,
                    "/_matrix/client/v3/rooms/" + room_id + "/state/" +
                        std::string(event_type::kRoomMember) + "/" + target,
                    "token-" + who, json{{"membership", membership_value}}.dump());
    }

    std::string membership_of(const std::string& room_id, const std::string& user) {
        return store->get_membership(room_id, user);
    }

    // The membership row is only half of it. The event is what other clients
    // render, and an extra one renders as the member leaving and coming back.
    int member_events_for(const std::string& room_id, const std::string& target) {
        int n = 0;
        for (const auto& ev : store->get_room_events(room_id, 1000)) {
            if (ev.type == event_type::kRoomMember && ev.state_key && *ev.state_key == target) {
                ++n;
            }
        }
        return n;
    }

    bool in_joined_rooms(const std::string& room_id, const std::string& user) {
        auto rooms_v = store->get_joined_rooms(user);
        return std::find(rooms_v.begin(), rooms_v.end(), room_id) != rooms_v.end();
    }

    bool in_invited_rooms(const std::string& room_id, const std::string& user) {
        auto rooms_v = store->get_invited_rooms(user);
        return std::find(rooms_v.begin(), rooms_v.end(), room_id) != rooms_v.end();
    }
};

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

} // namespace

// ── 1. the bug ───────────────────────────────────────────────────────────

TEST(InviteIdempotency, InvitingAJoinedMemberDoesNotDemoteThem) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin);
    f.join_directly(room, bob);
    ASSERT_EQ(f.member_events_for(room, bob), 1);

    auto res = f.invite(room, "admin", bob);

    // Success, not a refusal: the caller asked for a state of the world that
    // already holds, which is not an error in the UI that sends this.
    EXPECT_TRUE(IsOk(res)) << res.body;
    EXPECT_EQ(res.body, "{}");

    EXPECT_EQ(f.membership_of(room, bob), membership::kJoin)
        << "the invite demoted a joined member back to an invitee";
    EXPECT_EQ(f.member_events_for(room, bob), 1)
        << "a second member event: every other client renders bob leaving";
}

// The blast radius in miniature. These two projections ARE /sync's room
// sections, so this is the difference between "nothing happened" and "the
// channel vanished from bob's sidebar and came back as an invite card".
TEST(InviteIdempotency, TheDemotionWouldHaveMovedTheRoomOutOfTheJoinedSection) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin);
    f.join_directly(room, bob);

    ASSERT_TRUE(IsOk(f.invite(room, "admin", bob)));

    EXPECT_TRUE(f.in_joined_rooms(room, bob))
        << "bob's /sync lost rooms.join for a channel he is in";
    EXPECT_FALSE(f.in_invited_rooms(room, bob))
        << "bob is being offered an invite to a channel he is already in";
    // The same helper that gates posting, voice, /state, /members and push.
    EXPECT_TRUE(f.store->is_room_member(room, bob))
        << "bob can no longer post in a channel nobody removed him from";
}

// Repeating it is still a no-op. The dialog can be clicked twice.
TEST(InviteIdempotency, RepeatedInvitesOfAJoinedMemberStayANoOp) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin);
    f.join_directly(room, bob);

    for (int attempt = 0; attempt < 3; ++attempt) {
        EXPECT_TRUE(IsOk(f.invite(room, "admin", bob))) << "attempt " << attempt;
    }
    EXPECT_EQ(f.membership_of(room, bob), membership::kJoin);
    EXPECT_EQ(f.member_events_for(room, bob), 1);
}

// ── 2. the same bug through the generic state route ──────────────────────

TEST(InviteIdempotency, TheStateRouteCannotDemoteAJoinedMemberEither) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin);
    f.join_directly(room, bob);

    auto res = f.set_member_state(room, "admin", bob, membership::kInvite);

    EXPECT_TRUE(IsOk(res)) << res.body;
    EXPECT_EQ(f.membership_of(room, bob), membership::kJoin)
        << "PUT /state/m.room.member/{user} with 'invite' demoted a joined member";
    EXPECT_EQ(f.member_events_for(room, bob), 1);
}

// The same intent serves {"membership":"join"}, which is how a Matrix client
// writes a force-join. Against somebody already joined it is equally a no-op,
// and writing it anyway produced a duplicate join event and an audit record for
// a change that did not happen.
TEST(InviteIdempotency, TheStateRouteDoesNotRewriteAnExistingJoin) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin);
    f.join_directly(room, bob);

    EXPECT_TRUE(IsOk(f.set_member_state(room, "admin", bob, membership::kJoin)));
    EXPECT_EQ(f.membership_of(room, bob), membership::kJoin);
    EXPECT_EQ(f.member_events_for(room, bob), 1);
}

// The no-op must not have disarmed the DELIBERATE downgrades that share this
// code path. A kick is a downgrade of a joined member and is the whole point of
// the route's moderation branch.
TEST(InviteIdempotency, TheStateRouteCanStillRemoveAJoinedMember) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin);
    f.join_directly(room, bob);

    EXPECT_TRUE(IsOk(f.set_member_state(room, "admin", bob, membership::kLeave)));
    EXPECT_EQ(f.membership_of(room, bob), membership::kLeave);
    EXPECT_EQ(f.member_events_for(room, bob), 2);
}

// ── 3. what the guard must NOT catch ─────────────────────────────────────

// Re-admission. The invite has to still WRITE for a kicked user, because the
// write is what clears the removal marker — see the file header.
TEST(InviteIdempotency, ReAdmissionAfterAKickStillWrites) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(admin);
    f.join_directly(room, mallory);

    ASSERT_TRUE(IsOk(f.kick(room, "admin", mallory)));
    ASSERT_EQ(f.membership_of(room, mallory), membership::kLeave);
    const int after_kick = f.member_events_for(room, mallory);

    ASSERT_TRUE(IsOk(f.invite(room, "admin", mallory)));

    EXPECT_EQ(f.membership_of(room, mallory), membership::kInvite)
        << "the idempotence guard swallowed a re-admission; the kick is now permanent";
    EXPECT_EQ(f.member_events_for(room, mallory), after_kick + 1);

    // The mechanism, asserted directly rather than only through its effect: the
    // fresh invite event replaces the kick's, and carries no removal marker.
    auto current = f.store->get_state_event(room, std::string(event_type::kRoomMember), mallory);
    ASSERT_TRUE(current.has_value());
    EXPECT_EQ(current->content.data.value("membership", ""), membership::kInvite);
    EXPECT_FALSE(current->content.data.contains("bsfchat.removed_by"))
        << "the removal marker outlived the invite that was supposed to clear it";

    // And the effect: mallory can actually get back in.
    EXPECT_TRUE(IsOk(f.join_as(room, "mallory")));
    EXPECT_EQ(f.membership_of(room, mallory), membership::kJoin);
}

// Leaving is how somebody hides a channel on this deployment — auto-join puts
// everyone in everything — so invite-after-leave is ordinary use, not an edge
// case, and the guard must not swallow it either.
TEST(InviteIdempotency, SomebodyWhoLeftCanStillBeInvitedBack) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin);
    f.join_directly(room, bob);

    ASSERT_TRUE(IsOk(f.leave_as(room, "bob")));
    ASSERT_EQ(f.membership_of(room, bob), membership::kLeave);

    ASSERT_TRUE(IsOk(f.invite(room, "admin", bob)));
    EXPECT_EQ(f.membership_of(room, bob), membership::kInvite);
}

// The ordinary case, which is the control for every mutation of this guard: a
// stranger is still invited.
TEST(InviteIdempotency, InvitingSomebodyWhoIsNotInTheChannelStillWorks) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto carol = f.add_user("carol");
    auto room = f.add_channel(admin);

    ASSERT_TRUE(IsOk(f.invite(room, "admin", carol)));
    EXPECT_EQ(f.membership_of(room, carol), membership::kInvite);
    EXPECT_EQ(f.member_events_for(room, carol), 1);
    EXPECT_TRUE(f.in_invited_rooms(room, carol));
}

// A pending invitee is not a joined member, so the guard does not apply and a
// second invite is still sent. Pinned so that widening the guard to "has any
// membership row" fails here as well as at re-admission.
TEST(InviteIdempotency, ASecondInviteToAPendingInviteeIsStillWritten) {
    Fixture f;
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto carol = f.add_user("carol");
    auto room = f.add_channel(admin);

    ASSERT_TRUE(IsOk(f.invite(room, "admin", carol)));
    ASSERT_TRUE(IsOk(f.invite(room, "admin", carol)));
    EXPECT_EQ(f.membership_of(room, carol), membership::kInvite);
}
