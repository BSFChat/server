// Kick enforcement — docs/audit-requests-2026-09.md finding 6.
//
// A kick used to set `membership = 'leave'` and nothing else, and POST
// /rooms/{id}/join checked only the server ban list, the room's existence, the
// DM guard and the join_rule. Since the client hardcodes visibility="public"
// for every channel — privacy here is an @everyone DENY VIEW_CHANNEL override,
// not a join rule — the rule check always passed, so a kicked user was back
// with one empty POST. The middle rung of the moderation ladder did not exist.
//
// The rule now: /join refuses when the caller's current m.room.member says
// `leave` AND that event records a removal by somebody else.
//
// WHY THE SENDER ALONE IS NOT THE TEST, which is the whole subtlety here.
// "sender != the user" looks like it identifies a kick, and it does not: the
// UNBAN path writes `{"membership":"leave"}` with sender = the moderator into
// every room where the target's row was `ban`
// (RoomHandler::project_membership_everywhere, via unban_intent). Its comment
// says plainly that this is meant to restore the user's ability to come back —
// "it does not decide for them that they have". A sender-only rule would
// therefore lock every unbanned user out of every channel on the server,
// permanently, which is a far worse bug than the one being fixed. So the kick
// marks its own event at the one place that knows which act is happening, and
// /join reads the marker.
//
// The marker is on the KICK rather than on the unban on purpose: rows written
// before this change carry neither, so marking the kick means historical kicks
// stay rejoinable (today's behaviour, no regression) while marking the unban
// would silently re-lock everyone unbanned before the upgrade.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <memory>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

::testing::AssertionResult IsForbidden(const httplib::Response& res) {
    if (res.status == 403) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure()
           << "expected 403, got " << res.status << ", body: " << res.body;
}

struct Fixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<RoomHandler> handler;

    Fixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        seed_roles();
        handler = std::make_unique<RoomHandler>(*store, *sync, config);
    }

    // A moderator role that outranks a plain member: every moderation endpoint
    // refuses on RANK before it refuses on permission, so an actor at the same
    // position as the target produces a 403 whatever the rest of the code does.
    void seed_roles() {
        ServerRolesContent c;
        ServerRole everyone;
        everyone.id = std::string(permission::role_id::kEveryone);
        everyone.name = "everyone";
        everyone.position = 0;
        everyone.permissions = permission::kEveryoneDefault;
        c.roles.push_back(everyone);

        ServerRole mod;
        mod.id = std::string(permission::role_id::kModerator);
        mod.name = "moderator";
        mod.position = 10;
        mod.permissions = permission::kEveryoneDefault | permission::kKickMembers |
                          permission::kBanMembers | permission::kManageChannels;
        c.roles.push_back(mod);

        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart, bool moderator = false) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev");
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        if (moderator) c.role_ids.push_back(std::string(permission::role_id::kModerator));
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    // A channel exactly as the client creates one: join_rule "public", which is
    // why the join_rule check was never the gate.
    std::string add_channel(const std::string& creator) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomJoinRules), std::string(""),
                            json{{"join_rule", "public"}}.dump(), 1000);
        return room_id;
    }

    void join_directly(const std::string& room, const std::string& user) {
        store->set_membership(room, user, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room, user,
                            std::string(event_type::kRoomMember), user,
                            json{{"membership", membership::kJoin}}.dump(), 1001);
    }

    httplib::Response post(void (RoomHandler::*method)(const httplib::Request&,
                                                       httplib::Response&),
                           const std::string& path, const std::string& token,
                           const std::string& body = "") {
        auto req = make_request(path, token, body);
        httplib::Response res;
        ((*handler).*method)(req, res);
        return res;
    }

    httplib::Response join_as(const std::string& room, const std::string& who) {
        return post(&RoomHandler::handle_join, "/_matrix/client/v3/rooms/" + room + "/join",
                    "token-" + who);
    }

    httplib::Response leave_as(const std::string& room, const std::string& who) {
        return post(&RoomHandler::handle_leave, "/_matrix/client/v3/rooms/" + room + "/leave",
                    "token-" + who);
    }

    httplib::Response kick(const std::string& room, const std::string& mod_localpart,
                           const std::string& target) {
        return post(&RoomHandler::handle_kick, "/_matrix/client/v3/rooms/" + room + "/kick",
                    "token-" + mod_localpart, json{{"user_id", target}}.dump());
    }

    httplib::Response ban(const std::string& room, const std::string& mod_localpart,
                          const std::string& target) {
        return post(&RoomHandler::handle_ban, "/_matrix/client/v3/rooms/" + room + "/ban",
                    "token-" + mod_localpart, json{{"user_id", target}}.dump());
    }

    httplib::Response unban(const std::string& room, const std::string& mod_localpart,
                            const std::string& target) {
        return post(&RoomHandler::handle_unban, "/_matrix/client/v3/rooms/" + room + "/unban",
                    "token-" + mod_localpart, json{{"user_id", target}}.dump());
    }

    httplib::Response invite(const std::string& room, const std::string& mod_localpart,
                             const std::string& target) {
        return post(&RoomHandler::handle_invite, "/_matrix/client/v3/rooms/" + room + "/invite",
                    "token-" + mod_localpart, json{{"user_id", target}}.dump());
    }

    std::string membership_of(const std::string& room, const std::string& user) {
        return store->get_membership(room, user);
    }
};

} // namespace

// ── The bug itself ────────────────────────────────────────────────────────

TEST(KickEnforcement, AKickedUserCannotRejoin) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(mod);
    f.join_directly(room, mallory);

    ASSERT_TRUE(IsOk(f.kick(room, "mod", mallory)));
    ASSERT_EQ(f.membership_of(room, mallory), membership::kLeave);

    EXPECT_TRUE(IsForbidden(f.join_as(room, "mallory")));
    EXPECT_EQ(f.membership_of(room, mallory), membership::kLeave)
        << "the refused join still wrote a membership row";
}

// The join_rule was never the gate and must not be mistaken for one: the client
// hardcodes public for every channel, so a fix that leaned on join_rules would
// do nothing at all on a real deployment. Asserted explicitly so nobody
// "simplifies" the check into one.
TEST(KickEnforcement, RefusalHoldsOnAPublicJoinRuleChannel) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(mod);
    f.join_directly(room, mallory);

    auto rules = f.store->get_state_event(room, std::string(event_type::kRoomJoinRules), "");
    ASSERT_TRUE(rules.has_value());
    ASSERT_EQ(rules->content.data.value("join_rule", ""), "public")
        << "fixture no longer reproduces the shape the client creates";

    ASSERT_TRUE(IsOk(f.kick(room, "mod", mallory)));
    EXPECT_TRUE(IsForbidden(f.join_as(room, "mallory")));
}

// ── What must keep working ────────────────────────────────────────────────

// Leaving is how a user hides a channel they do not want on this deployment —
// auto-join puts everybody in everything — so leave-and-rejoin is ordinary use,
// not an edge case.
TEST(KickEnforcement, AUserWhoLeftVoluntarilyCanRejoin) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto alice = f.add_user("alice");
    auto room = f.add_channel(mod);
    f.join_directly(room, alice);

    ASSERT_TRUE(IsOk(f.leave_as(room, "alice")));
    ASSERT_EQ(f.membership_of(room, alice), membership::kLeave);

    EXPECT_TRUE(IsOk(f.join_as(room, "alice")));
    EXPECT_EQ(f.membership_of(room, alice), membership::kJoin);
}

// The un-kick path, which is now the ONLY way back in. It has to work, and it
// has to work through the endpoint that already exists.
TEST(KickEnforcement, AnInviteAfterAKickReadmits) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(mod);
    f.join_directly(room, mallory);

    ASSERT_TRUE(IsOk(f.kick(room, "mod", mallory)));
    ASSERT_TRUE(IsForbidden(f.join_as(room, "mallory")));

    ASSERT_TRUE(IsOk(f.invite(room, "mod", mallory)));
    EXPECT_TRUE(IsOk(f.join_as(room, "mallory")));
    EXPECT_EQ(f.membership_of(room, mallory), membership::kJoin);
}

// And the readmitted user is fully readmitted: a second voluntary leave must
// not resurrect the old removal.
TEST(KickEnforcement, AReadmittedUserCanLeaveAndRejoinAgain) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(mod);
    f.join_directly(room, mallory);

    ASSERT_TRUE(IsOk(f.kick(room, "mod", mallory)));
    ASSERT_TRUE(IsOk(f.invite(room, "mod", mallory)));
    ASSERT_TRUE(IsOk(f.join_as(room, "mallory")));

    ASSERT_TRUE(IsOk(f.leave_as(room, "mallory")));
    EXPECT_TRUE(IsOk(f.join_as(room, "mallory")))
        << "a stale kick marker outlived the re-invite that cleared it";
}

// ── Bans are a different act and are unaffected ───────────────────────────

TEST(KickEnforcement, ABanStillRefusesTheJoinOnItsOwnTerms) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(mod);
    f.join_directly(room, mallory);

    ASSERT_TRUE(IsOk(f.ban(room, "mod", mallory)));
    // The ban revoked the token, so re-authenticating is the precondition for
    // even reaching the join handler. Reissue one: the point under test is that
    // the SERVER BAN refuses the join, ahead of and independently of the kick
    // rule, and it must keep doing so.
    f.store->store_access_token("token-mallory", mallory, "dev");
    EXPECT_TRUE(IsForbidden(f.join_as(room, "mallory")));
}

// THE REGRESSION A SENDER-ONLY RULE WOULD HAVE CAUSED.
//
// Unbanning writes `{"membership":"leave"}` with the MODERATOR as sender into
// every room the target was banned in, deliberately, so that lifting a ban
// restores the ability to come back without deciding they have. That event is
// indistinguishable from a kick by sender alone, so a sender-only rule would
// have left every unbanned account locked out of every channel on the server
// with no way back except an invite per channel.
TEST(KickEnforcement, AnUnbannedUserCanRejoinEveryChannel) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto mallory = f.add_user("mallory");
    auto room_a = f.add_channel(mod);
    auto room_b = f.add_channel(mod);
    f.join_directly(room_a, mallory);
    f.join_directly(room_b, mallory);

    ASSERT_TRUE(IsOk(f.ban(room_a, "mod", mallory)));
    ASSERT_TRUE(IsOk(f.unban(room_a, "mod", mallory)));

    // The projection wrote a moderator-sent `leave` into both rooms.
    for (const auto& room : {room_a, room_b}) {
        auto ev = f.store->get_state_event(room, std::string(event_type::kRoomMember), mallory);
        ASSERT_TRUE(ev.has_value());
        ASSERT_EQ(ev->content.data.value("membership", ""), membership::kLeave);
        ASSERT_NE(ev->sender, mallory) << "fixture no longer reproduces the ambiguity";
    }

    f.store->store_access_token("token-mallory", mallory, "dev");
    EXPECT_TRUE(IsOk(f.join_as(room_a, "mallory")));
    EXPECT_TRUE(IsOk(f.join_as(room_b, "mallory")));
}

// ── Last-writer semantics, checked rather than assumed ────────────────────

// You cannot kick somebody who has already left through the dedicated endpoint:
// kick_intent requires the target to be in the room. So a self-leave cannot be
// retroactively converted into a removal there, and the user stays rejoinable.
TEST(KickEnforcement, TheKickEndpointRefusesATargetWhoAlreadyLeft) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto alice = f.add_user("alice");
    auto room = f.add_channel(mod);
    f.join_directly(room, alice);

    ASSERT_TRUE(IsOk(f.leave_as(room, "alice")));
    EXPECT_TRUE(IsForbidden(f.kick(room, "mod", alice)));
    EXPECT_TRUE(IsOk(f.join_as(room, "alice")))
        << "a refused kick still made the user unrejoinable";
}

// The generic state route CAN write `leave` over an existing `leave`
// (classify_transition clears require_target_in_room there, so a Matrix client's
// harmless no-op write is not a 403). That makes "self-leave, then a moderator
// writes leave" reachable, and last writer wins: the most recent member event
// was written by the moderator and records a removal, so the user is kicked.
// That is the intended reading — the moderator deliberately removed them — and
// it is asserted rather than assumed.
TEST(KickEnforcement, AModeratorLeaveWriteOverASelfLeaveCounts) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto alice = f.add_user("alice");
    auto room = f.add_channel(mod);
    f.join_directly(room, alice);

    ASSERT_TRUE(IsOk(f.leave_as(room, "alice")));
    ASSERT_TRUE(IsOk(f.join_as(room, "alice"))) << "precondition: a self-leaver may rejoin";
    ASSERT_TRUE(IsOk(f.leave_as(room, "alice")));

    auto res = f.post(&RoomHandler::handle_set_state,
                      "/_matrix/client/v3/rooms/" + room + "/state/" +
                          std::string(event_type::kRoomMember) + "/" + alice,
                      "token-mod", json{{"membership", membership::kLeave}}.dump());
    ASSERT_TRUE(IsOk(res)) << res.body;

    EXPECT_TRUE(IsForbidden(f.join_as(room, "alice")));
}

// The mirror image: the marker belongs to the LATEST member event, so a kick
// followed by a legitimate readmission and a fresh voluntary leave leaves no
// trace of the kick. Covered above by AReadmittedUserCanLeaveAndRejoinAgain;
// this asserts the underlying property directly on the stored state.
TEST(KickEnforcement, TheMarkerLivesOnTheLatestMemberEventOnly) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(mod);
    f.join_directly(room, mallory);

    ASSERT_TRUE(IsOk(f.kick(room, "mod", mallory)));
    auto kicked = f.store->get_state_event(room, std::string(event_type::kRoomMember), mallory);
    ASSERT_TRUE(kicked.has_value());
    EXPECT_EQ(kicked->content.data.value("bsfchat.removed_by", ""), "@mod:test");

    ASSERT_TRUE(IsOk(f.invite(room, "mod", mallory)));
    auto invited = f.store->get_state_event(room, std::string(event_type::kRoomMember), mallory);
    ASSERT_TRUE(invited.has_value());
    EXPECT_FALSE(invited->content.data.contains("bsfchat.removed_by"));
}

// A kick is per-channel. It must not become a soft server ban by accident.
TEST(KickEnforcement, AKickFromOneChannelDoesNotAffectAnother) {
    Fixture f;
    auto mod = f.add_user("mod", true);
    auto mallory = f.add_user("mallory");
    auto room_a = f.add_channel(mod);
    auto room_b = f.add_channel(mod);
    f.join_directly(room_a, mallory);
    f.join_directly(room_b, mallory);

    ASSERT_TRUE(IsOk(f.kick(room_a, "mod", mallory)));
    EXPECT_TRUE(IsForbidden(f.join_as(room_a, "mallory")));

    ASSERT_TRUE(IsOk(f.leave_as(room_b, "mallory")));
    EXPECT_TRUE(IsOk(f.join_as(room_b, "mallory")));
}
