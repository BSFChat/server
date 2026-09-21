// Server-scope enforcement for membership moderation, and the nickname
// permissions that previously enforced nothing.
//
// The properties under test, in the order they appear below:
//   1. KICK_MEMBERS and BAN_MEMBERS are evaluated at SERVER scope. A per-channel
//      override that allows them inside a channel confers nothing — including
//      through the generic state-PUT route, which performs the same membership
//      transitions and was therefore the bypass.
//   2. The state-PUT route applies the same rank check the dedicated endpoints do.
//   3. A refused moderation attempt writes no audit record; an allowed one writes
//      exactly one. A scope change must not silently drop an audit call site.
//   4. Nicknames are gated in all four own/other x has/lacks combinations, at
//      server scope, with the kick/ban rank check on the "other" path.
//   5. A nickname is not forgeable: it cannot be set through the self-membership
//      state write, and it cannot be another account's username.
//   6. The nickname survives the four code paths that rewrite a member event's
//      displayname from the global profile — the reason it is a column and not
//      just room state.

#include <gtest/gtest.h>

#include "api/ProfileHandler.h"
#include "api/RoomHandler.h"
#include "audit/AuditLog.h"
#include "auth/AutoJoin.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "identity/Nickname.h"
#include "store/Migrations.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-scope-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

::testing::AssertionResult IsForbidden(const httplib::Response& res) {
    if (res.status == 403) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected 403, got status " << res.status
                                         << ", body: " << res.body;
}

// A 403 refused for the REASON given, not merely a 403.
//
// This distinction is load-bearing and was found by mutation testing: every
// moderation endpoint refuses for two separate reasons — insufficient permission
// and insufficient rank — and an actor at the same role position as their target
// is refused by RANK whatever the permission check decided. A scope-regression
// test written with a same-rank actor therefore stays green after the scope fix is
// reverted, which is a test that cannot fail. Asserting the reason, and giving the
// actor a rank above the target, is what makes these tests actually bite.
::testing::AssertionResult IsForbiddenBecause(const httplib::Response& res,
                                              const std::string& needle) {
    if (res.status != 403) {
        return ::testing::AssertionFailure() << "expected 403, got status " << res.status
                                             << ", body: " << res.body;
    }
    if (res.body.find(needle) == std::string::npos) {
        return ::testing::AssertionFailure()
               << "403 for the wrong reason: expected a message containing \"" << needle
               << "\", got: " << res.body;
    }
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult IsBadRequest(const httplib::Response& res) {
    if (res.status == 400) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected 400, got status " << res.status
                                         << ", body: " << res.body;
}

template <typename Handler, typename Method>
httplib::Response call(Handler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
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
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    // Written straight into server_state rather than through
    // write_server_scoped_state so fixture setup lands no audit records and the
    // "a refused action writes nothing" assertions start from an empty log.
    //
    // `everyone_flags` is a parameter because kEveryoneDefault INCLUDES
    // CHANGE_NICKNAME: testing "a user who lacks CHANGE_NICKNAME" requires an
    // @everyone that does not grant it, and hardcoding the default would make that
    // case unreachable.
    void seed_roles(permission::Flags everyone_flags = permission::kEveryoneDefault) {
        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0, everyone_flags));
        // A moderator with the membership flags but NOT the nickname ones, so each
        // gate is exercised on its own flag rather than on a bundle.
        content.roles.push_back(role(permission::role_id::kModerator, 10,
                                     everyone_flags | permission::kKickMembers |
                                         permission::kBanMembers));
        // Outranks a plain member and grants NOTHING beyond @everyone. Required by
        // every "lacks the permission" test: an actor at the same position as the
        // target is refused by the RANK check regardless of the permission check, so
        // without this role those tests pass whether or not the scope fix is present.
        content.roles.push_back(role("helper", 5, everyone_flags));
        // Nickname management without ADMINISTRATOR, so MANAGE_NICKNAMES is tested
        // on its own flag and not on the god-mode short-circuit.
        content.roles.push_back(role("nickmod", 20, everyone_flags | permission::kManageNicknames));
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

    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "text"}}.dump(), 1001);
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, user_id,
                            std::string(event_type::kRoomMember), user_id,
                            member_event_content(*store, user_id,
                                                 std::string(membership::kJoin)).dump(),
                            1002);
    }

    // A per-channel override, written the way handle_set_state writes one.
    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny = 0) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target, j.dump(), 1003);
    }

    std::vector<SqliteStore::AuditRecord> records() {
        return store->list_audit_records(limits::kMaxAuditLimit, std::nullopt).records;
    }

    // The latest m.room.member content for a user in a room — what clients render.
    json member_content(const std::string& room_id, const std::string& user_id) {
        auto ev = store->get_state_event(room_id, std::string(event_type::kRoomMember), user_id);
        if (!ev) return json::object();
        return ev->content.data;
    }
};

const std::string kRoomsPrefix = "/_matrix/client/v3/rooms/";

std::string kick_path(const std::string& room) { return kRoomsPrefix + room + "/kick"; }
std::string ban_path(const std::string& room) { return kRoomsPrefix + room + "/ban"; }
std::string unban_path(const std::string& room) { return kRoomsPrefix + room + "/unban"; }
std::string member_state_path(const std::string& room, const std::string& target) {
    return kRoomsPrefix + room + "/state/" + std::string(event_type::kRoomMember) + "/" + target;
}
std::string nickname_path(const std::string& user) {
    return "/_matrix/client/v3/profile/" + user + "/nickname";
}

std::string target_body(const std::string& user) { return json{{"user_id", user}}.dump(); }
std::string nickname_body(const json& value) { return json{{"nickname", value}}.dump(); }

} // namespace

// ══ 1. Kick / ban / unban are server-scoped ═══════════════════════════════

TEST(ModerationScope, ServerWideKickPermissionStillWorks) {
    Fixture f("kick-allowed");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_kick, kick_path(room), "token-mod",
                          target_body(victim))));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kLeave);
}

TEST(ModerationScope, PerChannelOverrideDoesNotConferKick) {
    Fixture f("kick-override");
    f.seed_roles();
    // "helper" outranks a plain member, so the rank check PASSES and the only thing
    // that can refuse this request is the permission check. With a same-rank actor
    // this test stayed green even with the scope fix reverted.
    auto member = f.add_user("member", {"helper"});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);

    // The grant a per-channel editor could plausibly write, if it offered the
    // flag at all. It must confer nothing: kick is server-wide only.
    f.set_override(room, "user:" + member, permission::kKickMembers);

    // The engine itself must disagree between the two scopes, or the handler
    // assertion below would pass for the wrong reason.
    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(member, room, permission::kKickMembers))
        << "override did not apply at channel scope; the test proves nothing";
    ASSERT_FALSE(perms.can(member, std::string(), permission::kKickMembers));
    ASSERT_TRUE(perms.outranks(member, victim))
        << "actor must outrank the target, or the rank check refuses regardless of scope";

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_kick, kick_path(room),
                                        "token-member", target_body(victim)),
                                   "Insufficient permissions to kick"));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);
}

TEST(ModerationScope, PerChannelOverrideDoesNotConferBan) {
    Fixture f("ban-override");
    f.seed_roles();
    auto member = f.add_user("member", {"helper"}); // outranks victim; see kick test
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.set_override(room, "user:" + member, permission::kBanMembers);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_ban, ban_path(room),
                                        "token-member", target_body(victim)),
                                   "Insufficient permissions to ban"));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);
}

TEST(ModerationScope, PerChannelOverrideDoesNotConferUnban) {
    Fixture f("unban-override");
    f.seed_roles();
    auto member = f.add_user("member", {"helper"}); // outranks victim; see kick test
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.store->set_membership(room, victim, std::string(membership::kBan));
    f.set_override(room, "user:" + member, permission::kBanMembers);

    // Unban must move with ban. If it stayed channel-scoped, an override would let
    // someone lift bans they could never have placed.
    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_unban, unban_path(room),
                                        "token-member", target_body(victim)),
                                   "Insufficient permissions to unban"));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kBan);
}

TEST(ModerationScope, RoleGrantedKickIsNotRevokedByAChannelDeny) {
    Fixture f("kick-deny");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);
    // The mirror image of the bug: server scope means channel overrides are not
    // consulted AT ALL, so a deny cannot subtract a server-wide capability either.
    // Worth pinning — it is the half of the change a reader is most likely to
    // assume works the other way.
    f.set_override(room, "user:" + mod, 0, permission::kKickMembers);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_kick, kick_path(room), "token-mod",
                          target_body(victim))));
}

// ══ 2. The generic state-PUT route — the bypass ═══════════════════════════

TEST(StatePutBypass, PerChannelKickOverrideCannotBanThroughStatePut) {
    Fixture f("statput-override");
    f.seed_roles();
    auto member = f.add_user("member", {"helper"}); // outranks victim; see kick test
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.set_override(room, "user:" + member, permission::kKickMembers);

    // This route writes m.room.member for another user, which IS a ban. Had only
    // the dedicated endpoints moved to server scope, this would still convert a
    // per-channel KICK_MEMBERS override into a working ban.
    //
    // The refusal now names "ban", not "this state event", and that is the second
    // property this assertion carries: the route no longer has a permission map of
    // its own. It used to gate EVERY member write on KICK_MEMBERS, so a
    // kick-only moderator could ban here after being refused at POST
    // /rooms/{id}/ban; the transition is classified once, in
    // apply_membership_moderation, and a ban means BAN_MEMBERS wherever it arrives.
    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_set_state,
                                        member_state_path(room, victim), "token-member",
                                        json{{"membership", membership::kBan}}.dump()),
                                   "Insufficient permissions to ban"));

    // Both halves, because they can no longer disagree: the event and the
    // membership row are written together or not at all.
    EXPECT_EQ(f.member_content(room, victim).value("membership", ""), membership::kJoin);
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);
    EXPECT_FALSE(f.store->is_server_banned(victim));
}

// A KICK-only moderator cannot ban through the state route.
//
// This is the divergence the old route hid: it mapped every m.room.member write
// to KICK_MEMBERS, so BAN_MEMBERS was enforced at POST /rooms/{id}/ban and
// nowhere else. The actor here holds KICK_MEMBERS at SERVER scope — the real
// thing, not a channel override — and outranks the target, so the permission
// check is the only thing that can refuse, and it must refuse for the ban and
// allow the kick.
TEST(StatePutBypass, KickPermissionDoesNotConferBanThroughStatePut) {
    Fixture f("statput-kickonly");
    f.seed_roles();
    // "kickonly" sits above a plain member and carries KICK_MEMBERS but NOT
    // BAN_MEMBERS. seed_roles' moderator has both, which is why it cannot be used.
    {
        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault));
        content.roles.push_back(role("kickonly", 10,
                                     permission::kEveryoneDefault | permission::kKickMembers));
        json j;
        to_json(j, content);
        f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                  j.dump());
    }
    auto mod = f.add_user("mod", {"kickonly"});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(mod, std::string(), permission::kKickMembers));
    ASSERT_FALSE(perms.can(mod, std::string(), permission::kBanMembers))
        << "actor must lack BAN_MEMBERS or this test proves nothing";
    ASSERT_TRUE(perms.outranks(mod, victim))
        << "actor must outrank the target, or the rank check refuses regardless";

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_set_state,
                                        member_state_path(room, victim), "token-mod",
                                        json{{"membership", membership::kBan}}.dump()),
                                   "Insufficient permissions to ban"));
    EXPECT_FALSE(f.store->is_server_banned(victim));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);

    // The same actor CAN kick, so the refusal above is about the flag and not
    // about this actor being powerless.
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          member_state_path(room, victim), "token-mod",
                          json{{"membership", membership::kLeave}}.dump())));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kLeave);
}

TEST(StatePutBypass, ServerWideKickPermissionStillWorksThroughStatePut) {
    Fixture f("statput-allowed");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          member_state_path(room, victim), "token-mod",
                          json{{"membership", membership::kLeave}}.dump())));
    EXPECT_EQ(f.member_content(room, victim).value("membership", ""), membership::kLeave);
}

// REPLACES StatePutWritesOnlyTheEventAndNotTheMembershipRow, which pinned the
// defect: the generic state route wrote the m.room.member EVENT and never called
// set_membership, so room_members still said "join" after a ban placed here.
// Clients rebuild member lists from events and so did hide the user, and the audit
// log recorded the ban — while every server-side membership check (sync, room
// reads, search, push, and the membership guard on this very route) still treated
// them as a joined member. A moderator was told they had banned somebody who was,
// server-side, still fully present.
//
// The two now move together because there is only one implementation left: this
// route delegates to apply_membership_moderation, the same function POST
// /rooms/{id}/ban runs.
//
// This test CAN fail — the previous one could not. Under the old code
// get_membership returns "join" and is_room_member returns true, so the first two
// expectations below both flip. (The test it replaces asserted exactly that, which
// is why it stayed green through every change to this route.)
TEST(StatePutBypass, StatePutWritesTheMembershipRowAndNotJustTheEvent) {
    Fixture f("statput-consistent");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    ASSERT_TRUE(f.store->is_room_member(room, victim))
        << "victim must start as a real member, or the assertions below prove nothing";

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          member_state_path(room, victim), "token-mod",
                          json{{"membership", membership::kBan}}.dump())));

    EXPECT_EQ(f.store->get_membership(room, victim), membership::kBan);
    EXPECT_FALSE(f.store->is_room_member(room, victim));
    // And the event still says the same thing the row does.
    EXPECT_EQ(f.member_content(room, victim).value("membership", ""), membership::kBan);
    // A ban is a ban wherever it is placed: the state route reaches the same
    // server-wide ban list as the dedicated endpoint.
    EXPECT_TRUE(f.store->is_server_banned(victim));
}

TEST(StatePutBypass, CannotModerateAUserOfHigherRankThroughStatePut) {
    Fixture f("statput-rank");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(mod, "general");
    f.join(room, admin);

    RoomHandler handler(*f.store, *f.sync, f.config);
    // Refused at the dedicated endpoint...
    EXPECT_TRUE(IsForbidden(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                                 target_body(admin))));
    // ...and must be refused here too, or the rank check is decorative.
    EXPECT_TRUE(IsForbidden(call(handler, &RoomHandler::handle_set_state,
                                 member_state_path(room, admin), "token-mod",
                                 json{{"membership", membership::kBan}}.dump())));
    EXPECT_EQ(f.store->get_membership(room, admin), membership::kJoin);
}

TEST(StatePutBypass, LeavingAChannelYourselfIsStillChannelScoped) {
    Fixture f("statput-self");
    f.seed_roles();
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");

    // Self-membership must NOT have moved to server scope: joining and leaving a
    // channel is a genuinely per-channel action, and a plain member has no
    // server-wide membership permission at all.
    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          member_state_path(room, member), "token-member",
                          json{{"membership", membership::kLeave}}.dump())));
    EXPECT_EQ(f.store->get_membership(room, member), membership::kLeave);
}

// ══ 3. The scope change did not drop an audit call site ═══════════════════

TEST(ModerationScopeAudit, RefusedModerationRecordsNothing) {
    Fixture f("audit-refused");
    f.seed_roles();
    auto member = f.add_user("member", {"helper"}); // outranks victim; see kick test
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.set_override(room, "user:" + member, permission::kKickMembers | permission::kBanMembers);

    RoomHandler handler(*f.store, *f.sync, f.config);
    call(handler, &RoomHandler::handle_kick, kick_path(room), "token-member", target_body(victim));
    call(handler, &RoomHandler::handle_ban, ban_path(room), "token-member", target_body(victim));
    call(handler, &RoomHandler::handle_set_state, member_state_path(room, victim), "token-member",
         json{{"membership", membership::kBan}}.dump());

    EXPECT_TRUE(f.records().empty());
}

TEST(ModerationScopeAudit, AllowedModerationStillRecordsExactlyOnePerAction) {
    Fixture f("audit-allowed");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_unban, unban_path(room), "token-mod",
                          target_body(victim))));

    auto recs = f.records();
    ASSERT_EQ(recs.size(), 2u);
    // Newest first.
    EXPECT_EQ(recs[0].action, audit_action::kMemberUnban);
    EXPECT_EQ(recs[1].action, audit_action::kMemberBan);
    EXPECT_EQ(recs[0].actor, mod);
    EXPECT_EQ(recs[0].target_user, victim);
}

TEST(ModerationScopeAudit, StatePutModerationIsStillRecorded) {
    Fixture f("audit-statput");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          member_state_path(room, victim), "token-mod",
                          json{{"membership", membership::kBan}}.dump())));

    auto recs = f.records();
    ASSERT_EQ(recs.size(), 1u);
    EXPECT_EQ(recs[0].action, audit_action::kMemberBan);
    EXPECT_EQ(recs[0].target_user, victim);
}

// ══ 4. Nickname gating: own/other x has/lacks ════════════════════════════

TEST(NicknameGating, OwnWithChangeNicknameIsAllowed) {
    Fixture f("nick-own-yes");
    f.seed_roles(); // kEveryoneDefault includes CHANGE_NICKNAME
    auto member = f.add_user("member");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("Bobby"))));
    EXPECT_EQ(f.store->get_nickname(member).value_or(""), "Bobby");
}

TEST(NicknameGating, OwnWithoutChangeNicknameIsRefused) {
    Fixture f("nick-own-no");
    // An @everyone that does NOT grant CHANGE_NICKNAME. The bit is in the shipped
    // default, so this is the only way to reach the refusal path.
    f.seed_roles(permission::kEveryoneDefault & ~permission::kChangeNickname);
    auto member = f.add_user("member");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &ProfileHandler::handle_put_nickname,
                                 nickname_path(member), "token-member",
                                 nickname_body("Bobby"))));
    EXPECT_FALSE(f.store->get_nickname(member).has_value());
}

TEST(NicknameGating, OtherWithManageNicknamesIsAllowed) {
    Fixture f("nick-other-yes");
    f.seed_roles();
    auto nickmod = f.add_user("nickmod", {"nickmod"});
    auto target = f.add_user("target");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(target),
                          "token-nickmod", nickname_body("Renamed"))));
    EXPECT_EQ(f.store->get_nickname(target).value_or(""), "Renamed");
}

TEST(NicknameGating, OtherWithoutManageNicknamesIsRefused) {
    Fixture f("nick-other-no");
    f.seed_roles();
    // Has CHANGE_NICKNAME (via @everyone) but not MANAGE_NICKNAMES. Renaming
    // yourself must not imply renaming anybody else.
    //
    // "helper" so the actor outranks the target: at equal rank this is refused by
    // the rank check and the test would pass even if the gate used the wrong flag.
    auto member = f.add_user("member", {"helper"});
    auto target = f.add_user("target");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &ProfileHandler::handle_put_nickname,
                                        nickname_path(target), "token-member",
                                        nickname_body("Renamed")),
                                   "other members' nicknames"));
    EXPECT_FALSE(f.store->get_nickname(target).has_value());
}

TEST(NicknameGating, ManageNicknamesAloneDoesNotConferChangingYourOwn) {
    Fixture f("nick-discord-parity");
    // Discord parity: the two flags are independent, not a hierarchy. A moderator
    // whose roles grant MANAGE_NICKNAMES but not CHANGE_NICKNAME can rename others
    // and not themselves.
    f.seed_roles(permission::kEveryoneDefault & ~permission::kChangeNickname);
    auto nickmod = f.add_user("nickmod", {"nickmod"});
    auto target = f.add_user("target");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &ProfileHandler::handle_put_nickname,
                                 nickname_path(nickmod), "token-nickmod",
                                 nickname_body("Self"))));
    EXPECT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(target),
                          "token-nickmod", nickname_body("Other"))));
}

TEST(NicknameGating, CannotRenameAUserOfHigherRank) {
    Fixture f("nick-rank");
    f.seed_roles();
    auto nickmod = f.add_user("nickmod", {"nickmod"});           // position 20
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)}); // position 100

    // Renaming someone is a visible act of authority over them. It respects the
    // same rank rule as kick and ban, so a moderator cannot relabel an admin.
    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &ProfileHandler::handle_put_nickname,
                                 nickname_path(admin), "token-nickmod",
                                 nickname_body("Clown"))));
    EXPECT_FALSE(f.store->get_nickname(admin).has_value());
}

TEST(NicknameGating, PerChannelOverrideDoesNotConferEitherNicknameFlag) {
    Fixture f("nick-override");
    f.seed_roles(permission::kEveryoneDefault & ~permission::kChangeNickname);
    auto member = f.add_user("member", {"helper"}); // outranks target
    auto target = f.add_user("target");
    auto room = f.add_channel(member, "general");
    f.join(room, target);
    f.set_override(room, "user:" + member,
                   permission::kChangeNickname | permission::kManageNicknames);

    // The override really does grant both flags at channel scope, so these
    // refusals can only come from the checks being evaluated at server scope.
    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(member, room, permission::kChangeNickname));
    ASSERT_TRUE(perms.can(member, room, permission::kManageNicknames));
    ASSERT_TRUE(perms.outranks(member, target));

    // A nickname is one value for the whole server. A channel-scoped grant of it
    // would be meaningless, so it must not work.
    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &ProfileHandler::handle_put_nickname,
                                        nickname_path(member), "token-member",
                                        nickname_body("Self")),
                                   "change your nickname"));
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &ProfileHandler::handle_put_nickname,
                                        nickname_path(target), "token-member",
                                        nickname_body("Other")),
                                   "other members' nicknames"));
}

TEST(NicknameGating, AdministratorCanRenameAnyone) {
    Fixture f("nick-admin");
    f.seed_roles(permission::kEveryoneDefault & ~permission::kChangeNickname);
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto target = f.add_user("target");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(target),
                          "token-admin", nickname_body("Renamed"))));
    EXPECT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(admin),
                          "token-admin", nickname_body("Boss"))));
}

TEST(NicknameGating, UnauthenticatedIsRefused) {
    Fixture f("nick-noauth");
    f.seed_roles();
    auto member = f.add_user("member");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                    "bogus-token", nickname_body("Bobby"));
    EXPECT_EQ(res.status, 401);
    EXPECT_FALSE(f.store->get_nickname(member).has_value());
}

// ══ 5. A nickname is not forgeable ═══════════════════════════════════════

TEST(NicknameForgery, SelfMembershipWriteCannotSetANickname) {
    Fixture f("nick-forge-state");
    f.seed_roles(permission::kEveryoneDefault & ~permission::kChangeNickname);
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");

    // The self-membership route already refuses to echo a client-supplied
    // displayname. It must equally refuse a client-supplied nickname, or the
    // permission gate above is bypassable by anyone who can join a channel.
    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          member_state_path(room, member), "token-member",
                          json{{"membership", membership::kJoin},
                               {"displayname", "Administrator"},
                               {kNicknameContentKey, "Administrator"}}.dump())));

    auto content = f.member_content(room, member);
    EXPECT_FALSE(content.contains("displayname"));
    EXPECT_FALSE(content.contains(kNicknameContentKey));
    EXPECT_FALSE(f.store->get_nickname(member).has_value());
}

TEST(NicknameValidation, RejectsAnotherMembersUsername) {
    Fixture f("nick-impersonate");
    f.seed_roles();
    auto member = f.add_user("member");
    f.add_user("alice");

    // "alice" is the localpart of a real account, so a member list showing it is
    // showing the exact string a reader would use to find the real @alice.
    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsBadRequest(call(handler, &ProfileHandler::handle_put_nickname,
                                  nickname_path(member), "token-member",
                                  nickname_body("alice"))));
    EXPECT_TRUE(IsBadRequest(call(handler, &ProfileHandler::handle_put_nickname,
                                  nickname_path(member), "token-member",
                                  nickname_body("Alice"))));
    EXPECT_FALSE(f.store->get_nickname(member).has_value());
}

TEST(NicknameValidation, KeepingYourOwnUsernameAsANicknameIsFine) {
    Fixture f("nick-self-localpart");
    f.seed_roles();
    auto member = f.add_user("member");

    // The impersonation check must exclude the target themselves, or nobody can
    // set their own username as their nickname.
    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("member"))));
}

TEST(NicknameValidation, RejectsMxidShapedAndUnsafeCharacters) {
    Fixture f("nick-unsafe");
    f.seed_roles();
    auto member = f.add_user("member");
    ProfileHandler handler(*f.store, *f.sync, f.config);

    // Bodies are hand-written JSON carrying \uXXXX escapes rather than dumped from
    // a json object. That is the shape a real request takes: a control or invisible
    // character survives JSON transport only as an escape, and the parser turns it
    // back into the real character before the validator sees it. Dumping a json
    // object holding the raw character would instead throw inside the test and
    // prove nothing about the handler.
    const std::vector<std::pair<std::string, std::string>> bad_bodies = {
        {"mxid shape",             "{\"nickname\":\"@someone:test\"}"},
        {"newline",                "{\"nickname\":\"Bob\\u000aAdmin\"}"},
        {"carriage return",        "{\"nickname\":\"Bob\\u000dAdmin\"}"},
        {"tab",                    "{\"nickname\":\"Bob\\u0009Admin\"}"},
        {"nul",                    "{\"nickname\":\"Bob\\u0000Admin\"}"},
        {"C1 control",             "{\"nickname\":\"Bob\\u0085Admin\"}"},
        {"soft hyphen",            "{\"nickname\":\"Bo\\u00adb\"}"},
        {"right-to-left override", "{\"nickname\":\"Bob\\u202enimda\"}"},
        {"left-to-right mark",     "{\"nickname\":\"Bob\\u200e\"}"},
        {"zero width space",       "{\"nickname\":\"Bo\\u200bb\"}"},
        {"bidi isolate",           "{\"nickname\":\"\\u2066Bob\"}"},
        {"word joiner",            "{\"nickname\":\"Bo\\u2060b\"}"},
        {"byte order mark",        "{\"nickname\":\"\\ufeffBob\"}"},
        {"too long",               "{\"nickname\":\"" + std::string(33, 'a') + "\"}"},
    };

    for (const auto& [label, body] : bad_bodies) {
        auto res = call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                        "token-member", body);
        EXPECT_TRUE(IsBadRequest(res)) << "accepted " << label;
        EXPECT_FALSE(f.store->get_nickname(member).has_value()) << "stored " << label;
    }
}

TEST(NicknameValidation, RejectsMalformedUtf8AtTheValidator) {
    Fixture f("nick-utf8");
    f.seed_roles();
    auto member = f.add_user("member");

    // Malformed UTF-8 cannot be expressed in JSON at all, so it is asserted
    // directly against the validator rather than through the handler. It still
    // matters: the length and character checks reason about code points, and a
    // decoder that guessed at broken input would let bytes past them.
    const std::vector<std::pair<std::string, std::string>> bad = {
        {"truncated 2-byte sequence", "Bob\xC3"},
        {"overlong encoding", "Bob\xC0\xAF"},
        {"lone continuation byte", "Bob\x80"},
        {"surrogate half", "Bob\xED\xA0\x80"},
        {"truncated 3-byte sequence", "Bob\xE6\x97"},
    };

    for (const auto& [label, value] : bad) {
        auto check = validate_nickname(value, member, f.config, *f.store);
        EXPECT_FALSE(check.ok) << "accepted " << label;
    }

    EXPECT_TRUE(validate_nickname("Bob", member, f.config, *f.store).ok);
}

TEST(NicknameValidation, AcceptsNonLatinScriptsUpToTheCodepointLimit) {
    Fixture f("nick-unicode");
    f.seed_roles();
    auto member = f.add_user("member");
    ProfileHandler handler(*f.store, *f.sync, f.config);

    // The limit is code points, not bytes: 32 three-byte characters is a name a
    // user perceives as 32 characters and a byte limit would wrongly reject.
    std::string thirty_two;
    for (int i = 0; i < 32; ++i) thirty_two += "\xE6\x97\xA5"; // U+65E5
    EXPECT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body(thirty_two))));

    EXPECT_TRUE(IsBadRequest(call(handler, &ProfileHandler::handle_put_nickname,
                                  nickname_path(member), "token-member",
                                  nickname_body(thirty_two + "\xE6\x97\xA5"))));
}

TEST(NicknameValidation, TrimsWhitespaceAndTreatsBlankAsClear) {
    Fixture f("nick-blank");
    f.seed_roles();
    auto member = f.add_user("member");
    ProfileHandler handler(*f.store, *f.sync, f.config);

    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("  Bobby  "))));
    EXPECT_EQ(f.store->get_nickname(member).value_or(""), "Bobby");

    // Emptying the field is how a nickname is removed; it is not an error, and it
    // must not store "" as a nickname that renders as a nameless member.
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("   "))));
    EXPECT_FALSE(f.store->get_nickname(member).has_value());

    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("Bobby"))));
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body(nullptr))));
    EXPECT_FALSE(f.store->get_nickname(member).has_value());
}

// ══ 6. The nickname survives every member-event rewrite ══════════════════

TEST(NicknameStorage, IsMirroredIntoEveryJoinedRoomsMemberEvent) {
    Fixture f("nick-mirror");
    f.seed_roles();
    auto member = f.add_user("member");
    auto a = f.add_channel(member, "one");
    auto b = f.add_channel(member, "two");
    f.join(a, member);
    f.join(b, member);
    f.store->set_display_name(member, "Global Name");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("Nick"))));

    // `displayname` carries the EFFECTIVE name so existing clients render the
    // nickname with no change; the explicit key is what lets a client tell the two
    // apart and offer "clear nickname".
    for (const auto& room : {a, b}) {
        auto content = f.member_content(room, member);
        EXPECT_EQ(content.value("displayname", ""), "Nick") << "room " << room;
        EXPECT_EQ(content.value(kNicknameContentKey, ""), "Nick") << "room " << room;
    }
}

TEST(NicknameStorage, SurvivesAnUnrelatedProfileChange) {
    Fixture f("nick-survives-profile");
    f.seed_roles();
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");
    f.join(room, member);

    ProfileHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("Nick"))));

    // THE reason the nickname is a column and not just room state: this handler
    // rewrites the displayname of every joined room from the profile. Stored in
    // room state alone, the nickname would be erased right here by a user changing
    // their avatar.
    // A real object, uploaded by this account: since audit F5, handle_put_
    // avatar_url refuses an avatar the caller did not upload, because the
    // avatar fall-through in MediaAccess is what makes a room-less object
    // readable server-wide and an unvalidated write there launders a redacted
    // attachment into a public one. Nothing about THIS test changes — it is
    // about the nickname surviving an unrelated profile write — but the
    // profile write now has to be one the server would accept.
    const std::string avatar_id = "000000000000000000000000000000a1";
    const std::string avatar = "mxc://test/" + avatar_id;
    f.store->insert_media(avatar_id, member, "image/png", "p.png", 8, "/x/" + avatar_id);
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_avatar_url,
                          "/_matrix/client/v3/profile/" + member + "/avatar_url",
                          "token-member", json{{"avatar_url", avatar}}.dump())));

    EXPECT_EQ(f.store->get_nickname(member).value_or(""), "Nick");
    auto content = f.member_content(room, member);
    EXPECT_EQ(content.value("displayname", ""), "Nick");
    EXPECT_EQ(content.value("avatar_url", ""), avatar);

    // And a later global-name change does not become the rendered name.
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_displayname,
                          "/_matrix/client/v3/profile/" + member + "/displayname",
                          "token-member", json{{"displayname", "Global"}}.dump())));
    EXPECT_EQ(f.member_content(room, member).value("displayname", ""), "Nick");
}

TEST(NicknameStorage, AppliesToAChannelJoinedAfterItWasSet) {
    Fixture f("nick-autojoin");
    f.seed_roles();
    auto member = f.add_user("member");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("Nick"))));

    // A channel created later force-joins everyone. Built by hand from the global
    // profile, that join would reintroduce the global name and quietly undo the
    // nickname in the newest channel.
    auto room = f.add_channel("@server:test", "later");
    auto_join_all_users(*f.store, *f.sync, f.config, room, "@server:test");
    ASSERT_TRUE(f.store->is_room_member(room, member));

    auto content = f.member_content(room, member);
    EXPECT_EQ(content.value("displayname", ""), "Nick");
    EXPECT_EQ(content.value(kNicknameContentKey, ""), "Nick");
}

TEST(NicknameStorage, ClearingRestoresTheGlobalDisplayName) {
    Fixture f("nick-clear-mirror");
    f.seed_roles();
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");
    f.join(room, member);
    f.store->set_display_name(member, "Global Name");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("Nick"))));
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body(nullptr))));

    auto content = f.member_content(room, member);
    EXPECT_EQ(content.value("displayname", ""), "Global Name");
    EXPECT_FALSE(content.contains(kNicknameContentKey));
}

// ══ 7. Nickname auditing ═════════════════════════════════════════════════

TEST(NicknameAudit, ModeratorRenamingSomeoneElseIsRecordedOnce) {
    Fixture f("nick-audit-other");
    f.seed_roles();
    auto nickmod = f.add_user("nickmod", {"nickmod"});
    auto target = f.add_user("target");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(target),
                          "token-nickmod", nickname_body("Renamed"))));

    auto recs = f.records();
    ASSERT_EQ(recs.size(), 1u);
    EXPECT_EQ(recs[0].action, audit_action::kMemberNicknameSet);
    EXPECT_EQ(recs[0].actor, nickmod);
    EXPECT_EQ(recs[0].target_user, target);
    // nullopt records as JSON null, so "cleared" and "set to empty" cannot be
    // confused by a reader.
    EXPECT_EQ(json::parse(recs[0].before_json)["nickname"], nullptr);
    EXPECT_EQ(json::parse(recs[0].after_json)["nickname"], "Renamed");
}

TEST(NicknameAudit, RenamingYourselfIsNotAModerationAction) {
    Fixture f("nick-audit-self");
    f.seed_roles();
    auto member = f.add_user("member");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                          "token-member", nickname_body("Bobby"))));

    EXPECT_TRUE(f.records().empty());
}

TEST(NicknameAudit, RefusedAndNoOpRenamesRecordNothing) {
    Fixture f("nick-audit-noop");
    f.seed_roles();
    auto nickmod = f.add_user("nickmod", {"nickmod"});
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto target = f.add_user("target");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    // Refused by rank.
    call(handler, &ProfileHandler::handle_put_nickname, nickname_path(admin), "token-nickmod",
         nickname_body("Clown"));
    EXPECT_TRUE(f.records().empty());

    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(target),
                          "token-nickmod", nickname_body("Same"))));
    ASSERT_EQ(f.records().size(), 1u);
    // Resubmitting an unchanged value is not an event.
    ASSERT_TRUE(IsOk(call(handler, &ProfileHandler::handle_put_nickname, nickname_path(target),
                          "token-nickmod", nickname_body("Same"))));
    EXPECT_EQ(f.records().size(), 1u);
}

// ── Role hierarchy ────────────────────────────────────────────────────────
//
// MANAGE_ROLES is the permission an owner hands to a trusted-but-not-admin
// "builder". It used to be the WHOLE gate on both role state events, with no
// rank check anywhere on the path — so one request turned it into full
// ADMINISTRATOR:
//
//   PUT /rooms/{any}/state/bsfchat.member.roles/@self  {"role_ids":["admin"]}
//
// and rewriting bsfchat.server.roles to put ADMINISTRATOR on @everyone was the
// same escalation from the other side. Permissions.h already named role
// assignment as something outranks() gates; it was the one case that did not
// use it.

namespace {

// A builder: MANAGE_ROLES, ranked below admin. Position 30 sits above the
// fixture's helper/moderator/nickmod and well below admin at 100.
std::string add_builder(Fixture& f) {
    auto roles = f.store->get_server_roles();
    roles.push_back(role("builder", 30,
                         permission::kEveryoneDefault | permission::kManageRoles));
    ServerRolesContent content;
    content.roles = roles;
    json j;
    to_json(j, content);
    f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                              j.dump());
    return f.add_user("builder", {"builder"});
}

std::string member_roles_path(const std::string& room, const std::string& target) {
    return kRoomsPrefix + room + "/state/" + std::string(event_type::kMemberRoles) + "/" + target;
}
std::string server_roles_path(const std::string& room) {
    return kRoomsPrefix + room + "/state/" + std::string(event_type::kServerRoles) + "/";
}
std::string assignment_body(const std::vector<std::string>& ids) {
    MemberRolesContent c;
    c.role_ids = ids;
    json j;
    to_json(j, c);
    return j.dump();
}
std::string roles_body(const std::vector<ServerRole>& roles) {
    ServerRolesContent c;
    c.roles = roles;
    json j;
    to_json(j, c);
    return j.dump();
}

bool holds_admin(Fixture& f, const std::string& user) {
    PermissionsEngine perms(*f.store, f.config);
    return perms.can(user, std::string(), permission::kAdministrator);
}

} // namespace

TEST(RoleHierarchy, ManageRolesCannotMakeYouAnAdministrator) {
    Fixture f("role-self-promote");
    f.seed_roles();
    auto builder = add_builder(f);
    auto room = f.add_channel("@server:test", "general");
    f.join(room, builder);
    ASSERT_FALSE(holds_admin(f, builder));

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_set_state,
                    member_roles_path(room, builder), "token-builder",
                    assignment_body({std::string(permission::role_id::kEveryone), "builder",
                                     std::string(permission::role_id::kAdmin)}));
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_FALSE(holds_admin(f, builder)) << "MANAGE_ROLES became ADMINISTRATOR";
}

TEST(RoleHierarchy, ManageRolesCannotGrantAdministratorToEveryone) {
    Fixture f("role-everyone-admin");
    f.seed_roles();
    auto builder = add_builder(f);
    auto victim = f.add_user("victim");
    auto room = f.add_channel("@server:test", "general");
    f.join(room, builder);

    auto roles = f.store->get_server_roles();
    for (auto& r : roles) {
        if (r.id == permission::role_id::kEveryone) r.permissions = permission::kAllFlags;
    }

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_set_state, server_roles_path(room),
                    "token-builder", roles_body(roles));
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_FALSE(holds_admin(f, victim)) << "every user on the server became an admin";
}

TEST(RoleHierarchy, ManageRolesCannotRaiseItsOwnRoleAboveTheOwner) {
    Fixture f("role-reposition");
    f.seed_roles();
    auto builder = add_builder(f);
    auto room = f.add_channel("@server:test", "general");
    f.join(room, builder);

    auto roles = f.store->get_server_roles();
    for (auto& r : roles) {
        if (r.id == "builder") r.position = 200;   // above admin at 100
    }

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_set_state, server_roles_path(room),
                    "token-builder", roles_body(roles));
    EXPECT_EQ(res.status, 403) << res.body;

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_LT(perms.highest_role_position(builder), 100);
}

TEST(RoleHierarchy, ManageRolesCannotDeleteTheAdminRole) {
    Fixture f("role-delete-admin");
    f.seed_roles();
    auto builder = add_builder(f);
    auto owner = f.add_user("owner", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel("@server:test", "general");
    f.join(room, builder);

    auto roles = f.store->get_server_roles();
    roles.erase(std::remove_if(roles.begin(), roles.end(),
                               [](const ServerRole& r) {
                                   return r.id == permission::role_id::kAdmin;
                               }),
                roles.end());

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_set_state, server_roles_path(room),
                    "token-builder", roles_body(roles));
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(holds_admin(f, owner)) << "the owner was demoted";
}

TEST(RoleHierarchy, ManageRolesCannotStripAHigherRankedUsersRoles) {
    Fixture f("role-strip-owner");
    f.seed_roles();
    auto builder = add_builder(f);
    auto owner = f.add_user("owner", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel("@server:test", "general");
    f.join(room, builder);

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_set_state,
                    member_roles_path(room, owner), "token-builder",
                    assignment_body({std::string(permission::role_id::kEveryone)}));
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(holds_admin(f, owner)) << "a builder demoted the owner";
}

// The permission has to keep doing its job: a builder manages roles BELOW
// their own rank. A guard that simply refused everything would pass every
// test above and break the feature.
TEST(RoleHierarchy, ManageRolesStillManagesLowerRoles) {
    Fixture f("role-legit");
    f.seed_roles();
    auto builder = add_builder(f);
    auto member = f.add_user("member");
    auto room = f.add_channel("@server:test", "general");
    f.join(room, builder);

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_set_state,
                    member_roles_path(room, member), "token-builder",
                    assignment_body({std::string(permission::role_id::kEveryone), "helper"}));
    ASSERT_TRUE(IsOk(res)) << res.status << " " << res.body;

    auto ids = f.store->get_member_role_ids(member);
    EXPECT_NE(std::find(ids.begin(), ids.end(), "helper"), ids.end());
}

TEST(RoleHierarchy, AnAdministratorIsStillUnrestricted) {
    Fixture f("role-admin-ok");
    f.seed_roles();
    auto owner = f.add_user("owner", {std::string(permission::role_id::kAdmin)});
    auto member = f.add_user("member");
    auto room = f.add_channel("@server:test", "general");
    f.join(room, owner);

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &RoomHandler::handle_set_state,
                    member_roles_path(room, member), "token-owner",
                    assignment_body({std::string(permission::role_id::kEveryone),
                                     std::string(permission::role_id::kAdmin)}));
    ASSERT_TRUE(IsOk(res)) << res.status << " " << res.body;
    EXPECT_TRUE(holds_admin(f, member));
}
