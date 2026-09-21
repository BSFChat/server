// The containment rule.
//
// This file owns findings F1, F2 and F6 of docs/audit-permissions-2026-09.md.
// The first five tests are that audit's own proofs, brought across verbatim
// from tests/test_permission_audit_2026_09.cpp on branch
// `audit/permissions-2026-09` and un-DISABLED: they failed against main at
// 7801693 and they are the acceptance criteria for the fix, so they are
// reproduced rather than rewritten. Everything after them is this branch's
// own, and splits into two halves that both matter:
//
//   * THE RULE IS NOT WIDER THAN IT CLAIMS. A delegated builder must still be
//     able to make a channel private, let somebody in, and hand a bot a
//     channel; an owner must still be able to do everything. A containment
//     rule that stops ordinary administration has not been made safe, it has
//     been made useless, and the next person will loosen it in the wrong
//     place.
//   * THE RULE IS NOT NARROWER THAN IT CLAIMS. The audit's proofs describe
//     particular attacks; the tests below describe the shapes NEXT to those
//     attacks — removing a deny rather than adding an allow, a bot that does
//     hold @everyone, an override aimed at a role rather than a user.
//
// The actor in every negative test is `builder` (MANAGE_ROLES and nothing
// else) or `botmod` (MANAGE_BOTS and nothing else), never an administrator:
// ADMINISTRATOR short-circuits every flag inside PermissionsEngine::compute,
// so a refusal proven against an admin proves nothing at all.
//
// See auth/Permissions.h for the rule itself, stated once.

#include <gtest/gtest.h>

#include "api/BotHandler.h"
#include "api/RoomHandler.h"
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

#include <unistd.h>

#include <filesystem>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-containment-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

::testing::AssertionResult IsForbidden(const httplib::Response& res) {
    if (res.status == 403) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected 403, got status " << res.status
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

std::string override_body(permission::Flags allow, permission::Flags deny = 0) {
    ChannelPermissionOverride ov;
    ov.allow = allow;
    ov.deny = deny;
    json j;
    to_json(j, ov);
    return j.dump();
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
        config.password_hash_cost = 10;
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    // `builder` is THE ACTOR THESE PROOFS ARE ABOUT: a delegated, non-admin
    // holder of MANAGE_ROLES — the role an owner hands to somebody trusted to
    // arrange who may see which channel and deliberately NOT trusted to run
    // the server. `senior` sits above the builder and holds no special flag,
    // so "ranked above you" can be tested without invoking ADMINISTRATOR.
    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        content.roles.push_back(role("builder", 10,
                                     permission::kEveryoneDefault | permission::kManageRoles));
        content.roles.push_back(role("botmod", 10,
                                     permission::kEveryoneDefault | permission::kManageBots));
        // Two roles that exist purely to pin the ROLE half of rank: `patrol`
        // can moderate and `helper` cannot, `helper` holds a flag `patrol`
        // does not, and `patrol` sits above it. Rank must still say "yes" to
        // that pair — see RankStillGovernsTheRoleHalf below.
        content.roles.push_back(role("helper", 5,
                                     permission::kEveryoneDefault |
                                         permission::kManageMessages));
        content.roles.push_back(role("patrol", 10,
                                     permission::kEveryoneDefault |
                                         permission::kKickMembers));
        content.roles.push_back(role("senior", 50, permission::kEveryoneDefault));
        // MANAGE_SERVER WITHOUT ADMINISTRATOR: the legitimate holder of the
        // flag F1 is about. Renaming the server must keep working for them.
        content.roles.push_back(role("host", 60,
                                     permission::kEveryoneDefault | permission::kManageServer));
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
        assign_roles(uid, extra_roles);
        return uid;
    }

    void assign_roles(const std::string& uid, const std::vector<std::string>& extra_roles) {
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
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
    }

    // Written straight into the store, so a test can set up an override the
    // handler would now refuse and still be about what compute() does with it.
    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny = 0) {
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target,
                            override_body(allow, deny), 1003);
    }
};

const std::string kRoomsPrefix = "/_matrix/client/v3/rooms/";

std::string state_path(const std::string& room, const std::string& type,
                       const std::string& key = "") {
    auto p = kRoomsPrefix + room + "/state/" + type;
    if (!key.empty()) p += "/" + key;
    return p;
}

// The latest bsfchat.server.info content anywhere on the server, which is what
// the client renders: ServerConnection applies whichever copy reaches it
// through /sync, whatever room it arrived in.
std::string server_display_name(SqliteStore& store, const std::string& room_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kServerInfo), "");
    return ev ? ev->content.data.value("name", "") : std::string();
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// The audit's proofs. F1, F2a, F2b, F2c, F6.
// ═════════════════════════════════════════════════════════════════════════════

// F1 — bsfchat.server.info was gated at ROOM scope, so a per-channel ALLOW
// override granting MANAGE_SERVER in one channel was enough to rewrite the
// whole deployment's name and icon.
TEST(PermissionContainment, F1_ChannelOverrideCannotGrantAServerWideRename) {
    Fixture f("f1-rename");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    // An ordinary member. Not a builder, not an admin — the weakest account
    // the server has.
    auto mallory = f.add_user("mallory");

    auto room = f.add_channel(admin, "general");
    f.join(room, mallory);

    RoomHandler rooms(*f.store, *f.sync, f.config);

    // Control: without the override, an ordinary member is refused. If this
    // fails the test proves nothing.
    ASSERT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kServerInfo)),
                                 "token-mallory", json{{"name", "control"}}.dump())));

    // An admin gives Mallory MANAGE_SERVER IN THIS ONE CHANNEL. Nothing about
    // this gesture says "you may rename the server".
    ASSERT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + mallory),
                          "token-admin", override_body(permission::kManageServer))));

    auto res = call(rooms, &RoomHandler::handle_set_state,
                    state_path(room, std::string(event_type::kServerInfo)), "token-mallory",
                    json{{"name", "Owned"}, {"avatar", "mxc://test/evil"}}.dump());

    EXPECT_TRUE(IsForbidden(res))
        << "a per-channel MANAGE_SERVER override rewrote bsfchat.server.info";
    EXPECT_NE(server_display_name(*f.store, room), "Owned")
        << "the server's name was changed by a user holding only a channel override";
}

// F2a — a delegated MANAGE_ROLES holder grants itself every flag in the channel.
TEST(PermissionContainment, F2a_ManageRolesCannotGrantItselfEveryChannelFlag) {
    Fixture f("f2a-selfgrant");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    PermissionsEngine before(*f.store, f.config);
    ASSERT_FALSE(before.can(builder, room, permission::kManageChannels));
    ASSERT_FALSE(before.can(builder, room, permission::kManageMessages));
    ASSERT_FALSE(before.can(builder, room, permission::kMentionEveryone));

    RoomHandler rooms(*f.store, *f.sync, f.config);
    auto res = call(rooms, &RoomHandler::handle_set_state,
                    state_path(room, std::string(event_type::kChannelPermissions),
                               "user:" + builder),
                    "token-builder", override_body(permission::kAllFlags));

    EXPECT_TRUE(IsForbidden(res))
        << "MANAGE_ROLES let the holder grant itself permissions it does not hold";

    PermissionsEngine after(*f.store, f.config);
    EXPECT_FALSE(after.can(builder, room, permission::kManageChannels))
        << "self-granted MANAGE_CHANNELS — this is DELETE /rooms/{id} on this channel";
    EXPECT_FALSE(after.can(builder, room, permission::kManageMessages))
        << "self-granted MANAGE_MESSAGES — redact anyone's message in this channel";
    EXPECT_FALSE(after.can(builder, room, permission::kMentionEveryone));
}

// F2b — the chain. F2a plus F1: MANAGE_ROLES in ONE channel becomes a
// server-wide act. Either fix alone closes it, which is why the audit asked
// for both.
TEST(PermissionContainment, F2b_ManageRolesInOneChannelCannotRenameTheServer) {
    Fixture f("f2b-chain");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    RoomHandler rooms(*f.store, *f.sync, f.config);

    call(rooms, &RoomHandler::handle_set_state,
         state_path(room, std::string(event_type::kChannelPermissions), "user:" + builder),
         "token-builder", override_body(permission::kManageServer));

    call(rooms, &RoomHandler::handle_set_state,
         state_path(room, std::string(event_type::kServerInfo)), "token-builder",
         json{{"name", "Owned"}}.dump());

    EXPECT_NE(server_display_name(*f.store, room), "Owned")
        << "MANAGE_ROLES in one channel was a two-request path to a server-wide setting";
}

// F2c — no rank check on a `user:<target>` override. A delegated MANAGE_ROLES
// holder silences somebody who outranks it in a channel it administers.
TEST(PermissionContainment, F2c_NoOverrideAgainstAUserRankedAboveYou) {
    Fixture f("f2c-rank");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    auto res = call(rooms, &RoomHandler::handle_set_state,
                    state_path(room, std::string(event_type::kChannelPermissions),
                               "user:" + admin),
                    "token-builder",
                    override_body(0, permission::kSendMessages | permission::kAddReactions));

    EXPECT_TRUE(IsForbidden(res))
        << "a channel override was written against a user ranked above the actor, "
           "with no rank check anywhere on the path";
}

// F2c, said about a target the DENY actually bites. ADMINISTRATOR
// short-circuits inside compute() before overrides are applied, so the admin
// above keeps every flag whatever is written; `senior` holds nothing but
// @everyone at position 50 and would really have been silenced.
TEST(PermissionContainment, F2c_TheSilencingIsRealForANonAdministrator) {
    Fixture f("f2c-real");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});
    auto senior = f.add_user("senior", {"senior"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);
    f.join(room, senior);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kChannelPermissions),
                                            "user:" + senior),
                                 "token-builder", override_body(0, permission::kSendMessages))));

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_TRUE(perms.can(senior, room, permission::kSendMessages))
        << "a builder muted a member ranked above it";
}

// F6 — the bot rank check measured roles, and a scoped bot holds none.
//
// BotHandler.h prescribes the per-channel override as THE way to scope a bot
// and handle_create_bot writes each new bot an explicitly empty role
// assignment, so a correctly scoped bot sat at position 0 forever and every
// MANAGE_BOTS holder at position >= 1 "outranked" it.
TEST(PermissionContainment, F6_BotRankSeesChannelOverrides) {
    Fixture f("f6-botrank");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto botmod = f.add_user("botmod", {"botmod"});

    // A channel the bot administrator is explicitly shut out of.
    auto secret = f.add_channel(admin, "leadership");
    f.join(secret, botmod);
    f.set_override(secret, "user:" + botmod, 0, permission::kViewChannel);

    // A bot, scoped the way BotHandler.h says to scope one: no roles at all,
    // plus a `user:<bot>` ALLOW override on the channel it is for.
    const std::string bot_id = "@bot_minutes:test";
    f.store->create_user(bot_id, std::string());
    {
        MemberRolesContent none;  // exactly what handle_create_bot writes
        json j;
        to_json(j, none);
        f.store->set_server_state(std::string(event_type::kMemberRoles), bot_id,
                                  "@server:test", j.dump());
    }
    f.set_override(secret, "user:" + bot_id,
                   permission::kViewChannel | permission::kSendMessages);
    f.join(secret, bot_id);

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_FALSE(perms.can(botmod, secret, permission::kViewChannel))
        << "precondition: the bot administrator cannot see #leadership";
    ASSERT_TRUE(perms.can(bot_id, secret, permission::kViewChannel))
        << "precondition: the bot can";

    EXPECT_FALSE(perms.outranks(botmod, bot_id))
        << "a MANAGE_BOTS holder outranks a channel-scoped bot, so POST "
           "/bsfchat/bots/{id}/token hands them a non-expiring credential for an "
           "account with access they do not have";
}

// ═════════════════════════════════════════════════════════════════════════════
// The rule is not wider than it claims: legitimate administration.
// ═════════════════════════════════════════════════════════════════════════════

// F1 moved a SCOPE, not a flag. The account that legitimately holds
// MANAGE_SERVER — from a role, at server scope — must still rename the server,
// and must still be able to do it from whichever room the client happens to
// have active, because that is how ServerConnection writes it.
TEST(PermissionContainment, AServerScopedManageServerHolderStillRenamesTheServer) {
    Fixture f("f1-legit");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto host = f.add_user("host", {"host"});  // MANAGE_SERVER, no ADMINISTRATOR

    auto room = f.add_channel(admin, "general");
    f.join(room, host);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kServerInfo)), "token-host",
                          json{{"name", "Renamed"}}.dump())));
    EXPECT_EQ(server_display_name(*f.store, room), "Renamed");
}

// The other direction of the same rule, and the reason server scope is the
// right instrument rather than "refuse unless you are an administrator": a
// per-channel DENY must not block a server-wide act either. Otherwise anyone
// holding MANAGE_ROLES in one channel could lock the owner out of the server's
// own name by writing a deny into it.
TEST(PermissionContainment, AChannelDenyCannotBlockAServerWideRename) {
    Fixture f("f1-deny");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto host = f.add_user("host", {"host"});

    auto room = f.add_channel(admin, "general");
    f.join(room, host);
    f.set_override(room, "user:" + host, 0, permission::kManageServer);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kServerInfo)), "token-host",
                          json{{"name", "Renamed"}}.dump())));
}

// Making a channel private is `@everyone DENY VIEW_CHANNEL`
// (docs/membership-vs-visibility.md), and it is the single most common thing
// MANAGE_ROLES is delegated FOR. It must survive the containment rule: the
// builder holds VIEW_CHANNEL in that channel, so it is theirs to deny, and
// @everyone is the floor rather than a principal ranked above anybody.
TEST(PermissionContainment, ABuilderCanStillMakeAChannelPrivate) {
    Fixture f("legit-private");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});
    auto member = f.add_user("member");

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);
    f.join(room, member);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     std::string("role:") + permission::role_id::kEveryone),
                          "token-builder", override_body(0, permission::kViewChannel))));

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_FALSE(perms.can(member, room, permission::kViewChannel));
}

// ...and letting somebody back in is the other half of the same job. An ALLOW
// of a bit the actor holds in the channel, aimed at anybody — including an
// account ranked ABOVE the actor, because handing a senior more access takes
// nothing from anyone and a channel's own manager must be able to let their
// own administrators in.
TEST(PermissionContainment, ABuilderCanStillGrantAccessIncludingToASenior) {
    Fixture f("legit-grant");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});
    auto member = f.add_user("member");
    auto senior = f.add_user("senior", {"senior"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);
    f.set_override(room, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);
    f.set_override(room, "user:" + builder, permission::kViewChannel);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + member),
                          "token-builder", override_body(permission::kViewChannel))));
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + senior),
                          "token-builder", override_body(permission::kViewChannel))));

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_TRUE(perms.can(member, room, permission::kViewChannel));
    EXPECT_TRUE(perms.can(senior, room, permission::kViewChannel));
}

// Granting a bot a channel is the documented way to scope one (BotHandler.h,
// "THERE IS NO WRITE SIBLING, deliberately"), so it goes through this route
// and must keep working for exactly the authority it took before: MANAGE_ROLES
// in the channel being granted.
TEST(PermissionContainment, ABuilderCanStillScopeABotIntoItsChannel) {
    Fixture f("legit-bot-scope");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    const std::string bot_id = "@bot_minutes:test";
    f.store->create_user(bot_id, std::string());

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + bot_id),
                          "token-builder",
                          override_body(permission::kViewChannel | permission::kSendMessages))));

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_TRUE(perms.can(bot_id, room, permission::kViewChannel));
}

// An administrator is bound by nothing here, as everywhere else on this
// server. If this fails, the fix has neutered the one account that must be
// able to repair everything.
TEST(PermissionContainment, AnAdministratorIsBoundByNeitherHalfOfTheRule) {
    Fixture f("legit-admin");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto senior = f.add_user("senior", {"senior"});
    auto room = f.add_channel(admin, "general");
    f.join(room, senior);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    // Every flag the server defines except the one nothing may say here, aimed
    // at an account the admin does not "outrank" by much, in both directions.
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + senior),
                          "token-admin",
                          override_body(permission::kAllFlags & ~permission::kAdministrator,
                                        permission::kMentionEveryone))));
}

// Echoing an override back unmodified is not a change, so neither rule has
// anything to say about it. This is what keeps a client that re-PUTs the state
// it just read from being refused, and it is why both rules are scoped to the
// difference rather than to the document.
TEST(PermissionContainment, EchoingAnExistingOverrideBackIsNotAChange) {
    Fixture f("legit-echo");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});
    auto senior = f.add_user("senior", {"senior"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);
    // An override the builder could never have written itself: a flag it does
    // not hold, aimed at somebody ranked above it.
    f.set_override(room, "user:" + senior, permission::kManageMessages,
                   permission::kMentionEveryone);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + senior),
                          "token-builder",
                          override_body(permission::kManageMessages,
                                        permission::kMentionEveryone))));
}

// Ordinary moderation is untouched. outranks() grew a second half, and the
// second half must be silent on a server where nobody has been given anything
// out of the ordinary — otherwise every kick, ban and nickname change on a
// normally-configured deployment starts failing.
TEST(PermissionContainment, RankIsUnchangedWhereNoChannelGrantsAnythingUnusual) {
    Fixture f("rank-ordinary");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});
    auto member = f.add_user("member");
    auto room = f.add_channel(admin, "general");
    f.join(room, builder);
    f.join(room, member);
    // A private channel exists and the builder is IN it, which is the case
    // that must not be confused with the one F6 is about.
    auto priv = f.add_channel(admin, "leadership");
    f.set_override(priv, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);
    f.set_override(priv, "user:" + builder, permission::kViewChannel);

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_TRUE(perms.outranks(builder, member));
    EXPECT_TRUE(perms.outranks(admin, builder));
    EXPECT_FALSE(perms.outranks(member, builder));
    EXPECT_EQ(perms.channel_access_excess(member, builder), 0u);
}

// ═════════════════════════════════════════════════════════════════════════════
// The rule is not narrower than it claims: the shapes next to the attacks.
// ═════════════════════════════════════════════════════════════════════════════

// REMOVING A DENY IS A GRANT. Containment scoped to "what the edit adds to
// allow" — which is how the audit sketched it — would miss this entirely: the
// builder writes an override whose `allow` is empty and whose `deny` has lost
// a bit, and everybody governed by that override gets MANAGE_MESSAGES back in
// a channel where somebody had deliberately taken it away. That is why the
// rule is stated over the symmetric difference of both fields.
TEST(PermissionContainment, RemovingADenyIsAGrantAndIsContainedToo) {
    Fixture f("grant-by-removal");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});
    auto senior = f.add_user("senior", {"senior"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);
    f.join(room, senior);
    // The server owner has decided nobody moderates messages in this channel.
    f.set_override(room, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kManageMessages);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    // The builder does not hold MANAGE_MESSAGES, so it may not un-deny it.
    EXPECT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kChannelPermissions),
                                            std::string("role:") +
                                                permission::role_id::kEveryone),
                                 "token-builder", override_body(0, 0))));
}

// TAKING A GRANT BACK IS MODERATION. The mirror of the test above: dropping an
// ALLOW the owner wrote for somebody senior removes their access just as
// surely as writing a DENY, so it answers to the rank rule and not only to
// containment.
TEST(PermissionContainment, WithdrawingAnAllowFromASeniorIsRefused) {
    Fixture f("withdraw-allow");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});
    auto senior = f.add_user("senior", {"senior"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);
    f.join(room, senior);
    f.set_override(room, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);
    f.set_override(room, "user:" + builder, permission::kViewChannel);
    f.set_override(room, "user:" + senior, permission::kViewChannel);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kChannelPermissions),
                                            "user:" + senior),
                                 "token-builder", override_body(0, 0))));

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_TRUE(perms.can(senior, room, permission::kViewChannel));
}

// The rank rule reaches a ROLE-keyed override too. Silencing a role in a
// channel and editing that role are the same act performed through different
// state, and may_edit_role_definitions already refuses the second.
TEST(PermissionContainment, NoTakeAwayAgainstARoleRankedAboveYou) {
    Fixture f("role-rank");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    // "senior" sits at 50, the builder at 10.
    EXPECT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kChannelPermissions),
                                            "role:senior"),
                                 "token-builder", override_body(0, permission::kSendMessages))));
    // ...and a role BELOW it is ordinary channel administration.
    f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                              [&] {
                                  auto roles = f.store->get_server_roles();
                                  ServerRolesContent c;
                                  c.roles = roles;
                                  c.roles.push_back(role("junior", 5,
                                                         permission::kEveryoneDefault));
                                  json j;
                                  to_json(j, c);
                                  return j.dump();
                              }());
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "role:junior"),
                          "token-builder", override_body(0, permission::kSendMessages))));
}

// ADMINISTRATOR means nothing in an override — compute() short-circuits it out
// of the ROLE BASE before a single override is applied — so writing it is
// always either a misunderstanding or an attempt, and the refusal binds
// everybody including an administrator. A stored one can still be cleared, so
// no channel is left unfixable.
TEST(PermissionContainment, AnOverrideMayNotGrantAdministratorEvenFromAnAdmin) {
    Fixture f("no-admin-bit");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto member = f.add_user("member");
    auto room = f.add_channel(admin, "general");
    f.join(room, member);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kChannelPermissions),
                                            "user:" + member),
                                 "token-admin", override_body(permission::kAdministrator))));

    // And the escape hatch: one written by an older build can be taken away.
    f.set_override(room, "user:" + member, permission::kAdministrator);
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + member),
                          "token-admin", override_body(0))));
}

// An override has to name somebody compute() will actually look for. Anything
// else is a permission grant that is stored, mirrored to every client through
// /sync and recorded in the audit log as a permission change, and then read by
// nothing — the same "store what we do not understand" shape this route
// already refuses for an unlisted event type.
TEST(PermissionContainment, AnOverrideMustNameAUserOrARole) {
    Fixture f("key-shape");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(admin, "general");

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kChannelPermissions),
                                            "everyone"),
                                 "token-admin", override_body(permission::kViewChannel))));
}

// F6, for the bot configuration that is actually the common one. Every bot on
// a running server already holds @everyone explicitly, because bootstrap_roles
// wrote it at creation — so the bot's SERVER-WIDE permissions are identical to
// the bot administrator's, and a rank rule that only compared the two accounts'
// baselines would see no difference at all. What separates them is one channel.
TEST(PermissionContainment, F6_HoldsForABotThatDoesHoldEveryone) {
    Fixture f("f6-everyone-bot");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto botmod = f.add_user("botmod", {"botmod"});

    auto secret = f.add_channel(admin, "leadership");
    f.set_override(secret, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);

    const std::string bot_id = "@bot_minutes:test";
    f.store->create_user(bot_id, std::string());
    f.assign_roles(bot_id, {});  // @everyone, spelled out, as bootstrap writes it
    f.set_override(secret, "user:" + bot_id, permission::kViewChannel);
    f.join(secret, bot_id);

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_EQ(perms.compute(bot_id, std::string()) & permission::kEveryoneDefault,
              permission::kEveryoneDefault)
        << "precondition: this bot does hold @everyone at server scope";
    ASSERT_FALSE(perms.can(botmod, secret, permission::kViewChannel));
    ASSERT_TRUE(perms.can(bot_id, secret, permission::kViewChannel));

    EXPECT_FALSE(perms.outranks(botmod, bot_id));
}

// F6 end to end, through the endpoint that hands out the credential.
TEST(PermissionContainment, F6_TokenRotationIsRefusedForAChannelScopedBot) {
    Fixture f("f6-rotate");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto botmod = f.add_user("botmod", {"botmod"});

    BotHandler bots(*f.store, *f.sync, f.config);
    auto created = call(bots, &BotHandler::handle_create_bot,
                        "/_matrix/client/v3/bsfchat/bots", "token-admin",
                        json{{"localpart", "bot_minutes"}}.dump());
    ASSERT_EQ(created.status, 201) << created.body;
    const std::string bot_id = json::parse(created.body).value("user_id", "");
    ASSERT_FALSE(bot_id.empty());

    auto secret = f.add_channel(admin, "leadership");
    f.set_override(secret, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);
    f.set_override(secret, "user:" + bot_id,
                   permission::kViewChannel | permission::kSendMessages);
    f.join(secret, bot_id);

    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.can(botmod, std::string(), permission::kManageBots));
        ASSERT_FALSE(perms.can(botmod, std::string(), permission::kAdministrator));
        ASSERT_FALSE(perms.can(botmod, secret, permission::kViewChannel));
        ASSERT_TRUE(perms.can(bot_id, secret, permission::kViewChannel));
    }

    auto res = call(bots, &BotHandler::handle_rotate_token,
                    "/_matrix/client/v3/bsfchat/bots/" + bot_id + "/token", "token-botmod");
    EXPECT_TRUE(IsForbidden(res))
        << "a delegated bot administrator rotated the token of a bot that reads a "
           "channel they are denied";
    // No credential in the body, checked as a FIELD: the refusal message
    // legitimately contains the word "token".
    auto body = json::parse(res.body, nullptr, false);
    ASSERT_FALSE(body.is_discarded());
    EXPECT_FALSE(body.contains("token"));

    // The control: an administrator is still able to rotate it, so the fix has
    // not left an unmaintainable bot behind.
    EXPECT_TRUE(IsOk(call(bots, &BotHandler::handle_rotate_token,
                          "/_matrix/client/v3/bsfchat/bots/" + bot_id + "/token",
                          "token-admin")));
}

// THE ROLE HALF OF RANK IS UNCHANGED, and this is the test that stops the
// channel half being written too widely. `patrol` holds KICK_MEMBERS and not
// MANAGE_MESSAGES; `helper` holds MANAGE_MESSAGES and sits below it. Comparing
// the two accounts' effective permissions room by room and demanding a superset
// would make `patrol` unable to moderate `helper` anywhere — which is the
// arrangement `position` exists to express, and it is why
// channel_access_excess() subtracts the server-scope difference before it
// looks at anything.
//
// On a server WITH a private channel, so the sweep actually runs.
TEST(PermissionContainment, RankStillGovernsTheRoleHalf) {
    Fixture f("rank-role-half");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto patrol = f.add_user("patrol", {"patrol"});
    auto helper = f.add_user("helper", {"helper"});

    auto priv = f.add_channel(admin, "leadership");
    f.set_override(priv, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_FALSE(perms.can(patrol, std::string(), permission::kManageMessages))
        << "precondition: the moderator does NOT hold what the target holds";
    ASSERT_TRUE(perms.can(helper, std::string(), permission::kManageMessages));

    EXPECT_EQ(perms.channel_access_excess(helper, patrol), 0u)
        << "a server-wide role difference was counted as channel access";
    EXPECT_TRUE(perms.outranks(patrol, helper))
        << "a moderator can no longer moderate anybody holding a flag they lack";
}

// The engine re-checks MANAGE_ROLES itself rather than trusting the caller to
// have done it. Deliberately redundant with RoomHandler's own gate today, and
// therefore deliberately pinned HERE, at the engine, so the redundancy is a
// tested property rather than a line somebody deletes as dead.
TEST(PermissionContainment, TheEngineIsTheAuthorityAndRechecksManageRoles) {
    Fixture f("engine-authority");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto member = f.add_user("member");
    auto room = f.add_channel(admin, "general");
    f.join(room, member);

    PermissionsEngine perms(*f.store, f.config);
    ChannelPermissionOverride before;
    ChannelPermissionOverride proposed;
    proposed.allow = permission::kViewChannel;  // a bit the member does hold

    auto verdict = perms.may_write_channel_override(member, room, "user:" + member, before,
                                                    proposed);
    EXPECT_FALSE(verdict.allowed)
        << "the engine granted an override to an actor with no Manage Roles";
}

// F2a with ADMINISTRATOR taken out of the request.
//
// The audit's F2a writes `allow = kAllFlags`, which contains ADMINISTRATOR —
// and ADMINISTRATOR in an override is refused by a separate, earlier rule that
// binds everybody. So F2a on its own would go green even if containment were
// deleted, which is precisely the "passes for the wrong reason" failure these
// proofs exist to avoid. This is the same attack asking for exactly the flags
// that made it serious: delete the channel, redact anyone in it, ping
// everybody.
TEST(PermissionContainment, F2a_ContainmentAloneRefusesTheSelfGrant) {
    Fixture f("f2a-no-admin-bit");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});
    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kChannelPermissions),
                                            "user:" + builder),
                                 "token-builder",
                                 override_body(permission::kManageChannels |
                                               permission::kManageMessages |
                                               permission::kMentionEveryone))));

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_FALSE(perms.can(builder, room, permission::kManageChannels));
    EXPECT_FALSE(perms.can(builder, room, permission::kManageMessages));
    EXPECT_FALSE(perms.can(builder, room, permission::kMentionEveryone));
}

// ── "here is your own channel" ──────────────────────────────────────────────
//
// The arrangement handle_set_state's own comments call "the natural way to
// give someone their own channel": an ordinary member, holding no role beyond
// @everyone, handed MANAGE_ROLES (and more) by an ALLOW override on one room.
// They sit at role position 0 forever, because an override confers no rank.
//
// Both of these pin a place where the containment rule could be written a
// plausible-looking degree too strictly and silently take the feature away.

// Containment is measured IN THE CHANNEL, not at server scope. What the
// channel gave this actor is theirs to pass on inside it — that is the whole
// of what "your own channel" means — and measuring against their server-wide
// permissions instead would leave them able to administer nothing.
TEST(PermissionContainment, AChannelManagerMayShareWhatTheChannelGaveThem) {
    Fixture f("own-channel-grant");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto owner = f.add_user("owner");    // no roles at all beyond @everyone
    auto friend_ = f.add_user("friendo");

    auto room = f.add_channel(admin, "owners-corner");
    f.join(room, owner);
    f.join(room, friend_);
    f.set_override(room, "user:" + owner,
                   permission::kManageRoles | permission::kManageMessages);

    PermissionsEngine before(*f.store, f.config);
    ASSERT_FALSE(before.can(owner, std::string(), permission::kManageRoles))
        << "precondition: this authority exists only inside the channel";
    ASSERT_EQ(before.highest_role_position(owner), 0)
        << "precondition: an override confers no rank";

    RoomHandler rooms(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + friend_),
                          "token-owner", override_body(permission::kManageMessages))));

    PermissionsEngine after(*f.store, f.config);
    EXPECT_TRUE(after.can(friend_, room, permission::kManageMessages));
}

// ...and @everyone is exempt from the rank rule, which is the only reason that
// same actor can make their channel private. @everyone sits at position 0 and
// so does an actor whose authority is an override, so a rank test applied here
// would compare 0 against 0, refuse, and remove "make this channel private"
// from everybody who was given a channel rather than a role.
TEST(PermissionContainment, AChannelManagerAtPositionZeroMayStillDenyEveryone) {
    Fixture f("own-channel-private");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto owner = f.add_user("owner");
    auto member = f.add_user("member");

    auto room = f.add_channel(admin, "owners-corner");
    f.join(room, owner);
    f.join(room, member);
    // MANAGE_ROLES plus VIEW_CHANNEL, because the @everyone deny below strips
    // VIEW from the actor's base too — it is a statement about the CHANNEL,
    // not about the role — and only the later user: override puts it back.
    f.set_override(room, "user:" + owner,
                   permission::kManageRoles | permission::kViewChannel);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     std::string("role:") + permission::role_id::kEveryone),
                          "token-owner", override_body(0, permission::kViewChannel))));

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_FALSE(perms.can(member, room, permission::kViewChannel));
    // The owner keeps their own access: their user: override is applied after
    // the @everyone one, which is the ordering compute() documents.
    EXPECT_TRUE(perms.can(owner, room, permission::kViewChannel));
}

// The door refuses an ADMINISTRATOR override; this pins the other half of that
// pair, which is older and more important: an override carrying the bit — one
// stored by a build before the refusal, or written by the synthetic @server
// actor — CONFERS NOTHING. compute() takes the administrator short-circuit
// from the ROLE base, before a single override is applied.
//
// Kept as a test in its own right precisely because the write is now refused:
// the day the door-level rule is the only thing pinning this, somebody will
// relax the door and discover the model never protected them. Written straight
// into the store for that reason, bypassing the route entirely.
TEST(PermissionContainment, AnAdministratorOverrideStoredByAnOlderBuildConfersNothing) {
    Fixture f("inert-admin-override");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto member = f.add_user("member");
    auto room = f.add_channel(admin, "general");
    f.join(room, member);
    f.set_override(room, "user:" + member, permission::kAdministrator);

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_FALSE(perms.can(member, room, permission::kManageServer));
    EXPECT_FALSE(perms.can(member, room, permission::kManageChannels));
    EXPECT_FALSE(perms.can(member, room, permission::kManageBots));
    EXPECT_FALSE(perms.can(member, std::string(), permission::kAdministrator));
    // And it confers no RANK either, which is the F6 half of the same question.
    EXPECT_EQ(perms.highest_role_position(member), 0);
    EXPECT_FALSE(perms.outranks(member, admin));
}
