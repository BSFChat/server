// GET /_matrix/client/v3/bsfchat/permissions/{userId} — the read an integration
// uses to answer "may this person administer me?" without keeping an allowlist.
//
// The properties under test, in the order they appear below:
//   1. The mask is the SERVER-SCOPE answer, and a per-channel override can
//      neither add a flag to it nor take one away. This is the bug the endpoint
//      would most plausibly grow: compute() takes a room id, and passing one
//      would make the endpoint confidently predict a verdict the enforcing
//      endpoints (which all evaluate MANAGE_BOTS at server scope) do not reach.
//   2. The values on the wire are the ones protocol/Permissions.h defines and
//      docs/bots.md promises — not merely values this build agrees with itself
//      about. See the note on drift below.
//   3. It is the ONE authority: the answer equals PermissionsEngine's, so a
//      second copy of the algorithm cannot be introduced here unnoticed.
//   4. It stays correct across a reassignment with no invalidation step,
//      because it caches nothing.
//   5. The authorization rule — self, a shared channel the caller may VIEW, or
//      MANAGE_ROLES at server scope — holds in every direction, including the
//      three ways this codebase has got that shape wrong before: membership
//      mistaken for visibility, the category exemption escaping the sidebar,
//      and a per-channel grant unlocking a server-wide capability.
//   6. It is not an account-existence oracle: a stranger and a user who never
//      existed get byte-identical refusals.
//
// ON DERIVING EXPECTATIONS. The client has a known hazard here — a test named
// everyEnforcedPermissionHasASwitchInTheRoleEditor compared the client's mask
// to the CLIENT's own kAllFlags, so protocol drift was structurally invisible
// and the test could not fail. The equivalent mistake in this file would be to
// assert only "the endpoint says what PermissionsEngine says", which is true of
// any two copies of the same bug. So the numeric expectations below are built
// from protocol constants (permission::kEveryoneDefault, kAllFlags,
// kManageBots), and one test pins the literal hex a bot author copies out of
// docs/bots.md. The engine-agreement test is kept as well, but it is testing a
// STRUCTURAL property — that no second implementation exists — and is labelled
// as such rather than being mistaken for a correctness check.

#include <gtest/gtest.h>

#include "api/PermissionsHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-effperm-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

std::string path_for(const std::string& user_id) {
    return std::string(api_path::kPermissions) + "/" + user_id;
}

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

::testing::AssertionResult IsRefused(const httplib::Response& res, int expected_status) {
    if (res.status != expected_status) {
        return ::testing::AssertionFailure() << "expected " << expected_status << ", got status "
                                             << res.status << ", body: " << res.body;
    }
    return ::testing::AssertionSuccess();
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
    std::unique_ptr<PermissionsHandler> handler;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        handler = std::make_unique<PermissionsHandler>(*store, config);
        seed_roles();
    }

    ~Fixture() {
        handler.reset();
        store.reset();
        remove_db(db_path);
    }

    // Written straight into server_state rather than through
    // write_server_scoped_state, so fixture setup neither writes audit records
    // nor depends on a mirror room existing — which is the whole point of the
    // endpoint: an integration must not need to be in the mirror room.
    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault));
        // MANAGE_BOTS WITHOUT ADMINISTRATOR, so the flag is exercised on its own
        // rather than on the god-mode short-circuit. A test that only ever sees
        // an administrator cannot tell the two apart.
        content.roles.push_back(role("botadmin", 10,
                                     permission::kEveryoneDefault | permission::kManageBots));
        // MANAGE_ROLES without ADMINISTRATOR, for the read-authorization branch.
        content.roles.push_back(role("rolemod", 20,
                                     permission::kEveryoneDefault | permission::kManageRoles));
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
        assign(uid, extra_roles);
        return uid;
    }

    void assign(const std::string& uid, const std::vector<std::string>& extra_roles) {
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
    }

    std::string add_channel(const std::string& creator, const std::string& name,
                            const std::string& room_type = "text") {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", room_type}}.dump(), 1001);
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
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

    httplib::Response ask(const std::string& token, const std::string& about) {
        return ask_path(token, path_for(about));
    }

    httplib::Response ask_path(const std::string& token, const std::string& path) {
        httplib::Request req;
        req.path = path;
        if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        handler->handle_get_permissions(req, res);
        return res;
    }
};

permission::Flags reported(const httplib::Response& res) {
    return permission::flags_from_hex(json::parse(res.body)["permissions"].get<std::string>());
}

} // namespace

// ══ 1. The answer ══════════════════════════════════════════════════════════

// ADMINISTRATOR short-circuits to every flag, so a bot's check is a plain mask
// test with no special case for administrators. Expectation taken from
// protocol's kAllFlags, not from anything this server computed.
TEST(BotPermissionQuery, AnAdministratorReadsBackEveryFlagTheProtocolDefines) {
    Fixture f("admin");
    auto bot = f.add_user("bot_tibiaguru");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(admin, "general");
    f.join(room, bot);

    auto res = f.ask("token-bot_tibiaguru", admin);
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    EXPECT_EQ(body["user_id"], admin);
    EXPECT_EQ(body["scope"], "server");
    EXPECT_EQ(reported(res), permission::kAllFlags);
    EXPECT_TRUE(permission::has(reported(res), permission::kManageBots));
}

// The complement, and the one that actually protects the bot: an ordinary
// member reads back exactly @everyone's default set and no more.
TEST(BotPermissionQuery, APlainMemberReadsBackExactlyTheEveryoneDefault) {
    Fixture f("member");
    auto bot = f.add_user("bot_tibiaguru");
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");
    f.join(room, bot);

    auto res = f.ask("token-bot_tibiaguru", member);
    ASSERT_TRUE(IsOk(res));
    EXPECT_EQ(reported(res), permission::kEveryoneDefault);
    EXPECT_FALSE(permission::has(reported(res), permission::kManageBots));
}

// MANAGE_BOTS held through an ordinary role, with no ADMINISTRATOR anywhere.
// Without this the suite could not tell "the endpoint reports MANAGE_BOTS" from
// "the endpoint reports the god-mode short-circuit".
TEST(BotPermissionQuery, ManageBotsHeldThroughARoleIsReported) {
    Fixture f("botadmin");
    auto bot = f.add_user("bot_tibiaguru");
    auto lead = f.add_user("lead", {"botadmin"});
    auto room = f.add_channel(lead, "general");
    f.join(room, bot);

    auto res = f.ask("token-bot_tibiaguru", lead);
    ASSERT_TRUE(IsOk(res));
    EXPECT_TRUE(permission::has(reported(res), permission::kManageBots));
    EXPECT_FALSE(permission::has(reported(res), permission::kAdministrator))
        << "this fixture must reach MANAGE_BOTS without ADMINISTRATOR, or it proves nothing";
    EXPECT_EQ(reported(res), permission::kEveryoneDefault | permission::kManageBots);
}

// THE WIRE CONTRACT, pinned to the literal a bot author copies out of
// docs/bots.md §8 rather than to a constant this build could rename or move.
// If MANAGE_BOTS is ever renumbered, every deployed bot silently starts
// authorizing the wrong people; this is the test that stops that landing
// quietly, and it is deliberately written with the number spelled out.
TEST(BotPermissionQuery, TheDocumentedHexForManageBotsIsWhatTheEndpointReports) {
    Fixture f("wire");
    auto bot = f.add_user("bot_tibiaguru");
    auto lead = f.add_user("lead", {"botadmin"});
    auto plain = f.add_user("plain");
    auto room = f.add_channel(lead, "general");
    f.join(room, bot);
    f.join(room, plain);

    constexpr std::uint64_t kDocumentedManageBots = 0x2000ULL;  // bots.md §8, bit 13
    ASSERT_EQ(permission::kManageBots, kDocumentedManageBots)
        << "protocol moved MANAGE_BOTS; docs/bots.md and every deployed bot say 0x2000";

    auto held = f.ask("token-bot_tibiaguru", lead);
    ASSERT_TRUE(IsOk(held));
    auto held_body = json::parse(held.body);
    ASSERT_TRUE(held_body["permissions"].is_string())
        << "permissions is a hex STRING; JSON cannot carry 64 bits as a number";
    EXPECT_NE(permission::flags_from_hex(held_body["permissions"].get<std::string>()) &
                  kDocumentedManageBots, 0u);
    // The exact spelling, so a bot doing a string comparison or a client reusing
    // flags_from_hex both see what every other permission field on the wire uses.
    EXPECT_EQ(held_body["permissions"],
              permission::flags_to_hex(permission::kEveryoneDefault | permission::kManageBots));

    auto lacking = f.ask("token-bot_tibiaguru", plain);
    ASSERT_TRUE(IsOk(lacking));
    EXPECT_EQ(permission::flags_from_hex(
                  json::parse(lacking.body)["permissions"].get<std::string>()) &
                  kDocumentedManageBots, 0u);
}

// MINIMUM DISCLOSURE, pinned as an exact key set rather than as "contains".
//
// The question is "what may this person do", and the answer is a mask. The
// member's ROLE IDS are strictly more than that — they would name private roles
// ("mods-in-training", "trust-level-3", "shadowbanned") to a caller whose whole
// claim is sharing one channel, and a role id is a durable label a bot could
// log, correlate and keep. The engine has roles_of() sitting right there and
// adding it to this response is a one-line convenience somebody will reach for,
// so the test asserts the response has exactly three keys and names them.
//
// If a field is deliberately added later, change this test and say why in the
// same commit; that is the point of spelling the set out.
TEST(BotPermissionQuery, TheResponseDisclosesTheMaskAndNothingElse) {
    Fixture f("shape");
    auto bot = f.add_user("bot_tibiaguru");
    auto lead = f.add_user("lead", {"botadmin"});
    auto room = f.add_channel(lead, "general");
    f.join(room, bot);

    auto res = f.ask("token-bot_tibiaguru", lead);
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    ASSERT_TRUE(body.is_object());
    std::vector<std::string> keys;
    for (auto it = body.begin(); it != body.end(); ++it) keys.push_back(it.key());
    std::sort(keys.begin(), keys.end());
    EXPECT_EQ(keys, (std::vector<std::string>{"permissions", "scope", "user_id"}))
        << "the response grew a field; role ids in particular are a disclosure "
           "this endpoint's authorization rule does not pay for. Body: " << res.body;
}

// STRUCTURAL, not numeric: proves the handler delegates rather than computing.
// It cannot catch a bug the engine and the handler share — that is what the
// protocol-derived tests above are for — but it is the thing that fails the day
// somebody "optimises" the handler by OR-ing role bits locally, which is the
// drift that produced client/src/util/PermissionMath.cpp's divergence.
TEST(BotPermissionQuery, TheAnswerIsThePermissionsEngineAnswerAtServerScope) {
    Fixture f("authority");
    auto bot = f.add_user("bot_tibiaguru");
    auto room = f.add_channel(bot, "general");
    std::vector<std::string> targets = {
        f.add_user("plain"),
        f.add_user("lead", {"botadmin"}),
        f.add_user("rolemod", {"rolemod"}),
        f.add_user("admin", {std::string(permission::role_id::kAdmin)}),
    };
    for (const auto& t : targets) f.join(room, t);

    for (const auto& target : targets) {
        auto res = f.ask("token-bot_tibiaguru", target);
        ASSERT_TRUE(IsOk(res)) << target;
        PermissionsEngine perms(*f.store, f.config);
        EXPECT_EQ(reported(res), perms.compute(target, std::string()))
            << "the endpoint disagrees with the engine about " << target;
    }
}

// The answer must not go stale, and it does not need an invalidation step to
// avoid it: nothing is cached, so the call AFTER a reassignment is already
// right. This is the property that decided the design — a mirror-into-every-room
// scheme would leave a bot that missed or never received the event authorizing
// somebody who has just been demoted.
TEST(BotPermissionQuery, AReassignmentIsVisibleToTheVeryNextCall) {
    Fixture f("reassign");
    auto bot = f.add_user("bot_tibiaguru");
    auto lead = f.add_user("lead", {"botadmin"});
    auto room = f.add_channel(lead, "general");
    f.join(room, bot);

    ASSERT_TRUE(permission::has(reported(f.ask("token-bot_tibiaguru", lead)),
                                permission::kManageBots));

    // Demoted. No restart, no cache flush, no event delivered to the bot.
    f.assign(lead, {});
    EXPECT_FALSE(permission::has(reported(f.ask("token-bot_tibiaguru", lead)),
                                 permission::kManageBots));

    // And back, so the test is about tracking the value rather than about the
    // answer decaying in one direction.
    f.assign(lead, {"botadmin"});
    EXPECT_TRUE(permission::has(reported(f.ask("token-bot_tibiaguru", lead)),
                                permission::kManageBots));
}

// Editing the ROLE rather than the assignment is the other half of the same
// property, and it is a separate code path in the engine (the role document,
// not the member's ids).
TEST(BotPermissionQuery, ARoleEditIsVisibleToTheVeryNextCall) {
    Fixture f("roleedit");
    auto bot = f.add_user("bot_tibiaguru");
    auto lead = f.add_user("lead", {"botadmin"});
    auto room = f.add_channel(lead, "general");
    f.join(room, bot);

    ASSERT_TRUE(permission::has(reported(f.ask("token-bot_tibiaguru", lead)),
                                permission::kManageBots));

    ServerRolesContent content;
    content.roles.push_back(role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
    content.roles.push_back(role("botadmin", 10, permission::kEveryoneDefault));  // flag removed
    json j;
    to_json(j, content);
    f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test", j.dump());

    EXPECT_FALSE(permission::has(reported(f.ask("token-bot_tibiaguru", lead)),
                                 permission::kManageBots));
}

// ══ 2. Server scope ════════════════════════════════════════════════════════

// The likeliest future bug: handing compute() a room id. A channel override
// that genuinely grants MANAGE_BOTS inside one channel must not appear in this
// answer, because BotHandler evaluates MANAGE_BOTS at SERVER scope — so an
// endpoint that reported the channel answer would tell a bot that somebody may
// administer it who would in fact be refused by the server.
TEST(BotPermissionQueryScope, AChannelOverrideCannotGrantManageBotsInTheAnswer) {
    Fixture f("scopegrant");
    auto bot = f.add_user("bot_tibiaguru");
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");
    f.join(room, bot);
    f.set_override(room, "user:" + member, permission::kManageBots);
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.can(member, room, permission::kManageBots))
            << "the override must actually grant it in-channel, or this proves nothing";
    }

    auto res = f.ask("token-bot_tibiaguru", member);
    ASSERT_TRUE(IsOk(res));
    EXPECT_FALSE(permission::has(reported(res), permission::kManageBots));
    EXPECT_EQ(reported(res), permission::kEveryoneDefault);
    EXPECT_EQ(json::parse(res.body)["scope"], "server");
}

// The mirror image. A channel DENY must not subtract from a server-scoped
// answer either — a bot told "this administrator holds nothing" would refuse
// the one person who can actually fix it.
TEST(BotPermissionQueryScope, AChannelOverrideCannotRemoveAServerScopedFlagFromTheAnswer) {
    Fixture f("scopedeny");
    auto bot = f.add_user("bot_tibiaguru");
    auto lead = f.add_user("lead", {"botadmin"});
    auto room = f.add_channel(lead, "general");
    f.join(room, bot);
    f.set_override(room, "user:" + lead, 0, permission::kManageBots);
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_FALSE(perms.can(lead, room, permission::kManageBots))
            << "the override must actually deny it in-channel, or this proves nothing";
    }

    auto res = f.ask("token-bot_tibiaguru", lead);
    ASSERT_TRUE(IsOk(res));
    EXPECT_TRUE(permission::has(reported(res), permission::kManageBots));
}

// ══ 3. Who may ask about whom ══════════════════════════════════════════════

// Self-introspection must work before the bot is in any channel: a shared
// library calls it at startup, and an integration that has just been created
// has been invited nowhere.
TEST(BotPermissionQueryAccess, ACallerMayAlwaysAskAboutItself) {
    Fixture f("self");
    auto bot = f.add_user("bot_tibiaguru");
    ASSERT_TRUE(f.store->get_joined_rooms(bot).empty());

    auto res = f.ask("token-bot_tibiaguru", bot);
    ASSERT_TRUE(IsOk(res));
    EXPECT_EQ(json::parse(res.body)["user_id"], bot);
}

// The legitimate case, and it costs no privilege at all: the bot was invited
// into the channel it is being commanded from, and that is the whole claim.
TEST(BotPermissionQueryAccess, ASharedChannelIsEnoughAndNeedsNoPrivilege) {
    Fixture f("shared");
    auto bot = f.add_user("bot_tibiaguru");
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");
    f.join(room, bot);
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_FALSE(perms.can(bot, std::string(), permission::kManageRoles))
            << "the bot must hold no role privilege, or this proves nothing";
    }

    EXPECT_TRUE(IsOk(f.ask("token-bot_tibiaguru", member)));
}

// No shared channel, no answer. This is the anti-enumeration rule: without it
// any account holding any token could walk the user namespace and build a map
// of who holds power on the server.
TEST(BotPermissionQueryAccess, ACallerSharingNothingIsRefused) {
    Fixture f("stranger");
    auto bot = f.add_user("bot_tibiaguru");
    auto stranger = f.add_user("stranger");
    f.add_channel(stranger, "theirs");   // the bot is not in it
    f.join(f.add_channel(bot, "mine"), bot);  // and the stranger is not in this one

    EXPECT_TRUE(IsRefused(f.ask("token-bot_tibiaguru", stranger), 403));
}

// MEMBERSHIP IS NOT VISIBILITY. Every channel on this server is created public
// and force-joined, and a "private" one is a channel where VIEW_CHANNEL was
// denied afterwards — so "joined but not permitted to see" is the normal state,
// not an edge case. A rule written on membership alone would let anyone read
// anyone, because everyone is joined to everything. This is the test that would
// fail if the VIEW_CHANNEL term were dropped.
TEST(BotPermissionQueryAccess, MembershipWithoutViewChannelIsNotEnough) {
    Fixture f("blindmember");
    auto bot = f.add_user("bot_tibiaguru");
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "secret");
    f.join(room, bot);
    f.set_override(room, "user:" + bot, 0, permission::kViewChannel);
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_FALSE(perms.can(bot, room, permission::kViewChannel))
            << "the bot must genuinely be unable to view the room, or this proves nothing";
        ASSERT_TRUE(f.store->is_room_member(room, bot))
            << "and must genuinely still be a member, or this tests the wrong thing";
    }

    EXPECT_TRUE(IsRefused(f.ask("token-bot_tibiaguru", member), 403));
}

// The category exemption belongs to LISTING a room, not to a request that acts.
// can_view_room() lets a category through whatever VIEW_CHANNEL says, so that
// the sidebar can draw a container whose children are hidden. Importing that
// helper here would quietly restore "any account may ask about any account",
// because the categories are exactly the rooms everybody is in.
TEST(BotPermissionQueryAccess, ACategoryDoesNotCountAsASharedChannel) {
    Fixture f("category");
    auto bot = f.add_user("bot_tibiaguru");
    auto member = f.add_user("member");
    auto category = f.add_channel(member, "Text Channels", "category");
    f.join(category, bot);
    f.set_override(category, "user:" + bot, 0, permission::kViewChannel);
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_FALSE(perms.can(bot, category, permission::kViewChannel));
    }

    EXPECT_TRUE(IsRefused(f.ask("token-bot_tibiaguru", member), 403))
        << "the category exemption must not leak out of the sidebar into this rule";
}

// A caller who can REWRITE the assignment graph may read it. Server scope.
TEST(BotPermissionQueryAccess, ManageRolesAtServerScopeAsksAboutAnyone) {
    Fixture f("rolemod");
    auto mod = f.add_user("rolemod", {"rolemod"});
    auto stranger = f.add_user("stranger");
    f.add_channel(stranger, "theirs");
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_FALSE(perms.can(mod, std::string(), permission::kAdministrator))
            << "MANAGE_ROLES must be reached without ADMINISTRATOR, or this proves nothing";
    }

    EXPECT_TRUE(IsOk(f.ask("token-rolemod", stranger)));
}

// ...but MANAGE_ROLES granted inside ONE channel unlocks nothing. This shape
// has been a real hole in this codebase more than once, which is why the
// handler passes the empty room id and has no room to be confused about.
TEST(BotPermissionQueryAccess, ManageRolesInsideOneChannelUnlocksNothing) {
    Fixture f("chanrolemod");
    auto member = f.add_user("member");
    auto stranger = f.add_user("stranger");
    auto room = f.add_channel(member, "mine");
    f.set_override(room, "user:" + member, permission::kManageRoles);
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.can(member, room, permission::kManageRoles))
            << "the override must actually grant it in-channel, or this proves nothing";
    }

    EXPECT_TRUE(IsRefused(f.ask("token-member", stranger), 403));
}

// NOT AN EXISTENCE ORACLE. A stranger and an account that never existed must be
// indistinguishable — same status AND same body, because "M_FORBIDDEN vs
// M_NOT_FOUND" is a perfectly good oracle. GET /profile/{userId} still answers
// 404 vs 200 for authenticated callers; this endpoint is not going to add a
// second way to walk the namespace.
TEST(BotPermissionQueryAccess, AnUnknownUserIsRefusedIdenticallyToAStranger) {
    Fixture f("oracle");
    auto bot = f.add_user("bot_tibiaguru");
    auto stranger = f.add_user("stranger");
    f.add_channel(stranger, "theirs");

    auto known = f.ask("token-bot_tibiaguru", stranger);
    auto unknown = f.ask("token-bot_tibiaguru", "@nobody_at_all:test");
    ASSERT_TRUE(IsRefused(known, 403));
    ASSERT_TRUE(IsRefused(unknown, 403));
    EXPECT_EQ(known.status, unknown.status);
    EXPECT_EQ(known.body, unknown.body)
        << "the two refusals differ, which is an account-existence oracle";
}

// The synthetic @server actor short-circuits to every flag inside
// PermissionsEngine. If it were answerable, a bot would be told that anything
// wearing that sender is a full administrator. It is not a row in `users`, so
// the existence check stops it — including on the MANAGE_ROLES branch, which
// the shared-channel rule would not have covered.
TEST(BotPermissionQueryAccess, TheSyntheticServerActorIsNotQueryable) {
    Fixture f("serveractor");
    auto mod = f.add_user("rolemod", {"rolemod"});
    const std::string server_actor = "@server:" + f.config.server_name;
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_EQ(perms.compute(server_actor, std::string()), permission::kAllFlags)
            << "if the engine stops short-circuiting this actor, this test is about nothing";
    }

    EXPECT_TRUE(IsRefused(f.ask("token-rolemod", server_actor), 403));
}

// A banned identity is told nothing. The ban projection rewrites its membership
// rows, so the shared-channel rule refuses on its own — but a ban does not touch
// roles, so without the explicit check a banned MANAGE_ROLES holder would keep
// reading the whole server.
TEST(BotPermissionQueryAccess, ABannedCallerIsRefused) {
    Fixture f("banned");
    auto mod = f.add_user("rolemod", {"rolemod"});
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");
    f.join(room, mod);
    ASSERT_TRUE(IsOk(f.ask("token-rolemod", member)));

    f.store->set_server_ban(mod, "@server:test", "spam", 0);
    EXPECT_TRUE(IsRefused(f.ask("token-rolemod", member), 403));
}

TEST(BotPermissionQueryAccess, AnUnauthenticatedRequestIsRefused) {
    Fixture f("noauth");
    auto member = f.add_user("member");

    EXPECT_TRUE(IsRefused(f.ask("", member), 401));
    EXPECT_TRUE(IsRefused(f.ask("not-a-real-token", member), 401));
}

// Clients percent-encode the user id in a path segment, because it contains '@'
// and ':'. The router decodes it; this pins that the endpoint resolves the same
// account either way, so a correctly-behaved HTTP client is not answered 403 for
// a target it may perfectly well ask about.
TEST(BotPermissionQueryAccess, APercentEncodedUserIdResolves) {
    Fixture f("encoded");
    auto bot = f.add_user("bot_tibiaguru");
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "general");
    f.join(room, bot);

    auto res = f.ask_path("token-bot_tibiaguru",
                          std::string(api_path::kPermissions) + "/%40member%3Atest");
    ASSERT_TRUE(IsOk(res));
    EXPECT_EQ(json::parse(res.body)["user_id"], member);
    EXPECT_EQ(json::parse(res.body)["permissions"],
              permission::flags_to_hex(permission::kEveryoneDefault));
}
