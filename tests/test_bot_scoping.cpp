// Scoping a bot: what a bot account may do, and where.
//
// The feature is one rule — a bot does not inherit the implicit @everyone role
// — plus the machinery that already existed. So most of what is asserted here
// is that the EXISTING machinery now says something it could not say before,
// and that it still says everything it used to for everybody else.
//
// The properties, in the order they appear:
//   1. A bot created today can do nothing, anywhere, until it is granted
//      something — and the identical human account is unchanged.
//   2. @everyone is still a role a bot may be GIVEN, and giving it back
//      reproduces exactly today's behaviour. This is also the upgrade path:
//      every bot that exists on a running server already holds it explicitly.
//   3. A per-channel `user:<bot>` override is how a bot is let into a channel,
//      and it grants that channel and no other.
//   4. Server-wide grants still go through roles, including ADMINISTRATOR,
//      which must not become meaningless for bots.
//   5. The boundary cannot be escaped from inside: a bot cannot self-assign a
//      role, and an un-bootstrapped server does not hand it the default either.
//   6. Bootstrap does not re-grant @everyone to a bot on the next restart, and
//      the one-time backfill that keeps existing bots working runs exactly once.
//   7. GET /bsfchat/bots/{id}/access answers "where can this bot go" from
//      PermissionsEngine, gated like every other bot-administration endpoint
//      and filtered by what the CALLER may be told about.
//   8. THE OPERATOR'S ACTUAL FIRST RUN — create, token, join, post — end to
//      end through the handlers, which nothing covered before. The rule in 1
//      was tested against PermissionsEngine; this is the same rule as the
//      four HTTP responses an operator sees, and every one of them says what
//      it is doing.
//
// Expectations are derived from protocol constants (kEveryoneDefault,
// kAllFlags, kViewChannel...), never from what auth/Permissions.cpp computes.

#include <gtest/gtest.h>

#include "api/BotHandler.h"
#include "api/EventHandler.h"
#include "api/RoleHandler.h"
#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "http/Middleware.h"
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
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

const std::string kServerScope;

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-botscope-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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
    if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
    return req;
}

template <typename Handler, typename Method>
httplib::Response call(Handler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
}

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

::testing::AssertionResult HasStatus(const httplib::Response& res, int expected) {
    if (res.status == expected) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected " << expected << ", got status "
                                         << res.status << ", body: " << res.body;
}

// A refusal for the REASON given. A handler that refuses for two reasons keeps
// refusing once the interesting guard is reverted, so a status-only assertion
// cannot fail — the same point test_bots.cpp makes about its own gates.
::testing::AssertionResult RefusedBecause(const httplib::Response& res, int status,
                                          const std::string& needle) {
    if (res.status != status) {
        return ::testing::AssertionFailure() << "expected " << status << ", got status "
                                             << res.status << ", body: " << res.body;
    }
    if (res.body.find(needle) == std::string::npos) {
        return ::testing::AssertionFailure()
               << status << " for the wrong reason: expected a message containing \"" << needle
               << "\", got: " << res.body;
    }
    return ::testing::AssertionSuccess();
}

ServerRole role(const std::string& id, int position, permission::Flags flags,
                bool self_assignable = false) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    r.self_assignable = self_assignable;
    return r;
}

const std::string kBotsPath{api_path::kBots};

std::string access_path(const std::string& user_id) {
    return kBotsPath + "/" + user_id + "/access";
}

struct Fixture {
    std::string db_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<BotHandler> bots;
    std::unique_ptr<RoleHandler> roles;
    std::unique_ptr<RoomHandler> rooms;
    std::unique_ptr<EventHandler> events;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        config.password_hash_cost = 10;
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        bots = std::make_unique<BotHandler>(*store, *sync, config);
        roles = std::make_unique<RoleHandler>(*store, *sync, config);
        rooms = std::make_unique<RoomHandler>(*store, *sync, config);
        events = std::make_unique<EventHandler>(*store, *sync, config);
    }

    ~Fixture() {
        events.reset();
        rooms.reset();
        roles.reset();
        bots.reset();
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    // Written straight into server_state rather than through
    // write_server_scoped_state, so fixture setup lands no audit records.
    void seed_roles(const std::vector<ServerRole>& extra = {}) {
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        // MANAGE_BOTS without ADMINISTRATOR. An admin would only exercise the
        // god-mode short-circuit and say nothing about the gate.
        content.roles.push_back(
            role("botmod", 10, permission::kEveryoneDefault | permission::kManageBots));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        for (const auto& r : extra) content.roles.push_back(r);
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
        std::vector<std::string> ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) ids.push_back(r);
        assign(uid, ids);
        return uid;
    }

    void assign(const std::string& uid, const std::vector<std::string>& role_ids) {
        MemberRolesContent c;
        c.role_ids = role_ids;
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
    }

    std::string add_channel(const std::string& creator, const std::string& name,
                            const std::string& type = "text") {
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
                            json{{"join_rule", join_rule::kPublic}}.dump(), 1002);
        return room_id;
    }

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

    std::pair<std::string, std::string> make_bot(const std::string& admin_token,
                                                 const std::string& localpart) {
        auto res = call(*bots, &BotHandler::handle_create_bot, kBotsPath, admin_token,
                        json{{"localpart", localpart}}.dump());
        EXPECT_TRUE(HasStatus(res, 201));
        auto body = json::parse(res.body);
        return {body.value("user_id", ""), body.value("token", "")};
    }

    permission::Flags effective(const std::string& user_id, const std::string& room_id) {
        PermissionsEngine perms(*store, config);
        return perms.compute(user_id, room_id);
    }
};

} // namespace

// ── 1. A bot starts with nothing ────────────────────────────────────────────

TEST(BotScoping, ANewBotHoldsNoPermissionAnywhere) {
    Fixture fx("new-bot-empty");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto channel = fx.add_channel(admin, "general");

    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    // Server scope AND channel scope. The channel case is the one that matters:
    // kEveryoneDefault carries VIEW_CHANNEL and SEND_MESSAGES, so before this
    // change the bot could read and post in every channel on the server.
    EXPECT_EQ(fx.effective(bot, kServerScope), 0u);
    EXPECT_EQ(fx.effective(bot, channel), 0u);
}

TEST(BotScoping, AnOrdinaryMemberIsUnaffected) {
    // The control, and the half that would hurt. Asserting the rule with a bot
    // alone would pass just as well if @everyone had stopped applying to
    // EVERYBODY, which is a server where nobody can read anything.
    Fixture fx("human-unaffected");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto channel = fx.add_channel(admin, "general");
    auto bob = fx.add_user("bob");

    EXPECT_EQ(fx.effective(bob, kServerScope), permission::kEveryoneDefault);
    EXPECT_EQ(fx.effective(bob, channel), permission::kEveryoneDefault);

    // And IMPLICITLY, which is the half the assertions above cannot see:
    // add_user writes ["everyone"] into the assignment, so they would pass just
    // as well on a server where @everyone had stopped being implicit and was
    // merely usually listed. A member whose assignment does not name it still
    // has it — that is what makes it the default role, and it is what a bot is
    // now excluded from.
    fx.assign(bob, {});
    EXPECT_EQ(fx.effective(bob, kServerScope), permission::kEveryoneDefault);
}

TEST(BotScoping, CreationRecordsAnExplicitEmptyAssignment) {
    // Not merely "no row". The assignment is WRITTEN, so the bot's scope is a
    // document an operator can read, an audit record names, and the client
    // mirror carries — the same shape every human account has.
    Fixture fx("explicit-empty");
    fx.seed_roles();
    fx.add_user("alice", {std::string(permission::role_id::kAdmin)});

    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    auto stored = fx.store->get_server_state(std::string(event_type::kMemberRoles), bot);
    ASSERT_TRUE(stored.has_value()) << "a bot must carry a role assignment like anyone else";
    MemberRolesContent assignment;
    from_json(json::parse(*stored), assignment);
    EXPECT_TRUE(assignment.role_ids.empty());
}

// ── 2. @everyone is still available, explicitly ─────────────────────────────

TEST(BotScoping, GivingABotEveryoneReproducesTodaysBehaviour) {
    // The escape hatch, and the upgrade path: every bot on a running server
    // already holds ["everyone"], written by bootstrap_roles at creation, so
    // this is what an existing deployment looks like after the change.
    Fixture fx("explicit-everyone");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto channel = fx.add_channel(admin, "general");
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    fx.assign(bot, {std::string(permission::role_id::kEveryone)});

    EXPECT_EQ(fx.effective(bot, kServerScope), permission::kEveryoneDefault);
    EXPECT_EQ(fx.effective(bot, channel), permission::kEveryoneDefault);
}

// ── 3. Per-channel grants ───────────────────────────────────────────────────

TEST(BotScoping, AUserOverrideLetsABotIntoExactlyOneChannel) {
    Fixture fx("override-one-channel");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto allowed = fx.add_channel(admin, "releases");
    auto other = fx.add_channel(admin, "leadership");
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    const permission::Flags grant = permission::kViewChannel | permission::kSendMessages;
    fx.set_override(allowed, "user:" + bot, grant);

    EXPECT_EQ(fx.effective(bot, allowed), grant);
    EXPECT_EQ(fx.effective(bot, other), 0u);
    // And the grant does not leak upward: a channel permission is not a server
    // permission, which is what every server-scoped endpoint relies on.
    EXPECT_EQ(fx.effective(bot, kServerScope), 0u);
}

TEST(BotScoping, TheEveryoneChannelDenyOnAPrivateChannelStaysADeny) {
    // A private channel is "@everyone DENY VIEW_CHANNEL plus explicit allows"
    // (docs/membership-vs-visibility.md). A bot holding nothing must not be
    // let in by the allow half written for somebody else's role.
    Fixture fx("private-channel");
    fx.seed_roles({role("staff", 5, permission::kEveryoneDefault)});
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto secret = fx.add_channel(admin, "leadership");
    fx.set_override(secret, std::string("role:") + permission::role_id::kEveryone, 0,
                    permission::kViewChannel);
    fx.set_override(secret, "role:staff", permission::kViewChannel);
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    EXPECT_EQ(fx.effective(bot, secret), 0u);

    // A member of staff still gets in — the control that proves the channel is
    // shaped the way a real private channel is, not merely broken for everyone.
    auto carol = fx.add_user("carol", {"staff"});
    EXPECT_TRUE(permission::has(fx.effective(carol, secret), permission::kViewChannel));
}

// ── 4. Server-wide grants still come from roles ─────────────────────────────

TEST(BotScoping, ARoleGrantsABotServerWidePermissionsAsBefore) {
    Fixture fx("role-grant");
    fx.seed_roles({role("moderation", 20,
                        permission::kEveryoneDefault | permission::kKickMembers)});
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto channel = fx.add_channel(admin, "general");
    auto [bot, _token] = fx.make_bot("token-alice", "bot_moderator");

    fx.assign(bot, {"moderation"});

    const permission::Flags expected = permission::kEveryoneDefault | permission::kKickMembers;
    EXPECT_EQ(fx.effective(bot, kServerScope), expected);
    EXPECT_EQ(fx.effective(bot, channel), expected);
}

TEST(BotScoping, AdministratorStillShortCircuitsForABot) {
    // ADMINISTRATOR must not become a flag that means less on a bot than on a
    // person. A bot given the admin role is a full administrator, exactly as
    // an operator asking for that would expect.
    Fixture fx("bot-admin");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto channel = fx.add_channel(admin, "general");
    // Denied by name in the channel, to prove the short-circuit is what answers.
    auto [bot, _token] = fx.make_bot("token-alice", "bot_ops");
    fx.set_override(channel, "user:" + bot, 0, permission::kAllFlags);

    fx.assign(bot, {std::string(permission::role_id::kAdmin)});

    EXPECT_EQ(fx.effective(bot, kServerScope), permission::kAllFlags);
    EXPECT_EQ(fx.effective(bot, channel), permission::kAllFlags);
}

// ── 5. The boundary cannot be escaped from inside ───────────────────────────

TEST(BotScoping, ABotCannotSelfAssignARole) {
    // The obvious escape, and it needs no privilege at all: self-assignment
    // bypasses the rank rules by design, and a self-assignable role's
    // permissions are capped at @everyone's — which is precisely the set a
    // scoped bot was not given. A bot holding a token could therefore have
    // clicked its own way back to member-level access in one request.
    Fixture fx("no-self-assign");
    fx.seed_roles({role("pings", 5, permission::kEveryoneDefault, /*self_assignable=*/true)});
    fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto [bot, bot_token] = fx.make_bot("token-alice", "bot_deploy");

    auto res = call(*fx.roles, &RoleHandler::handle_add_self_role,
                    std::string(api_path::kSelfRoles) + "/pings", bot_token);
    EXPECT_TRUE(RefusedBecause(res, 403, "bot"));
    EXPECT_EQ(fx.effective(bot, kServerScope), 0u);

    // The control: the same role, the same request, from a person. Opt-in roles
    // are a feature for humans and must keep working.
    auto bob = fx.add_user("bob");
    auto ok = call(*fx.roles, &RoleHandler::handle_add_self_role,
                   std::string(api_path::kSelfRoles) + "/pings", "token-bob");
    EXPECT_TRUE(IsOk(ok));
    auto held = fx.store->get_member_role_ids(bob);
    EXPECT_NE(std::find(held.begin(), held.end(), "pings"), held.end());
}

TEST(BotScoping, AnUnbootstrappedServerDoesNotHandABotTheDefault) {
    // compute() has a fallback for a server with no roles and no assignments,
    // so that a fresh deployment is usable before bootstrap runs. It returns
    // kEveryoneDefault, which for a bot is the exact grant being withheld.
    Fixture fx("unbootstrapped");
    // No seed_roles(), no assignments: the un-bootstrapped shape.
    fx.store->create_user("@bot_early:test", "");
    fx.store->create_user("@alice:test", "hash");

    EXPECT_EQ(fx.effective("@bot_early:test", kServerScope), 0u);
    EXPECT_EQ(fx.effective("@alice:test", kServerScope), permission::kEveryoneDefault);
}

// ── 6. Bootstrap ────────────────────────────────────────────────────────────

TEST(BotScoping, BootstrapDoesNotGrantEveryoneToABotOnTheNextRestart) {
    // bootstrap_roles runs at every boot and assigns @everyone to any account
    // with no assignment. Without an exclusion it would quietly undo a bot's
    // scoping overnight — the same class of bug backfill_auto_join was for
    // bots and auto-join.
    Fixture fx("bootstrap-skips-bots");
    fx.seed_roles();
    fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    bootstrap_roles(*fx.store, *fx.sync, fx.config);
    bootstrap_roles(*fx.store, *fx.sync, fx.config);

    EXPECT_TRUE(fx.store->get_member_role_ids(bot).empty());
    EXPECT_EQ(fx.effective(bot, kServerScope), 0u);
}

TEST(BotScoping, AnExistingBotWithNoAssignmentIsBackfilledOnce) {
    // The upgrade case that must not break a running integration: a bot that
    // predates this change and — for whatever reason — carries no assignment
    // would otherwise lose every permission at the first restart after the
    // upgrade. It is given the @everyone it had, once.
    Fixture fx("backfill");
    fx.seed_roles();
    fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    // The pre-upgrade shape, built directly: a bot row with no assignment.
    SqliteStore::BotRecord record;
    record.user_id = "@bot_legacy:test";
    record.display_name = "Legacy";
    record.owner_id = "@alice:test";
    record.created_by = "@alice:test";
    record.created_at = 1000;
    ASSERT_TRUE(fx.store->create_bot(record));
    ASSERT_TRUE(fx.store->get_member_role_ids("@bot_legacy:test").empty());

    bootstrap_roles(*fx.store, *fx.sync, fx.config);

    auto held = fx.store->get_member_role_ids("@bot_legacy:test");
    EXPECT_EQ(held, std::vector<std::string>{std::string(permission::role_id::kEveryone)});
    EXPECT_EQ(fx.effective("@bot_legacy:test", kServerScope), permission::kEveryoneDefault);

    // ...and ONCE. An operator who then scopes that bot down must not have
    // @everyone handed back at the next boot; that is the difference between
    // an upgrade step and a policy.
    fx.assign("@bot_legacy:test", {});
    bootstrap_roles(*fx.store, *fx.sync, fx.config);
    EXPECT_TRUE(fx.store->get_member_role_ids("@bot_legacy:test").empty());
}

TEST(BotScoping, TheBackfillDoesNotTouchABotCreatedAfterTheUpgrade) {
    // Ordering hazard: the backfill sweeps bots with no assignment, and a bot
    // created after the upgrade has an assignment that is EMPTY. If the two
    // cases are confused, every new bot is un-scoped at the first restart.
    Fixture fx("backfill-vs-new");
    fx.seed_roles();
    fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto [bot, _token] = fx.make_bot("token-alice", "bot_new");

    bootstrap_roles(*fx.store, *fx.sync, fx.config);

    EXPECT_TRUE(fx.store->get_member_role_ids(bot).empty());
}

// ── 7. GET /bsfchat/bots/{id}/access ────────────────────────────────────────

TEST(BotAccess, ReportsTheBotsEffectivePermissionsPerChannel) {
    Fixture fx("access-report");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto releases = fx.add_channel(admin, "releases");
    auto other = fx.add_channel(admin, "general");
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    const permission::Flags grant = permission::kViewChannel | permission::kSendMessages;
    fx.set_override(releases, "user:" + bot, grant);

    auto res = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bot),
                    "token-alice");
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);

    EXPECT_EQ(body.value("user_id", ""), bot);
    EXPECT_EQ(body.value("server_permissions", ""), permission::flags_to_hex(0));

    // Both channels are reported — the picker has to offer the ones the bot
    // cannot see, or there is no way to grant them.
    ASSERT_TRUE(body.contains("channels"));
    std::map<std::string, json> by_id;
    for (const auto& c : body["channels"]) by_id[c.value("room_id", "")] = c;
    ASSERT_EQ(by_id.count(releases), 1u);
    ASSERT_EQ(by_id.count(other), 1u);

    EXPECT_EQ(by_id[releases].value("permissions", ""), permission::flags_to_hex(grant));
    EXPECT_EQ(by_id[other].value("permissions", ""), permission::flags_to_hex(0));

    // The override is echoed so the editor can tell "granted here" from
    // "inherited from nowhere", and it is present only where one exists.
    ASSERT_TRUE(by_id[releases].contains("override"));
    EXPECT_EQ(by_id[releases]["override"].value("allow", ""),
              permission::flags_to_hex(grant));
    EXPECT_FALSE(by_id[other].contains("override"));
}

TEST(BotAccess, IsGatedOnManageBotsAtServerScope) {
    // The same gate every other bot-administration endpoint carries: a
    // per-channel override granting MANAGE_BOTS inside one channel must
    // unlock nothing here.
    Fixture fx("access-gate");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto channel = fx.add_channel(admin, "general");
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    auto mallory = fx.add_user("mallory");
    fx.set_override(channel, "user:" + mallory, permission::kManageBots);

    auto res = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bot),
                    "token-mallory");
    EXPECT_TRUE(RefusedBecause(res, 403, "permissions"));
}

TEST(BotAccess, RefusesForABotThatOutranksTheCaller) {
    // Reading a bot's access is reading where a credential you may rotate can
    // go. It gets the rank rule the rest of bot administration gets.
    Fixture fx("access-rank");
    fx.seed_roles({role("senior", 50, permission::kEveryoneDefault)});
    fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto botmod = fx.add_user("bob", {"botmod"});
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");
    fx.assign(bot, {"senior"});

    auto res = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bot),
                    "token-bob");
    EXPECT_TRUE(RefusedBecause(res, 403, "ranks at or above"));
}

TEST(BotAccess, ShowsOnlyChannelsTheCallerMayBeToldAbout) {
    // MANAGE_BOTS is not a licence to enumerate the server. A delegated bot
    // administrator who cannot see #leadership must not learn it exists, or
    // how its overrides are shaped, by asking about a bot.
    Fixture fx("access-caller-filter");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto open = fx.add_channel(admin, "general");
    auto secret = fx.add_channel(admin, "leadership");
    fx.set_override(secret, std::string("role:") + permission::role_id::kEveryone, 0,
                    permission::kViewChannel);
    fx.add_user("bob", {"botmod"});
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    auto res = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bot),
                    "token-bob");
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);

    std::vector<std::string> ids;
    for (const auto& c : body["channels"]) ids.push_back(c.value("room_id", ""));
    EXPECT_NE(std::find(ids.begin(), ids.end(), open), ids.end());
    EXPECT_EQ(std::find(ids.begin(), ids.end(), secret), ids.end());
    EXPECT_EQ(res.body.find("leadership"), std::string::npos);

    // The control: an administrator asking the same question sees both, or the
    // filter above is indistinguishable from the endpoint being broken.
    auto full = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bot),
                     "token-alice");
    ASSERT_TRUE(IsOk(full));
    EXPECT_NE(full.body.find("leadership"), std::string::npos);
}

TEST(BotAccess, IsNotAnExistenceOracleForNonBotAccounts) {
    // The path takes a user id. Asking about a person must answer the same way
    // asking about a bot that does not exist does.
    Fixture fx("access-not-oracle");
    fx.seed_roles();
    fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = fx.add_user("bob");

    auto person = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bob),
                       "token-alice");
    auto missing = call(*fx.bots, &BotHandler::handle_get_bot_access,
                        access_path("@bot_nope:test"), "token-alice");
    EXPECT_EQ(person.status, 404);
    EXPECT_EQ(person.body, missing.body);
}

// ── 8. The operator's first run, end to end ─────────────────────────────────
//
// Everything above tests the RULE. This tests the SEQUENCE, because the rule
// was right and the sequence was still a dead end: create the bot, mint the
// token, join a public channel, post — and the first three answer 2xx and the
// fourth answers "No access to this channel", which is a sentence about the
// channel and the channel is fine.
//
// Nothing covered this. test_bots.cpp drives creation and the admin endpoints;
// the tests above drive PermissionsEngine. Between them sat the four requests
// an operator actually makes, and they passed individually.
//
// The join genuinely succeeds and must go on succeeding — membership is not a
// permission here and bot scoping depends on that (docs/bot-scoping.md §4). So
// what is asserted is not that the sequence works, it is that every step of it
// SAYS WHAT IT IS DOING: the 201 declares the empty scope, the join warns that
// it granted nothing, and the 403 names the bot's roles instead of the channel.

namespace {

std::string send_path(const std::string& room_id, const std::string& txn) {
    return "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn;
}

std::string join_path(const std::string& room_id) {
    return "/_matrix/client/v3/rooms/" + room_id + "/join";
}

std::string text_message(const std::string& body) {
    return json{{"msgtype", "m.text"}, {"body", body}}.dump();
}

} // namespace

TEST(BotFirstRun, ANewBotJoinsAPublicChannelAndCannotPostInIt) {
    // The reproduction, exactly as it was reported: four requests, and the
    // fourth is the first one that mentions the problem.
    Fixture fx("first-run-repro");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto general = fx.add_channel(admin, "general");

    auto created = call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-alice",
                        json{{"localpart", "bot_deploy"}}.dump());
    ASSERT_TRUE(HasStatus(created, 201));
    auto body = json::parse(created.body);
    const std::string bot = body.at("user_id");
    const std::string bot_token = body.at("token");

    // The join succeeds, and it is supposed to.
    auto joined = call(*fx.rooms, &RoomHandler::handle_join, join_path(general), bot_token);
    ASSERT_TRUE(IsOk(joined));
    EXPECT_EQ(json::parse(joined.body).value("room_id", ""), general);
    EXPECT_TRUE(fx.store->is_room_member(general, bot));

    // And the post does not. This is the pair that made it confusing, and it
    // is pinned as a pair so that neither half can be "fixed" alone: a change
    // that starts refusing the join, or one that starts allowing the send,
    // fails here.
    auto sent = call(*fx.events, &EventHandler::handle_send_event, send_path(general, "t1"),
                     bot_token, text_message("hello"));
    EXPECT_TRUE(HasStatus(sent, 403));
}

TEST(BotFirstRun, TheRefusalNamesTheBotsRolesAndNotTheChannel) {
    // The actual bug. "No access to this channel" sends an operator to look at
    // the channel's overrides, where there is nothing to find — the cause is an
    // empty bsfchat.member.roles on the account.
    Fixture fx("first-run-refusal");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto general = fx.add_channel(admin, "general");
    auto [bot, bot_token] = fx.make_bot("token-alice", "bot_deploy");
    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_join, join_path(general), bot_token)));

    auto sent = call(*fx.events, &EventHandler::handle_send_event, send_path(general, "t1"),
                     bot_token, text_message("hello"));
    ASSERT_TRUE(HasStatus(sent, 403));
    auto err = json::parse(sent.body);

    // The sentence still STARTS with what it always said, because a client is
    // matching substrings of it (ErrorCodes.h, standing rule 1). Asserted as a
    // prefix, not as a contains, so a reworded opening is a failure here rather
    // than a silently dead branch in the client.
    const std::string sentence = err.at("error");
    EXPECT_EQ(sentence.rfind("No access to this channel", 0), 0u) << sentence;
    // ...and then explains itself. Checked as the words an operator would
    // search for, not as the whole string, which nobody should have to match.
    EXPECT_NE(sentence.find("no roles"), std::string::npos) << sentence;
    EXPECT_NE(sentence.find("/access"), std::string::npos) << sentence;

    // The machine-readable half. Written out by hand: the client compares this
    // against a literal of its own in another repository, so an assertion
    // through the constant would pass against any typo. Same reasoning as
    // protocol/tests/test_error_codes.cpp.
    EXPECT_EQ(err.at("errcode"), "M_FORBIDDEN");
    EXPECT_EQ(err.at("bsfchat.errcode"), "BSFCHAT.BOT_NOT_SCOPED");
}

TEST(BotFirstRun, AHumanDeniedInAChannelStillGetsTheChannelRefusal) {
    // The control, and the half that would hurt. The test above passes just as
    // well on a server that has started blaming the account for every refusal,
    // which would send an operator looking at roles when the cause really is a
    // deny override in one channel.
    Fixture fx("first-run-human-control");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto secret = fx.add_channel(admin, "leadership");
    fx.set_override(secret, std::string("role:") + permission::role_id::kEveryone, 0,
                    permission::kViewChannel);
    auto bob = fx.add_user("bob");
    fx.store->set_membership(secret, bob, std::string(membership::kJoin));

    auto sent = call(*fx.events, &EventHandler::handle_send_event, send_path(secret, "t1"),
                     "token-bob", text_message("hello"));
    ASSERT_TRUE(HasStatus(sent, 403));
    auto err = json::parse(sent.body);
    EXPECT_EQ(err.at("error"), "No access to this channel");
    EXPECT_EQ(err.at("bsfchat.errcode"), "BSFCHAT.NO_VIEW_CHANNEL");

    // And a human whose assignment document is EMPTY is still a human: they
    // hold @everyone implicitly, so "this account has no roles" would be a
    // false explanation and would send the reader to the wrong page. This is
    // the reason the predicate is the conjunction and not the role list alone.
    fx.assign(bob, {});
    auto again = call(*fx.events, &EventHandler::handle_send_event, send_path(secret, "t2"),
                      "token-bob", text_message("hello"));
    ASSERT_TRUE(HasStatus(again, 403));
    EXPECT_EQ(json::parse(again.body).at("bsfchat.errcode"), "BSFCHAT.NO_VIEW_CHANNEL");
}

TEST(BotFirstRun, AScopedBotRefusedInOneChannelGetsTheChannelRefusal) {
    // The other direction of the same control: once a bot has been granted
    // something, a refusal somewhere else IS a channel fact again, and telling
    // it the account holds nothing would be wrong.
    Fixture fx("first-run-scoped-bot");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto general = fx.add_channel(admin, "general");
    auto [bot, bot_token] = fx.make_bot("token-alice", "bot_deploy");
    fx.assign(bot, {std::string(permission::role_id::kEveryone)});
    fx.set_override(general, std::string("role:") + permission::role_id::kEveryone, 0,
                    permission::kViewChannel);
    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_join, join_path(general), bot_token)));

    auto sent = call(*fx.events, &EventHandler::handle_send_event, send_path(general, "t1"),
                     bot_token, text_message("hello"));
    ASSERT_TRUE(HasStatus(sent, 403));
    EXPECT_EQ(json::parse(sent.body).at("error"), "No access to this channel");
    EXPECT_EQ(json::parse(sent.body).at("bsfchat.errcode"), "BSFCHAT.NO_VIEW_CHANNEL");
}

TEST(BotFirstRun, CreationSaysTheBotHoldsNothing) {
    // The earliest point the fact can be stated. An operator reading only this
    // response now knows what they have.
    Fixture fx("first-run-create-body");
    fx.seed_roles();
    fx.add_user("alice", {std::string(permission::role_id::kAdmin)});

    auto res = call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-alice",
                    json{{"localpart", "bot_deploy"}}.dump());
    ASSERT_TRUE(HasStatus(res, 201));
    auto body = json::parse(res.body);

    // Everything that was in this body before is still in it, unchanged. The
    // token especially: this is the only response that ever carries it.
    EXPECT_EQ(body.value("user_id", ""), "@bot_deploy:test");
    EXPECT_EQ(body.value("display_name", ""), "bot_deploy");
    EXPECT_FALSE(body.value("token", "").empty());

    // The assignment, spelt as GET /bots/{id}/access spells it.
    ASSERT_TRUE(body.contains("role_ids"));
    EXPECT_TRUE(body.at("role_ids").is_array());
    EXPECT_TRUE(body.at("role_ids").empty());

    // And a sentence, because the field above is only legible to somebody who
    // already knows the rule. Hand-written key: a client in another repository
    // reads it.
    ASSERT_TRUE(body.contains("bsfchat.warning"));
    const std::string warning = body.at("bsfchat.warning");
    EXPECT_NE(warning.find("no roles"), std::string::npos) << warning;
    EXPECT_NE(warning.find("/access"), std::string::npos) << warning;
}

TEST(BotFirstRun, TheJoinWarnsThatItGrantedNothing) {
    // The step the operator misreads. It still answers 200 and still answers
    // room_id, because the join is correct; it now also says what it did not do.
    Fixture fx("first-run-join-warning");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto general = fx.add_channel(admin, "general");
    auto [bot, bot_token] = fx.make_bot("token-alice", "bot_deploy");

    auto res = call(*fx.rooms, &RoomHandler::handle_join, join_path(general), bot_token);
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    EXPECT_EQ(body.value("room_id", ""), general);
    ASSERT_TRUE(body.contains("bsfchat.warning"));
    EXPECT_NE(body.at("bsfchat.warning").get<std::string>().find("cannot see or post"),
              std::string::npos);

    // A HUMAN's join is byte-identical to what it always was. An advisory key
    // that appeared on every join would be noise, and noise is ignored.
    auto bob = fx.add_user("bob");
    auto human = call(*fx.rooms, &RoomHandler::handle_join, join_path(general), "token-bob");
    ASSERT_TRUE(IsOk(human));
    const std::string plain_general = json{{"room_id", general}}.dump();
    EXPECT_EQ(human.body, plain_general);

    // And so is a granted bot's, which is what makes the key mean something.
    fx.assign(bot, {std::string(permission::role_id::kEveryone)});
    auto other = fx.add_channel(admin, "releases");
    auto scoped = call(*fx.rooms, &RoomHandler::handle_join, join_path(other), bot_token);
    ASSERT_TRUE(IsOk(scoped));
    const std::string plain_other = json{{"room_id", other}}.dump();
    EXPECT_EQ(scoped.body, plain_other);
}

TEST(BotFirstRun, GrantingTheBotAChannelMakesTheSameSequenceWork) {
    // The end of the story, and the assertion that the refusals above are
    // about scope and not about bots being broken. One override, and the exact
    // four requests from the reproduction succeed.
    Fixture fx("first-run-granted");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto general = fx.add_channel(admin, "general");
    auto [bot, bot_token] = fx.make_bot("token-alice", "bot_deploy");

    fx.set_override(general, "user:" + bot,
                    permission::kViewChannel | permission::kSendMessages);

    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_join, join_path(general), bot_token)));
    auto sent = call(*fx.events, &EventHandler::handle_send_event, send_path(general, "t1"),
                     bot_token, text_message("hello"));
    ASSERT_TRUE(IsOk(sent));
    EXPECT_FALSE(json::parse(sent.body).value("event_id", "").empty());
}

TEST(BotAccess, SaysInOneFieldWhetherTheBotCanSeeAnythingAtAll) {
    // The report already carried the answer, spread over a role list, a
    // server-scope mask and one hex string per channel. An operator diagnosing
    // a silent bot should not have to reduce that themselves.
    Fixture fx("access-summary");
    fx.seed_roles();
    auto admin = fx.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto general = fx.add_channel(admin, "general");
    auto [bot, _token] = fx.make_bot("token-alice", "bot_deploy");

    auto before = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bot),
                       "token-alice");
    ASSERT_TRUE(IsOk(before));
    EXPECT_FALSE(json::parse(before.body).at("can_view_any_listed_channel"));

    // SEND_MESSAGES without VIEW_CHANNEL is not access to anything — the flag
    // is a prerequisite for everything in a channel — so the summary must not
    // turn true on "some bit is set".
    fx.set_override(general, "user:" + bot, permission::kSendMessages);
    auto useless = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bot),
                        "token-alice");
    ASSERT_TRUE(IsOk(useless));
    EXPECT_FALSE(json::parse(useless.body).at("can_view_any_listed_channel"));

    fx.set_override(general, "user:" + bot,
                    permission::kViewChannel | permission::kSendMessages);
    auto after = call(*fx.bots, &BotHandler::handle_get_bot_access, access_path(bot),
                      "token-alice");
    ASSERT_TRUE(IsOk(after));
    EXPECT_TRUE(json::parse(after.body).at("can_view_any_listed_channel"));
}
