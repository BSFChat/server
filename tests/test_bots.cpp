// First-class bot accounts (schema v19).
//
// The properties under test, in the order they appear below:
//   1. v19 applies to a real, populated v18 database and loses nothing, and a
//      fresh database lands on the same shape.
//   2. Creation produces a user account with kind = 'bot', an empty password
//      hash, a bots row, a role assignment, and a token shown exactly once.
//   3. The "bot_" namespace is reserved BOTH ways: a human cannot register into
//      it, and a bot cannot be created outside it.
//   4. A bot can never authenticate with a password — structurally, not because
//      a handler remembers to check. Verified against the store as well as the
//      endpoint, because the store filter is the actual guarantee.
//   5. Rotation invalidates the previous token, atomically, and the new one works.
//   6. Revocation (deactivation) is immediate: the very next request with a
//      revoked token fails.
//   7. Bots are excluded from auto-join — at creation, when a channel is created,
//      and across a simulated backfill_auto_join re-run, which is the sweep that
//      runs unconditionally at EVERY boot and would otherwise undo the other two.
//   8. Every endpoint is gated on MANAGE_BOTS at SERVER scope: a per-channel
//      override granting the flag inside a channel unlocks nothing.
//   9. DELETE is idempotent, and writes exactly one audit record however many
//      times it is called.
//  10. The bot token is non-expiring, and no response or audit record anywhere
//      carries token material.

#include <gtest/gtest.h>

#include "api/AuthHandler.h"
#include "api/BotHandler.h"
#include "api/ProfileHandler.h"
#include "api/RoomHandler.h"
#include "audit/AuditLog.h"
#include "auth/AutoJoin.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "http/Middleware.h"
#include "store/Migrations.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <sqlite3.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-bots-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

// A refusal for the REASON given, not merely a refusal.
//
// The same distinction test_permission_scope.cpp documents: an endpoint that
// refuses for two different reasons will keep refusing after the interesting
// guard is reverted, so a test that only asserts the status code cannot fail.
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

// Runs arbitrary SQL on a SEPARATE connection to the same database file, so an
// assertion can be about what the DATABASE holds rather than about what
// SqliteStore chose to report.
int64_t raw_int(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return -1;
    sqlite3_stmt* stmt = nullptr;
    int64_t out = -1;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) out = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

std::string raw_text(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return {};
    sqlite3_stmt* stmt = nullptr;
    std::string out;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            out = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

const std::string kBotsPath{api_path::kBots};

std::string bot_token_path(const std::string& user_id) {
    return kBotsPath + "/" + user_id + "/token";
}
std::string bot_path(const std::string& user_id) {
    return kBotsPath + "/" + user_id;
}

std::string create_body(const std::string& localpart, const std::string& display_name = "",
                        const std::string& description = "") {
    return json{{"localpart", localpart},
                {"display_name", display_name},
                {"description", description}}
        .dump();
}

struct Fixture {
    std::string db_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<BotHandler> bots;
    std::unique_ptr<AuthHandler> auth;
    std::unique_ptr<ProfileHandler> profile;
    std::unique_ptr<RoomHandler> rooms;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        // The PBKDF2 cost is the dominant runtime of anything that creates a
        // human account; the tests care about which hash verifies, not how long
        // it took to derive.
        config.password_hash_cost = 10;
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        bots = std::make_unique<BotHandler>(*store, *sync, config);
        auth = std::make_unique<AuthHandler>(*store, *sync, config);
        profile = std::make_unique<ProfileHandler>(*store, *sync, config);
        rooms = std::make_unique<RoomHandler>(*store, *sync, config);
    }

    ~Fixture() {
        rooms.reset();
        profile.reset();
        auth.reset();
        bots.reset();
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    // Written straight into server_state rather than through
    // write_server_scoped_state, so fixture setup lands no audit records and the
    // "exactly one record" assertions start from an empty log.
    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        // MANAGE_BOTS on its own flag, WITHOUT ADMINISTRATOR. Testing the gate
        // against an admin would only exercise the god-mode short-circuit in
        // PermissionsEngine::compute and would say nothing about bit 13.
        content.roles.push_back(role("botmod", 10,
                                     permission::kEveryoneDefault | permission::kManageBots));
        // Everything EXCEPT bots, so "this user is privileged but not for this"
        // is a case the tests can express. Without it, the only unprivileged
        // actor would be a plain member and a gate that accidentally keyed on
        // "has any elevated flag" would pass.
        content.roles.push_back(role("everything_else", 20,
                                     permission::kAllFlags & ~permission::kManageBots &
                                         ~permission::kAdministrator));
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

    // A PUBLIC channel — join_rules must actually say so, because that is what
    // list_public_rooms() selects on and therefore what auto-join sweeps.
    std::string add_public_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "text"}}.dump(), 1001);
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

    std::vector<SqliteStore::AuditRecord> records() {
        return store->list_audit_records(limits::kMaxAuditLimit, std::nullopt).records;
    }

    // Creates a bot through the endpoint and returns (user_id, token).
    std::pair<std::string, std::string> make_bot(const std::string& admin_token,
                                                 const std::string& localpart,
                                                 const std::string& display_name = "") {
        auto res = call(*bots, &BotHandler::handle_create_bot, kBotsPath, admin_token,
                        create_body(localpart, display_name));
        EXPECT_TRUE(HasStatus(res, 201));
        auto body = json::parse(res.body);
        return {body.value("user_id", ""), body.value("token", "")};
    }
};

} // namespace

// ── 1. The migration ────────────────────────────────────────────────────────

// v19 has to apply to a database that already holds users, tokens and rooms —
// the shape of a real deployment — and change nothing about any of them.
TEST(BotMigration, AppliesToAPopulatedV18DatabaseWithoutLoss) {
    auto path = temp_db_path("v18-upgrade");
    remove_db(path);

    // Build a v18 database the ordinary way, populate it, then rewind
    // user_version so the v19 step re-runs against real data.
    {
        SqliteStore store(path);
        store.initialize();
        store.create_user("@alice:test", "hash-alice");
        store.create_user("@bob:test", "hash-bob");
        store.store_access_token("tok-alice", "@alice:test", "dev-a");
        auto room = generate_room_id("test");
        store.create_room(room, "@alice:test");
        store.set_membership(room, "@alice:test", std::string(membership::kJoin));
    }

    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        // Drop what v19 added and rewind, so the step is genuinely re-applied
        // rather than skipped as already-current.
        ASSERT_EQ(sqlite3_exec(db, "DROP TABLE IF EXISTS bots", nullptr, nullptr, nullptr),
                  SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, "PRAGMA user_version = 18", nullptr, nullptr, nullptr),
                  SQLITE_OK);
        // The two ADD COLUMNs are guarded by column_exists(), so leaving the
        // columns in place also proves the step is re-runnable — which is what
        // protects a deployment whose migration was interrupted.
        sqlite3_close(db);
    }

    {
        SqliteStore store(path);
        store.initialize();  // runs migrate_v19
        EXPECT_EQ(raw_int(path, "PRAGMA user_version"), kTargetSchemaVersion);
        EXPECT_EQ(raw_int(path, "SELECT COUNT(*) FROM users"), 2);
        EXPECT_EQ(raw_int(path, "SELECT COUNT(*) FROM access_tokens"), 1);
        EXPECT_EQ(raw_int(path, "SELECT COUNT(*) FROM rooms"), 1);
        EXPECT_EQ(raw_int(path, "SELECT COUNT(*) FROM bots"), 0);
        // Pre-existing accounts are people. A default of anything else would
        // have locked every account on the server out of password login.
        EXPECT_EQ(raw_int(path, "SELECT COUNT(*) FROM users WHERE kind = 'user'"), 2);
        // ...and the token they already had is still an ordinary access token.
        EXPECT_EQ(raw_int(path, "SELECT COUNT(*) FROM access_tokens WHERE token_kind = 'access'"),
                  1);
        // The existing session still resolves: nobody is logged out by v19.
        EXPECT_EQ(store.get_user_by_token("tok-alice").value_or(""), "@alice:test");
        // And the password path still works for a human.
        EXPECT_EQ(store.get_password_hash("@alice:test").value_or(""), "hash-alice");
    }

    remove_db(path);
}

TEST(BotMigration, FreshDatabaseLandsOnTheSameShape) {
    Fixture fx("fresh");
    EXPECT_EQ(raw_int(fx.db_path, "PRAGMA user_version"), kTargetSchemaVersion);
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM pragma_table_info('bots')"),
              6);
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'kind'"),
              1);
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM pragma_table_info('access_tokens') "
                      "WHERE name = 'token_kind'"),
              1);
}

// ── 2. Creation ─────────────────────────────────────────────────────────────

TEST(BotCreate, ProducesAUserAccountWithATokenShownOnce) {
    Fixture fx("create");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});

    auto res = call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-admin",
                    create_body("bot_deploy", "Deploy Bot", "Announces releases"));
    ASSERT_TRUE(HasStatus(res, 201));

    auto body = json::parse(res.body);
    EXPECT_EQ(body["user_id"], "@bot_deploy:test");
    EXPECT_EQ(body["display_name"], "Deploy Bot");
    ASSERT_TRUE(body.contains("token"));
    const std::string token = body["token"];
    EXPECT_FALSE(token.empty());

    // It is a user, and the ordinary bearer middleware resolves it. This is the
    // whole design in one assertion: no bot-specific authentication path exists
    // because the bot arrives through the one every other account uses.
    EXPECT_TRUE(fx.store->user_exists("@bot_deploy:test"));
    EXPECT_EQ(authenticate(*fx.store, "Bearer " + token).value_or(""), "@bot_deploy:test");

    // ...marked as a bot, with an empty password hash.
    EXPECT_TRUE(fx.store->is_bot("@bot_deploy:test"));
    EXPECT_EQ(raw_text(fx.db_path, "SELECT kind FROM users WHERE user_id = '@bot_deploy:test'"),
              "bot");
    EXPECT_EQ(raw_text(fx.db_path,
                       "SELECT password_hash FROM users WHERE user_id = '@bot_deploy:test'"),
              "");

    // ...with its metadata recorded and its creator named.
    auto bot = fx.store->get_bot("@bot_deploy:test");
    ASSERT_TRUE(bot.has_value());
    EXPECT_EQ(bot->owner_id, admin);
    EXPECT_EQ(bot->created_by, admin);
    EXPECT_EQ(bot->description, "Announces releases");
    EXPECT_FALSE(bot->deactivated_at.has_value());

    // ...and a role assignment, so it goes through PermissionsEngine like anyone
    // else rather than falling through to the un-bootstrapped default.
    EXPECT_FALSE(fx.store->get_member_role_ids("@bot_deploy:test").empty());

    // The PLAINTEXT is not in the database anywhere. Only its hash is, exactly
    // like an access token post-v7.
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM access_tokens WHERE token_hash = '" + token + "'"),
              0);
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM access_tokens WHERE token_hash = '" +
                          hash_access_token(token) + "'"),
              1);
}

TEST(BotCreate, TokenIsNonExpiringAndMarkedAsABotToken) {
    Fixture fx("nonexpiring");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_ci");

    // lifetime_ms = 0 is what get_user_by_token reads as "never expires, never
    // slides". A bot has no human to re-authenticate it, so a finite lifetime
    // would be an integration that dies on a date nobody wrote down.
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT lifetime_ms FROM access_tokens WHERE user_id = '" + bot_id + "'"),
              0);
    EXPECT_EQ(raw_text(fx.db_path,
                       "SELECT token_kind FROM access_tokens WHERE user_id = '" + bot_id + "'"),
              "bot");

    // A human's token, by contrast, still carries a finite lifetime. Asserted so
    // that a change making EVERY token non-expiring cannot pass this file.
    EXPECT_GT(raw_int(fx.db_path,
                      "SELECT lifetime_ms FROM access_tokens WHERE user_id = '@admin:test'"),
              0);
}

TEST(BotCreate, DisplayNameDefaultsToTheLocalpart) {
    Fixture fx("defaultname");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});

    auto res = call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-admin",
                    create_body("bot_quiet"));
    ASSERT_TRUE(HasStatus(res, 201));
    EXPECT_EQ(json::parse(res.body)["display_name"], "bot_quiet");
}

TEST(BotCreate, RefusesADuplicateLocalpart) {
    Fixture fx("dupe");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    fx.make_bot("token-admin", "bot_dupe");

    auto res = call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-admin",
                    create_body("bot_dupe"));
    EXPECT_TRUE(HasStatus(res, 400));
    // The failed second attempt must not have left a half-created account
    // behind: one bots row, one users row, one token.
    EXPECT_EQ(fx.store->list_bots().size(), 1u);
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM access_tokens WHERE user_id = '@bot_dupe:test'"),
              1);
}

TEST(BotCreate, RefusesADescriptionOverTheLimit) {
    Fixture fx("longdesc");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});

    auto res = call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-admin",
                    create_body("bot_verbose", "V",
                                std::string(limits::kMaxBotDescriptionLength + 1, 'x')));
    EXPECT_TRUE(HasStatus(res, 400));
    EXPECT_FALSE(fx.store->user_exists("@bot_verbose:test"));
}

// A banned identity must not be able to come back as a bot. The ban list holds
// no foreign key to users(user_id) by design, so without this check the ban row
// would still be sitting there while the account it names answered requests.
TEST(BotCreate, RefusesAUserIdThatIsServerBanned) {
    Fixture fx("bannedid");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    fx.store->set_server_ban("@bot_spam:test", "@admin:test", "abuse");

    auto res = call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-admin",
                    create_body("bot_spam"));
    EXPECT_TRUE(RefusedBecause(res, 403, "banned"));
    EXPECT_FALSE(fx.store->user_exists("@bot_spam:test"));
}

// ── 3. The reserved namespace, both ways ────────────────────────────────────

// A human must not be able to register a name a client will badge as a bot.
TEST(BotNamespace, RegistrationRefusesTheBotPrefix) {
    Fixture fx("reserve-human");
    fx.config.registration_enabled = true;
    AuthHandler auth(*fx.store, *fx.sync, fx.config);

    for (const auto& localpart : {"bot_deploy", "bot_", "bot_x"}) {
        httplib::Request req;
        req.path = std::string(api_path::kRegister);
        req.body = json{{"username", localpart}, {"password", "hunter2hunter2"}}.dump();
        httplib::Response res;
        auth.handle_register(req, res);
        EXPECT_TRUE(RefusedBecause(res, 400, "reserved")) << "localpart: " << localpart;
        EXPECT_FALSE(fx.store->user_exists("@" + std::string(localpart) + ":test"));
    }

    // The neighbouring reservations still hold — this extended that list, it did
    // not replace it.
    for (const auto& localpart : {"server", "oidc_josh"}) {
        httplib::Request req;
        req.path = std::string(api_path::kRegister);
        req.body = json{{"username", localpart}, {"password", "hunter2hunter2"}}.dump();
        httplib::Response res;
        auth.handle_register(req, res);
        EXPECT_TRUE(RefusedBecause(res, 400, "reserved")) << "localpart: " << localpart;
    }

    // ...and an ordinary name is still accepted, so the guard is a reservation
    // and not a blanket refusal.
    {
        httplib::Request req;
        req.path = std::string(api_path::kRegister);
        req.body = json{{"username", "robotnik"}, {"password", "hunter2hunter2"}}.dump();
        httplib::Response res;
        auth.handle_register(req, res);
        EXPECT_TRUE(IsOk(res));
        EXPECT_TRUE(fx.store->user_exists("@robotnik:test"));
        // And it is a person, not a bot: "bot" appearing in a name means nothing.
        EXPECT_FALSE(fx.store->is_bot("@robotnik:test"));
    }
}

// ...and the other direction: a bot cannot be created outside the namespace, so
// the two sets are disjoint by construction rather than by inspection.
TEST(BotNamespace, BotCreationRequiresTheBotPrefix) {
    Fixture fx("reserve-bot");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});

    const char* rejected[] = {
        "deploy",       // no prefix at all
        "bot_",         // the prefix alone is not a name
        "BOT_deploy",   // uppercase is not in the localpart grammar
        "bot deploy",   // nor is a space
        "xbot_deploy",  // the prefix must be a PREFIX, not a substring
        "",
    };
    for (const auto* localpart : rejected) {
        auto res = call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-admin",
                        create_body(localpart));
        EXPECT_TRUE(HasStatus(res, 400)) << "localpart: " << localpart;
    }
    EXPECT_TRUE(fx.store->list_bots().empty());
}

// ── 4. A bot can never log in ───────────────────────────────────────────────

// The guarantee lives in the STORE, not in a handler. Asserted here directly
// because a handler-level test would still pass if the store filter were removed
// and a check were left behind in only one of the password paths.
TEST(BotLogin, TheStoreWillNotYieldABotsPasswordHash) {
    Fixture fx("nohash");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_nologin");

    EXPECT_FALSE(fx.store->get_password_hash(bot_id).has_value());

    // Even if somebody writes a real hash onto the row — a botched admin script,
    // a future migration, a bug — the filter still refuses to hand it out. That
    // is the difference between a structural guarantee and "bots have an empty
    // hash, so verification happens to fail".
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(fx.db_path.c_str(), &db), SQLITE_OK);
        const std::string sql = "UPDATE users SET password_hash = '" +
                                hash_password("letmein123", 10) + "' WHERE user_id = '" +
                                bot_id + "'";
        ASSERT_EQ(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    }
    EXPECT_NE(raw_text(fx.db_path, "SELECT password_hash FROM users WHERE user_id = '" +
                                       bot_id + "'"),
              "");
    EXPECT_FALSE(fx.store->get_password_hash(bot_id).has_value())
        << "a bot's password hash must be unreachable even when the column is populated";

    // A human's hash is of course still reachable — the filter is a filter, not
    // an outage.
    EXPECT_TRUE(fx.store->get_password_hash("@admin:test").has_value());
}

TEST(BotLogin, PasswordLoginIsRefusedForABot) {
    Fixture fx("nologin");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_nologin");

    // Plant a working password on the row, as above, so this tests the refusal
    // and not merely "the empty string is not a valid hash".
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(fx.db_path.c_str(), &db), SQLITE_OK);
        const std::string sql = "UPDATE users SET password_hash = '" +
                                hash_password("letmein123", 10) + "' WHERE user_id = '" +
                                bot_id + "'";
        ASSERT_EQ(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    }

    httplib::Request req;
    req.path = std::string(api_path::kLogin);
    req.body = json{{"type", "m.login.password"},
                    {"identifier", {{"type", "m.id.user"}, {"user", "bot_nologin"}}},
                    {"password", "letmein123"}}
                   .dump();
    httplib::Response res;
    fx.auth->handle_login(req, res);
    EXPECT_TRUE(HasStatus(res, 403));
    // No session was minted: the bot still has exactly its one bot token.
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM access_tokens WHERE user_id = '" + bot_id + "'"),
              1);
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM access_tokens WHERE user_id = '" + bot_id +
                          "' AND token_kind = 'access'"),
              0);
}

// m.login.token maps an OIDC subject into the "oidc_" namespace, and "oidc_" and
// "bot_" are disjoint prefixes — so no identity token can ever land on a bot
// account. Asserted rather than assumed, because the property depends on the
// prefix being applied before sanitisation and that is easy to reorder.
TEST(BotLogin, OidcSubjectsCannotLandOnTheBotNamespace) {
    EXPECT_NE(std::string("oidc_").rfind(std::string(bot::kLocalpartPrefix), 0), 0u);
    EXPECT_NE(std::string(bot::kLocalpartPrefix).rfind("oidc_", 0), 0u);
    EXPECT_FALSE(bot::is_bot_user_id("@oidc_josh:test"));
}

// The cheap classifier a hot path (a rate limiter, a renderer) uses instead of a
// database round trip. It must agree with the store for every account the server
// can actually produce — the reservation is what makes that true, so a
// disagreement means the reservation has been broken somewhere.
TEST(BotIdentity, IdOnlyClassifierAgreesWithTheStore) {
    Fixture fx("identity");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto human = fx.add_user("robotnik");  // "bot" in the name means nothing
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_keyed");

    for (const auto& uid : {admin, human, bot_id}) {
        EXPECT_EQ(bot::is_bot_user_id(uid), fx.store->is_bot(uid)) << "disagreed on " << uid;
    }

    // Shapes that must not be mistaken for the namespace.
    EXPECT_TRUE(bot::is_bot_user_id("@bot_x:test"));
    EXPECT_FALSE(bot::is_bot_user_id("@xbot_x:test"));   // prefix, not substring
    EXPECT_FALSE(bot::is_bot_user_id("bot_x:test"));     // no leading @
    EXPECT_FALSE(bot::is_bot_user_id("@bot:test"));      // "bot" is not "bot_"
    EXPECT_FALSE(bot::is_bot_user_id("@bot"));           // too short to be either
    EXPECT_FALSE(bot::is_bot_user_id(""));
}

// ── 5. Rotation ─────────────────────────────────────────────────────────────

TEST(BotToken, RotationInvalidatesThePreviousToken) {
    Fixture fx("rotate");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    auto [bot_id, first] = fx.make_bot("token-admin", "bot_rotate");

    ASSERT_EQ(authenticate(*fx.store, "Bearer " + first).value_or(""), bot_id);

    auto res = call(*fx.bots, &BotHandler::handle_rotate_token, bot_token_path(bot_id),
                    "token-admin");
    ASSERT_TRUE(IsOk(res));
    const std::string second = json::parse(res.body).value("token", "");
    ASSERT_FALSE(second.empty());
    EXPECT_NE(second, first);

    // The old one is dead, immediately, on the very next request.
    EXPECT_FALSE(authenticate(*fx.store, "Bearer " + first).has_value());
    // The new one works.
    EXPECT_EQ(authenticate(*fx.store, "Bearer " + second).value_or(""), bot_id);

    // Exactly one token row survives — rotation replaces, it does not accumulate.
    // Anything else would mean an old credential lingering in the database.
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM access_tokens WHERE user_id = '" + bot_id + "'"),
              1);

    // Repeated rotation keeps only the newest: token N-1 dies when N is issued.
    auto res3 = call(*fx.bots, &BotHandler::handle_rotate_token, bot_token_path(bot_id),
                     "token-admin");
    ASSERT_TRUE(IsOk(res3));
    const std::string third = json::parse(res3.body).value("token", "");
    EXPECT_FALSE(authenticate(*fx.store, "Bearer " + second).has_value());
    EXPECT_EQ(authenticate(*fx.store, "Bearer " + third).value_or(""), bot_id);
}

TEST(BotToken, RotationRefusesAnUnknownBotAndADeactivatedOne) {
    Fixture fx("rotate-refuse");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_gone");

    EXPECT_TRUE(HasStatus(call(*fx.bots, &BotHandler::handle_rotate_token,
                               bot_token_path("@bot_nosuch:test"), "token-admin"),
                          404));

    // A human account is not a bot, and must not be issuable a non-expiring
    // credential through this route.
    EXPECT_TRUE(HasStatus(call(*fx.bots, &BotHandler::handle_rotate_token,
                               bot_token_path("@admin:test"), "token-admin"),
                          404));

    ASSERT_TRUE(IsOk(call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(bot_id),
                          "token-admin")));
    // Rotating must not revive a deactivated bot, or "deactivated" would only
    // mean "until somebody rotates it".
    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_rotate_token,
                                    bot_token_path(bot_id), "token-admin"),
                               400, "deactivated"));
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM access_tokens WHERE user_id = '" + bot_id + "'"),
              0);
}

// ── 6. Revocation is immediate ──────────────────────────────────────────────

TEST(BotToken, DeactivationRevokesImmediately) {
    Fixture fx("revoke");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_doomed");
    ASSERT_EQ(authenticate(*fx.store, "Bearer " + token).value_or(""), bot_id);

    ASSERT_TRUE(IsOk(call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(bot_id),
                          "token-admin")));

    // Immediate: no grace period, no next-sweep, no expiry to wait for. The very
    // next authenticated request fails.
    EXPECT_FALSE(authenticate(*fx.store, "Bearer " + token).has_value());
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM access_tokens WHERE user_id = '" + bot_id + "'"),
              0);

    // The account is not deleted — it keeps its user id, so its past messages
    // still resolve to a name and the localpart cannot be re-registered.
    EXPECT_TRUE(fx.store->user_exists(bot_id));
    auto bot = fx.store->get_bot(bot_id);
    ASSERT_TRUE(bot.has_value());
    EXPECT_TRUE(bot->deactivated_at.has_value());
}

TEST(BotToken, DeactivationLeavesEveryRoom) {
    Fixture fx("revoke-rooms");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto room_a = fx.add_public_channel(admin, "general");
    auto room_b = fx.add_public_channel(admin, "random");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_leaver");

    // Explicitly joined, which is the only way a bot is ever in a room.
    fx.store->set_membership(room_a, bot_id, std::string(membership::kJoin));
    fx.store->set_membership(room_b, bot_id, std::string(membership::kJoin));
    ASSERT_EQ(fx.store->get_joined_rooms(bot_id).size(), 2u);

    ASSERT_TRUE(IsOk(call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(bot_id),
                          "token-admin")));

    EXPECT_TRUE(fx.store->get_joined_rooms(bot_id).empty());
    // And everyone else sees it go: a leave member event per room, so a synced
    // client's member list stops showing a bot that can no longer act.
    for (const auto& room : {room_a, room_b}) {
        auto ev = fx.store->get_state_event(room, std::string(event_type::kRoomMember), bot_id);
        ASSERT_TRUE(ev.has_value()) << "no member event in " << room;
        EXPECT_EQ(ev->content.data.value("membership", ""), membership::kLeave);
    }
}

// ── 7. Auto-join exclusion ──────────────────────────────────────────────────

TEST(BotAutoJoin, ABotIsNotJoinedToExistingPublicChannelsAtCreation) {
    Fixture fx("autojoin-create");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    fx.add_public_channel(admin, "general");
    fx.add_public_channel(admin, "random");

    auto [bot_id, token] = fx.make_bot("token-admin", "bot_shy");
    EXPECT_TRUE(fx.store->get_joined_rooms(bot_id).empty());

    // Belt and braces: even calling the sweep directly, as registration does,
    // must not join it. The guard is in AutoJoin's own funnel, not only in the
    // bot handler's choice not to call it.
    auto_join_public_rooms(*fx.store, *fx.sync, fx.config, bot_id);
    EXPECT_TRUE(fx.store->get_joined_rooms(bot_id).empty());
}

TEST(BotAutoJoin, ABotIsNotSweptIntoAChannelCreatedLater) {
    Fixture fx("autojoin-newchannel");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto human = fx.add_user("carol");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_later");

    auto room = fx.add_public_channel(admin, "announcements");
    auto_join_all_users(*fx.store, *fx.sync, fx.config, room, admin);

    // The human IS swept in — that is what auto-join is for, and asserting it
    // here is what stops this test passing because auto-join broke entirely.
    EXPECT_TRUE(fx.store->is_room_member(room, human));
    EXPECT_FALSE(fx.store->is_room_member(room, bot_id));
}

// The important one. backfill_auto_join runs unconditionally at EVERY boot, so
// an exclusion that only holds at creation is undone by the next restart or
// deploy — and the operator has already been told the bot was excluded. This is
// the same shape as the kick-undone-by-restart bug the funnel's membership check
// exists to prevent.
TEST(BotAutoJoin, BackfillReRunDoesNotForceJoinABot) {
    Fixture fx("autojoin-backfill");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto human = fx.add_user("dave");
    fx.add_public_channel(admin, "general");
    fx.add_public_channel(admin, "random");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_persistent");

    // Simulate three server boots.
    for (int boot = 0; boot < 3; ++boot) {
        backfill_auto_join(*fx.store, *fx.sync, fx.config);
        EXPECT_TRUE(fx.store->get_joined_rooms(bot_id).empty())
            << "bot was force-joined by backfill pass " << boot;
    }

    // The human is in both channels, so the backfill genuinely ran.
    EXPECT_EQ(fx.store->get_joined_rooms(human).size(), 2u);

    // And no membership row of ANY kind was invented for the bot — not even a
    // leave, which would be a record of a join that should never have happened.
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM room_members WHERE user_id = '" + bot_id + "'"),
              0);

    // A bot that explicitly joined a channel STAYS joined across a backfill. The
    // exclusion must not become "bots get evicted from channels they were
    // invited to", which would be a different bug with the same cause.
    auto rooms = fx.store->list_public_rooms();
    ASSERT_FALSE(rooms.empty());
    fx.store->set_membership(rooms.front(), bot_id, std::string(membership::kJoin));
    backfill_auto_join(*fx.store, *fx.sync, fx.config);
    EXPECT_EQ(fx.store->get_joined_rooms(bot_id).size(), 1u);
}

// ── 8. Permission gating, at server scope ───────────────────────────────────

TEST(BotPermissions, EveryEndpointRequiresManageBots) {
    Fixture fx("gate");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    // Holds every flag EXCEPT MANAGE_BOTS (and ADMINISTRATOR). "Privileged, but
    // not for this" — a gate keyed on any other elevated flag would pass.
    fx.add_user("mallory", {"everything_else"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_guarded");

    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath,
                                    "token-mallory", create_body("bot_sneaky")),
                               403, "Insufficient permissions"));
    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_list_bots, kBotsPath,
                                    "token-mallory"),
                               403, "Insufficient permissions"));
    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_rotate_token,
                                    bot_token_path(bot_id), "token-mallory"),
                               403, "Insufficient permissions"));
    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_deactivate_bot,
                                    bot_path(bot_id), "token-mallory"),
                               403, "Insufficient permissions"));

    EXPECT_FALSE(fx.store->user_exists("@bot_sneaky:test"));
    // Nothing was rotated or revoked by the refused calls.
    EXPECT_EQ(authenticate(*fx.store, "Bearer " + token).value_or(""), bot_id);
    EXPECT_FALSE(fx.store->get_bot(bot_id)->deactivated_at.has_value());
}

TEST(BotPermissions, UnauthenticatedCallsAreRefused) {
    Fixture fx("gate-anon");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_anon");

    EXPECT_TRUE(HasStatus(call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "",
                               create_body("bot_nope")),
                          401));
    EXPECT_TRUE(HasStatus(call(*fx.bots, &BotHandler::handle_list_bots, kBotsPath, ""), 401));
    EXPECT_TRUE(HasStatus(call(*fx.bots, &BotHandler::handle_rotate_token,
                               bot_token_path(bot_id), ""),
                          401));
    EXPECT_TRUE(HasStatus(call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(bot_id),
                               ""),
                          401));
}

// The escalation shape this codebase has had twice already: a per-channel
// override granting the flag inside one channel must confer nothing server-wide.
// Minting credentials is the worst place for it to happen a third time.
TEST(BotPermissions, APerChannelOverrideDoesNotUnlockBotAdministration) {
    Fixture fx("gate-scope");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto mallory = fx.add_user("mallory", {"everything_else"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_scoped");

    auto room = fx.add_public_channel(admin, "mallorys-channel");
    fx.set_override(room, "user:" + mallory, permission::kManageBots);

    // Sanity: the override really does grant the flag INSIDE that channel, so
    // this test is about scope and not about the override failing to apply.
    PermissionsEngine perms(*fx.store, fx.config);
    ASSERT_TRUE(perms.can(mallory, room, permission::kManageBots));
    ASSERT_FALSE(perms.can(mallory, "", permission::kManageBots));

    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath,
                                    "token-mallory", create_body("bot_escalated")),
                               403, "Insufficient permissions"));
    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_list_bots, kBotsPath,
                                    "token-mallory"),
                               403, "Insufficient permissions"));
    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_rotate_token,
                                    bot_token_path(bot_id), "token-mallory"),
                               403, "Insufficient permissions"));
    EXPECT_TRUE(RefusedBecause(call(*fx.bots, &BotHandler::handle_deactivate_bot,
                                    bot_path(bot_id), "token-mallory"),
                               403, "Insufficient permissions"));

    EXPECT_FALSE(fx.store->user_exists("@bot_escalated:test"));
    EXPECT_EQ(authenticate(*fx.store, "Bearer " + token).value_or(""), bot_id);
}

// ADMINISTRATOR passes without the flag being granted explicitly, because
// compute() short-circuits it from the role base. Adding a flag to kAllFlags and
// forgetting what that implies is how an admin ends up locked out of a new
// feature on an existing deployment.
TEST(BotPermissions, AdministratorPassesWithoutAnExplicitGrant) {
    Fixture fx("gate-admin");
    fx.seed_roles();
    fx.add_user("root", {std::string(permission::role_id::kAdmin)});
    EXPECT_TRUE(HasStatus(call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-root",
                               create_body("bot_byadmin")),
                          201));

    // ...and MANAGE_BOTS is in kAllFlags, which is what makes that true for an
    // Admin role seeded before this flag existed.
    EXPECT_TRUE(permission::has(permission::kAllFlags, permission::kManageBots));
    // ...but emphatically NOT in the @everyone default.
    EXPECT_FALSE(permission::has(permission::kEveryoneDefault, permission::kManageBots));
}

// ── 9. Idempotent delete, and the audit trail ───────────────────────────────

TEST(BotDelete, IsIdempotent) {
    Fixture fx("idempotent");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto room = fx.add_public_channel(admin, "general");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_twice");
    fx.store->set_membership(room, bot_id, std::string(membership::kJoin));

    for (int attempt = 0; attempt < 3; ++attempt) {
        auto res = call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(bot_id),
                        "token-admin");
        EXPECT_TRUE(IsOk(res)) << "attempt " << attempt;
        EXPECT_EQ(res.body, "{}");
    }

    auto bot = fx.store->get_bot(bot_id);
    ASSERT_TRUE(bot.has_value());
    ASSERT_TRUE(bot->deactivated_at.has_value());
    const int64_t first_deactivation = *bot->deactivated_at;

    // A repeat call must not move the timestamp. "When did this stop being live"
    // has one answer, and it is the first one.
    auto again = fx.store->get_bot(bot_id);
    EXPECT_EQ(*again->deactivated_at, first_deactivation);

    // Exactly ONE deactivation record, not three. A log that says a bot was
    // deactivated three times describes something that did not happen.
    int deactivations = 0;
    for (const auto& r : fx.records()) {
        if (r.action == audit_action::kBotDeactivate) ++deactivations;
    }
    EXPECT_EQ(deactivations, 1);

    // Deleting a bot that never existed is a 404, not a silent success: an
    // operator typing the wrong id should be told, and idempotency is about
    // repeating a real action, not about pretending an unreal one happened.
    EXPECT_TRUE(HasStatus(call(*fx.bots, &BotHandler::handle_deactivate_bot,
                               bot_path("@bot_never:test"), "token-admin"),
                          404));
}

TEST(BotAudit, CreateRotateAndDeactivateAreEachRecordedOnce) {
    Fixture fx("audit");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    ASSERT_TRUE(fx.records().empty());

    auto [bot_id, first] = fx.make_bot("token-admin", "bot_audited", "Audited Bot");
    ASSERT_TRUE(IsOk(call(*fx.bots, &BotHandler::handle_rotate_token, bot_token_path(bot_id),
                          "token-admin")));
    ASSERT_TRUE(IsOk(call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(bot_id),
                          "token-admin")));

    auto all = fx.records();
    // bootstrap_roles writes role records of its own during creation, so filter
    // to the bot actions rather than asserting on the total.
    std::vector<SqliteStore::AuditRecord> bot_records;
    for (const auto& r : all) {
        if (r.action == audit_action::kBotCreate || r.action == audit_action::kBotTokenRotate ||
            r.action == audit_action::kBotDeactivate) {
            bot_records.push_back(r);
        }
    }
    ASSERT_EQ(bot_records.size(), 3u);
    for (const auto& r : bot_records) {
        EXPECT_EQ(r.actor, admin);
        // The bot goes in target_user, so filtering the log by a user id returns
        // both what an account did and what was done to it.
        EXPECT_EQ(r.target_user, bot_id);
    }

    // NO audit record anywhere carries token material. The audit log has no
    // delete path, so a token written into it would be "shown once" turned into
    // "stored forever and readable by whoever holds MANAGE_SERVER".
    for (const auto& r : all) {
        EXPECT_EQ(r.before_json.find(first), std::string::npos);
        EXPECT_EQ(r.after_json.find(first), std::string::npos);
    }

    // A REFUSED action writes nothing — a scope change must not silently drop or
    // add an audit call site.
    fx.add_user("mallory", {"everything_else"});
    const auto before = fx.records().size();
    call(*fx.bots, &BotHandler::handle_create_bot, kBotsPath, "token-mallory",
         create_body("bot_refused"));
    EXPECT_EQ(fx.records().size(), before);
}

// ── 10. Listing, and what it must never contain ─────────────────────────────

TEST(BotList, ReportsEveryBotAndNoTokenMaterial) {
    Fixture fx("list");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto [a_id, a_tok] = fx.make_bot("token-admin", "bot_alpha", "Alpha");
    auto [b_id, b_tok] = fx.make_bot("token-admin", "bot_beta", "Beta");
    ASSERT_TRUE(IsOk(call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(b_id),
                          "token-admin")));

    auto res = call(*fx.bots, &BotHandler::handle_list_bots, kBotsPath, "token-admin");
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    ASSERT_TRUE(body.contains("bots"));
    ASSERT_EQ(body["bots"].size(), 2u);

    std::map<std::string, json> by_id;
    for (const auto& entry : body["bots"]) by_id[entry.value("user_id", "")] = entry;

    ASSERT_TRUE(by_id.count(a_id));
    const auto& alpha = by_id[a_id];
    EXPECT_EQ(alpha["display_name"], "Alpha");
    EXPECT_EQ(alpha["owner_id"], admin);
    EXPECT_FALSE(alpha["deactivated"].get<bool>());
    EXPECT_GT(alpha["created_at"].get<int64_t>(), 0);

    // A deactivated bot is listed and FLAGGED, not hidden: it still owns its
    // user id, and "why can't I create bot_beta?" has no answer otherwise.
    ASSERT_TRUE(by_id.count(b_id));
    EXPECT_TRUE(by_id[b_id]["deactivated"].get<bool>());

    // No token material, in any field, for any bot — plaintext or hash.
    EXPECT_EQ(res.body.find(a_tok), std::string::npos);
    EXPECT_EQ(res.body.find(b_tok), std::string::npos);
    EXPECT_EQ(res.body.find(hash_access_token(a_tok)), std::string::npos);
    EXPECT_EQ(res.body.find("token"), std::string::npos);
}

// ── 11. Surfacing bot-ness to clients ───────────────────────────────────────

TEST(BotProfile, ProfileAndWhoamiReportBotNess) {
    Fixture fx("surface");
    fx.seed_roles();
    fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_badge", "Badge Bot");

    const std::string key{bot::kProfileKey};

    // Profile of the bot, fetched by anyone.
    auto res = call(*fx.profile, &ProfileHandler::handle_get_profile,
                    "/_matrix/client/v3/profile/" + bot_id, "token-admin");
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    ASSERT_TRUE(body.contains(key));
    EXPECT_TRUE(body[key].get<bool>());
    EXPECT_EQ(body["displayname"], "Badge Bot");

    // A human's profile omits the key entirely. Absent means "not a bot", the
    // same way an unset displayname is absent rather than "".
    auto human = call(*fx.profile, &ProfileHandler::handle_get_profile,
                      "/_matrix/client/v3/profile/@admin:test", "token-admin");
    ASSERT_TRUE(IsOk(human));
    EXPECT_FALSE(json::parse(human.body).contains(key));

    // whoami, for the bot itself — which is how a bot's own client learns not to
    // offer password and session-expiry affordances that mean nothing for it.
    auto who = call(*fx.auth, &AuthHandler::handle_whoami, std::string(api_path::kWhoami),
                    token);
    ASSERT_TRUE(IsOk(who));
    auto who_body = json::parse(who.body);
    EXPECT_EQ(who_body["user_id"], bot_id);
    ASSERT_TRUE(who_body.contains(key));
    EXPECT_TRUE(who_body[key].get<bool>());

    // ...and for a human.
    auto who_human = call(*fx.auth, &AuthHandler::handle_whoami,
                          std::string(api_path::kWhoami), "token-admin");
    ASSERT_TRUE(IsOk(who_human));
    EXPECT_FALSE(json::parse(who_human.body).contains(key));
}

// A bot is subject to the ordinary permission machinery with no special-casing:
// give it a role and it has that role's flags; give it none and it has
// @everyone's. If this ever stops being true, the "a bot is a user" property has
// been broken somewhere.
TEST(BotPermissions, ABotGoesThroughRolesLikeAnyoneElse) {
    Fixture fx("botroles");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_roled");
    auto room = fx.add_public_channel(admin, "general");

    {
        PermissionsEngine perms(*fx.store, fx.config);
        EXPECT_TRUE(perms.can(bot_id, room, permission::kSendMessages));
        EXPECT_FALSE(perms.can(bot_id, room, permission::kManageChannels));
    }

    fx.assign_roles(bot_id, {"everything_else"});
    {
        PermissionsEngine perms(*fx.store, fx.config);
        EXPECT_TRUE(perms.can(bot_id, room, permission::kManageChannels));
        // A bot can even be given MANAGE_BOTS. Nothing about bot-ness changes the
        // evaluation — which is the point, and also why the namespace reservation
        // rather than a permission carve-out is what keeps bots distinguishable.
        EXPECT_FALSE(perms.can(bot_id, "", permission::kManageBots));
    }

    // A per-channel deny applies to a bot exactly as it would to a person.
    fx.set_override(room, "user:" + bot_id, 0, permission::kSendMessages);
    {
        PermissionsEngine perms(*fx.store, fx.config);
        EXPECT_FALSE(perms.can(bot_id, room, permission::kSendMessages));
    }
}

// ── 12. How a bot actually gets into a channel ──────────────────────────────

// Auto-join is excluded, so joining has to work by the ordinary routes with the
// bot's OWN token — no bot-specific join endpoint, no admin-side force-join.
// These are exactly the gestures an operator is left with, so they are pinned.
TEST(BotJoin, ABotCanSelfJoinAPublicChannelWithItsOwnToken) {
    Fixture fx("selfjoin");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto room = fx.add_public_channel(admin, "general");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_joiner");

    ASSERT_TRUE(fx.store->get_joined_rooms(bot_id).empty());

    // POST /_matrix/client/v3/join/{roomId}, authenticated as the bot itself.
    auto res = call(*fx.rooms, &RoomHandler::handle_join,
                    "/_matrix/client/v3/join/" + room, token);
    ASSERT_TRUE(IsOk(res));
    EXPECT_EQ(json::parse(res.body).value("room_id", ""), room);

    EXPECT_TRUE(fx.store->is_room_member(room, bot_id));
    EXPECT_EQ(fx.store->get_joined_rooms(bot_id).size(), 1u);

    // The membership is a real join event, so everyone else sees the bot arrive.
    auto ev = fx.store->get_state_event(room, std::string(event_type::kRoomMember), bot_id);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->content.data.value("membership", ""), membership::kJoin);

    // The alternate spelling of the same route works too.
    auto room2 = fx.add_public_channel(admin, "random");
    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_join,
                          "/_matrix/client/v3/rooms/" + room2 + "/join", token)));
    EXPECT_TRUE(fx.store->is_room_member(room2, bot_id));
}

// An invite-only channel still refuses a bot that has not been invited, and
// accepts it once it has. The bot cannot SEE the invite in /sync (there is no
// rooms.invite section), but joining by room id after being invited works — which
// is the documented workaround, so it is pinned here.
TEST(BotJoin, AnInviteOnlyChannelNeedsAnInviteFirst) {
    Fixture fx("invitejoin");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_invited");

    auto room = generate_room_id("test");
    fx.store->create_room(room, admin);
    fx.store->set_membership(room, admin, std::string(membership::kJoin));
    fx.store->insert_event(generate_event_id("test"), room, admin,
                           std::string(event_type::kRoomJoinRules), std::string(""),
                           json{{"join_rule", join_rule::kInvite}}.dump(), 1002);

    EXPECT_TRUE(RefusedBecause(call(*fx.rooms, &RoomHandler::handle_join,
                                    "/_matrix/client/v3/join/" + room, token),
                               403, "invite"));
    EXPECT_FALSE(fx.store->is_room_member(room, bot_id));

    fx.store->set_membership(room, bot_id, std::string(membership::kInvite));
    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_join,
                          "/_matrix/client/v3/join/" + room, token)));
    EXPECT_TRUE(fx.store->is_room_member(room, bot_id));
}

// A deactivated bot cannot join anything: its token is gone, so the request is
// not authenticated at all. Asserted because "revoked but still able to join"
// would make deactivation cosmetic.
TEST(BotJoin, ADeactivatedBotCannotJoin) {
    Fixture fx("deadjoin");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod"});
    auto room = fx.add_public_channel(admin, "general");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_dead");

    ASSERT_TRUE(IsOk(call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(bot_id),
                          "token-admin")));

    EXPECT_TRUE(HasStatus(call(*fx.rooms, &RoomHandler::handle_join,
                               "/_matrix/client/v3/join/" + room, token),
                          401));
    EXPECT_FALSE(fx.store->is_room_member(room, bot_id));
}

// ── 13. Auto-join on invite ─────────────────────────────────────────────────
//
// Inviting a bot joins it immediately. A bot has no human to accept an invite
// and cannot see one (SyncResponse::rooms has a `join` map and no `invite`
// section), so an invite row for a bot is invisible to the bot and
// indistinguishable from a no-op to the operator who sent it.
//
// This does NOT contradict the auto-join exclusion above, and the tests are
// deliberately adjacent so the difference is visible: that exclusion is about
// the untargeted sweeps that repeat forever, this is one named bot added to one
// named channel by one person who just passed the permission check.

namespace {
std::string invite_path(const std::string& room) {
    return "/_matrix/client/v3/rooms/" + room + "/invite";
}
std::string invite_body(const std::string& user) { return json{{"user_id", user}}.dump(); }
} // namespace

TEST(BotInvite, InvitingABotJoinsItAndEmitsAJoinEvent) {
    Fixture fx("invite-join");
    fx.seed_roles();
    // The inviter needs MANAGE_CHANNELS (what the invite path requires) as well
    // as MANAGE_BOTS (to create the bot in the first place).
    auto admin = fx.add_user("admin", {"botmod", "everything_else"});
    auto room = fx.add_public_channel(admin, "general");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_invited");

    ASSERT_TRUE(fx.store->get_joined_rooms(bot_id).empty());

    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_invite, invite_path(room),
                          "token-admin", invite_body(bot_id))));

    // Joined outright — not left sitting on an invite nobody can accept.
    EXPECT_TRUE(fx.store->is_room_member(room, bot_id));
    EXPECT_EQ(fx.store->get_membership(room, bot_id), membership::kJoin);
    EXPECT_EQ(fx.store->get_joined_rooms(bot_id).size(), 1u);

    // A real m.room.member join event, sent BY the bot, so every other member
    // sees it arrive through the ordinary membership machinery.
    auto ev = fx.store->get_state_event(room, std::string(event_type::kRoomMember), bot_id);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->content.data.value("membership", ""), membership::kJoin);
    EXPECT_EQ(ev->sender, bot_id);
    // ...carrying a name, so it renders as something other than a raw user id
    // from the very first sync.
    EXPECT_FALSE(ev->content.data.value("displayname", "").empty());

    // Audited, with the INVITER as actor: "who gave this bot access to that
    // channel" is the question the record exists to answer.
    int membership_records = 0;
    for (const auto& r : fx.records()) {
        if (r.target_user != bot_id || r.target_room != room) continue;
        ++membership_records;
        EXPECT_EQ(r.actor, admin);
        EXPECT_EQ(json::parse(r.after_json).value("membership", ""), membership::kJoin);
    }
    EXPECT_EQ(membership_records, 1);
}

TEST(BotInvite, IsIdempotent) {
    Fixture fx("invite-idem");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod", "everything_else"});
    auto room = fx.add_public_channel(admin, "general");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_twiceinvited");

    for (int attempt = 0; attempt < 3; ++attempt) {
        auto res = call(*fx.rooms, &RoomHandler::handle_invite, invite_path(room),
                        "token-admin", invite_body(bot_id));
        EXPECT_TRUE(IsOk(res)) << "attempt " << attempt;
        EXPECT_EQ(res.body, "{}");
    }

    EXPECT_TRUE(fx.store->is_room_member(room, bot_id));

    // Exactly ONE join event, not three: a duplicate would render in every
    // client as the bot arriving again.
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM events WHERE room_id = '" + room +
                          "' AND event_type = 'm.room.member' AND state_key = '" + bot_id + "'"),
              1);

    // ...and exactly one audit record, for an event that happened once.
    int membership_records = 0;
    for (const auto& r : fx.records()) {
        if (r.target_user == bot_id && r.target_room == room) ++membership_records;
    }
    EXPECT_EQ(membership_records, 1);
}

TEST(BotInvite, RefusesADeactivatedBot) {
    Fixture fx("invite-dead");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod", "everything_else"});
    auto room = fx.add_public_channel(admin, "general");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_deadinvite");
    ASSERT_TRUE(IsOk(call(*fx.bots, &BotHandler::handle_deactivate_bot, bot_path(bot_id),
                          "token-admin")));

    EXPECT_TRUE(RefusedBecause(call(*fx.rooms, &RoomHandler::handle_invite, invite_path(room),
                                    "token-admin", invite_body(bot_id)),
                               403, "deactivated"));

    // Nothing was written: no membership row of any kind, no event.
    EXPECT_FALSE(fx.store->is_room_member(room, bot_id));
    EXPECT_EQ(raw_int(fx.db_path,
                      "SELECT COUNT(*) FROM room_members WHERE room_id = '" + room +
                          "' AND user_id = '" + bot_id + "'"),
              0);
}

TEST(BotInvite, RefusesAServerBannedBot) {
    Fixture fx("invite-banned");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod", "everything_else"});
    auto room = fx.add_public_channel(admin, "general");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_bannedinvite");
    fx.store->set_server_ban(bot_id, admin, "misbehaving");

    EXPECT_TRUE(RefusedBecause(call(*fx.rooms, &RoomHandler::handle_invite, invite_path(room),
                                    "token-admin", invite_body(bot_id)),
                               403, "banned"));
    EXPECT_FALSE(fx.store->is_room_member(room, bot_id));
}

// The inviter's own permission check is untouched — this changes what happens
// AFTER it passes, not whether it runs.
TEST(BotInvite, StillRequiresTheInvitersPermission) {
    Fixture fx("invite-perm");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod", "everything_else"});
    auto room = fx.add_public_channel(admin, "general");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_unauthorized");

    // A plain member of the channel, with no MANAGE_CHANNELS.
    auto plain = fx.add_user("plain");
    fx.store->set_membership(room, plain, std::string(membership::kJoin));

    EXPECT_TRUE(RefusedBecause(call(*fx.rooms, &RoomHandler::handle_invite, invite_path(room),
                                    "token-plain", invite_body(bot_id)),
                               403, "Insufficient permissions"));
    EXPECT_FALSE(fx.store->is_room_member(room, bot_id));
}

// Human invite semantics must not change at all. A human gets an `invite` row
// and an `invite` event, exactly as before — this is a bot-only branch.
TEST(BotInvite, AHumanInviteStillProducesAnInviteAndNotAJoin) {
    Fixture fx("invite-human");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod", "everything_else"});
    auto room = fx.add_public_channel(admin, "general");
    auto human = fx.add_user("carol");

    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_invite, invite_path(room),
                          "token-admin", invite_body(human))));

    EXPECT_EQ(fx.store->get_membership(room, human), membership::kInvite);
    // Not a member: an invited human still has to accept.
    EXPECT_FALSE(fx.store->is_room_member(room, human));

    auto ev = fx.store->get_state_event(room, std::string(event_type::kRoomMember), human);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->content.data.value("membership", ""), membership::kInvite);
    // Sent by the INVITER, which is how a human invite has always been emitted.
    EXPECT_EQ(ev->sender, admin);

    // And the invited human can then accept it, as before.
    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_join,
                          "/_matrix/client/v3/join/" + room, "token-carol")));
    EXPECT_TRUE(fx.store->is_room_member(room, human));
}

// The exclusion and the invite coexist: an invited bot stays in the ONE channel
// it was invited to, and backfill does not drag it into any of the others. This
// is the test that fails if somebody "reconciles" the two behaviours.
TEST(BotInvite, AnInvitedBotIsNotSweptIntoOtherChannelsByBackfill) {
    Fixture fx("invite-vs-backfill");
    fx.seed_roles();
    auto admin = fx.add_user("admin", {"botmod", "everything_else"});
    auto invited_room = fx.add_public_channel(admin, "general");
    fx.add_public_channel(admin, "random");
    fx.add_public_channel(admin, "offtopic");
    auto [bot_id, token] = fx.make_bot("token-admin", "bot_scoped_join");

    ASSERT_TRUE(IsOk(call(*fx.rooms, &RoomHandler::handle_invite, invite_path(invited_room),
                          "token-admin", invite_body(bot_id))));
    ASSERT_EQ(fx.store->get_joined_rooms(bot_id).size(), 1u);

    // Three simulated boots. The bot stays in exactly the one channel it was
    // invited to — not evicted from it, not added to the other two.
    for (int boot = 0; boot < 3; ++boot) {
        backfill_auto_join(*fx.store, *fx.sync, fx.config);
        auto joined = fx.store->get_joined_rooms(bot_id);
        ASSERT_EQ(joined.size(), 1u) << "after backfill pass " << boot;
        EXPECT_EQ(joined.front(), invited_room);
    }

    // The human is in all three, so the backfill genuinely ran.
    auto human = fx.add_user("dave");
    backfill_auto_join(*fx.store, *fx.sync, fx.config);
    EXPECT_EQ(fx.store->get_joined_rooms(human).size(), 3u);
    EXPECT_EQ(fx.store->get_joined_rooms(bot_id).size(), 1u);
}
