#include <gtest/gtest.h>
#include "auth/LocalAuth.h"
#include "auth/OidcAuth.h"
#include "store/SqliteStore.h"

#include <bsfchat/Identifiers.h>

using namespace bsfchat;

TEST(LocalAuth, HashAndVerify) {
    auto hash = hash_password("mysecret", 10);
    EXPECT_TRUE(hash.starts_with("$pbkdf2$"));
    EXPECT_TRUE(verify_password("mysecret", hash));
    EXPECT_FALSE(verify_password("wrongpassword", hash));
}

TEST(LocalAuth, DifferentHashesForSamePassword) {
    auto h1 = hash_password("test", 10);
    auto h2 = hash_password("test", 10);
    EXPECT_NE(h1, h2); // different salts
    EXPECT_TRUE(verify_password("test", h1));
    EXPECT_TRUE(verify_password("test", h2));
}

class StoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
    }

    std::unique_ptr<SqliteStore> store;
};

TEST_F(StoreTest, CreateUser) {
    EXPECT_TRUE(store->create_user("@alice:test", hash_password("pass", 10)));
    EXPECT_TRUE(store->user_exists("@alice:test"));
    EXPECT_FALSE(store->user_exists("@bob:test"));
}

TEST_F(StoreTest, DuplicateUser) {
    EXPECT_TRUE(store->create_user("@alice:test", hash_password("pass", 10)));
    EXPECT_FALSE(store->create_user("@alice:test", hash_password("pass2", 10)));
}

TEST_F(StoreTest, AccessTokens) {
    store->create_user("@alice:test", hash_password("pass", 10));
    store->store_access_token("tok123", "@alice:test", "DEVICE1");

    auto user = store->get_user_by_token("tok123");
    ASSERT_TRUE(user.has_value());
    EXPECT_EQ(*user, "@alice:test");

    EXPECT_FALSE(store->get_user_by_token("invalid").has_value());

    store->delete_access_token("tok123");
    EXPECT_FALSE(store->get_user_by_token("tok123").has_value());
}

TEST_F(StoreTest, PasswordVerification) {
    auto pw_hash = hash_password("secret123", 10);
    store->create_user("@alice:test", pw_hash);

    auto stored = store->get_password_hash("@alice:test");
    ASSERT_TRUE(stored.has_value());
    EXPECT_TRUE(verify_password("secret123", *stored));
    EXPECT_FALSE(verify_password("wrongpass", *stored));
}

// --- AuthHandler HTTP-level tests ---

#include "api/AuthHandler.h"
#include "auth/OidcAuth.h"
#include "sync/SyncEngine.h"
#include "core/Config.h"

#include <bsfchat/JwtUtils.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <thread>

class AuthHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        config.password_hash_cost = 10; // keep tests fast
        sync_engine = std::make_unique<SyncEngine>(*store, config);
        handler = std::make_unique<AuthHandler>(*store, *sync_engine, config);

        store->create_user("@alice:test", hash_password("password1", 10));
        store->store_access_token("alice-token", "@alice:test", "DEV1");
    }

    httplib::Response do_register(const std::string& username, const std::string& password) {
        httplib::Request req;
        req.body = nlohmann::json{{"username", username}, {"password", password}}.dump();
        httplib::Response res;
        handler->handle_register(req, res);
        return res;
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
    std::unique_ptr<AuthHandler> handler;
};

TEST_F(AuthHandlerTest, WhoamiReturnsCanonicalUserId) {
    httplib::Request req;
    req.set_header("Authorization", "Bearer alice-token");
    httplib::Response res;
    handler->handle_whoami(req, res);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["user_id"], "@alice:test");
}

TEST_F(AuthHandlerTest, WhoamiRejectsMissingToken) {
    httplib::Request req;
    httplib::Response res;
    handler->handle_whoami(req, res);
    EXPECT_EQ(res.status, 401);
}

TEST_F(AuthHandlerTest, WhoamiRejectsUnknownToken) {
    httplib::Request req;
    req.set_header("Authorization", "Bearer bogus");
    httplib::Response res;
    handler->handle_whoami(req, res);
    EXPECT_EQ(res.status, 401);
}

// A username containing '@' or ':' must never survive registration —
// "@" + "@josh" + ":test" would mint the malformed id "@@josh:test",
// which breaks every string-equality self-check in clients.
// An identity-only server (identity.required, local accounts off) advertises
// no password login flow, so a locally registered account could never sign
// in. Registration must refuse up front and point at the identity provider
// instead of minting a dead account.
TEST_F(AuthHandlerTest, RegisterRefusedOnIdentityOnlyServer) {
    IdentityConfig id;
    id.provider_url = "https://id.example.com";
    id.required = true;
    id.allow_local_accounts = false;
    config.identity = id;   // handler holds a reference to config

    auto res = do_register("newcomer", "password1");
    EXPECT_EQ(res.status, 403);
    EXPECT_FALSE(store->user_exists("@newcomer:test"));
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["errcode"], "M_FORBIDDEN");
    EXPECT_NE(body["error"].get<std::string>().find("https://id.example.com"), std::string::npos);
}

// Identity required but local accounts still allowed: registration stays open.
TEST_F(AuthHandlerTest, RegisterAllowedWhenIdentityPermitsLocalAccounts) {
    IdentityConfig id;
    id.provider_url = "https://id.example.com";
    id.required = true;
    id.allow_local_accounts = true;
    config.identity = id;

    auto res = do_register("newcomer", "password1");
    EXPECT_EQ(res.status, 200);
    EXPECT_TRUE(store->user_exists("@newcomer:test"));
}

TEST_F(AuthHandlerTest, RegisterRejectsAtSignInUsername) {
    auto res = do_register("@josh", "password1");
    EXPECT_EQ(res.status, 400);
    EXPECT_FALSE(store->user_exists("@@josh:test"));
}

TEST_F(AuthHandlerTest, RegisterRejectsColonInUsername) {
    auto res = do_register("josh:evil", "password1");
    EXPECT_EQ(res.status, 400);
}

TEST_F(AuthHandlerTest, RegisterAcceptsValidLocalpart) {
    auto res = do_register("new.user_1-ok", "password1");
    EXPECT_EQ(res.status, 200);
    EXPECT_TRUE(store->user_exists("@new.user_1-ok:test"));

    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["user_id"], "@new.user_1-ok:test");
}


// --- Identity (m.login.token) account creation ---------------------------
//
// An identity-only deployment — identity.required with allow_local_accounts
// off, which is the shape BSFChat actually ships — refuses local
// registration outright, so m.login.token is the ONLY way an account is ever
// created on it. handle_register calls bootstrap_roles after creating an
// account; the identity path did not, so a user created through identity
// held no bsfchat.member.roles row and fell through to @everyone until the
// next server restart happened to run the startup bootstrap.
//
// For the FIRST user that is a deadlock, and it is the exact deadlock
// RoleBootstrap exists to prevent: they should be the admin, they came out
// with no admin role, so they had no MANAGE_CHANNELS and could not create
// the first channel on their own server.
//
// This fixture stands up a real identity provider — RSA keypair, discovery
// document, JWKS — on loopback, so the test drives the true code path
// through OidcAuth rather than asserting on a stub.
class IdentityLoginTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto [priv, pub] = bsfchat::generate_rsa_keypair();
        private_pem = priv;

        provider.Get("/.well-known/openid-configuration",
                     [this](const httplib::Request&, httplib::Response& res) {
            res.set_content(nlohmann::json{
                {"issuer", issuer()},
                {"jwks_uri", issuer() + "/jwks.json"},
            }.dump(), "application/json");
        });
        provider.Get("/jwks.json", [pub](const httplib::Request&, httplib::Response& res) {
            res.set_content(nlohmann::json{
                {"keys", nlohmann::json::array({bsfchat::pem_to_jwk(pub, "test-key-1")})}
            }.dump(), "application/json");
        });

        port = provider.bind_to_any_port("127.0.0.1");
        ASSERT_GT(port, 0);
        serving = std::thread([this] { provider.listen_after_bind(); });
        provider.wait_until_ready();
        ASSERT_TRUE(provider.is_running());

        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        config.password_hash_cost = 10;
        IdentityConfig id;
        id.provider_url = issuer();
        id.required = true;
        id.allow_local_accounts = false;   // identity-only: no local registration
        id.client_id = "bsfchat-server";
        config.identity = id;

        sync_engine = std::make_unique<SyncEngine>(*store, config);
        oidc = std::make_unique<OidcAuth>(issuer());
        ASSERT_TRUE(oidc->refresh_keys());
        handler = std::make_unique<AuthHandler>(*store, *sync_engine, config, oidc.get());
    }

    void TearDown() override {
        provider.stop();
        if (serving.joinable()) serving.join();
    }

    std::string issuer() const {
        return "http://127.0.0.1:" + std::to_string(port);
    }

    std::string id_token_for(const std::string& subject) {
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        bsfchat::JwtClaims claims;
        claims.sub = subject;
        claims.iss = issuer();
        claims.aud = "bsfchat-server";
        claims.iat = now;
        claims.exp = now + 600;
        return bsfchat::jwt_sign(claims, private_pem, "test-key-1");
    }

    httplib::Response login_with(const std::string& subject) {
        httplib::Request req;
        req.body = nlohmann::json{{"type", "m.login.token"},
                                  {"token", id_token_for(subject)}}.dump();
        httplib::Response res;
        handler->handle_login(req, res);
        return res;
    }

    static bool has_role(const std::vector<std::string>& ids, const std::string& want) {
        return std::find(ids.begin(), ids.end(), want) != ids.end();
    }

    httplib::Server provider;
    std::thread serving;
    int port = 0;
    std::string private_pem;
    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
    std::unique_ptr<OidcAuth> oidc;
    std::unique_ptr<AuthHandler> handler;
};

TEST_F(IdentityLoginTest, FirstIdentityUserIsAdminWithoutARestart) {
    auto res = login_with("alice-subject");
    ASSERT_EQ(res.status < 0 ? 200 : res.status, 200) << res.body;
    const auto user_id = nlohmann::json::parse(res.body)["user_id"].get<std::string>();
    EXPECT_TRUE(store->user_exists(user_id));

    auto roles = store->get_member_role_ids(user_id);
    EXPECT_TRUE(has_role(roles, "admin"))
        << "the first identity user holds no admin role, so they cannot "
           "create the first channel on their own server";
}

TEST_F(IdentityLoginTest, LaterIdentityUsersAreNotAdmin) {
    ASSERT_EQ(login_with("alice-subject").status < 0 ? 200 : 200, 200);
    auto res = login_with("bob-subject");
    ASSERT_EQ(res.status < 0 ? 200 : res.status, 200) << res.body;

    const auto bob = nlohmann::json::parse(res.body)["user_id"].get<std::string>();
    auto roles = store->get_member_role_ids(bob);
    EXPECT_FALSE(has_role(roles, "admin")) << "second user was made an admin";
    EXPECT_FALSE(roles.empty()) << "second user has no role assignment at all";
}

TEST_F(IdentityLoginTest, RepeatLoginDoesNotReprovision) {
    ASSERT_EQ(login_with("alice-subject").status < 0 ? 200 : 200, 200);
    const auto first = store->get_member_role_ids("@oidc_alice-subject:test");
    ASSERT_EQ(login_with("alice-subject").status < 0 ? 200 : 200, 200);
    EXPECT_EQ(store->get_member_role_ids("@oidc_alice-subject:test"), first);
}

// OIDC key-refresh backoff.
//
// validate_token() used to call refresh_keys() unconditionally — twice, in
// fact: once because "never refreshed" reads as infinitely stale, and again
// on the unknown-kid path. Each call is a discovery fetch plus a JWKS fetch
// with a 10 s connect and a 10 s read timeout, performed inline on an httplib
// worker thread. With the default four workers, four requests carrying any
// Authorization header were enough to make an identity-backed server
// unresponsive for ~40 s at a time, for as long as the identity service was
// down, from anyone who can reach the port. The schedule below is what bounds
// that, and what paces the startup retry when the identity container is
// simply slower to come up than we are.
TEST(OidcBackoff, DoublesFromOneSecond) {
    using bsfchat::oidc_detail::next_backoff_seconds;
    EXPECT_EQ(next_backoff_seconds(1), 2);
    EXPECT_EQ(next_backoff_seconds(2), 4);
    EXPECT_EQ(next_backoff_seconds(4), 8);
    EXPECT_EQ(next_backoff_seconds(8), 16);
}

TEST(OidcBackoff, ClampsAtFiveMinutes) {
    using bsfchat::oidc_detail::next_backoff_seconds;
    // Must saturate rather than grow without bound: a provider that comes
    // back after an hour has to be noticed within five minutes, and the
    // multiplication must never overflow.
    EXPECT_EQ(next_backoff_seconds(256), 300);
    EXPECT_EQ(next_backoff_seconds(300), 300);
    EXPECT_EQ(next_backoff_seconds(4096), 300);
    EXPECT_EQ(next_backoff_seconds(1LL << 40), 300);
}

TEST(OidcBackoff, NeverReturnsZeroOrNegative) {
    using bsfchat::oidc_detail::next_backoff_seconds;
    // A zero would put the retry loop into a hot spin against the provider,
    // which is the failure this whole change exists to prevent.
    EXPECT_EQ(next_backoff_seconds(0), 1);
    EXPECT_EQ(next_backoff_seconds(-1), 1);
    EXPECT_EQ(next_backoff_seconds(-1000000), 1);
}

// Destroying an OidcAuth whose background retry never succeeded must not
// hang or crash — the provider being permanently unreachable is exactly when
// a shutdown gets attempted.
TEST(OidcBackoff, BackgroundRefreshIsJoinedOnDestruction) {
    bsfchat::OidcAuth auth("http://127.0.0.1:1/");  // nothing listens here
    auth.start_background_refresh();
    EXPECT_FALSE(auth.has_keys());
}
