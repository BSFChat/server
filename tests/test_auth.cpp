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
#include "sync/SyncEngine.h"
#include "core/Config.h"

#include <nlohmann/json.hpp>

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
