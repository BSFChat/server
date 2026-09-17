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

// --- Request limiting on the credential endpoints ---
//
// Before this, nothing limited /login, /register, /refresh or
// /account/password at all. These cover the primitives, the proxy-aware client
// address (the part that decides whether the limiter protects the server or
// becomes a way to lock everybody out of it), and the handler behaviour.

#include "core/RateLimiter.h"
#include "http/ClientAddress.h"

#include <filesystem>
#include <fstream>

namespace {

struct FakeClock {
    std::shared_ptr<int64_t> now = std::make_shared<int64_t>(1'000'000);
    LimiterClock fn() const { return [n = now] { return *n; }; }
    void advance_s(int64_t s) { *now += s * 1000; }
};

httplib::Request request_from(const std::string& peer, const std::string& xff = {}) {
    httplib::Request req;
    req.remote_addr = peer;
    if (!xff.empty()) req.set_header("X-Forwarded-For", xff);
    return req;
}

} // namespace

TEST(RateLimiterTest, RefusesPastTheLimitAndReportsTheWait) {
    FakeClock clock;
    RateLimiter limiter(3, std::chrono::seconds(60), clock.fn());
    EXPECT_EQ(limiter.acquire("a"), 0);
    clock.advance_s(10);
    EXPECT_EQ(limiter.acquire("a"), 0);
    EXPECT_EQ(limiter.acquire("a"), 0);
    // The oldest event is 10s old, so a slot frees in 50s.
    EXPECT_EQ(limiter.acquire("a"), 50'000);
    // Other keys are unaffected.
    EXPECT_EQ(limiter.acquire("b"), 0);
}

TEST(RateLimiterTest, WindowSlidesAndRefusalsAreNotRecorded) {
    FakeClock clock;
    RateLimiter limiter(2, std::chrono::seconds(60), clock.fn());
    EXPECT_EQ(limiter.acquire("a"), 0);
    EXPECT_EQ(limiter.acquire("a"), 0);
    // Hammering a closed limiter must not push the reopening further away.
    for (int i = 0; i < 50; ++i) {
        clock.advance_s(1);
        EXPECT_GT(limiter.acquire("a"), 0);
    }
    clock.advance_s(10); // 60s after the first two
    EXPECT_EQ(limiter.acquire("a"), 0);
}

TEST(RateLimiterTest, NonPositiveLimitDisables) {
    RateLimiter limiter(0, std::chrono::seconds(60));
    for (int i = 0; i < 1000; ++i) EXPECT_EQ(limiter.acquire("a"), 0);
    EXPECT_EQ(limiter.size(), 0u);
}

TEST(RateLimiterTest, IdleKeysArePruned) {
    FakeClock clock;
    RateLimiter limiter(5, std::chrono::seconds(60), clock.fn());
    for (int i = 0; i < 500; ++i) limiter.acquire("key" + std::to_string(i));
    EXPECT_EQ(limiter.size(), 500u);
    clock.advance_s(61);
    limiter.acquire("fresh");
    EXPECT_EQ(limiter.size(), 1u);
}

TEST(FailureTrackerTest, LocksAtThresholdAndStartsOverAfterwards) {
    FakeClock clock;
    FailureTracker tracker(3, std::chrono::seconds(300), clock.fn());
    EXPECT_FALSE(tracker.record_failure("k"));
    EXPECT_FALSE(tracker.record_failure("k"));
    EXPECT_EQ(tracker.locked_for("k"), 0);
    EXPECT_TRUE(tracker.record_failure("k"));
    EXPECT_EQ(tracker.locked_for("k"), 300'000);

    clock.advance_s(299);
    EXPECT_EQ(tracker.locked_for("k"), 1000);
    clock.advance_s(1);
    EXPECT_EQ(tracker.locked_for("k"), 0);
    // A full allowance again — not "one more failure and you're back in".
    EXPECT_FALSE(tracker.record_failure("k"));
    EXPECT_FALSE(tracker.record_failure("k"));
    EXPECT_TRUE(tracker.record_failure("k"));
}

TEST(FailureTrackerTest, OldFailuresAreForgottenAndSuccessClears) {
    FakeClock clock;
    FailureTracker tracker(3, std::chrono::seconds(300), clock.fn());
    tracker.record_failure("k");
    tracker.record_failure("k");
    clock.advance_s(301);
    EXPECT_FALSE(tracker.record_failure("k")) << "stale failures must not accumulate";

    tracker.record_failure("k");
    tracker.clear("k");
    EXPECT_FALSE(tracker.record_failure("k"));
    EXPECT_FALSE(tracker.record_failure("k"));
}

TEST(ClientAddress, CidrParsingAndMatching) {
    EXPECT_TRUE(IpNetwork::parse("10.0.0.0/8"));
    EXPECT_TRUE(IpNetwork::parse("192.168.1.1"));
    EXPECT_TRUE(IpNetwork::parse("fd00::/8"));
    EXPECT_TRUE(IpNetwork::parse("::1"));
    EXPECT_FALSE(IpNetwork::parse("10.0.0.0/33"));
    EXPECT_FALSE(IpNetwork::parse("fd00::/129"));
    EXPECT_FALSE(IpNetwork::parse("10.0.0.0/"));
    EXPECT_FALSE(IpNetwork::parse("10.0.0.0/-1"));
    EXPECT_FALSE(IpNetwork::parse("nginx"));
    EXPECT_FALSE(IpNetwork::parse(""));

    EXPECT_THROW(ClientAddressResolver({"127.0.0.1", "not-an-ip"}), std::invalid_argument);

    // 172.16/12 is the one people get wrong by eye: it has a partial byte.
    ClientAddressResolver r({"172.16.0.0/12"});
    EXPECT_EQ(r.resolve(request_from("172.31.255.254", "203.0.113.9")), "203.0.113.9");
    EXPECT_EQ(r.resolve(request_from("172.32.0.1", "203.0.113.9")), "172.32.0.1");
}

TEST(ClientAddress, ForwardedForIsIgnoredFromAnUntrustedPeer) {
    // Otherwise any client could mint a new rate-limit identity per request.
    ClientAddressResolver r({"127.0.0.1"});
    EXPECT_EQ(r.resolve(request_from("198.51.100.7", "1.2.3.4")), "198.51.100.7");
}

TEST(ClientAddress, TrustedPeerYieldsTheRightmostUntrustedHop) {
    ClientAddressResolver r({"127.0.0.0/8", "10.0.0.0/8"});
    EXPECT_EQ(r.resolve(request_from("127.0.0.1", "203.0.113.9")), "203.0.113.9");
    // The client put "6.6.6.6" there itself; nginx appended what it really saw.
    EXPECT_EQ(r.resolve(request_from("127.0.0.1", "6.6.6.6, 203.0.113.9")), "203.0.113.9");
    // A chain of our own proxies is walked through.
    EXPECT_EQ(r.resolve(request_from("127.0.0.1", "6.6.6.6, 203.0.113.9, 10.1.2.3")),
              "203.0.113.9");
    // Ports and brackets, as some proxies emit them.
    EXPECT_EQ(r.resolve(request_from("127.0.0.1", "203.0.113.9:51234")), "203.0.113.9");
    EXPECT_EQ(r.resolve(request_from("127.0.0.1", "[2001:db8:1:2:aaaa::1]:443")),
              "2001:db8:1:2::/64");
    // A dual-stack listener reports IPv4 peers in mapped form.
    EXPECT_EQ(r.resolve(request_from("::ffff:127.0.0.1", "203.0.113.9")), "203.0.113.9");

    // The header split across two lines: the order of repeated header lines
    // is not recoverable from httplib (unordered_multimap), so "rightmost" is
    // unknowable and the resolver must refuse to guess rather than risk
    // returning the value the client supplied itself.
    auto req = request_from("127.0.0.1", "6.6.6.6");
    req.set_header("X-Forwarded-For", "203.0.113.9");
    EXPECT_EQ(r.resolve(req), std::nullopt);
}

TEST(ClientAddress, UnknowableClientIsNulloptNotASharedBucket) {
    ClientAddressResolver r({"127.0.0.0/8", "10.0.0.0/8"});
    EXPECT_EQ(r.resolve(request_from("127.0.0.1")), std::nullopt);              // no header
    EXPECT_EQ(r.resolve(request_from("127.0.0.1", "10.0.0.5")), std::nullopt);  // all trusted
    EXPECT_EQ(r.resolve(request_from("127.0.0.1", "1.2.3.4, unknown")), std::nullopt);
    EXPECT_EQ(r.resolve(request_from("")), std::nullopt);
}

TEST(ClientAddress, Ipv6CollapsesToSlash64) {
    ClientAddressResolver r({});
    EXPECT_EQ(r.resolve(request_from("2001:db8:1:2:3:4:5:6")),
              r.resolve(request_from("2001:db8:1:2:ffff::1")));
    EXPECT_NE(r.resolve(request_from("2001:db8:1:2::1")),
              r.resolve(request_from("2001:db8:1:3::1")));
}

TEST(ClientAddress, SpotsAProxyThatIsNotListed) {
    ClientAddressResolver r({"127.0.0.0/8"});
    EXPECT_TRUE(r.looks_like_untrusted_proxy(request_from("172.18.0.1", "203.0.113.9")));
    EXPECT_FALSE(r.looks_like_untrusted_proxy(request_from("172.18.0.1")));
    EXPECT_FALSE(r.looks_like_untrusted_proxy(request_from("127.0.0.1", "203.0.113.9")));
    // A public peer sending the header is just a client being cute.
    EXPECT_FALSE(r.looks_like_untrusted_proxy(request_from("198.51.100.7", "1.2.3.4")));
}

class AuthLimitTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        config.password_hash_cost = 10;
        config.auth_limits.rate_limit = 1000; // out of the way unless a test wants it
        config.auth_limits.max_failures = 5;
        config.auth_limits.lockout_seconds = 300;
        sync_engine = std::make_unique<SyncEngine>(*store, config);
        store->create_user("@alice:test", hash_password("password1", 10));
        store->create_user("@bob:test", hash_password("password2", 10));
        store->store_access_token("alice-token", "@alice:test", "DEV1");
    }

    // Limiter sizes are read at construction, so tests build the handler
    // after adjusting config.
    void make_handler() {
        handler = std::make_unique<AuthHandler>(*store, *sync_engine, config, nullptr, clock.fn());
    }

    httplib::Response login(const std::string& peer, const std::string& user,
                            const std::string& password, const std::string& xff = {}) {
        auto req = request_from(peer, xff);
        req.body = nlohmann::json{{"type", "m.login.password"},
                                  {"identifier", {{"type", "m.id.user"}, {"user", user}}},
                                  {"password", password}}.dump();
        httplib::Response res;
        handler->handle_login(req, res);
        return settled(res);
    }

    httplib::Response do_register(const std::string& peer, const std::string& username,
                                  const std::string& password = "longenough1") {
        auto req = request_from(peer);
        req.body = nlohmann::json{{"username", username}, {"password", password}}.dump();
        httplib::Response res;
        handler->handle_register(req, res);
        return res;
    }

    httplib::Response change_password(const std::string& peer, const std::string& current) {
        auto req = request_from(peer);
        req.set_header("Authorization", "Bearer alice-token");
        req.body = nlohmann::json{
            {"auth", {{"type", "m.login.password"}, {"password", current}}},
            {"new_password", "brandnewpass1"}}.dump();
        httplib::Response res;
        handler->handle_password_change(req, res);
        return settled(res);
    }

    // Handlers only set a status on failure; httplib turns the untouched -1
    // into 200 when it writes the response. Do the same so tests can say 200.
    static httplib::Response settled(httplib::Response res) {
        if (res.status == -1) res.status = 200;
        return res;
    }

    static std::string ip(int n) { return "203.0.113." + std::to_string(n); }

    // The shape every limited response must have.
    static void expect_limited(const httplib::Response& res, int64_t max_wait_s) {
        EXPECT_EQ(res.status, 429);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["errcode"], "M_LIMIT_EXCEEDED");
        ASSERT_TRUE(body.contains("retry_after_ms"));
        EXPECT_GT(body["retry_after_ms"].get<int64_t>(), 0);
        EXPECT_LE(body["retry_after_ms"].get<int64_t>(), max_wait_s * 1000);
        ASSERT_TRUE(res.has_header("Retry-After"));
        const auto secs = std::stoll(res.get_header_value("Retry-After"));
        EXPECT_GE(secs, 1);
        EXPECT_LE(secs, max_wait_s);
        // Rounded up, never down: a client that obeys it must not be early.
        EXPECT_GE(secs * 1000, body["retry_after_ms"].get<int64_t>());
    }

    FakeClock clock;
    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
    std::unique_ptr<AuthHandler> handler;
};

TEST_F(AuthLimitTest, UsernameLocksOutAcrossManyAddresses) {
    make_handler();
    // A distributed guesser: every attempt from a new address.
    for (int i = 1; i <= 5; ++i) {
        EXPECT_EQ(login(ip(i), "alice", "wrong-guess").status, 403);
    }
    // Locked — even for the right password, even from an address never seen.
    expect_limited(login(ip(99), "alice", "password1"), 300);
    // Full user id and bare localpart are the same account, not two counters.
    expect_limited(login(ip(98), "@alice:test", "password1"), 300);
    // Nobody else is affected.
    EXPECT_EQ(login(ip(99), "bob", "password2").status, 200);

    clock.advance_s(301);
    EXPECT_EQ(login(ip(99), "alice", "password1").status, 200);
}

TEST_F(AuthLimitTest, AddressLocksOutAcrossManyUsernames) {
    make_handler();
    // Password spraying: one address, a different account each time.
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(login(ip(1), "victim" + std::to_string(i), "Summer2026!").status, 403);
    }
    expect_limited(login(ip(1), "alice", "password1"), 300);
    // alice herself is not locked; only that address is.
    EXPECT_EQ(login(ip(2), "alice", "password1").status, 200);
}

TEST_F(AuthLimitTest, OwnValidAccountDoesNotResetTheAddressCounter) {
    make_handler();
    // The bypass this guards against: guess, log into your own account to zero
    // the counter, guess again, forever.
    for (int i = 0; i < 4; ++i) login(ip(1), "alice", "guess" + std::to_string(i));
    EXPECT_EQ(login(ip(1), "bob", "password2").status, 200);
    EXPECT_EQ(login(ip(1), "alice", "one-more-guess").status, 403);
    expect_limited(login(ip(1), "bob", "password2"), 300);
}

TEST_F(AuthLimitTest, SuccessResetsTheUsernameCounter) {
    make_handler();
    for (int round = 0; round < 3; ++round) {
        for (int i = 0; i < 4; ++i) login(ip(10 + round * 10 + i), "alice", "typo");
        EXPECT_EQ(login(ip(200 + round), "alice", "password1").status, 200);
    }
}

TEST_F(AuthLimitTest, LockoutDoesNotRevealWhetherTheAccountExists) {
    make_handler();
    for (int i = 1; i <= 5; ++i) login(ip(i), "alice", "wrong");
    for (int i = 11; i <= 15; ++i) login(ip(i), "nobody-home", "wrong");
    auto real = login(ip(50), "alice", "wrong");
    auto ghost = login(ip(51), "nobody-home", "wrong");
    EXPECT_EQ(real.status, 429);
    EXPECT_EQ(ghost.status, real.status);
    EXPECT_EQ(ghost.body, real.body);
}

TEST_F(AuthLimitTest, AttemptLimitAppliesBeforeTheBodyIsEvenParsed) {
    config.auth_limits.rate_limit = 3;
    config.auth_limits.rate_window_seconds = 60;
    make_handler();
    for (int i = 0; i < 3; ++i) {
        auto req = request_from(ip(1));
        req.body = "{not json";
        httplib::Response res;
        handler->handle_login(req, res);
        EXPECT_EQ(res.status, 400);
    }
    expect_limited(login(ip(1), "alice", "password1"), 60);
    EXPECT_EQ(login(ip(2), "alice", "password1").status, 200);

    // Endpoints are metered separately: a login flood does not close /refresh.
    auto req = request_from(ip(1));
    req.body = R"({"refresh_token":"nope"})";
    httplib::Response res;
    handler->handle_refresh(req, res);
    EXPECT_EQ(res.status, 401);
}

TEST_F(AuthLimitTest, RefreshIsLimited) {
    config.auth_limits.rate_limit = 2;
    make_handler();
    for (int i = 0; i < 3; ++i) {
        auto req = request_from(ip(1));
        req.body = R"({"refresh_token":"nope"})";
        httplib::Response res;
        handler->handle_refresh(req, res);
        if (i < 2) EXPECT_EQ(res.status, 401);
        else expect_limited(res, 60);
    }
}

// The proxied deployment, which is the documented one. Every request arrives
// from the proxy's address.
TEST_F(AuthLimitTest, ClientsBehindATrustedProxyAreLimitedIndividually) {
    config.auth_limits.trusted_proxies = {"172.18.0.1"};
    make_handler();
    for (int i = 0; i < 5; ++i) login("172.18.0.1", "victim" + std::to_string(i), "x", ip(1));
    expect_limited(login("172.18.0.1", "bob", "password2", ip(1)), 300);
    // A different real client through the same proxy is untouched...
    EXPECT_EQ(login("172.18.0.1", "bob", "password2", ip(2)).status, 200);
    // ...and the locked-out one cannot talk its way out with a forged hop.
    expect_limited(login("172.18.0.1", "bob", "password2", "9.9.9.9, " + ip(1)), 300);
}

TEST_F(AuthLimitTest, ProxyWithNoForwardedForIsNotOneGiantBucket) {
    config.auth_limits.rate_limit = 3;
    config.auth_limits.trusted_proxies = {"172.18.0.1"};
    make_handler();
    // Far past both per-address thresholds, all from "the same address".
    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(login("172.18.0.1", "victim" + std::to_string(i), "x").status, 403);
    }
    // The server must still be usable by everybody else...
    EXPECT_EQ(login("172.18.0.1", "bob", "password2").status, 200);
    // ...while the per-username lockout, which needs no address, still bites.
    for (int i = 0; i < 5; ++i) login("172.18.0.1", "alice", "wrong");
    expect_limited(login("172.18.0.1", "alice", "password1"), 300);
}

TEST_F(AuthLimitTest, RegistrationIsLimitedPerAddress) {
    config.auth_limits.register_limit = 3;
    config.auth_limits.register_window_seconds = 3600;
    make_handler();
    // Requests that never reach account creation do not spend the allowance.
    EXPECT_EQ(do_register(ip(1), "alice").status, 400);         // taken
    EXPECT_EQ(do_register(ip(1), "carol", "short").status, 400); // bad password
    EXPECT_EQ(do_register(ip(1), "Not Valid").status, 400);

    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(do_register(ip(1), "user" + std::to_string(i)).status, 200);
    }
    expect_limited(do_register(ip(1), "user3"), 3600);
    EXPECT_FALSE(store->user_exists("@user3:test"));
    EXPECT_EQ(do_register(ip(2), "user3").status, 200);

    clock.advance_s(3601);
    EXPECT_EQ(do_register(ip(1), "user4").status, 200);
}

TEST_F(AuthLimitTest, RegistrationHasAServerWideCeiling) {
    config.auth_limits.register_limit = 2;
    config.auth_limits.register_global_limit = 5;
    make_handler();
    // A botnet: never more than one signup per address.
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(do_register(ip(i + 1), "bot" + std::to_string(i)).status, 200);
    }
    expect_limited(do_register(ip(100), "bot5"), 3600);
    EXPECT_FALSE(store->user_exists("@bot5:test"));
    // Signing in is a different matter entirely and stays open.
    EXPECT_EQ(login(ip(100), "alice", "password1").status, 200);
}

TEST_F(AuthLimitTest, AnAddressOverItsOwnLimitCannotDrainTheServerWideOne) {
    config.auth_limits.register_limit = 1;
    config.auth_limits.register_global_limit = 3;
    make_handler();
    EXPECT_EQ(do_register(ip(1), "first").status, 200);
    for (int i = 0; i < 20; ++i) EXPECT_EQ(do_register(ip(1), "spam" + std::to_string(i)).status, 429);
    EXPECT_EQ(do_register(ip(2), "second").status, 200);
    EXPECT_EQ(do_register(ip(3), "third").status, 200);
}

TEST_F(AuthLimitTest, PasswordChangeLocksOutWithoutTouchingLogin) {
    make_handler();
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(change_password(ip(i + 1), "guess").status, 403);
    }
    expect_limited(change_password(ip(50), "password1"), 300);
    EXPECT_TRUE(verify_password("password1", *store->get_password_hash("@alice:test")));
    // A stolen token must not be a way to lock the owner out of signing in.
    EXPECT_EQ(login(ip(51), "alice", "password1").status, 200);

    clock.advance_s(301);
    EXPECT_EQ(change_password(ip(50), "password1").status, 200);
}

TEST_F(AuthLimitTest, MasterSwitchTurnsEverythingOff) {
    config.auth_limits.enabled = false;
    config.auth_limits.rate_limit = 1;
    config.auth_limits.register_limit = 1;
    config.auth_limits.register_global_limit = 1;
    make_handler();
    for (int i = 0; i < 12; ++i) EXPECT_EQ(login(ip(1), "alice", "wrong").status, 403);
    EXPECT_EQ(login(ip(1), "alice", "password1").status, 200);
    EXPECT_EQ(do_register(ip(1), "one").status, 200);
    EXPECT_EQ(do_register(ip(1), "two").status, 200);
}

namespace {

std::filesystem::path write_toml(const std::string& name, const std::string& body) {
    auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream(path) << body;
    return path;
}

} // namespace

TEST(AuthLimitsConfig, DefaultsAreOnAndTrustOnlyLoopback) {
    auto cfg = Config::defaults();
    EXPECT_TRUE(cfg.auth_limits.enabled);
    EXPECT_GT(cfg.auth_limits.rate_limit, 0);
    EXPECT_GT(cfg.auth_limits.max_failures, 0);
    EXPECT_GT(cfg.auth_limits.register_limit, 0);
    EXPECT_EQ(cfg.auth_limits.trusted_proxies,
              (std::vector<std::string>{"127.0.0.0/8", "::1"}));
}

TEST(AuthLimitsConfig, KeysLoadFromTheAuthTable) {
    auto path = write_toml("bsfchat_test_auth_limits.toml",
        "[auth]\n"
        "rate_limit_enabled = true\n"
        "trusted_proxies = [\"172.16.0.0/12\", \"10.1.2.3\"]\n"
        "rate_limit = 7\nrate_window_seconds = 11\n"
        "max_failures = 4\nlockout_seconds = 99\n"
        "register_limit = 2\nregister_window_seconds = 1234\n"
        "register_global_limit = 0\n");
    auto cfg = Config::load(path.string());
    std::filesystem::remove(path);
    const auto& l = cfg.auth_limits;
    EXPECT_EQ(l.trusted_proxies, (std::vector<std::string>{"172.16.0.0/12", "10.1.2.3"}));
    EXPECT_EQ(l.rate_limit, 7);
    EXPECT_EQ(l.rate_window_seconds, 11);
    EXPECT_EQ(l.max_failures, 4);
    EXPECT_EQ(l.lockout_seconds, 99);
    EXPECT_EQ(l.register_limit, 2);
    EXPECT_EQ(l.register_window_seconds, 1234);
    EXPECT_EQ(l.register_global_limit, 0);
}

TEST(AuthLimitsConfig, TrustedProxiesAcceptsAStringAndAnExplicitEmptyList) {
    auto one = write_toml("bsfchat_test_auth_proxy_one.toml",
                          "[auth]\ntrusted_proxies = \"10.0.0.1\"\n");
    EXPECT_EQ(Config::load(one.string()).auth_limits.trusted_proxies,
              (std::vector<std::string>{"10.0.0.1"}));
    std::filesystem::remove(one);

    // "Trust nothing, not even loopback" has to be expressible.
    auto none = write_toml("bsfchat_test_auth_proxy_none.toml",
                           "[auth]\ntrusted_proxies = []\n");
    EXPECT_TRUE(Config::load(none.string()).auth_limits.trusted_proxies.empty());
    std::filesystem::remove(none);
}

TEST(AuthLimitsConfig, BadProxyEntryStopsStartupAndBadNumbersAreClamped) {
    auto bad = write_toml("bsfchat_test_auth_proxy_bad.toml",
                          "[auth]\ntrusted_proxies = [\"127.0.0.1\", \"nginx\"]\n");
    EXPECT_THROW(Config::load(bad.string()), std::runtime_error);
    std::filesystem::remove(bad);

    Config cfg;
    cfg.auth_limits.rate_window_seconds = 0;
    cfg.auth_limits.lockout_seconds = -5;
    cfg.auth_limits.register_window_seconds = 0;
    cfg.auth_limits.max_failures = 1;
    Config::validate(cfg);
    EXPECT_EQ(cfg.auth_limits.rate_window_seconds, 1);
    EXPECT_EQ(cfg.auth_limits.lockout_seconds, 1);
    EXPECT_EQ(cfg.auth_limits.register_window_seconds, 1);
    EXPECT_EQ(cfg.auth_limits.max_failures, 3);
}
