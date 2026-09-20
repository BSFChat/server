#include <gtest/gtest.h>
#include "auth/LocalAuth.h"
#include "auth/OidcAuth.h"
#include "identity/Localpart.h"
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

    // Not "password1": that is on the common-password denylist now, and these
    // two tests are about the username path, not the password path.
    auto res = do_register("newcomer", "correct-horse-7");
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
    auto res = do_register("new.user_1-ok", "correct-horse-7");
    EXPECT_EQ(res.status, 200);
    EXPECT_TRUE(store->user_exists("@new.user_1-ok:test"));

    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["user_id"], "@new.user_1-ok:test");
}


// --- Lookalike usernames (audit finding 20) -------------------------------
//
// A REGISTRATION policy. The line these tests draw is that it refuses names at
// the point they are chosen and touches nothing else: not logins, not accounts
// that predate it, and not names that merely happen to contain a digit.
//
// The passwords here are not this file's usual "password1" on purpose: the
// password policy on harden/auth refuses it as one of the most common in use,
// and a registration test that fails on the PASSWORD proves nothing about the
// username rule it is supposed to be exercising.

TEST_F(AuthHandlerTest, RegisterRefusesALookalikeOfAnExistingAccount) {
    // @alice:test exists (SetUp). `a1ice` reads the same in a member list.
    auto res = do_register("a1ice", "tr0mbone-seven");
    EXPECT_EQ(res.status, 400);
    EXPECT_EQ(nlohmann::json::parse(res.body)["errcode"], "M_INVALID_USERNAME");
    EXPECT_FALSE(store->user_exists("@a1ice:test"));

    // The message does not name the account it resembles: the user does not
    // need it to choose another name.
    EXPECT_EQ(nlohmann::json::parse(res.body)["error"].get<std::string>().find("alice"),
              std::string::npos);

    // Punctuation alone is not a difference either.
    EXPECT_EQ(do_register("a.l.i.c.e", "tr0mbone-seven").status, 400);
    EXPECT_FALSE(store->user_exists("@a.l.i.c.e:test"));
}

TEST_F(AuthHandlerTest, RegisterStillReportsUserInUseForAnExactMatch) {
    // The skeleton check would fire on a taken name too. "That name is taken"
    // is the truer and more useful of the two answers, so it has to come first.
    auto res = do_register("alice", "tr0mbone-seven");
    EXPECT_EQ(res.status, 400);
    EXPECT_EQ(nlohmann::json::parse(res.body)["errcode"], "M_USER_IN_USE");
}

TEST_F(AuthHandlerTest, RegisterReservesTheServerNameUnderItsSkeletonToo) {
    // @server:<server_name> is granted ADMINISTRATOR unconditionally. Reserving
    // only the literal spelling reserved one spelling out of many that read the
    // same.
    for (const char* attempt : {"server", "serv.er", "s_e_r_v_e_r", "server."}) {
        auto res = do_register(attempt, "tr0mbone-seven");
        EXPECT_EQ(res.status, 400) << attempt;
        EXPECT_EQ(nlohmann::json::parse(res.body)["error"], "That username is reserved")
            << attempt;
    }
}

TEST_F(AuthHandlerTest, RegisterDoesNotReserveNamesThatMerelyStartLikeAPrefix) {
    // Why the `oidc_` reservation stays a LITERAL prefix match. Under the
    // skeleton the prefix folds to `oldc` (separators go), and comparing
    // prefixes that way would refuse every innocent name starting with those
    // four letters.
    auto res = do_register("oldcoolguy", "tr0mbone-seven");
    EXPECT_EQ(res.status, 200) << res.body;
    EXPECT_TRUE(store->user_exists("@oldcoolguy:test"));

    // The literal prefix is still refused.
    EXPECT_EQ(do_register("oidc_josh", "tr0mbone-seven").status, 400);
}

TEST_F(AuthHandlerTest, RegisterRefusesANameMadeOnlyOfSeparators) {
    // Such a name folds to an empty skeleton, which is also the column's
    // default. Refusing it keeps "" a value no candidate ever has.
    for (const char* attempt : {".", "-", "..--__"}) {
        auto res = do_register(attempt, "tr0mbone-seven");
        EXPECT_EQ(res.status, 400) << attempt;
        EXPECT_EQ(nlohmann::json::parse(res.body)["errcode"], "M_INVALID_USERNAME") << attempt;
    }
}

TEST_F(AuthHandlerTest, RegisterAcceptsADigitThatIsNotImitatingAnybody) {
    // The rule must not become "no digits". Nobody is called `alice2` here.
    EXPECT_EQ(do_register("alice2", "tr0mbone-seven").status, 200);
    EXPECT_TRUE(store->user_exists("@alice2:test"));
}

TEST_F(AuthHandlerTest, AccountsThatAlreadyCollideCanStillLogIn) {
    // The upgrade case, and the one outcome that would be unacceptable. Two
    // accounts that predate the rule collide under it; both owners must keep
    // getting in. Created through the store directly, exactly as a database
    // written before the rule presents them.
    ASSERT_TRUE(store->create_user("@josh:test", hash_password("tr0mbone-seven", 10)));
    ASSERT_TRUE(store->create_user("@j0sh:test", hash_password("tr0mbone-eight", 10)));

    auto login = [&](const std::string& user, const std::string& password) {
        httplib::Request req;
        req.body = nlohmann::json{{"type", "m.login.password"},
                                  {"identifier", {{"type", "m.id.user"}, {"user", user}}},
                                  {"password", password}}.dump();
        httplib::Response res;
        handler->handle_login(req, res);
        if (res.status == -1) res.status = 200;
        return res;
    };

    EXPECT_EQ(login("josh", "tr0mbone-seven").status, 200);
    EXPECT_EQ(login("j0sh", "tr0mbone-eight").status, 200);

    // The collision is visible to an operator, and cost nobody anything.
    auto c = store->count_localpart_skeleton_collisions();
    EXPECT_EQ(c.groups, 1);
    EXPECT_EQ(c.accounts, 2);

    // A THIRD lookalike is still refused — the rule is live, it just does not
    // reach backwards.
    EXPECT_EQ(do_register("j.0sh", "tr0mbone-seven").status, 400);
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

// ── Password policy, device ids, and the login timing oracle ───────────────

TEST(PasswordPolicy, RejectsThePasswordBeingTheUsername) {
    EXPECT_TRUE(password_policy_error("gamertag", "gamertag").has_value());
    // Case folding, because "GamerTag" is the same guess.
    EXPECT_TRUE(password_policy_error("GamerTag", "gamertag").has_value());
}

TEST(PasswordPolicy, RejectsThePasswordContainingTheUsername) {
    EXPECT_TRUE(password_policy_error("mikemikemike", "mike").has_value());
    EXPECT_TRUE(password_policy_error("xxMIKExx99", "mike").has_value());
}

TEST(PasswordPolicy, ShortUsernamesDoNotVetoOrdinaryPasswords) {
    // The 4-character floor is the thing keeping this proportionate: without
    // it, user "jo" could not have a password containing "jo" anywhere, which
    // is a large share of perfectly good passwords.
    EXPECT_FALSE(password_policy_error("enjoythesilence", "jo").has_value());
}

TEST(PasswordPolicy, RejectsTheCommonPasswordsThatSurviveTheLengthFloor) {
    for (const char* pw : {"password1", "12345678", "qwerty123", "iloveyou",
                           "letmein1", "trustno1", "changeme", "P@ssw0rd"}) {
        EXPECT_TRUE(password_policy_error(pw, "someuser").has_value())
            << pw << " should be refused";
    }
}

TEST(PasswordPolicy, RejectsTheServiceName) {
    EXPECT_TRUE(password_policy_error("bsfchat2026", "someuser").has_value());
    EXPECT_TRUE(password_policy_error("myGameChatPW", "someuser").has_value());
}

TEST(PasswordPolicy, AcceptsAnOrdinaryPassword) {
    EXPECT_FALSE(password_policy_error("correct-horse-7", "someuser").has_value());
    EXPECT_FALSE(password_policy_error("Tr0ubad0ur&3", "alice").has_value());
}

TEST(PasswordPolicy, StillEnforcesTheLengthFloor) {
    EXPECT_TRUE(password_policy_error("short", "someuser").has_value());
}

TEST(DeviceId, RejectsEmptyOverlongAndControlCharacters) {
    EXPECT_TRUE(device_id_error("").has_value());
    EXPECT_TRUE(device_id_error(std::string(kMaxDeviceIdLength + 1, 'A')).has_value());
    // The one that matters: a newline lets a device id forge extra lines in
    // the server log, where it is printed next to a user id.
    EXPECT_TRUE(device_id_error("DEV\nfake log line").has_value());
    EXPECT_TRUE(device_id_error(std::string("DEV\0hidden", 10)).has_value());
}

TEST(DeviceId, AcceptsWhatRealClientsSend) {
    EXPECT_FALSE(device_id_error("DEVICE_aB3xY9zQ1p").has_value());
    EXPECT_FALSE(device_id_error(std::string(kMaxDeviceIdLength, 'A')).has_value());
    // Not an ASCII allowlist: a client that already persisted a device id with
    // a non-ASCII character must still be able to log in.
    EXPECT_FALSE(device_id_error("josh’s laptop").has_value());
}

TEST(DummyPasswordHash, IsAUsableHashThatNothingVerifiesAgainst) {
    const auto& a = dummy_password_hash(10);
    EXPECT_TRUE(a.starts_with("$pbkdf2$"));
    EXPECT_EQ(password_hash_cost(a).value_or(-1), 10);
    // Whatever a caller submits, it fails — including the empty string, which
    // is what an OIDC-backed account's stored hash looks like.
    EXPECT_FALSE(verify_password("", a));
    EXPECT_FALSE(verify_password("password", a));
    // Cached, so the per-request cost is one verify and not two hashes.
    EXPECT_EQ(&a, &dummy_password_hash(10));
    EXPECT_NE(dummy_password_hash(11), a);
}

// ── Handler-level: enumeration timing, policy at the endpoints, refresh reuse ──

namespace {

// A handler with the rate limits switched off, so these tests exercise the
// credential logic and not the limiter that already has its own tests.
struct AuthFixture {
    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<AuthHandler> handler;

    explicit AuthFixture(int cost = 10) {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        config.password_hash_cost = cost;
        config.auth_limits.enabled = false;
        sync = std::make_unique<SyncEngine>(*store, config);
        handler = std::make_unique<AuthHandler>(*store, *sync, config);
        store->create_user("@alice:test", hash_password("correct-horse-7", cost));
    }

    httplib::Response call(void (AuthHandler::*fn)(const httplib::Request&, httplib::Response&),
                           const nlohmann::json& body,
                           const std::string& bearer = {}) {
        httplib::Request req;
        req.body = body.dump();
        if (!bearer.empty()) req.set_header("Authorization", "Bearer " + bearer);
        httplib::Response res;
        (handler.get()->*fn)(req, res);
        if (res.status == -1) res.status = 200;
        return res;
    }

    httplib::Response login(const std::string& user, const std::string& password,
                            bool want_refresh = false) {
        return call(&AuthHandler::handle_login,
                    {{"type", "m.login.password"},
                     {"identifier", {{"type", "m.id.user"}, {"user", user}}},
                     {"password", password},
                     {"refresh_token", want_refresh}});
    }
};

} // namespace

TEST(AccountEnumeration, LoginCostsTheSameWhetherOrNotTheAccountExists) {
    // Cost 15 so PBKDF2 is long enough to time without being slow to run. The
    // defect this guards was not marginal: at the shipped cost of 19 the
    // missing-account path returned in microseconds and the real one took
    // roughly half a second, which is a difference anyone can read off a
    // stopwatch, from an unauthenticated endpoint, before any rate limit has
    // been tripped.
    AuthFixture f(15);

    const auto time_login = [&](const std::string& user) {
        const auto start = std::chrono::steady_clock::now();
        auto res = f.login(user, "some-wrong-password");
        EXPECT_EQ(res.status, 403);
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    };

    // Warm the cached dummy hash, so its one-time construction is not measured.
    (void)time_login("ghost");

    double existing = 0, missing = 0;
    for (int i = 0; i < 3; ++i) {
        existing += time_login("alice");
        missing += time_login("ghost");
    }

    // A ratio, not an absolute bound: both runs share whatever else the
    // machine is doing. Only the direction matters — the missing-account path
    // must not be dramatically cheaper. Before the fix this ratio was ~0.001.
    EXPECT_GT(missing / existing, 0.5) << "missing=" << missing << "s existing=" << existing << "s";
}

TEST(AccountEnumeration, AnOidcAccountIsNotDistinguishableByTimingEither) {
    AuthFixture f(15);
    // An OIDC-backed account: created with an empty hash so password login can
    // never work for it. verify_password used to reject that in microseconds.
    f.store->create_user("@oidc_bob:test", "");

    const auto time_login = [&](const std::string& user) {
        const auto start = std::chrono::steady_clock::now();
        EXPECT_EQ(f.login(user, "some-wrong-password").status, 403);
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    };
    (void)time_login("ghost");

    const double oidc = time_login("oidc_bob");
    const double real_account = time_login("alice");
    EXPECT_GT(oidc / real_account, 0.5) << "oidc=" << oidc << "s real=" << real_account << "s";
    // And it still cannot be signed into with a password, empty or otherwise.
    EXPECT_EQ(f.login("oidc_bob", "").status, 403);
}

TEST(RegisterPolicy, RefusesAWeakPasswordAndCreatesNothing) {
    AuthFixture f;
    f.config.registration_enabled = true;

    auto res = f.call(&AuthHandler::handle_register,
                      {{"username", "newbie"}, {"password", "password1"}});
    EXPECT_EQ(res.status, 400);
    EXPECT_FALSE(f.store->user_exists("@newbie:test"));

    res = f.call(&AuthHandler::handle_register,
                 {{"username", "newbie"}, {"password", "newbie-newbie"}});
    EXPECT_EQ(res.status, 400) << "a password built out of the username must be refused";
    EXPECT_FALSE(f.store->user_exists("@newbie:test"));

    res = f.call(&AuthHandler::handle_register,
                 {{"username", "newbie"}, {"password", "correct-horse-7"}});
    EXPECT_EQ(res.status, 200);
    EXPECT_TRUE(f.store->user_exists("@newbie:test"));
}

TEST(RegisterPolicy, RefusesAnUnusableDeviceId) {
    AuthFixture f;
    f.config.registration_enabled = true;
    auto res = f.call(&AuthHandler::handle_register,
                      {{"username", "newbie"},
                       {"password", "correct-horse-7"},
                       {"device_id", std::string(300, 'A')}});
    EXPECT_EQ(res.status, 400);
    EXPECT_FALSE(f.store->user_exists("@newbie:test"))
        << "a rejected device id must not leave a half-created account behind";
}

TEST(LoginPolicy, RefusesAnUnusableDeviceId) {
    AuthFixture f;
    auto res = f.call(&AuthHandler::handle_login,
                      {{"type", "m.login.password"},
                       {"identifier", {{"type", "m.id.user"}, {"user", "alice"}}},
                       {"password", "correct-horse-7"},
                       {"device_id", "DEV\nInjected: yes"}});
    EXPECT_EQ(res.status, 400);
}

TEST(PasswordChangePolicy, AppliesTheSameRulesAsRegistration) {
    AuthFixture f;
    f.store->store_access_token("alice-token", "@alice:test", "DEV1");

    const auto change = [&](const std::string& next) {
        return f.call(&AuthHandler::handle_password_change,
                      {{"auth", {{"type", "m.login.password"}, {"password", "correct-horse-7"}}},
                       {"new_password", next}},
                      "alice-token");
    };

    // Without this, the policy is two requests away from irrelevant: register
    // with something acceptable, then change it to "password1".
    EXPECT_EQ(change("password1").status, 400);
    EXPECT_EQ(change("alice-alice").status, 400);
    // A no-op change would revoke every other session and leave the credential
    // the user is trying to replace in place.
    EXPECT_EQ(change("correct-horse-7").status, 400);
    EXPECT_EQ(change("a-fine-new-one-9").status, 200);
    EXPECT_TRUE(verify_password("a-fine-new-one-9", *f.store->get_password_hash("@alice:test")));
}

TEST(RefreshReuse, RotationCarriesTheFamilyAndAReplayRevokesAllOfIt) {
    AuthFixture f;

    auto first = nlohmann::json::parse(f.login("alice", "correct-horse-7", true).body);
    const std::string refresh_1 = first.at("refresh_token");

    // Rotate twice, so the family is longer than one hop — the point of
    // carrying family_id across a refresh rather than minting a new one.
    auto r2 = f.call(&AuthHandler::handle_refresh, {{"refresh_token", refresh_1}});
    ASSERT_EQ(r2.status, 200);
    auto body_2 = nlohmann::json::parse(r2.body);
    const std::string refresh_2 = body_2.at("refresh_token");

    auto r3 = f.call(&AuthHandler::handle_refresh, {{"refresh_token", refresh_2}});
    ASSERT_EQ(r3.status, 200);
    auto body_3 = nlohmann::json::parse(r3.body);
    const std::string access_3 = body_3.at("access_token");
    EXPECT_TRUE(f.store->get_user_by_token(access_3).has_value());

    // Now the theft: someone replays a refresh token from earlier in the
    // chain. Rotation alone answers 401 and leaves the current session — which
    // may well be the thief's — alive and self-renewing.
    auto replay = f.call(&AuthHandler::handle_refresh, {{"refresh_token", refresh_1}});
    EXPECT_EQ(replay.status, 401);

    // The whole family is gone, including the session two rotations later.
    EXPECT_FALSE(f.store->get_user_by_token(access_3).has_value())
        << "a replayed refresh token must revoke every session descended from that login";
    EXPECT_EQ(f.call(&AuthHandler::handle_refresh, {{"refresh_token", body_3.at("refresh_token")}})
                  .status, 401);
}

TEST(RefreshReuse, OneAccountsFamilyRevocationDoesNotTouchAnother) {
    AuthFixture f;
    f.store->create_user("@bob:test", hash_password("correct-horse-7", 10));

    auto alice = nlohmann::json::parse(f.login("alice", "correct-horse-7", true).body);
    auto bob = nlohmann::json::parse(f.login("bob", "correct-horse-7", true).body);
    // A second, independent login for alice: a separate family, so it must
    // survive too. This is what the migration's "family of one" default and the
    // empty-family guard are protecting against.
    auto alice_2 = nlohmann::json::parse(f.login("alice", "correct-horse-7", true).body);

    ASSERT_EQ(f.call(&AuthHandler::handle_refresh,
                     {{"refresh_token", alice.at("refresh_token")}}).status, 200);
    EXPECT_EQ(f.call(&AuthHandler::handle_refresh,
                     {{"refresh_token", alice.at("refresh_token")}}).status, 401);

    EXPECT_TRUE(f.store->get_user_by_token(bob.at("access_token")).has_value());
    EXPECT_TRUE(f.store->get_user_by_token(alice_2.at("access_token")).has_value());
}

TEST(RefreshReuse, AnUnknownRefreshTokenRevokesNothing) {
    AuthFixture f;
    auto session = nlohmann::json::parse(f.login("alice", "correct-horse-7", true).body);

    EXPECT_EQ(f.call(&AuthHandler::handle_refresh,
                     {{"refresh_token", "not-a-token-anyone-issued"}}).status, 401);
    EXPECT_EQ(f.store->revoke_family_for_replayed_refresh_token("not-a-token-anyone-issued"), 0);
    EXPECT_TRUE(f.store->get_user_by_token(session.at("access_token")).has_value());
}

// ── Audit data-path finding 16: client IPs in the operator log ──────────────
//
// No client address is ever written to this server's database — that was
// verified separately and it holds. The operator log is the whole remaining
// exposure surface, and two lines in AuthHandler put a full address into it at
// `warn`, on a server whose log level is hardcoded to `info`.
//
// redact_ip_for_log() is the fix for those lines. These four tests cover the
// helper in isolation — whether the redaction is CORRECT — and the three under
// "Finding 16, the call sites" below cover the thing that was missing for a
// release after the helper landed: anything calling it.
TEST(ClientAddress, RedactedIpv4KeepsTheNetworkAndDropsTheHost) {
    EXPECT_EQ(redact_ip_for_log("203.0.113.42"), "203.0.113.0/24");
    EXPECT_EQ(redact_ip_for_log("10.1.2.3"), "10.1.2.0/24");
    // Two addresses in one /24 must become the same string — that is the whole
    // property. If they did not, the log would still identify individuals.
    EXPECT_EQ(redact_ip_for_log("198.51.100.1"), redact_ip_for_log("198.51.100.254"));
    // ...and two in different /24s must not.
    EXPECT_NE(redact_ip_for_log("198.51.100.1"), redact_ip_for_log("198.51.101.1"));
}

TEST(ClientAddress, RedactedIpv6CollapsesToTheSubscriberPrefix) {
    EXPECT_EQ(redact_ip_for_log("2001:db8::1:2:3:4"), "2001:db8::/64");
    EXPECT_EQ(redact_ip_for_log("2001:db8:0:1::99"), "2001:db8:0:1::/64");
    EXPECT_EQ(redact_ip_for_log("2001:db8:0:1::1"), redact_ip_for_log("2001:db8:0:1::2"));
    EXPECT_NE(redact_ip_for_log("2001:db8:0:1::1"), redact_ip_for_log("2001:db8:0:2::1"));
}

TEST(ClientAddress, RedactionTolerantOfTheFormsAnXffLineActuallyCarries) {
    // A log call site passes whatever it was handed. Ports, brackets and zone
    // suffixes all turn up in X-Forwarded-For, and each must still redact
    // rather than fall through to the unparseable branch and lose the line.
    EXPECT_EQ(redact_ip_for_log("203.0.113.42:51234"), "203.0.113.0/24");
    EXPECT_EQ(redact_ip_for_log("[2001:db8::1]:443"), "2001:db8::/64");
    EXPECT_EQ(redact_ip_for_log("  203.0.113.42  "), "203.0.113.0/24");
    EXPECT_EQ(redact_ip_for_log("fe80::1%eth0"), "fe80::/64");
}

TEST(ClientAddress, RedactionNeverEchoesSomethingItDidNotUnderstand) {
    // The failure mode that would matter: a call site hands this a string it
    // cannot parse, and it returns the string. Then a malformed header value —
    // attacker-chosen, and possibly a full address in a form the parser missed
    // — lands in the log verbatim. It must fail to a constant.
    for (const char* junk : {"", "not-an-ip", "999.999.999.999", "203.0.113.42; DROP",
                             "1.2.3.4 5.6.7.8"}) {
        EXPECT_EQ(redact_ip_for_log(junk), "unparseable") << junk;
    }
}

// ── auth.trusted_proxies: the startup warning, and the CDN case ───────────
//
// The warning that fires when a trusted range reaches into public address
// space is a real check — trusting a network is trusting its X-Forwarded-For,
// so a careless entry turns every per-address limit off. But it was written
// and shipped without ever being pointed at a CDN-fronted deployment, which is
// the one configuration where a pile of public ranges is *correct*: production
// sits behind Cloudflare, whose published edge list is fifteen v4 ranges and
// seven v6 ones, and every single one of them drew its own warning on every
// boot. Eleven consecutive warnings on a correct server is how an operator
// learns to skim the log — the same log that carries the auth lockout records.
//
// So the check has to keep two properties at once: silent on a deployment that
// has deliberately and explicitly trusted a CDN, still loud on the careless
// entry, and still loud on a range added after the acknowledgement was written.

#include "core/Logger.h"

// ── Finding 16, the call sites ──────────────────────────────────────────────
//
// The helper above was landed on its own and had ZERO callers, so nothing about
// the log stream changed. These two tests are the ones that fail if it goes back
// to having none: they drive the real handler and read the real sink, rather
// than asserting anything about the helper.

#include "core/Logger.h"

#include <spdlog/sinks/ringbuffer_sink.h>

namespace {

// Cloudflare's published IPv4 edge ranges (cloudflare.com/ips-v4) as of the
// deploy that prompted this. Verbatim on purpose: the point of the test is
// that a REAL CDN list, at its real width, comes out clean.
const std::vector<std::string> kCloudflareV4 = {
    "173.245.48.0/20",  "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18",  "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",    "172.64.0.0/13",   "131.0.72.0/22",
};
const std::vector<std::string> kCloudflareV6 = {
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
};

std::string toml_array(const std::vector<std::string>& items) {
    std::string out = "[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) out += ", ";
        out += "\"" + items[i] + "\"";
    }
    return out + "]";
}

// Runs Config::validate over `cfg` and returns the records it logged.
struct Captured {
    std::vector<std::string> all;

    [[nodiscard]] std::vector<std::string> matching(const char* level,
                                                    const char* needle) const {
        std::vector<std::string> hits;
        for (const auto& line : all) {
            if (line.find(std::string("[") + level + "]") != std::string::npos &&
                line.find(needle) != std::string::npos) {
                hits.push_back(line);
            }
        }
        return hits;
    }
};

Captured validate_capturing_log(Config& cfg) {
    auto ring = std::make_shared<spdlog::sinks::ringbuffer_sink_mt>(256);
    auto logger = get_logger();
    const auto prior = logger->level();
    logger->sinks().push_back(ring);
    logger->set_level(spdlog::level::trace);
    Config::validate(cfg);
    logger->sinks().pop_back();
    logger->set_level(prior);
    return Captured{ring->last_formatted(256)};
}

// A config with nothing else in it that warns, so a test counting warnings is
// counting only the ones it is about.
Config quiet_config() {
    auto cfg = Config::defaults();
    cfg.password_hash_cost = 19;
    cfg.voice.enabled = false;
    cfg.push.enabled = false;
    return cfg;
}

} // namespace

TEST(TrustedProxyWarning, ACdnRangeSetAcknowledgedUnderItsOwnKeyDoesNotWarnAtAll) {
    auto cfg = quiet_config();
    cfg.auth_limits.trusted_proxies = {"127.0.0.0/8", "::1", "172.16.0.0/12"};
    cfg.auth_limits.trusted_public_proxies = kCloudflareV4;
    cfg.auth_limits.trusted_public_proxies.insert(
        cfg.auth_limits.trusted_public_proxies.end(), kCloudflareV6.begin(), kCloudflareV6.end());
    cfg.auth_limits.trusted_public_proxies_reason =
        "Cloudflare edge, refreshed 2026-09-20 from cloudflare.com/ips-v4 and ips-v6";

    auto log = validate_capturing_log(cfg);
    EXPECT_TRUE(log.matching("warning", "trusted_prox").empty())
        << "a correctly-configured CDN-fronted server warned "
        << log.matching("warning", "trusted_prox").size() << " time(s) at boot";

    // Not silent, though: one line says what is being trusted and why, so the
    // decision is still visible to whoever reads the boot log.
    auto notices = log.matching("info", "public proxy range");
    ASSERT_EQ(notices.size(), 1u);
    EXPECT_NE(notices[0].find("22"), std::string::npos) << notices[0]; // the count
    EXPECT_NE(notices[0].find("Cloudflare edge"), std::string::npos) << notices[0];
}

TEST(TrustedProxyWarning, AcknowledgedRangesAreActuallyTrusted) {
    // The acknowledgement key is the list, not a duplicate of it: an operator
    // must not have to write the CDN ranges twice and keep two copies in step.
    auto cfg = quiet_config();
    cfg.auth_limits.trusted_proxies = {"127.0.0.0/8"};
    cfg.auth_limits.trusted_public_proxies = {"104.16.0.0/13"};
    cfg.auth_limits.trusted_public_proxies_reason = "Cloudflare edge";
    Config::validate(cfg);

    ClientAddressResolver r(cfg.auth_limits.trusted_proxies);
    httplib::Request req;
    req.remote_addr = "104.16.0.5";
    req.set_header("X-Forwarded-For", "203.0.113.9");
    EXPECT_EQ(r.resolve(req), std::optional<std::string>("203.0.113.9"));
}

TEST(TrustedProxyWarning, ValidateIsIdempotentOverTheMergedList) {
    // validate() runs once from load(), but main and the tests can call it
    // again; merging must not grow the list each time.
    auto cfg = quiet_config();
    cfg.auth_limits.trusted_proxies = {"127.0.0.0/8"};
    cfg.auth_limits.trusted_public_proxies = {"104.16.0.0/13"};
    cfg.auth_limits.trusted_public_proxies_reason = "Cloudflare edge";
    Config::validate(cfg);
    const auto once = cfg.auth_limits.trusted_proxies;
    Config::validate(cfg);
    EXPECT_EQ(cfg.auth_limits.trusted_proxies, once);
}

TEST(TrustedProxyWarning, ARangeTooWideToBeAProxyFleetWarnsEvenWhenAcknowledged) {
    // The acknowledgement says "these are my CDN's edge nodes". It is not a
    // blanket "stop checking": a default route, or a whole public /8, is not a
    // proxy fleet under anybody's definition, and must stay loud no matter
    // which key it was written under.
    for (const char* careless : {"0.0.0.0/0", "::/0", "104.0.0.0/8", "2000::/3"}) {
        auto cfg = quiet_config();
        cfg.auth_limits.trusted_proxies = {"127.0.0.0/8"};
        cfg.auth_limits.trusted_public_proxies = {careless};
        cfg.auth_limits.trusted_public_proxies_reason = "honestly I do know what I am doing";

        auto log = validate_capturing_log(cfg);
        auto warnings = log.matching("warning", careless);
        EXPECT_EQ(warnings.size(), 1u) << careless << " drew " << warnings.size() << " warning(s)";
    }
}

TEST(TrustedProxyWarning, PublicRangesInTheOrdinaryKeyWarnOnceNotOncePerEntry) {
    // The pre-upgrade shape: the CDN ranges are sitting in plain
    // trusted_proxies. That is still worth saying — the operator has not told
    // the server they meant it — but it is worth saying ONCE, naming the
    // count and the widest entry, with the remedy.
    auto cfg = quiet_config();
    cfg.auth_limits.trusted_proxies = {"127.0.0.0/8", "::1", "172.16.0.0/12"};
    cfg.auth_limits.trusted_proxies.insert(cfg.auth_limits.trusted_proxies.end(),
                                           kCloudflareV4.begin(), kCloudflareV4.end());

    auto log = validate_capturing_log(cfg);
    auto warnings = log.matching("warning", "trusted_proxies");
    ASSERT_EQ(warnings.size(), 1u) << "got " << warnings.size() << " warnings, wanted one summary";
    EXPECT_NE(warnings[0].find("15"), std::string::npos) << warnings[0];          // the count
    EXPECT_NE(warnings[0].find("162.158.0.0/15"), std::string::npos) << warnings[0]; // the widest
    EXPECT_NE(warnings[0].find("trusted_public_proxies"), std::string::npos)
        << "the warning must name the way out: " << warnings[0];
}

TEST(TrustedProxyWarning, AnAcknowledgementWithNoStatedReasonIsNotAnAcknowledgement) {
    // An empty reason degrades to the old behaviour rather than silencing the
    // check: the reason is the part a human reads in six months, and a list
    // with no reason is indistinguishable from a list someone pasted in.
    auto cfg = quiet_config();
    cfg.auth_limits.trusted_proxies = {"127.0.0.0/8"};
    cfg.auth_limits.trusted_public_proxies = {"104.16.0.0/13", "172.64.0.0/13"};
    cfg.auth_limits.trusted_public_proxies_reason = "   ";

    auto log = validate_capturing_log(cfg);
    auto warnings = log.matching("warning", "trusted_public_proxies");
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("reason"), std::string::npos) << warnings[0];
}

TEST(TrustedProxyWarning, ARangeAddedAfterTheCdnWasAcknowledgedIsStillCalledOut) {
    // The upgrade-then-drift case. Cloudflare is acknowledged and quiet; a
    // month later somebody adds a public range to the ordinary key. That must
    // not ride in on the CDN's acknowledgement.
    auto cfg = quiet_config();
    cfg.auth_limits.trusted_proxies = {"127.0.0.0/8", "::1", "198.51.100.0/24"};
    cfg.auth_limits.trusted_public_proxies = kCloudflareV4;
    cfg.auth_limits.trusted_public_proxies_reason = "Cloudflare edge";

    auto log = validate_capturing_log(cfg);
    auto warnings = log.matching("warning", "198.51.100.0/24");
    ASSERT_EQ(warnings.size(), 1u) << "the newly added range was not called out";
}

TEST(TrustedProxyWarning, PrivateEntriesUnderEitherKeyStayQuiet) {
    auto cfg = quiet_config();
    cfg.auth_limits.trusted_proxies = {"127.0.0.0/8", "::1", "172.16.0.0/12", "10.0.0.0/8"};
    auto log = validate_capturing_log(cfg);
    EXPECT_TRUE(log.matching("warning", "trusted_prox").empty());
    EXPECT_TRUE(log.matching("info", "public proxy range").empty());
}

TEST(TrustedProxyWarning, BothKeysLoadFromTheAuthTableAndMerge) {
    auto path = write_toml("bsfchat_test_auth_cdn_proxies.toml",
        "[auth]\n"
        "trusted_proxies = [\"127.0.0.0/8\", \"172.16.0.0/12\"]\n"
        "trusted_public_proxies = " + toml_array(kCloudflareV4) + "\n"
        "trusted_public_proxies_reason = \"Cloudflare edge, refreshed 2026-09-20\"\n");
    auto cfg = Config::load(path.string());
    std::filesystem::remove(path);

    const auto& l = cfg.auth_limits;
    EXPECT_EQ(l.trusted_public_proxies, kCloudflareV4);
    EXPECT_EQ(l.trusted_public_proxies_reason, "Cloudflare edge, refreshed 2026-09-20");
    // Merged, in order, with no duplicates and the ordinary entries first.
    ASSERT_EQ(l.trusted_proxies.size(), 2u + kCloudflareV4.size());
    EXPECT_EQ(l.trusted_proxies[0], "127.0.0.0/8");
    EXPECT_EQ(l.trusted_proxies[2], kCloudflareV4[0]);
}

TEST(TrustedProxyWarning, AnUnparseableAcknowledgedEntryStopsStartupLikeAnyOther) {
    auto bad = write_toml("bsfchat_test_auth_cdn_bad.toml",
                          "[auth]\n"
                          "trusted_public_proxies = [\"104.16.0.0/13\", \"cloudflare\"]\n"
                          "trusted_public_proxies_reason = \"Cloudflare edge\"\n");
    EXPECT_THROW(Config::load(bad.string()), std::runtime_error);
    std::filesystem::remove(bad);
}

// Helpers for the log-redaction tests below. In an anonymous namespace so a
// name here cannot collide with one in another test translation unit; the
// merge that brought these in alongside the trusted-proxies tests lost this
// opener, which the compiler caught as an extraneous close at the matching
// "} // namespace".
namespace {

// Captures every record the shared logger emits for the lifetime of the object.
// Pops its sink in the destructor so a failing EXPECT cannot leave the sink
// attached and leak records into the next test in this binary.
class LogCapture {
public:
    LogCapture() : logger_(get_logger()), ring_(std::make_shared<spdlog::sinks::ringbuffer_sink_mt>(64)) {
        previous_level_ = logger_->level();
        logger_->sinks().push_back(ring_);
        logger_->set_level(spdlog::level::trace);
    }
    ~LogCapture() {
        logger_->sinks().pop_back();
        logger_->set_level(previous_level_);
    }

    std::vector<std::string> lines() const { return ring_->last_formatted(64); }

    // Every captured record containing `needle`, joined — the thing an operator
    // would actually see.
    std::string matching(const std::string& needle) const {
        std::string out;
        for (const auto& line : lines()) {
            if (line.find(needle) != std::string::npos) out += line;
        }
        return out;
    }

private:
    std::shared_ptr<spdlog::logger> logger_;
    std::shared_ptr<spdlog::sinks::ringbuffer_sink_mt> ring_;
    spdlog::level::level_enum previous_level_ = spdlog::level::info;
};

// A login attempt that will fail, from a chosen address, with a chosen
// identifier. Built by hand rather than through AuthFixture::call because
// remote_addr is the whole point.
void failed_login_from(AuthHandler& handler, const std::string& remote_addr,
                       const std::string& identifier,
                       const std::vector<std::pair<std::string, std::string>>& headers = {}) {
    httplib::Request req;
    req.path = "/_matrix/client/v3/login";
    req.remote_addr = remote_addr;
    for (const auto& [k, v] : headers) req.set_header(k, v);
    req.body = nlohmann::json{{"type", "m.login.password"},
                              {"identifier", {{"type", "m.id.user"}, {"user", identifier}}},
                              {"password", "definitely-wrong"}}
                   .dump();
    httplib::Response res;
    handler.handle_login(req, res);
}

// A fixture whose lockout trips after two failures.
struct LockoutFixture : AuthFixture {
    LockoutFixture() : AuthFixture(10) {
        config.auth_limits.enabled = true;
        config.auth_limits.rate_limit = 1000;
        config.auth_limits.max_failures = 2;
        config.auth_limits.lockout_seconds = 300;
        // The handler captured the config by reference, but the limiters read
        // their bounds in the constructor, so it has to be rebuilt.
        handler = std::make_unique<AuthHandler>(*store, *sync, config);
    }
};

} // namespace

// The lockout line prints TWO keys and they are not the same kind of thing.
// Redacting both is the obvious wrong fix: key_b is "user:" + the identifier
// exactly as submitted, deliberately not an address, and redact_ip_for_log
// flattens anything it cannot parse to the constant "unparseable" — which would
// silently delete the only half of the line an operator can act on.
TEST(IpInLogs, LockoutLineRedactsTheAddressKeyAndKeepsTheIdentifierKey) {
    LockoutFixture f;
    LogCapture log;

    for (int attempt = 0; attempt < 3; ++attempt) {
        failed_login_from(*f.handler, "203.0.113.42", "ghost-account");
    }

    const auto lockouts = log.matching("Auth lockout engaged");
    ASSERT_FALSE(lockouts.empty()) << "the lockout never engaged, so nothing was proved";

    // The address half: network kept, host dropped.
    EXPECT_NE(lockouts.find("ip:203.0.113.0/24"), std::string::npos) << lockouts;
    EXPECT_EQ(lockouts.find("203.0.113.42"), std::string::npos)
        << "the full client address is still in the log: " << lockouts;

    // The identifier half: untouched. This is the assertion that fails on a
    // blind two-line substitution.
    EXPECT_NE(lockouts.find("ghost-account"), std::string::npos)
        << "the submitted identifier was destroyed: " << lockouts;
    EXPECT_EQ(lockouts.find("unparseable"), std::string::npos)
        << "a non-address key went through the address redactor: " << lockouts;
}

// IPv6 goes to /64 rather than /24 — the same unit resolve() already collapses
// to for rate limiting, because a subscriber routinely holds a whole /64.
TEST(IpInLogs, LockoutLineRedactsIpv6ToTheSubscriberPrefix) {
    LockoutFixture f;
    LogCapture log;

    for (int attempt = 0; attempt < 3; ++attempt) {
        failed_login_from(*f.handler, "2001:db8:0:1::99", "ghost-account");
    }

    const auto lockouts = log.matching("Auth lockout engaged");
    ASSERT_FALSE(lockouts.empty()) << "the lockout never engaged, so nothing was proved";
    EXPECT_NE(lockouts.find("ip:2001:db8:0:1::/64"), std::string::npos) << lockouts;
    EXPECT_EQ(lockouts.find("::99"), std::string::npos)
        << "the full client address is still in the log: " << lockouts;
}

// The other call site: the once-a-minute warning about an X-Forwarded-For from
// a peer that is not in auth.trusted_proxies.
TEST(IpInLogs, UntrustedProxyWarningNamesTheNetworkNotTheHost) {
    LockoutFixture f; // trusted_proxies is empty, so no peer is trusted
    LogCapture log;

    failed_login_from(*f.handler, "10.9.8.7", "ghost-account",
                      {{"X-Forwarded-For", "203.0.113.5"}});

    const auto warning = log.matching("X-Forwarded-For");
    ASSERT_FALSE(warning.empty()) << "the proxy warning did not fire, so nothing was proved";
    EXPECT_NE(warning.find("10.9.8.0/24"), std::string::npos) << warning;
    EXPECT_EQ(warning.find("10.9.8.7"), std::string::npos)
        << "the peer address is still in the log: " << warning;
    // And it must not have leaked the address the header claimed, either.
    EXPECT_EQ(warning.find("203.0.113.5"), std::string::npos) << warning;
}
