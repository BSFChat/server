// Account linking: one human, one account.
//
// THE PROBLEM, from production. One person owns `@josh:chat.bsfchat.com`
// (password, holds admin), `@oidc_a5cdbefe-…` (display name "josh") and
// `@oidc_76ea6af7-…` (display name "joshb"). Three accounts, one human, no
// relationship between them, and nothing in the client that says they are
// distinct. Roles, DMs and history do not follow the person — which is how the
// owner of the server ended up signed in as an account with no permissions.
//
// THE ACCEPTANCE CRITERION: after linking, signing in with the identity
// provider lands in the EXISTING account, with its roles and its history,
// instead of minting or reusing a parallel one.
//
// THE SECURITY CRITERION, which is the larger half of this file: linking
// requires proof of BOTH sides in the same request. Asserting an identity —
// naming a subject, presenting a token this server cannot verify, presenting
// somebody else's valid token without their session — must attach nothing. A
// version of this feature that took the caller's word for which identity they
// are would let the first person who guessed the owner's subject inherit the
// owner's account, and it would pass a test that only checked the happy path.
//
// The fixture stands up a real identity provider on loopback — RSA keypair,
// discovery document, JWKS — so every token here is signed and verified the
// way a real one is, and "an invalid token" means invalid to the real
// verifier rather than to a stub.

#include <gtest/gtest.h>

#include "api/AuthHandler.h"
#include "audit/AuditLog.h"
#include "auth/LocalAuth.h"
#include "auth/OidcAuth.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/JwtUtils.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

// httplib leaves status at -1 until a handler writes one; a handler that
// succeeded without setting it never touches it.
int status_of(const httplib::Response& res) { return res.status < 0 ? 200 : res.status; }

class AccountLinkTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto [priv, pub] = generate_rsa_keypair();
        private_pem = priv;

        // A SECOND keypair the provider never publishes. This is what makes
        // "an attacker asserts an identity" testable: a token that is
        // well-formed, carries the right issuer, audience and subject, and is
        // signed by a key this server has no reason to trust.
        auto [rogue_priv, rogue_pub] = generate_rsa_keypair();
        rogue_pem = rogue_priv;
        (void)rogue_pub;

        provider.Get("/.well-known/openid-configuration",
                     [this](const httplib::Request&, httplib::Response& res) {
            res.set_content(json{{"issuer", issuer()},
                                 {"jwks_uri", issuer() + "/jwks.json"}}.dump(),
                            "application/json");
        });
        provider.Get("/jwks.json", [pub](const httplib::Request&, httplib::Response& res) {
            res.set_content(json{{"keys", json::array({pem_to_jwk(pub, "test-key-1")})}}.dump(),
                            "application/json");
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
        id.required = false;
        id.allow_local_accounts = true;  // the mixed deployment: both flows live
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

    std::string issuer() const { return "http://127.0.0.1:" + std::to_string(port); }

    std::string id_token_for(const std::string& subject,
                             const std::optional<std::string>& name = std::nullopt,
                             bool sign_with_rogue_key = false) {
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        JwtClaims claims;
        claims.sub = subject;
        claims.iss = issuer();
        claims.aud = "bsfchat-server";
        claims.iat = now;
        claims.exp = now + 600;
        claims.name = name;
        return jwt_sign(claims, sign_with_rogue_key ? rogue_pem : private_pem, "test-key-1");
    }

    httplib::Response login_with_identity(const std::string& subject,
                                          const std::optional<std::string>& name = std::nullopt) {
        httplib::Request req;
        req.body = json{{"type", "m.login.token"}, {"token", id_token_for(subject, name)}}.dump();
        httplib::Response res;
        handler->handle_login(req, res);
        return res;
    }

    // The local, password-backed account the person wants to keep — the one
    // holding admin on production.
    std::string create_local_account(const std::string& localpart, const std::string& token,
                                     const std::vector<std::string>& roles = {}) {
        const std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("tr0mbone-seven", 10));
        store->store_access_token(token, uid, "dev");
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    httplib::Response link(const std::string& bearer, const std::string& body) {
        httplib::Request req;
        if (!bearer.empty()) req.set_header("Authorization", "Bearer " + bearer);
        req.body = body;
        httplib::Response res;
        handler->handle_link_identity(req, res);
        return res;
    }

    httplib::Response link_token(const std::string& bearer, const std::string& id_token) {
        return link(bearer, json{{"type", "m.login.token"}, {"token", id_token}}.dump());
    }

    httplib::Response linked_identities(const std::string& bearer) {
        httplib::Request req;
        if (!bearer.empty()) req.set_header("Authorization", "Bearer " + bearer);
        httplib::Response res;
        handler->handle_linked_identities(req, res);
        return res;
    }

    static bool has_role(const std::vector<std::string>& ids, const std::string& want) {
        return std::find(ids.begin(), ids.end(), want) != ids.end();
    }

    std::string logged_in_user(const httplib::Response& res) {
        return json::parse(res.body)["user_id"].get<std::string>();
    }

    httplib::Server provider;
    std::thread serving;
    int port = 0;
    std::string private_pem;
    std::string rogue_pem;
    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
    std::unique_ptr<OidcAuth> oidc;
    std::unique_ptr<AuthHandler> handler;
};

} // namespace

// ── The acceptance criterion ──────────────────────────────────────────────

TEST_F(AccountLinkTest, AfterLinkingTheIdentitySignsInAsTheExistingAccount) {
    const auto josh = create_local_account("josh", "josh-token",
                                           {std::string(permission::role_id::kAdmin)});

    auto linked = link_token("josh-token", id_token_for("a5cdbefe"));
    ASSERT_EQ(status_of(linked), 200) << linked.body;

    auto res = login_with_identity("a5cdbefe");
    ASSERT_EQ(status_of(res), 200) << res.body;

    // THE POINT. Not a new @oidc_a5cdbefe:test account — the one the person
    // already had, with the role that made them the owner of this server.
    EXPECT_EQ(logged_in_user(res), josh);
    EXPECT_TRUE(has_role(store->get_member_role_ids(josh),
                         std::string(permission::role_id::kAdmin)));
    EXPECT_FALSE(store->user_exists("@oidc_a5cdbefe:test"))
        << "a parallel account was created anyway";
}

TEST_F(AccountLinkTest, AnUnlinkedIdentityStillGetsItsOwnAccountExactlyAsBefore) {
    // The baseline this feature must not change. Linking is opt-in per
    // identity; a server whose users never link behaves the way it always did,
    // which is what makes this safe to deploy to an existing deployment.
    auto res = login_with_identity("76ea6af7", "joshb");
    ASSERT_EQ(status_of(res), 200) << res.body;
    EXPECT_EQ(logged_in_user(res), "@oidc_76ea6af7:test");
    EXPECT_EQ(store->get_display_name("@oidc_76ea6af7:test").value_or(""), "joshb");
}

// ── The security criterion ────────────────────────────────────────────────

TEST_F(AccountLinkTest, AssertingAnIdentityWithoutAVerifiableTokenAttachesNothing) {
    const auto josh = create_local_account("josh", "josh-token");

    // 1. A token signed by a key the provider does not publish. Right issuer,
    //    right audience, right subject, wrong signature — this is what an
    //    attacker who knows the victim's subject can actually construct.
    auto forged = link_token("josh-token", id_token_for("a5cdbefe", std::nullopt, true));
    EXPECT_EQ(status_of(forged), 403) << forged.body;

    // 2. No token at all: naming the subject in the body.
    auto asserted = link("josh-token", json{{"type", "m.login.token"},
                                            {"subject", "a5cdbefe"}}.dump());
    EXPECT_EQ(status_of(asserted), 400) << asserted.body;

    // 3. Not even a JSON object.
    EXPECT_EQ(status_of(link("josh-token", "\"a5cdbefe\"")), 400);

    // Nothing was attached by any of the three, so the identity still mints
    // its own account.
    auto res = login_with_identity("a5cdbefe");
    ASSERT_EQ(status_of(res), 200) << res.body;
    EXPECT_EQ(logged_in_user(res), "@oidc_a5cdbefe:test");
    EXPECT_TRUE(store->list_linked_identities(josh).empty());
}

TEST_F(AccountLinkTest, LinkingRequiresASessionForTheAccountItAttachesTo) {
    create_local_account("josh", "josh-token");

    // Holding a perfectly valid identity token is HALF the proof. Without a
    // session for the account, there is no account to attach it to — which is
    // what stops somebody who controls an identity from nominating whichever
    // account they would like it to become.
    auto res = link_token("", id_token_for("a5cdbefe"));
    EXPECT_EQ(status_of(res), 401) << res.body;

    auto bad_token = link_token("not-a-real-token", id_token_for("a5cdbefe"));
    EXPECT_EQ(status_of(bad_token), 401) << bad_token.body;
}

TEST_F(AccountLinkTest, AnIdentityAlreadyLinkedElsewhereCannotBeTakenOver) {
    const auto josh = create_local_account("josh", "josh-token");
    const auto mallory = create_local_account("mallory", "mallory-token");

    ASSERT_EQ(status_of(link_token("josh-token", id_token_for("a5cdbefe"))), 200);

    // Mallory has somehow obtained a valid id_token for the same identity — a
    // stolen one, or a shared device. She still cannot move the identity onto
    // her account: a link is never an update, and the account that would lose
    // its sign-in route is not the account making the request.
    auto res = link_token("mallory-token", id_token_for("a5cdbefe"));
    EXPECT_EQ(status_of(res), 409) << res.body;
    // And the refusal does not name the account that holds it. Mallory proved
    // control of the identity, not of whatever account it points at.
    EXPECT_EQ(res.body.find(josh), std::string::npos)
        << "the refusal disclosed which account owns the identity: " << res.body;

    EXPECT_EQ(store->find_linked_user(issuer(), "a5cdbefe").value_or(""), josh);
    EXPECT_TRUE(store->list_linked_identities(mallory).empty());
    EXPECT_EQ(logged_in_user(login_with_identity("a5cdbefe")), josh);
}

TEST_F(AccountLinkTest, ABannedAccountCannotAcquireANewWayToSignIn) {
    const auto josh = create_local_account("josh", "josh-token");
    store->set_server_ban(josh, "@admin:test", "spam", 0);

    auto res = link_token("josh-token", id_token_for("a5cdbefe"));
    EXPECT_EQ(status_of(res), 403) << res.body;
    EXPECT_TRUE(store->list_linked_identities(josh).empty());
}

TEST_F(AccountLinkTest, ABannedIdentityCannotBeLaunderedOntoAnUnbannedAccount) {
    // The other direction, and the more interesting one: the ban is on the
    // shadow account, and linking is the one operation that moves a login
    // between accounts. Without this check, "sign in, get banned, link the
    // identity to a second account" is a ban bypass.
    ASSERT_EQ(status_of(login_with_identity("a5cdbefe")), 200);
    store->set_server_ban("@oidc_a5cdbefe:test", "@admin:test", "spam", 0);

    create_local_account("josh", "josh-token");
    auto res = link_token("josh-token", id_token_for("a5cdbefe"));
    EXPECT_EQ(status_of(res), 403) << res.body;
    EXPECT_FALSE(store->find_linked_user(issuer(), "a5cdbefe").has_value());
}

TEST_F(AccountLinkTest, ABotCannotLinkAnIdentity) {
    SqliteStore::BotRecord bot;
    bot.user_id = "@bot_deploy:test";
    bot.display_name = "Deploy";
    bot.owner_id = "@josh:test";
    bot.created_by = "@josh:test";
    bot.created_at = 1;
    create_local_account("josh", "josh-token");
    ASSERT_TRUE(store->create_bot(bot));
    ASSERT_TRUE(store->rotate_bot_token("@bot_deploy:test", "bot-token", "bot-device"));

    auto res = link_token("bot-token", id_token_for("a5cdbefe"));
    EXPECT_EQ(status_of(res), 403) << res.body;
    EXPECT_TRUE(store->list_linked_identities("@bot_deploy:test").empty());
}

// ── The abandoned account ─────────────────────────────────────────────────

TEST_F(AccountLinkTest, TheSupersededAccountKeepsItsUserIdAndItsMessages) {
    // The person signed in with the identity first, so a shadow account exists
    // and has said things. This is production's shape exactly.
    ASSERT_EQ(status_of(login_with_identity("a5cdbefe", "josh")), 200);
    const std::string shadow = "@oidc_a5cdbefe:test";
    ASSERT_TRUE(store->user_exists(shadow));

    const auto room = generate_room_id("test");
    store->create_room(room, shadow);
    store->set_membership(room, shadow, std::string(membership::kJoin));
    const auto event_id = generate_event_id("test");
    store->insert_event(event_id, room, shadow, std::string(event_type::kRoomMessage),
                        std::nullopt, json{{"msgtype", "m.text"}, {"body", "hello"}}.dump(),
                        1000);

    const auto josh = create_local_account("josh", "josh-token");
    ASSERT_EQ(status_of(link_token("josh-token", id_token_for("a5cdbefe"))), 200);

    // 1. The user id stays TAKEN. Nothing is deleted, so it can never be
    //    handed to anybody else — which matters because the id embeds the
    //    provider subject and a recycled one would let a later account inherit
    //    the appearance of this person's history.
    EXPECT_TRUE(store->user_exists(shadow));

    // 2. The messages stay exactly where they are, under the OLD sender. They
    //    are deliberately not rewritten to @josh: that would make the
    //    surviving account appear to have said things it never said.
    auto events = store->get_room_events(room, 10);
    ASSERT_FALSE(events.empty());
    const auto found = std::find_if(events.begin(), events.end(),
                                    [&](const RoomEvent& e) { return e.event_id == event_id; });
    ASSERT_NE(found, events.end()) << "the message vanished";
    EXPECT_EQ(found->sender, shadow);

    // 3. But it is no longer a way to sign in: the identity now resolves to
    //    @josh, and the shadow account's password hash is empty.
    EXPECT_EQ(logged_in_user(login_with_identity("a5cdbefe")), josh);
}

TEST_F(AccountLinkTest, LinkingRevokesTheSupersededAccountsLiveSessions) {
    auto first = login_with_identity("a5cdbefe", "josh");
    ASSERT_EQ(status_of(first), 200) << first.body;
    const auto shadow_token = json::parse(first.body)["access_token"].get<std::string>();
    ASSERT_TRUE(store->get_user_by_token(shadow_token).has_value());

    create_local_account("josh", "josh-token");
    ASSERT_EQ(status_of(link_token("josh-token", id_token_for("a5cdbefe"))), 200);

    // After this request the person has one account. A still-valid token for
    // the other one is a session they did not ask to keep, and on a shared or
    // lost device it is one nobody would think to end.
    EXPECT_FALSE(store->get_user_by_token(shadow_token).has_value());
}

// ── Behaviour ─────────────────────────────────────────────────────────────

TEST_F(AccountLinkTest, TheStoreItselfRefusesToRepointAnIdentity) {
    // The SECOND line of defence, tested directly rather than through the
    // handler.
    //
    // handle_link_identity already refuses a conflict before it gets here, so
    // this looks redundant — and a mutation that turns the INSERT into an
    // upsert survives the endpoint tests for exactly that reason. It is not
    // redundant: it is the guarantee that holds when two link requests race
    // (both pass the handler's check, one reaches the table second) and the
    // guarantee that will still hold if a future caller reaches the store
    // without the handler's check. A link is an insert, never an update,
    // because re-pointing an identity takes the sign-in route away from an
    // account whose owner may no longer be around to object.
    const auto josh = create_local_account("josh", "josh-token");
    const auto mallory = create_local_account("mallory", "mallory-token");

    EXPECT_TRUE(store->link_identity(issuer(), "a5cdbefe", josh, josh, 1000));
    EXPECT_FALSE(store->link_identity(issuer(), "a5cdbefe", mallory, mallory, 2000));
    EXPECT_EQ(store->find_linked_user(issuer(), "a5cdbefe").value_or(""), josh);
    EXPECT_TRUE(store->list_linked_identities(mallory).empty());

    // The same identity from a DIFFERENT issuer is a different identity, and
    // is free. `sub` is only unique within an issuer, which is why the key is
    // the pair.
    EXPECT_TRUE(store->link_identity("https://other.example", "a5cdbefe", mallory,
                                     mallory, 3000));
    EXPECT_EQ(store->find_linked_user("https://other.example", "a5cdbefe").value_or(""),
              mallory);
}

TEST_F(AccountLinkTest, LinkingTheSameIdentityTwiceIsIdempotent) {
    const auto josh = create_local_account("josh", "josh-token");
    ASSERT_EQ(status_of(link_token("josh-token", id_token_for("a5cdbefe"))), 200);

    // A client retrying a request whose response it lost must not be told its
    // own link is a conflict.
    auto again = link_token("josh-token", id_token_for("a5cdbefe"));
    EXPECT_EQ(status_of(again), 200) << again.body;
    EXPECT_TRUE(json::parse(again.body).value("already_linked", false));
    EXPECT_EQ(store->list_linked_identities(josh).size(), 1u);
}

TEST_F(AccountLinkTest, ALinkedLoginDoesNotLetTheProviderRenameTheAccount) {
    const auto josh = create_local_account("josh", "josh-token");
    store->set_display_name(josh, "Josh (they/them)");
    ASSERT_EQ(status_of(link_token("josh-token", id_token_for("a5cdbefe"))), 200);

    // The IdP directory says "Joshua B". The person chose their display name
    // here; a link attaches a sign-in route, it does not hand the provider —
    // which on a corporate deployment somebody else administers — the power to
    // rename people on every sign-in.
    ASSERT_EQ(status_of(login_with_identity("a5cdbefe", "Joshua B")), 200);
    EXPECT_EQ(store->get_display_name(josh).value_or(""), "Josh (they/them)");
}

TEST_F(AccountLinkTest, LinkingIsAuditedWithExactlyTheIssuerAndTheSupersededAccount) {
    const auto josh = create_local_account("josh", "josh-token");
    ASSERT_EQ(status_of(login_with_identity("a5cdbefe", "josh")), 200);
    ASSERT_EQ(status_of(link_token("josh-token", id_token_for("a5cdbefe"))), 200);

    SqliteStore::AuditFilter filter;
    filter.action = std::string(audit_action::kAccountLink);
    auto page = store->list_audit_records(10, std::nullopt, filter);
    ASSERT_EQ(page.records.size(), 1u);
    const auto& record = page.records.front();
    EXPECT_EQ(record.actor, josh);
    EXPECT_EQ(record.target_user, josh);

    // THE EXACT KEY SET, not "contains what we expect". The audit log is
    // readable by every MANAGE_SERVER holder and has no delete path, so what
    // goes into it is a decision, and a decision is only enforced by asserting
    // on the whole payload: a later change that adds a field nobody weighed —
    // the raw subject, an email claim, the id_token itself — has to fail a
    // test rather than pass one that was only ever checking for absences it
    // happened to think of.
    auto after = json::parse(record.after_json);
    ASSERT_TRUE(after.is_object());
    std::vector<std::string> keys;
    for (auto it = after.begin(); it != after.end(); ++it) keys.push_back(it.key());
    std::sort(keys.begin(), keys.end());
    EXPECT_EQ(keys, (std::vector<std::string>{"issuer", "superseded_user_id"}))
        << record.after_json;
    EXPECT_EQ(after["issuer"], issuer());
    EXPECT_EQ(after["superseded_user_id"], "@oidc_a5cdbefe:test");
}

TEST_F(AccountLinkTest, TheProviderSubjectIsNotRecordedAsAClaimOfItsOwn) {
    // The sharp version of the rule, run on an identity that never signed in,
    // so there is no superseded account to carry a derived id.
    //
    // WHY THAT DISTINCTION MATTERS, because it is the obvious objection to the
    // previous test: `@oidc_a5cdbefe:test` visibly contains the subject. It
    // does, and it is recorded anyway — it is a USER ID ON THIS SERVER, already
    // shown in every member list and on every message that account ever sent,
    // and naming which account was superseded is the entire point of the
    // record. What must not happen is this server keeping the subject as a
    // claim in its own right, in a table that is append-only and readable by
    // anyone holding MANAGE_SERVER.
    const auto josh = create_local_account("josh", "josh-token");
    ASSERT_EQ(status_of(link_token("josh-token", id_token_for("76ea6af7"))), 200);

    SqliteStore::AuditFilter filter;
    filter.action = std::string(audit_action::kAccountLink);
    auto page = store->list_audit_records(10, std::nullopt, filter);
    ASSERT_EQ(page.records.size(), 1u);
    const auto& record = page.records.front();

    EXPECT_EQ(record.after_json.find("76ea6af7"), std::string::npos)
        << "the OIDC subject reached the audit log: " << record.after_json;
    EXPECT_EQ(record.target_key, "");
    EXPECT_EQ(record.reason, "");
    // No superseded account, so the key is absent rather than empty: a reader
    // must not have to tell "" apart from "the shadow account was @".
    EXPECT_FALSE(json::parse(record.after_json).contains("superseded_user_id"));
}

TEST_F(AccountLinkTest, ListingLinksShowsTheIssuerAndNeverTheSubject) {
    const auto josh = create_local_account("josh", "josh-token");
    ASSERT_EQ(status_of(link_token("josh-token", id_token_for("a5cdbefe"))), 200);

    auto res = linked_identities("josh-token");
    ASSERT_EQ(status_of(res), 200) << res.body;
    auto body = json::parse(res.body);
    ASSERT_EQ(body["identities"].size(), 1u);
    EXPECT_EQ(body["identities"][0]["issuer"], issuer());
    EXPECT_EQ(res.body.find("a5cdbefe"), std::string::npos)
        << "the subject was handed to a client: " << res.body;

    // And a second account sees its own links, which are none.
    create_local_account("mallory", "mallory-token");
    auto other = linked_identities("mallory-token");
    ASSERT_EQ(status_of(other), 200) << other.body;
    EXPECT_TRUE(json::parse(other.body)["identities"].empty());
}

TEST_F(AccountLinkTest, LinkingIsRefusedWhenTheServerHasNoIdentityProvider) {
    // A password-only deployment. The endpoint exists (routes are registered
    // unconditionally) and has to answer something coherent rather than
    // dereferencing a null OidcAuth.
    AuthHandler no_idp(*store, *sync_engine, config, nullptr);
    create_local_account("josh", "josh-token");

    httplib::Request req;
    req.set_header("Authorization", "Bearer josh-token");
    req.body = json{{"type", "m.login.token"}, {"token", "anything"}}.dump();
    httplib::Response res;
    no_idp.handle_link_identity(req, res);
    EXPECT_EQ(status_of(res), 400) << res.body;
}
