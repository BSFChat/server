#pragma once

#include "core/RateLimiter.h"
#include "http/ClientAddress.h"

#include <bsfchat/JwtUtils.h>
#include <httplib.h>

#include <atomic>
#include <optional>
#include <string>

namespace bsfchat {

class SqliteStore;
class OidcAuth;
class SyncEngine;
struct Config;

class AuthHandler {
public:
    // `clock` drives the rate limiters only; tests pass their own so a lockout
    // can be outlived without sleeping through it. Limiter sizes and the
    // trusted-proxy list are read from `config` here, once. Throws
    // std::invalid_argument on an unparseable auth.trusted_proxies entry.
    AuthHandler(SqliteStore& store, SyncEngine& sync_engine,
                const Config& config, OidcAuth* oidc_auth = nullptr,
                LimiterClock clock = limiter_steady_now_ms);

    void handle_versions(const httplib::Request& req, httplib::Response& res);
    void handle_login_flows(const httplib::Request& req, httplib::Response& res);
    void handle_login(const httplib::Request& req, httplib::Response& res);
    void handle_register(const httplib::Request& req, httplib::Response& res);
    void handle_logout(const httplib::Request& req, httplib::Response& res);
    // POST /_matrix/client/v3/logout/all — revokes every session for the
    // account, including the calling one.
    void handle_logout_all(const httplib::Request& req, httplib::Response& res);
    void handle_whoami(const httplib::Request& req, httplib::Response& res);
    // POST /_matrix/client/v3/account/password — authenticated password change.
    // Requires the current password (a valid access token is not enough) and
    // revokes the account's other sessions unless logout_devices is false.
    void handle_password_change(const httplib::Request& req, httplib::Response& res);
    // POST /_matrix/client/v3/refresh — exchanges a refresh token for a fresh
    // access/refresh pair, rotating both.
    void handle_refresh(const httplib::Request& req, httplib::Response& res);

    // POST /_matrix/client/v3/bsfchat/account/link_identity — attaches an
    // identity-provider identity to the CALLER's account, so that identity
    // signs in as this account from now on instead of minting a parallel
    // `oidc_*` one.
    //
    // Requires proof of both sides in the same request: the bearer token for
    // the account, and a valid id_token for the identity. See the block comment
    // on the definition for why nothing weaker is acceptable, and for what does
    // and does not happen to the superseded account.
    void handle_link_identity(const httplib::Request& req, httplib::Response& res);
    // GET /_matrix/client/v3/bsfchat/account/linked_identities — the caller's
    // own links. Issuer and date only; the subject never leaves the database,
    // and there is no way to ask about another account.
    void handle_linked_identities(const httplib::Request& req, httplib::Response& res);

private:
    // Configured access-token lifetime, in milliseconds.
    [[nodiscard]] int64_t token_lifetime_ms() const;

    // Rate-limit identity of the caller: "" when limiting is off or the client
    // cannot be told apart from others (see ClientAddressResolver::resolve),
    // in which case every per-address check below is skipped rather than
    // lumping strangers into one bucket.
    [[nodiscard]] std::string client_key(const httplib::Request& req);
    // Per-address attempt limit for one endpoint. Writes the 429 and returns
    // true when the caller is over it.
    bool over_attempt_limit(const char* endpoint, const std::string& client,
                            httplib::Response& res);
    // Failure lockout. Keys may be empty (= not applicable). Writes the 429
    // and returns true when any of them is locked.
    bool locked_out(const std::string& key_a, const std::string& key_b,
                    httplib::Response& res);
    // Records a failed attempt against up to two failure-tracker keys, and logs
    // a line when either trips the lockout.
    //
    // The parameters are NOT interchangeable and the names are the contract.
    // `ip_key` is client_key()'s "ip:<address>" and is redacted to its network
    // before it is logged; `id_key` is a "user:"/"pwchange:" key built from the
    // submitted identifier, which is not an address and must reach the log
    // intact. Either may be empty, meaning "not applicable". See the comment on
    // redact_ip_key in the .cpp for what goes wrong when they are treated alike.
    void record_failure(const std::string& ip_key, const std::string& id_key);

    // The one place an identity token is accepted as a credential — sign-in
    // (m.login.token) and link_identity both call it, so a token that could
    // not sign anybody in cannot link anything either.
    //
    // Accepts the token only when ALL of: the provider's signature and issuer
    // verify; `aud` is THIS server's own public URL (C1 — never the client
    // id, which every server used to share); `azp` is identity.client_id when
    // that is set; it carries a nonce; and this is the first presentation of
    // that nonce here. On refusal, writes nothing and sets `refusal` to the
    // message for the M_FORBIDDEN body.
    std::optional<JwtClaims> verify_identity_token(const std::string& token,
                                                   std::string& refusal);

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    OidcAuth* oidc_auth_ = nullptr;

    ClientAddressResolver client_address_;
    RateLimiter attempt_limiter_;         // per address, per endpoint
    RateLimiter register_limiter_;        // accounts created, per address
    RateLimiter register_global_limiter_; // accounts created, whole server
    FailureTracker failures_;             // "ip:<addr>" and "user:<id>" keys
    std::atomic<int64_t> last_proxy_warning_ms_{0};
};

} // namespace bsfchat
