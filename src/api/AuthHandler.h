#pragma once

#include "core/RateLimiter.h"
#include "http/ClientAddress.h"

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
