#pragma once

#include <bsfchat/JwtUtils.h>

#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace bsfchat {

namespace oidc_detail {

// Doubling backoff, clamped. Pure so the schedule can be pinned by a test
// without waiting on a real clock or a real identity provider.
int64_t next_backoff_seconds(int64_t current_seconds);

} // namespace oidc_detail

// OIDC token validation against the BSFChat ID service.
//
// Thread-safety: refresh_keys() runs on httplib worker threads (via
// validate_token) as well as at startup, while validate_token reads the cached
// key material concurrently. All shared state below is guarded by mutex_ — it
// was previously written and read with no synchronisation at all, which is a
// data race on std::string and therefore undefined behaviour.
class OidcAuth {
public:
    explicit OidcAuth(const std::string& provider_url);
    ~OidcAuth();

    OidcAuth(const OidcAuth&) = delete;
    OidcAuth& operator=(const OidcAuth&) = delete;

    // Validate an identity token. Returns its claims if valid.
    // `expected_audience` is this server's canonical public URL (see
    // expected_identity_audience()); when non-empty a token audienced to
    // anybody else is rejected. Callers that accept a token as a credential
    // must never pass it empty — AuthHandler::verify_identity_token refuses
    // outright instead.
    std::optional<JwtClaims> validate_token(const std::string& id_token,
                                             const std::string& expected_audience = std::string());

    // Fetch JWKS from the identity provider (called on startup and periodically).
    bool refresh_keys();

    // Keep retrying refresh_keys() on a bounded exponential backoff until it
    // succeeds, on a background thread. Returns immediately.
    //
    // Startup used to be a single blocking attempt: in a compose deployment
    // the server almost always wins the race against the identity container,
    // logged the failure at error level, and then left every subsequent token
    // validation to re-attempt the fetch inline. That is the bug this and the
    // throttle below exist to fix.
    void start_background_refresh();

    // True once any refresh has succeeded. Used only for logging.
    bool has_keys() const;

    // Records one presentation of an identity token, keyed on (issuer,
    // subject, nonce). Returns true the first time and false for every later
    // presentation until `expires_at` (the token's own `exp`, plus the
    // verifier's leeway) has passed.
    //
    // Why: an id_token is a bearer credential that is presented once, seconds
    // after it is minted. Audience binding (C1) already confines it to this
    // server; this confines it to one USE here, so a copy picked up on the way
    // — a proxy log, a crash dump, a debugging session — is worth nothing once
    // the real sign-in has happened. The client generates a fresh nonce per
    // authorization and the identity provider echoes it, so a nonce names one
    // token.
    //
    // In memory, deliberately: tokens live five minutes, so a restart forgets
    // at most five minutes of history, and a table would be one more thing to
    // migrate and prune. Bounded; when full of live entries it refuses (fails
    // closed) — filling it takes that many freshly minted tokens for THIS
    // server, which only the identity provider can produce.
    bool first_presentation(const std::string& issuer, const std::string& subject,
                            const std::string& nonce, int64_t expires_at);

private:
    // PEM for `kid`; falls back to the sole published key when the token names
    // no kid and exactly one key exists. Empty when unavailable.
    std::string key_for_kid(const std::string& kid) const;
    // Seconds since the last successful refresh, or a huge number if never.
    int64_t seconds_since_refresh() const;

    const std::string provider_url_;

    void background_refresh_loop();
    // refresh_keys() behind the on-demand rate limit below. Returns false
    // without touching the network when a refresh is not due yet.
    bool refresh_keys_throttled();

    mutable std::mutex mutex_;
    // kid -> PEM public key. Taking "the first RSA key in the JWKS" and
    // ignoring kid meant identity-provider key rotation broke logins
    // non-deterministically, depending on JWKS ordering.
    std::map<std::string, std::string> keys_by_kid_;
    std::string issuer_;
    int64_t last_key_refresh_ = 0;
    static constexpr int64_t kKeyRefreshIntervalSeconds = 6 * 3600; // 6 hours

    // Rate limit on refreshes triggered from validate_token().
    //
    // Without it, every token validation while the identity service is down
    // performed TWO discovery+JWKS fetches (the staleness check fires because
    // "never refreshed" reads as infinitely stale, then the unknown-kid path
    // fires again), each with a 10 s connect and a 10 s read timeout, on an
    // httplib worker thread. With the default four workers, four requests
    // carrying any token were enough to make the whole server unresponsive
    // for ~40 s at a time, repeatedly, for as long as the provider was down —
    // reachable by anyone who can send an Authorization header.
    int64_t next_on_demand_refresh_ = 0;   // unix seconds; 0 = allowed now
    int64_t on_demand_backoff_ = kMinBackoffSeconds;
    static constexpr int64_t kMinBackoffSeconds = 2;
    static constexpr int64_t kMaxBackoffSeconds = 300;

    // first_presentation() state: key -> expiry (unix seconds).
    std::mutex seen_mutex_;
    std::map<std::string, int64_t> seen_tokens_;
    static constexpr size_t kMaxSeenTokens = 100000;

    // Background startup retry.
    std::thread refresher_;
    std::mutex wake_mutex_;
    std::condition_variable wake_;
    bool stopping_ = false;
};

} // namespace bsfchat
