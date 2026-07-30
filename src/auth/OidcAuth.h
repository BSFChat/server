#pragma once

#include <bsfchat/JwtUtils.h>

#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace bsfchat {

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

    // Validate an identity token. Returns its claims if valid.
    // `expected_audience` is the relying party's client_id; when non-empty a
    // token minted for a different OAuth client is rejected.
    std::optional<JwtClaims> validate_token(const std::string& id_token,
                                             const std::string& expected_audience = std::string());

    // Fetch JWKS from the identity provider (called on startup and periodically).
    bool refresh_keys();

private:
    // PEM for `kid`; falls back to the sole published key when the token names
    // no kid and exactly one key exists. Empty when unavailable.
    std::string key_for_kid(const std::string& kid) const;
    // Seconds since the last successful refresh, or a huge number if never.
    int64_t seconds_since_refresh() const;

    const std::string provider_url_;

    mutable std::mutex mutex_;
    // kid -> PEM public key. Taking "the first RSA key in the JWKS" and
    // ignoring kid meant identity-provider key rotation broke logins
    // non-deterministically, depending on JWKS ordering.
    std::map<std::string, std::string> keys_by_kid_;
    std::string issuer_;
    int64_t last_key_refresh_ = 0;
    static constexpr int64_t kKeyRefreshIntervalSeconds = 6 * 3600; // 6 hours
};

} // namespace bsfchat
