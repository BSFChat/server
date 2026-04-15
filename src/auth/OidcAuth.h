#pragma once

#include <bsfchat/JwtUtils.h>
#include <optional>
#include <string>

namespace bsfchat {

// Stub for OIDC authentication against the BSFChat ID service.
// Phase 1E will implement JWKS fetching and token validation.

class OidcAuth {
public:
    explicit OidcAuth(const std::string& provider_url);

    // Validate an identity token. Returns the subject (user identity) if valid.
    std::optional<JwtClaims> validate_token(const std::string& id_token);

    // Fetch JWKS from the identity provider (called on startup and periodically)
    bool refresh_keys();

private:
    std::string provider_url_;
    std::string public_key_pem_; // cached from JWKS
    std::string jwks_uri_;
    std::string issuer_;
    int64_t last_key_refresh_ = 0;
    static constexpr int64_t kKeyRefreshIntervalSeconds = 6 * 3600; // 6 hours
};

} // namespace bsfchat
