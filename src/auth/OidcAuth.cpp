#include "auth/OidcAuth.h"
#include "core/Logger.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>

namespace bsfchat {

using json = nlohmann::json;

OidcAuth::OidcAuth(const std::string& provider_url)
    : provider_url_(provider_url) {
}

std::optional<JwtClaims> OidcAuth::validate_token(const std::string& id_token) {
    if (public_key_pem_.empty()) {
        get_logger()->warn("OIDC: No public key available, cannot validate token");
        return std::nullopt;
    }

    // Check if keys need refresh
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now - last_key_refresh_ > kKeyRefreshIntervalSeconds) {
        refresh_keys();
    }

    // Use discovered issuer if available, otherwise fall back to provider_url
    const auto& issuer = issuer_.empty() ? provider_url_ : issuer_;
    return jwt_verify(id_token, public_key_pem_, issuer);
}

bool OidcAuth::refresh_keys() {
    auto log = get_logger();

    try {
        // Step 1: Fetch OpenID Connect discovery document
        httplib::Client discovery_client(provider_url_);
        discovery_client.set_connection_timeout(10);
        discovery_client.set_read_timeout(10);

        auto discovery_res = discovery_client.Get("/.well-known/openid-configuration");
        if (!discovery_res || discovery_res->status != 200) {
            log->error("OIDC: Failed to fetch discovery document from {}", provider_url_);
            return false;
        }

        auto discovery = json::parse(discovery_res->body);
        auto jwks_uri = discovery.value("jwks_uri", "");
        auto issuer = discovery.value("issuer", "");

        if (jwks_uri.empty()) {
            log->error("OIDC: Discovery document missing jwks_uri");
            return false;
        }

        // Step 2: Parse the JWKS URI to get host and path
        std::string jwks_host;
        std::string jwks_path;

        // Simple URL parsing: extract scheme+host and path
        auto scheme_end = jwks_uri.find("://");
        if (scheme_end == std::string::npos) {
            log->error("OIDC: Invalid jwks_uri: {}", jwks_uri);
            return false;
        }
        auto host_start = scheme_end + 3;
        auto path_start = jwks_uri.find('/', host_start);
        if (path_start == std::string::npos) {
            jwks_host = jwks_uri;
            jwks_path = "/";
        } else {
            jwks_host = jwks_uri.substr(0, path_start);
            jwks_path = jwks_uri.substr(path_start);
        }

        // Step 3: Fetch JWKS
        httplib::Client jwks_client(jwks_host);
        jwks_client.set_connection_timeout(10);
        jwks_client.set_read_timeout(10);

        auto jwks_res = jwks_client.Get(jwks_path);
        if (!jwks_res || jwks_res->status != 200) {
            log->error("OIDC: Failed to fetch JWKS from {}", jwks_uri);
            return false;
        }

        auto jwks = json::parse(jwks_res->body);
        if (!jwks.contains("keys") || !jwks["keys"].is_array()) {
            log->error("OIDC: JWKS response missing keys array");
            return false;
        }

        // Step 4: Find the first RSA signing key
        for (const auto& key : jwks["keys"]) {
            if (key.value("kty", "") == "RSA" &&
                (key.value("use", "sig") == "sig")) {
                public_key_pem_ = jwk_to_pem(key);
                issuer_ = issuer;
                last_key_refresh_ = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                log->info("OIDC: Keys refreshed successfully from {}", provider_url_);
                return true;
            }
        }

        log->error("OIDC: No suitable RSA signing key found in JWKS");
        return false;

    } catch (const std::exception& e) {
        log->error("OIDC: Key refresh failed: {}", e.what());
        return false;
    }
}

} // namespace bsfchat
