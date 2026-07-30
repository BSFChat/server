#include "auth/OidcAuth.h"
#include "core/Logger.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <limits>

namespace bsfchat {

using json = nlohmann::json;

namespace {

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Reads the `kid` header of a JWT without verifying it. Header contents are
// untrusted at this point — the kid only selects which published key the
// signature is then verified against, so a bogus value simply fails to match
// and the token is rejected.
std::string token_kid(const std::string& token) {
    auto dot = token.find('.');
    if (dot == std::string::npos || dot == 0) return {};
    try {
        auto raw = base64url_decode(token.substr(0, dot));
        auto header = json::parse(std::string(raw.begin(), raw.end()), nullptr, false);
        if (header.is_discarded() || !header.is_object()) return {};
        auto it = header.find("kid");
        if (it == header.end() || !it->is_string()) return {};
        return it->get<std::string>();
    } catch (...) {
        // Malformed token; verification will reject it anyway.
        return {};
    }
}

} // namespace

OidcAuth::OidcAuth(const std::string& provider_url)
    : provider_url_(provider_url) {
}

int64_t OidcAuth::seconds_since_refresh() const {
    std::lock_guard lock(mutex_);
    if (last_key_refresh_ == 0) return std::numeric_limits<int64_t>::max();
    return now_seconds() - last_key_refresh_;
}

std::string OidcAuth::key_for_kid(const std::string& kid) const {
    std::lock_guard lock(mutex_);
    if (!kid.empty()) {
        auto it = keys_by_kid_.find(kid);
        return it == keys_by_kid_.end() ? std::string() : it->second;
    }
    // No kid in the token: only unambiguous when the provider publishes a
    // single key. Guessing among several is how rotation silently breaks.
    if (keys_by_kid_.size() == 1) return keys_by_kid_.begin()->second;
    return {};
}

std::optional<JwtClaims> OidcAuth::validate_token(const std::string& id_token,
                                                   const std::string& expected_audience) {
    if (seconds_since_refresh() > kKeyRefreshIntervalSeconds) {
        refresh_keys();
    }

    const std::string kid = token_kid(id_token);
    std::string pem = key_for_kid(kid);

    // A kid we've never seen usually means the provider rotated its keys since
    // our last refresh — pull the JWKS again once before giving up.
    if (pem.empty()) {
        if (refresh_keys()) pem = key_for_kid(kid);
    }
    if (pem.empty()) {
        get_logger()->warn("OIDC: no public key available for kid '{}', cannot validate token",
                           kid.empty() ? "<none>" : kid);
        return std::nullopt;
    }

    std::string issuer;
    {
        std::lock_guard lock(mutex_);
        issuer = issuer_.empty() ? provider_url_ : issuer_;
    }

    return jwt_verify(id_token, pem, issuer, expected_audience);
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

        // Step 4: Convert EVERY RSA signing key, indexed by kid. Previously
        // only the first was kept and kid was ignored entirely, so a provider
        // publishing old+new keys during rotation broke logins depending on
        // which one happened to come first in the JSON array.
        std::map<std::string, std::string> fresh_keys;
        for (const auto& key : jwks["keys"]) {
            if (key.value("kty", "") != "RSA") continue;
            if (key.value("use", "sig") != "sig") continue;
            try {
                fresh_keys[key.value("kid", "")] = jwk_to_pem(key);
            } catch (const std::exception& e) {
                log->warn("OIDC: skipping unusable JWKS key (kid '{}'): {}",
                          key.value("kid", ""), e.what());
            }
        }

        if (fresh_keys.empty()) {
            log->error("OIDC: No suitable RSA signing key found in JWKS");
            return false;
        }

        {
            std::lock_guard lock(mutex_);
            keys_by_kid_ = std::move(fresh_keys);
            issuer_ = issuer;
            last_key_refresh_ = now_seconds();
            log->info("OIDC: Keys refreshed successfully from {} ({} key(s))",
                      provider_url_, keys_by_kid_.size());
        }
        return true;

    } catch (const std::exception& e) {
        log->error("OIDC: Key refresh failed: {}", e.what());
        return false;
    }
}

} // namespace bsfchat
