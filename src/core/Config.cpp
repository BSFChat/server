#include "core/Config.h"
#include "core/Logger.h"

#include <toml++/toml.hpp>
#include <stdexcept>

namespace bsfchat {

Config Config::load(const std::string& path) {
    Config cfg;

    try {
        auto tbl = toml::parse_file(path);

        // toml++'s table::get returns nullptr for a missing key, so
        // every read must guard before value_or — a table that exists
        // with any key omitted would otherwise null-deref. Same
        // pattern as [voice] below.

        // [server]
        if (auto server = tbl["server"].as_table()) {
            if (auto v = server->get("name")) cfg.server_name = v->value_or(cfg.server_name);
            if (auto v = server->get("bind_address")) cfg.bind_address = v->value_or(cfg.bind_address);
            if (auto v = server->get("port")) cfg.port = v->value_or(cfg.port);
            if (auto v = server->get("workers")) cfg.workers = v->value_or(cfg.workers);
        }

        // [database]
        if (auto db = tbl["database"].as_table()) {
            if (auto v = db->get("path")) cfg.database_path = v->value_or(cfg.database_path);
        }

        // [media]
        if (auto media = tbl["media"].as_table()) {
            if (auto v = media->get("path")) cfg.media_path = v->value_or(cfg.media_path);
            if (auto v = media->get("max_upload_size_mb"))
                cfg.max_upload_size_mb = static_cast<size_t>(
                    v->value_or(static_cast<int64_t>(cfg.max_upload_size_mb)));
            if (auto v = media->get("require_auth"))
                cfg.require_media_auth = v->value_or(cfg.require_media_auth);
        }

        // [auth]
        if (auto auth = tbl["auth"].as_table()) {
            if (auto v = auth->get("registration_enabled")) cfg.registration_enabled = v->value_or(cfg.registration_enabled);
            if (auto v = auth->get("password_hash_cost")) cfg.password_hash_cost = v->value_or(cfg.password_hash_cost);
            if (auto v = auth->get("access_token_lifetime_days"))
                cfg.access_token_lifetime_days = v->value_or(cfg.access_token_lifetime_days);
        }

        // [tls]
        if (auto tls = tbl["tls"].as_table()) {
            if (auto v = tls->get("enabled")) cfg.tls_enabled = v->value_or(cfg.tls_enabled);
            if (auto v = tls->get("cert_file")) cfg.tls_cert_file = v->value_or(std::string{});
            if (auto v = tls->get("key_file")) cfg.tls_key_file = v->value_or(std::string{});
        }

        // [storage]
        if (auto storage = tbl["storage"].as_table()) {
            if (auto v = storage->get("type")) cfg.storage.type = v->value_or(cfg.storage.type);

            if (auto s3 = (*storage)["s3"].as_table()) {
                if (auto v = s3->get("endpoint")) cfg.storage.s3.endpoint = v->value_or(cfg.storage.s3.endpoint);
                if (auto v = s3->get("access_key")) cfg.storage.s3.access_key = v->value_or(cfg.storage.s3.access_key);
                if (auto v = s3->get("secret_key")) cfg.storage.s3.secret_key = v->value_or(cfg.storage.s3.secret_key);
                if (auto v = s3->get("bucket")) cfg.storage.s3.bucket = v->value_or(cfg.storage.s3.bucket);
                if (auto v = s3->get("region")) cfg.storage.s3.region = v->value_or(cfg.storage.s3.region);
                if (auto v = s3->get("use_path_style")) cfg.storage.s3.use_path_style = v->value_or(cfg.storage.s3.use_path_style);
            }
        }

        // [voice]
        if (auto voice = tbl["voice"].as_table()) {
            if (auto v = voice->get("enabled")) cfg.voice.enabled = v->value_or(cfg.voice.enabled);
            // turn_uri accepts a single string or an array of strings
            if (auto v = voice->get("turn_uri")) {
                if (auto arr = v->as_array()) {
                    for (const auto& el : *arr) {
                        if (auto s = el.value<std::string>()) cfg.voice.turn_uris.push_back(*s);
                    }
                } else if (auto s = v->value<std::string>()) {
                    cfg.voice.turn_uris.push_back(*s);
                }
            }
            if (auto v = voice->get("turn_username")) cfg.voice.turn_username = v->value_or(cfg.voice.turn_username);
            if (auto v = voice->get("turn_password")) cfg.voice.turn_password = v->value_or(cfg.voice.turn_password);
            if (auto v = voice->get("turn_secret")) cfg.voice.turn_secret = v->value_or(cfg.voice.turn_secret);
            if (auto v = voice->get("turn_ttl")) cfg.voice.turn_ttl = v->value_or(cfg.voice.turn_ttl);
            if (auto v = voice->get("stun_uri")) cfg.voice.stun_uri = v->value_or(cfg.voice.stun_uri);
            if (auto v = voice->get("allow_peer_to_peer")) cfg.voice.allow_peer_to_peer = v->value_or(cfg.voice.allow_peer_to_peer);
        }

        // [push]. No provider credentials here on purpose — see PushConfig.
        if (auto push = tbl["push"].as_table()) {
            if (auto v = push->get("enabled")) cfg.push.enabled = v->value_or(cfg.push.enabled);
            if (auto v = push->get("worker_poll_ms")) cfg.push.worker_poll_ms = v->value_or(cfg.push.worker_poll_ms);
            if (auto v = push->get("connect_timeout_s")) cfg.push.connect_timeout_s = v->value_or(cfg.push.connect_timeout_s);
            if (auto v = push->get("request_timeout_s")) cfg.push.request_timeout_s = v->value_or(cfg.push.request_timeout_s);
            if (auto v = push->get("max_attempts")) cfg.push.max_attempts = v->value_or(cfg.push.max_attempts);
            if (auto v = push->get("base_backoff_ms")) cfg.push.base_backoff_ms = v->value_or(cfg.push.base_backoff_ms);
            if (auto v = push->get("max_backoff_ms")) cfg.push.max_backoff_ms = v->value_or(cfg.push.max_backoff_ms);
            if (auto v = push->get("batch_size")) cfg.push.batch_size = v->value_or(cfg.push.batch_size);
            if (auto v = push->get("lease_ms")) cfg.push.lease_ms = v->value_or(cfg.push.lease_ms);
            // Accepts a single string or an array, same as voice.turn_uri.
            if (auto v = push->get("allowed_gateway_prefixes")) {
                if (auto arr = v->as_array()) {
                    for (auto&& el : *arr) {
                        if (auto s = el.value<std::string>()) {
                            cfg.push.allowed_gateway_prefixes.push_back(*s);
                        }
                    }
                } else if (auto s = v->value<std::string>()) {
                    cfg.push.allowed_gateway_prefixes.push_back(*s);
                }
            }
        }

        // [identity]
        if (auto id = tbl["identity"].as_table()) {
            IdentityConfig id_cfg;
            if (auto v = id->get("provider_url")) id_cfg.provider_url = v->value_or(std::string{});
            if (auto v = id->get("required")) id_cfg.required = v->value_or(false);
            if (auto v = id->get("allow_local_accounts")) id_cfg.allow_local_accounts = v->value_or(true);
            if (auto v = id->get("client_id")) id_cfg.client_id = v->value_or(id_cfg.client_id);
            if (!id_cfg.provider_url.empty()) {
                cfg.identity = id_cfg;
            }
        }

    } catch (const toml::parse_error& e) {
        throw std::runtime_error(std::string("Failed to parse config: ") + e.what());
    }

    validate(cfg);
    return cfg;
}

void Config::validate(Config& cfg) {
    auto log = get_logger();

    if (cfg.voice.enabled) {
        const bool has_relay = !cfg.voice.turn_uris.empty();
        const bool has_stun = !cfg.voice.stun_uri.empty();
        if (!cfg.voice.allow_peer_to_peer && !has_relay) {
            // Relay-only with zero relays configured means every call fails.
            // Fall back to peer-to-peer and say so loudly rather than shipping
            // a voice feature that is enabled but cannot ever connect.
            log->warn("voice.allow_peer_to_peer is false but no voice.turn_uri is configured — "
                      "that combination can never establish a call. Falling back to "
                      "peer-to-peer. Configure voice.turn_uri (and turn_secret or "
                      "turn_username/turn_password) to force relayed calls.");
            cfg.voice.allow_peer_to_peer = true;
        }
        if (!has_relay && !has_stun) {
            log->warn("voice.enabled is true but neither voice.stun_uri nor voice.turn_uri is "
                      "set — calls will only connect between clients on the same local network. "
                      "Set voice.stun_uri for NAT traversal.");
        }
    }

    if (cfg.password_hash_cost < 12) {
        log->warn("auth.password_hash_cost = {} is dangerously low ({} PBKDF2 iterations). "
                  "Raising to 12; 19 or higher is recommended.",
                  cfg.password_hash_cost, 1u << cfg.password_hash_cost);
        cfg.password_hash_cost = 12;
    }
    if (cfg.password_hash_cost > 24) {
        // 2^24 iterations would take seconds per login.
        cfg.password_hash_cost = 24;
    }

    if (cfg.access_token_lifetime_days < 1) {
        // A sub-day lifetime with no refresh flow in the shipped client means
        // users get logged out while they are still using the app.
        log->warn("auth.access_token_lifetime_days = {} is too short to be usable; raising to 1.",
                  cfg.access_token_lifetime_days);
        cfg.access_token_lifetime_days = 1;
    }
    if (cfg.access_token_lifetime_days > 3650) {
        log->warn("auth.access_token_lifetime_days = {} is effectively 'never expires'; "
                  "clamping to 3650.", cfg.access_token_lifetime_days);
        cfg.access_token_lifetime_days = 3650;
    }

    if (cfg.identity && cfg.identity->client_id.empty()) {
        log->warn("identity.client_id is empty — identity tokens will be accepted regardless of "
                  "their audience, so a token minted for any other OAuth client registered with "
                  "the same provider will be accepted as a chat login.");
    }

    if (cfg.push.worker_poll_ms < 50) cfg.push.worker_poll_ms = 50;
    if (cfg.push.batch_size < 1) cfg.push.batch_size = 1;
    if (cfg.push.max_attempts < 1) cfg.push.max_attempts = 1;
    if (cfg.push.base_backoff_ms < 100) cfg.push.base_backoff_ms = 100;
    if (cfg.push.max_backoff_ms < cfg.push.base_backoff_ms) {
        cfg.push.max_backoff_ms = cfg.push.base_backoff_ms;
    }
    if (cfg.push.connect_timeout_s < 1) cfg.push.connect_timeout_s = 1;
    if (cfg.push.request_timeout_s < 1) cfg.push.request_timeout_s = 1;
    {
        // A lease shorter than the request timeout would hand a still-in-flight
        // notification to the next wakeup, duplicating it on every slow gateway
        // response.
        const int64_t min_lease =
            static_cast<int64_t>(cfg.push.connect_timeout_s + cfg.push.request_timeout_s) * 1000 * 2;
        if (cfg.push.lease_ms < min_lease) {
            log->warn("push.lease_ms = {} is shorter than twice the configured HTTP timeouts; "
                      "raising to {} so a slow gateway cannot cause duplicate notifications.",
                      cfg.push.lease_ms, min_lease);
            cfg.push.lease_ms = min_lease;
        }
    }

    if (cfg.push.enabled && cfg.push.allowed_gateway_prefixes.empty()) {
        log->warn("push.allowed_gateway_prefixes is empty — any authenticated user can register "
                  "an arbitrary push gateway URL that this server will then POST to, which is a "
                  "server-side request forgery primitive against anything reachable from this "
                  "host. Set it to the URL prefix(es) of your push gateway if this instance has "
                  "accounts you do not fully trust.");
    }

    if (cfg.workers < 1) cfg.workers = 1;
}

Config Config::defaults() {
    return Config{};
}

} // namespace bsfchat
