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
        }

        // [auth]
        if (auto auth = tbl["auth"].as_table()) {
            if (auto v = auth->get("registration_enabled")) cfg.registration_enabled = v->value_or(cfg.registration_enabled);
            if (auto v = auth->get("password_hash_cost")) cfg.password_hash_cost = v->value_or(cfg.password_hash_cost);
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

        // [identity]
        if (auto id = tbl["identity"].as_table()) {
            IdentityConfig id_cfg;
            if (auto v = id->get("provider_url")) id_cfg.provider_url = v->value_or(std::string{});
            if (auto v = id->get("required")) id_cfg.required = v->value_or(false);
            if (auto v = id->get("allow_local_accounts")) id_cfg.allow_local_accounts = v->value_or(true);
            if (!id_cfg.provider_url.empty()) {
                cfg.identity = id_cfg;
            }
        }

    } catch (const toml::parse_error& e) {
        throw std::runtime_error(std::string("Failed to parse config: ") + e.what());
    }

    return cfg;
}

Config Config::defaults() {
    return Config{};
}

} // namespace bsfchat
