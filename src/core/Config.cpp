#include "core/Config.h"
#include "core/Logger.h"

#include <toml++/toml.hpp>
#include <stdexcept>

namespace bsfchat {

Config Config::load(const std::string& path) {
    Config cfg;

    try {
        auto tbl = toml::parse_file(path);

        // [server]
        if (auto server = tbl["server"].as_table()) {
            cfg.server_name = server->get("name")->value_or(cfg.server_name);
            cfg.bind_address = server->get("bind_address")->value_or(cfg.bind_address);
            cfg.port = server->get("port")->value_or(cfg.port);
            cfg.workers = server->get("workers")->value_or(cfg.workers);
        }

        // [database]
        if (auto db = tbl["database"].as_table()) {
            cfg.database_path = db->get("path")->value_or(cfg.database_path);
        }

        // [media]
        if (auto media = tbl["media"].as_table()) {
            cfg.media_path = media->get("path")->value_or(cfg.media_path);
            cfg.max_upload_size_mb = static_cast<size_t>(
                media->get("max_upload_size_mb")->value_or(static_cast<int64_t>(cfg.max_upload_size_mb)));
        }

        // [auth]
        if (auto auth = tbl["auth"].as_table()) {
            cfg.registration_enabled = auth->get("registration_enabled")->value_or(cfg.registration_enabled);
            cfg.password_hash_cost = auth->get("password_hash_cost")->value_or(cfg.password_hash_cost);
        }

        // [tls]
        if (auto tls = tbl["tls"].as_table()) {
            cfg.tls_enabled = tls->get("enabled")->value_or(cfg.tls_enabled);
            cfg.tls_cert_file = tls->get("cert_file")->value_or(std::string{});
            cfg.tls_key_file = tls->get("key_file")->value_or(std::string{});
        }

        // [storage]
        if (auto storage = tbl["storage"].as_table()) {
            cfg.storage.type = storage->get("type")->value_or(cfg.storage.type);

            if (auto s3 = (*storage)["s3"].as_table()) {
                cfg.storage.s3.endpoint = s3->get("endpoint")->value_or(cfg.storage.s3.endpoint);
                cfg.storage.s3.access_key = s3->get("access_key")->value_or(cfg.storage.s3.access_key);
                cfg.storage.s3.secret_key = s3->get("secret_key")->value_or(cfg.storage.s3.secret_key);
                cfg.storage.s3.bucket = s3->get("bucket")->value_or(cfg.storage.s3.bucket);
                cfg.storage.s3.region = s3->get("region")->value_or(cfg.storage.s3.region);
                cfg.storage.s3.use_path_style = s3->get("use_path_style")->value_or(cfg.storage.s3.use_path_style);
            }
        }

        // [voice]
        if (auto voice = tbl["voice"].as_table()) {
            if (auto v = voice->get("enabled")) cfg.voice.enabled = v->value_or(cfg.voice.enabled);
            if (auto v = voice->get("turn_uri")) cfg.voice.turn_uri = v->value_or(cfg.voice.turn_uri);
            if (auto v = voice->get("turn_username")) cfg.voice.turn_username = v->value_or(cfg.voice.turn_username);
            if (auto v = voice->get("turn_password")) cfg.voice.turn_password = v->value_or(cfg.voice.turn_password);
            if (auto v = voice->get("stun_uri")) cfg.voice.stun_uri = v->value_or(cfg.voice.stun_uri);
            if (auto v = voice->get("allow_peer_to_peer")) cfg.voice.allow_peer_to_peer = v->value_or(cfg.voice.allow_peer_to_peer);
        }

        // [identity]
        if (auto id = tbl["identity"].as_table()) {
            IdentityConfig id_cfg;
            id_cfg.provider_url = id->get("provider_url")->value_or(std::string{});
            id_cfg.required = id->get("required")->value_or(false);
            id_cfg.allow_local_accounts = id->get("allow_local_accounts")->value_or(true);
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
