#pragma once

#include <optional>
#include <string>

namespace bsfchat {

struct IdentityConfig {
    std::string provider_url;
    bool required = false;
    bool allow_local_accounts = true;
};

struct StorageS3Config {
    std::string endpoint = "http://localhost:9000";
    std::string access_key;
    std::string secret_key;
    std::string bucket = "bsfchat-media";
    std::string region = "us-east-1";
    bool use_path_style = true;
};

struct StorageConfig {
    std::string type = "local";  // "local" or "s3"
    StorageS3Config s3;
};

struct VoiceConfig {
    bool enabled = true;
    std::string turn_uri;
    std::string turn_username;
    std::string turn_password;
    std::string stun_uri; // No default — admin should configure their own STUN/TURN
    bool allow_peer_to_peer = false; // Default: TURN-only for IP privacy
};

struct Config {
    // Server
    std::string server_name = "localhost";
    std::string bind_address = "0.0.0.0";
    int port = 8448;
    int workers = 4;

    // Database
    std::string database_path = "./data/bsfchat.db";

    // Media
    std::string media_path = "./data/media/";
    size_t max_upload_size_mb = 50;

    // Storage
    StorageConfig storage;

    // Auth
    bool registration_enabled = true;
    int password_hash_cost = 12;

    // TLS
    bool tls_enabled = false;
    std::string tls_cert_file;
    std::string tls_key_file;

    // Identity (optional)
    std::optional<IdentityConfig> identity;

    // Voice
    VoiceConfig voice;

    static Config load(const std::string& path);
    static Config defaults();
};

} // namespace bsfchat
