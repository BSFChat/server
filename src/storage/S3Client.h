#pragma once

#include <optional>
#include <string>

namespace bsfchat {

struct S3Config {
    std::string endpoint;          // e.g. "http://localhost:9000"
    std::string access_key;
    std::string secret_key;
    std::string bucket;
    std::string region = "us-east-1";
    bool use_path_style = true;    // Minio requires path-style addressing
};

struct S3Object {
    std::string data;
    std::string content_type;
    size_t content_length = 0;
};

class S3Client {
public:
    explicit S3Client(S3Config config);

    /// Upload an object to the bucket.
    bool put_object(const std::string& key, const std::string& data,
                    const std::string& content_type);

    /// Download an object from the bucket.
    std::optional<S3Object> get_object(const std::string& key);

    /// Delete an object from the bucket.
    bool delete_object(const std::string& key);

    /// Check if an object exists and get its metadata.
    bool head_object(const std::string& key, std::string* content_type = nullptr,
                     size_t* content_length = nullptr);

    // Crypto/encoding utilities (public for testability)
    static std::string sha256_hex(const std::string& data);
    static std::string hmac_sha256(const std::string& key, const std::string& data);
    static std::string hmac_sha256_hex(const std::string& key, const std::string& data);
    static std::string uri_encode(const std::string& input, bool encode_slash = true);

private:
    struct ParsedUrl {
        std::string scheme;   // "http" or "https"
        std::string host;     // hostname:port
        int port = 0;
        bool ssl = false;
    };

    ParsedUrl parse_endpoint() const;

    std::string build_path(const std::string& key) const;

    // AWS Signature V4
    std::string sign_request(const std::string& method, const std::string& path,
                             const std::string& query_string,
                             const std::string& payload_hash,
                             const std::string& content_type,
                             const std::string& amz_date, const std::string& date_stamp,
                             const std::string& host) const;

    S3Config config_;
};

} // namespace bsfchat
