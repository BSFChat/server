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

    /// Download only [offset, offset + length) of an object, via a ranged GET.
    /// The service transfers just that window, so a small range on a large
    /// object costs a small transfer rather than the whole object.
    ///
    /// `data` may come back shorter than `length` if the window runs past the
    /// end of the object (including empty, when the offset is at or past the
    /// end — S3 answers 416 there, which is reported as a successful 0-byte
    /// read). nullopt means the object is missing or the request failed.
    std::optional<S3Object> get_object_range(const std::string& key, size_t offset,
                                             size_t length);

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
