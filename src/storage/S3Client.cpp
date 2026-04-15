#include "storage/S3Client.h"
#include "core/Logger.h"

#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace bsfchat {

S3Client::S3Client(S3Config config)
    : config_(std::move(config)) {
}

S3Client::ParsedUrl S3Client::parse_endpoint() const {
    ParsedUrl result;
    std::string url = config_.endpoint;

    if (url.starts_with("https://")) {
        result.scheme = "https";
        result.ssl = true;
        url = url.substr(8);
    } else if (url.starts_with("http://")) {
        result.scheme = "http";
        result.ssl = false;
        url = url.substr(7);
    } else {
        result.scheme = "http";
        result.ssl = false;
    }

    // Remove trailing slash
    if (!url.empty() && url.back() == '/') {
        url.pop_back();
    }

    result.host = url;

    // Extract port if present
    auto colon = url.rfind(':');
    if (colon != std::string::npos) {
        result.port = std::stoi(url.substr(colon + 1));
    } else {
        result.port = result.ssl ? 443 : 80;
    }

    return result;
}

std::string S3Client::build_path(const std::string& key) const {
    if (config_.use_path_style) {
        return "/" + config_.bucket + "/" + uri_encode(key, false);
    }
    return "/" + uri_encode(key, false);
}

std::string S3Client::sha256_hex(const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::string S3Client::hmac_sha256(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;

    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         result, &result_len);

    return std::string(reinterpret_cast<char*>(result), result_len);
}

std::string S3Client::hmac_sha256_hex(const std::string& key, const std::string& data) {
    auto raw = hmac_sha256(key, data);
    std::ostringstream oss;
    for (unsigned char c : raw) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c);
    }
    return oss.str();
}

std::string S3Client::uri_encode(const std::string& input, bool encode_slash) {
    std::ostringstream encoded;
    for (char c : input) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '~' || c == '.') {
            encoded << c;
        } else if (c == '/' && !encode_slash) {
            encoded << c;
        } else {
            encoded << '%' << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
                    << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    return encoded.str();
}

std::string S3Client::sign_request(const std::string& method, const std::string& path,
                                    const std::string& query_string,
                                    const std::string& payload_hash,
                                    const std::string& content_type,
                                    const std::string& amz_date, const std::string& date_stamp,
                                    const std::string& host) const {
    // Step 1: Create canonical request
    std::string signed_headers = "host;x-amz-content-sha256;x-amz-date";
    if (!content_type.empty()) {
        signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
    }

    std::ostringstream canonical;
    canonical << method << "\n";
    canonical << path << "\n";
    canonical << query_string << "\n";

    // Canonical headers (must be sorted by lowercase header name)
    if (!content_type.empty()) {
        canonical << "content-type:" << content_type << "\n";
    }
    canonical << "host:" << host << "\n";
    canonical << "x-amz-content-sha256:" << payload_hash << "\n";
    canonical << "x-amz-date:" << amz_date << "\n";
    canonical << "\n"; // blank line after headers

    canonical << signed_headers << "\n";
    canonical << payload_hash;

    std::string canonical_request = canonical.str();
    std::string canonical_hash = sha256_hex(canonical_request);

    // Step 2: Create string to sign
    std::string scope = date_stamp + "/" + config_.region + "/s3/aws4_request";
    std::string string_to_sign = "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope + "\n" + canonical_hash;

    // Step 3: Calculate signing key
    std::string k_date = hmac_sha256("AWS4" + config_.secret_key, date_stamp);
    std::string k_region = hmac_sha256(k_date, config_.region);
    std::string k_service = hmac_sha256(k_region, "s3");
    std::string k_signing = hmac_sha256(k_service, "aws4_request");

    // Step 4: Calculate signature
    std::string signature = hmac_sha256_hex(k_signing, string_to_sign);

    // Step 5: Build Authorization header
    return "AWS4-HMAC-SHA256 Credential=" + config_.access_key + "/" + scope +
           ", SignedHeaders=" + signed_headers +
           ", Signature=" + signature;
}

static std::pair<std::string, std::string> get_amz_timestamps() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&time_t, &tm);

    char amz_date[17];
    std::strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);

    char date_stamp[9];
    std::strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", &tm);

    return {std::string(amz_date), std::string(date_stamp)};
}

bool S3Client::put_object(const std::string& key, const std::string& data,
                           const std::string& content_type) {
    auto log = get_logger();
    auto parsed = parse_endpoint();
    auto [amz_date, date_stamp] = get_amz_timestamps();
    auto path = build_path(key);
    auto payload_hash = sha256_hex(data);

    auto auth = sign_request("PUT", path, "", payload_hash, content_type,
                             amz_date, date_stamp, parsed.host);

    httplib::Headers headers = {
        {"Authorization", auth},
        {"x-amz-date", amz_date},
        {"x-amz-content-sha256", payload_hash},
        {"Host", parsed.host}
    };

    std::unique_ptr<httplib::Client> client;
    if (parsed.ssl) {
        client = std::make_unique<httplib::Client>(config_.endpoint);
    } else {
        client = std::make_unique<httplib::Client>(config_.endpoint);
    }
    client->set_connection_timeout(10);
    client->set_read_timeout(60);

    auto res = client->Put(path, headers, data, content_type);
    if (!res) {
        log->error("S3 PUT failed for {}: connection error", key);
        return false;
    }

    if (res->status >= 200 && res->status < 300) {
        log->debug("S3 PUT {} => {} ({} bytes)", key, res->status, data.size());
        return true;
    }

    log->error("S3 PUT {} failed: HTTP {} - {}", key, res->status, res->body);
    return false;
}

std::optional<S3Object> S3Client::get_object(const std::string& key) {
    auto log = get_logger();
    auto parsed = parse_endpoint();
    auto [amz_date, date_stamp] = get_amz_timestamps();
    auto path = build_path(key);
    auto payload_hash = sha256_hex(""); // empty payload for GET

    auto auth = sign_request("GET", path, "", payload_hash, "",
                             amz_date, date_stamp, parsed.host);

    httplib::Headers headers = {
        {"Authorization", auth},
        {"x-amz-date", amz_date},
        {"x-amz-content-sha256", payload_hash},
        {"Host", parsed.host}
    };

    auto client = std::make_unique<httplib::Client>(config_.endpoint);
    client->set_connection_timeout(10);
    client->set_read_timeout(60);

    auto res = client->Get(path, headers);
    if (!res) {
        log->error("S3 GET failed for {}: connection error", key);
        return std::nullopt;
    }

    if (res->status == 200) {
        S3Object obj;
        obj.data = res->body;
        obj.content_type = res->get_header_value("Content-Type");
        if (obj.content_type.empty()) {
            obj.content_type = "application/octet-stream";
        }
        obj.content_length = obj.data.size();
        return obj;
    }

    if (res->status == 404) {
        return std::nullopt;
    }

    log->error("S3 GET {} failed: HTTP {} - {}", key, res->status, res->body);
    return std::nullopt;
}

bool S3Client::delete_object(const std::string& key) {
    auto log = get_logger();
    auto parsed = parse_endpoint();
    auto [amz_date, date_stamp] = get_amz_timestamps();
    auto path = build_path(key);
    auto payload_hash = sha256_hex("");

    auto auth = sign_request("DELETE", path, "", payload_hash, "",
                             amz_date, date_stamp, parsed.host);

    httplib::Headers headers = {
        {"Authorization", auth},
        {"x-amz-date", amz_date},
        {"x-amz-content-sha256", payload_hash},
        {"Host", parsed.host}
    };

    auto client = std::make_unique<httplib::Client>(config_.endpoint);
    client->set_connection_timeout(10);
    client->set_read_timeout(60);

    auto res = client->Delete(path, headers);
    if (!res) {
        log->error("S3 DELETE failed for {}: connection error", key);
        return false;
    }

    if (res->status >= 200 && res->status < 300) {
        log->debug("S3 DELETE {} => {}", key, res->status);
        return true;
    }

    log->error("S3 DELETE {} failed: HTTP {}", key, res->status);
    return false;
}

bool S3Client::head_object(const std::string& key, std::string* content_type,
                            size_t* content_length) {
    auto log = get_logger();
    auto parsed = parse_endpoint();
    auto [amz_date, date_stamp] = get_amz_timestamps();
    auto path = build_path(key);
    auto payload_hash = sha256_hex("");

    auto auth = sign_request("HEAD", path, "", payload_hash, "",
                             amz_date, date_stamp, parsed.host);

    httplib::Headers headers = {
        {"Authorization", auth},
        {"x-amz-date", amz_date},
        {"x-amz-content-sha256", payload_hash},
        {"Host", parsed.host}
    };

    auto client = std::make_unique<httplib::Client>(config_.endpoint);
    client->set_connection_timeout(10);
    client->set_read_timeout(30);

    auto res = client->Head(path, headers);
    if (!res) {
        return false;
    }

    if (res->status == 200) {
        if (content_type) {
            *content_type = res->get_header_value("Content-Type");
        }
        if (content_length) {
            auto cl = res->get_header_value("Content-Length");
            *content_length = cl.empty() ? 0 : std::stoull(cl);
        }
        return true;
    }

    return false;
}

} // namespace bsfchat
