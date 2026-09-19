#include "api/MediaTicket.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include <cstring>
#include <memory>
#include <stdexcept>

namespace bsfchat::media_ticket {
namespace {

constexpr char kSalt[] = "bsfchat/media-ticket/v1";
constexpr size_t kKeyLen = 32;

// A ticket whose exp is further out than this was not minted by a server with a
// working clock. Twice the TTL ceiling, so a legitimately maximal ticket is
// never caught by it.
constexpr int64_t kMaxSkewSeconds = kMaxTtlSeconds * 2;

constexpr char kB64Url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url_encode(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        const uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out.push_back(kB64Url[(v >> 18) & 0x3F]);
        out.push_back(kB64Url[(v >> 12) & 0x3F]);
        out.push_back(kB64Url[(v >> 6) & 0x3F]);
        out.push_back(kB64Url[v & 0x3F]);
    }
    if (i + 1 == len) {
        const uint32_t v = uint32_t(data[i]) << 16;
        out.push_back(kB64Url[(v >> 18) & 0x3F]);
        out.push_back(kB64Url[(v >> 12) & 0x3F]);
    } else if (i + 2 == len) {
        const uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out.push_back(kB64Url[(v >> 18) & 0x3F]);
        out.push_back(kB64Url[(v >> 12) & 0x3F]);
        out.push_back(kB64Url[(v >> 6) & 0x3F]);
    }
    // Unpadded. '=' is legal in a query string but has to be percent-encoded to
    // be unambiguous, and every consumer of this is ours.
    return out;
}

std::string b64url_encode(const std::string& s) {
    return b64url_encode(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

std::optional<std::string> b64url_decode(const std::string& in) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    // A 4n+1 group cannot encode anything: reject rather than silently drop it.
    if (in.size() % 4 == 1) return std::nullopt;

    std::string out;
    out.reserve(in.size() / 4 * 3);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        const int v = value(c);
        if (v < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }

    // Canonical encodings only: the bits left over at the end must be zero.
    //
    // 32 MAC bytes encode as 43 characters, and the last character carries only
    // two significant bits — so without this, four different `mt` strings decode
    // to the same signature and all four verify. Not a forgery (the MAC still
    // has to match), but a signature with four spellings is a signature that
    // cannot be compared, logged or deduplicated as a string, and the "flip the
    // last character" tamper test silently passed against an unchanged MAC.
    if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) return std::nullopt;

    return out;
}

void append_field(std::string& buf, const std::string& s) {
    const uint32_t n = static_cast<uint32_t>(s.size());
    for (int i = 3; i >= 0; --i) buf.push_back(static_cast<char>((n >> (i * 8)) & 0xFF));
    buf += s;
}

// See MediaTicket.h for why this is length-prefixed.
std::string mac_input(const std::string& server_name, const std::string& media_id,
                      const std::string& user_id, int64_t exp) {
    std::string buf(kSalt);
    append_field(buf, media_id);
    append_field(buf, user_id);
    append_field(buf, server_name);
    const uint64_t e = static_cast<uint64_t>(exp);
    for (int i = 7; i >= 0; --i) buf.push_back(static_cast<char>((e >> (i * 8)) & 0xFF));
    return buf;
}

std::vector<unsigned char> mac(const std::vector<unsigned char>& key, const std::string& input) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(input.data()), input.size(),
              out, &out_len)) {
        throw std::runtime_error("media ticket: HMAC failed");
    }
    return std::vector<unsigned char>(out, out + out_len);
}

} // namespace

std::vector<unsigned char> derive_key(const std::string& instance_secret,
                                      const std::string& server_name) {
    if (instance_secret.empty()) {
        throw std::runtime_error("media_ticket::derive_key: empty instance secret");
    }

    auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw std::runtime_error("media_ticket::derive_key: HKDF context allocation failed");
    }

    std::vector<unsigned char> key(kKeyLen);
    size_t out_len = kKeyLen;
    if (EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(kSalt),
                                    static_cast<int>(sizeof(kSalt) - 1)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(),
                                   reinterpret_cast<const unsigned char*>(instance_secret.data()),
                                   static_cast<int>(instance_secret.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(server_name.data()),
                                    static_cast<int>(server_name.size())) <= 0 ||
        EVP_PKEY_derive(ctx.get(), key.data(), &out_len) <= 0 ||
        out_len != kKeyLen) {
        throw std::runtime_error("media_ticket::derive_key: HKDF derivation failed");
    }
    return key;
}

std::string mint(const std::vector<unsigned char>& key,
                 const std::string& server_name,
                 const std::string& media_id,
                 const std::string& user_id,
                 int64_t exp_unix_seconds) {
    const auto sig = mac(key, mac_input(server_name, media_id, user_id, exp_unix_seconds));
    return b64url_encode(user_id) + "." + b64url_encode(sig.data(), sig.size());
}

std::optional<std::string> verify(const std::vector<unsigned char>& key,
                                  const std::string& server_name,
                                  const std::string& media_id,
                                  const std::string& mt,
                                  int64_t exp_unix_seconds,
                                  int64_t now_unix_seconds) {
    // Expiry first: it is the cheap check and the one that must never be
    // skipped. No grace period. A ticket is minted by this same server moments
    // before use, so there is no clock to be generous about.
    if (exp_unix_seconds <= now_unix_seconds) return std::nullopt;
    if (exp_unix_seconds - now_unix_seconds > kMaxSkewSeconds) return std::nullopt;

    const auto dot = mt.find('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= mt.size()) return std::nullopt;

    auto user_id = b64url_decode(mt.substr(0, dot));
    auto sig = b64url_decode(mt.substr(dot + 1));
    if (!user_id || !sig || user_id->empty()) return std::nullopt;

    const auto expected = mac(key, mac_input(server_name, media_id, *user_id, exp_unix_seconds));
    if (sig->size() != expected.size()) return std::nullopt;
    if (CRYPTO_memcmp(sig->data(), expected.data(), expected.size()) != 0) return std::nullopt;

    return user_id;
}

std::optional<int64_t> parse_exp(const std::string& raw) {
    if (raw.empty() || raw.size() > 19) return std::nullopt;
    int64_t v = 0;
    for (char c : raw) {
        if (c < '0' || c > '9') return std::nullopt;
        v = v * 10 + (c - '0');
    }
    return v;
}

} // namespace bsfchat::media_ticket
