#include "sync/SyncToken.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace bsfchat::sync_token {
namespace {

constexpr char kSalt[] = "bsfchat/sync-token/v1";
constexpr size_t kKeyLen = 32;   // AES-256
constexpr size_t kBlockLen = 16; // one AES block: 8 bytes position + 8 bytes tag

// The minted prefix. One character would do; two keeps it obviously distinct
// from the legacy "s" form at a glance in a log or a bug report.
constexpr char kPrefix[] = "t_";
constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;

// Domain separation for the user tag, so the tag is not a value that could also
// be produced by any other HMAC this key is ever used for.
constexpr char kTagLabel[] = "bsfchat/sync-token/user/v1";

// The tag is truncated to fill the second half of the block. 64 bits is not a
// collision bound here — it is a rejection bound for a token presented by the
// wrong account, and the wrong account gets one guess per request.
constexpr size_t kTagLen = 8;

std::vector<unsigned char> hkdf(const std::string& ikm, const std::string& info) {
    auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw std::runtime_error("sync_token::derive_key: HKDF context allocation failed");
    }

    std::vector<unsigned char> key(kKeyLen);
    size_t out_len = kKeyLen;
    if (EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(kSalt),
                                    static_cast<int>(sizeof(kSalt) - 1)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(),
                                   reinterpret_cast<const unsigned char*>(ikm.data()),
                                   static_cast<int>(ikm.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(info.data()),
                                    static_cast<int>(info.size())) <= 0 ||
        EVP_PKEY_derive(ctx.get(), key.data(), &out_len) <= 0 ||
        out_len != kKeyLen) {
        throw std::runtime_error("sync_token::derive_key: HKDF derivation failed");
    }
    return key;
}

// Length-prefixed, so the encoding is injective: without it a label ending in
// digits and a user id beginning with them could pack identically.
void user_tag(const std::vector<unsigned char>& key, const std::string& user_id,
              unsigned char* out /* kTagLen bytes */) {
    std::string input(kTagLabel);
    const uint32_t n = static_cast<uint32_t>(user_id.size());
    for (int i = 3; i >= 0; --i) input.push_back(static_cast<char>((n >> (i * 8)) & 0xFF));
    input += user_id;

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(input.data()), input.size(),
              mac, &mac_len) ||
        mac_len < kTagLen) {
        throw std::runtime_error("sync_token: HMAC failed");
    }
    std::memcpy(out, mac, kTagLen);
}

// One AES-256 block, no mode and no padding — "apply the permutation once".
// ECB is exactly right and exactly once here: there is a single block, so every
// property ECB is rightly criticised for (identical plaintext blocks producing
// identical ciphertext blocks) is the DETERMINISM this deliberately wants, and
// there is no second block for it to leak across.
void aes_block(const std::vector<unsigned char>& key, const unsigned char* in,
               unsigned char* out, bool encrypt) {
    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("sync_token: cipher context allocation failed");

    const int ok = encrypt
        ? EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ecb(), nullptr, key.data(), nullptr)
        : EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_ecb(), nullptr, key.data(), nullptr);
    if (ok != 1) throw std::runtime_error("sync_token: cipher init failed");
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    int len = 0;
    const int step = encrypt
        ? EVP_EncryptUpdate(ctx.get(), out, &len, in, static_cast<int>(kBlockLen))
        : EVP_DecryptUpdate(ctx.get(), out, &len, in, static_cast<int>(kBlockLen));
    if (step != 1 || len != static_cast<int>(kBlockLen)) {
        throw std::runtime_error("sync_token: block transform failed");
    }
    // No *_Final: padding is off and the input is exactly one block, so there
    // is nothing left to flush and Final would only re-report the same length.
}

std::string to_hex(const unsigned char* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

// Lowercase hex only. Accepting uppercase would give every token a second
// spelling that decodes to the same bytes — harmless for verification, but a
// token is compared as a STRING by the client's no-progress guard, so two
// spellings of one position would read as progress.
bool from_hex(const std::string& s, unsigned char* out, size_t out_len) {
    if (s.size() != out_len * 2) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (size_t i = 0; i < out_len; ++i) {
        const int hi = nibble(s[i * 2]);
        const int lo = nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

// THE LEGACY FORM. "s" followed by decimal digits, accepted on read only.
// See SyncToken.h for when this and its tests get deleted.
std::optional<int64_t> parse_legacy(const std::string& token) {
    if (token.size() < 2 || token[0] != 's') return std::nullopt;
    // Strict: digits only, no sign, no whitespace, and short enough that the
    // accumulation below cannot overflow. std::stoll used to throw out of the
    // handler on "sabc" and on "s99999999999999999999".
    if (token.size() > 19) return std::nullopt;
    int64_t v = 0;
    for (size_t i = 1; i < token.size(); ++i) {
        const char c = token[i];
        if (c < '0' || c > '9') return std::nullopt;
        v = v * 10 + (c - '0');
    }
    return v;
}

} // namespace

std::vector<unsigned char> derive_key(const std::string& instance_secret,
                                      const std::string& server_name) {
    if (instance_secret.empty()) {
        throw std::runtime_error("sync_token::derive_key: empty instance secret");
    }
    return hkdf(instance_secret, server_name);
}

std::string mint(const std::vector<unsigned char>& key,
                 const std::string& user_id,
                 int64_t position) {
    // Negative positions are not a thing on this stream; clamp rather than
    // encode a value no reader could act on.
    if (position < 0) position = 0;

    unsigned char block[kBlockLen];
    const uint64_t p = static_cast<uint64_t>(position);
    for (int i = 7; i >= 0; --i) block[7 - i] = static_cast<unsigned char>((p >> (i * 8)) & 0xFF);
    user_tag(key, user_id, block + 8);

    unsigned char out[kBlockLen];
    aes_block(key, block, out, /*encrypt=*/true);
    return std::string(kPrefix) + to_hex(out, kBlockLen);
}

std::optional<int64_t> parse(const std::vector<unsigned char>& key,
                             const std::string& user_id,
                             const std::string& token) {
    if (token.compare(0, kPrefixLen, kPrefix) != 0) return parse_legacy(token);

    unsigned char cipher[kBlockLen];
    if (!from_hex(token.substr(kPrefixLen), cipher, kBlockLen)) return std::nullopt;

    unsigned char block[kBlockLen];
    aes_block(key, cipher, block, /*encrypt=*/false);

    unsigned char expected[kTagLen];
    user_tag(key, user_id, expected);
    // Constant-time, as a habit rather than because a timing oracle on a value
    // that grants nothing would be worth much.
    if (CRYPTO_memcmp(block + 8, expected, kTagLen) != 0) return std::nullopt;

    uint64_t p = 0;
    for (size_t i = 0; i < 8; ++i) p = (p << 8) | block[i];
    // Only reachable from a token this server minted, which clamps at mint
    // time — so this is the guard against a corrupted row rather than a caller.
    if (p > static_cast<uint64_t>(INT64_MAX)) return std::nullopt;
    return static_cast<int64_t>(p);
}

} // namespace bsfchat::sync_token
