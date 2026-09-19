#include "auth/LocalAuth.h"

#include <bsfchat/Identifiers.h>

// The single-SHA-256 storage of access tokens in this file is only sound because
// the tokens are high-entropy: see hash_access_token() in the header. They were
// not. generate_access_token() drew from an mt19937 seeded with one 32-bit
// value, so every token this server ever issued was one of 2^32 strings — about
// 1.3 core-hours to enumerate — and hashing them changed nothing about that.
//
// The fix lives in the protocol library (protocol 671e803). This guard exists
// because the server does not always build against the protocol checkout
// sitting next to it: with no local copy present, cmake/Dependencies.cmake
// fetches protocol `main` from GitHub, so a green build is not by itself
// evidence of which version went in. Fail loudly here rather than ship a server
// that issues guessable bearer tokens under a comment promising 256 bits.
#ifndef BSFCHAT_PROTOCOL_CSPRNG_IDENTIFIERS
#error "This server requires a protocol library whose identifier generators use the CSPRNG. \
Update the bsfchat-protocol dependency: before that change, access and refresh tokens had \
32 bits of entropy regardless of their length."
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace bsfchat {

namespace {

std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::ostringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

std::string pbkdf2_hash(const std::string& password, const unsigned char* salt, size_t salt_len, int iterations) {
    unsigned char hash[32]; // SHA-256 output
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                            salt, static_cast<int>(salt_len),
                            iterations, EVP_sha256(), 32, hash) != 1) {
        throw std::runtime_error("PBKDF2 hash failed");
    }
    return bytes_to_hex(hash, 32);
}

} // namespace

std::string hash_password(const std::string& password, int cost) {
    // Generate 16-byte random salt
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }

    int iterations = 1 << cost; // 2^cost iterations
    std::string salt_hex = bytes_to_hex(salt, sizeof(salt));
    std::string hash_hex = pbkdf2_hash(password, salt, sizeof(salt), iterations);

    // Format: $pbkdf2$cost$salt_hex$hash_hex
    return "$pbkdf2$" + std::to_string(cost) + "$" + salt_hex + "$" + hash_hex;
}

std::optional<int> password_hash_cost(const std::string& stored_hash) {
    if (stored_hash.size() < 8 || stored_hash.compare(0, 8, "$pbkdf2$") != 0) return std::nullopt;
    size_t pos2 = stored_hash.find('$', 8);
    if (pos2 == std::string::npos) return std::nullopt;
    try {
        return std::stoi(stored_hash.substr(8, pos2 - 8));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool verify_password(const std::string& password, const std::string& stored_hash) {
    // Parse: $pbkdf2$cost$salt_hex$hash_hex
    if (stored_hash.size() < 8 || stored_hash.compare(0, 8, "$pbkdf2$") != 0) return false;

    size_t pos1 = 8;
    size_t pos2 = stored_hash.find('$', pos1);
    if (pos2 == std::string::npos) return false;

    int cost = 0;
    try {
        cost = std::stoi(stored_hash.substr(pos1, pos2 - pos1));
    } catch (const std::exception&) {
        return false;
    }
    // Guard against a hostile or corrupt stored value turning verification
    // into an unbounded amount of work (or into UB via a shift overflow).
    if (cost < 1 || cost > 24) return false;

    size_t pos3 = stored_hash.find('$', pos2 + 1);
    if (pos3 == std::string::npos) return false;

    std::string salt_hex = stored_hash.substr(pos2 + 1, pos3 - pos2 - 1);
    std::string expected_hash = stored_hash.substr(pos3 + 1);
    if (salt_hex.empty() || salt_hex.size() % 2 != 0) return false;

    auto salt_bytes = hex_to_bytes(salt_hex);
    int iterations = 1 << cost;
    std::string computed_hash = pbkdf2_hash(password, salt_bytes.data(), salt_bytes.size(), iterations);

    // Constant-time: std::string::operator== short-circuits on the first
    // differing byte, which leaks how much of the hash a guess got right.
    if (computed_hash.size() != expected_hash.size()) return false;
    return CRYPTO_memcmp(computed_hash.data(), expected_hash.data(),
                         computed_hash.size()) == 0;
}

std::string hash_access_token(const std::string& token) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(token.data(), token.size(), md, &len, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("SHA-256 of access token failed");
    }
    return bytes_to_hex(md, len);
}

} // namespace bsfchat
