#include "auth/LocalAuth.h"

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

bool verify_password(const std::string& password, const std::string& stored_hash) {
    // Parse: $pbkdf2$cost$salt_hex$hash_hex
    if (stored_hash.substr(0, 8) != "$pbkdf2$") return false;

    size_t pos1 = 8;
    size_t pos2 = stored_hash.find('$', pos1);
    if (pos2 == std::string::npos) return false;

    int cost = std::stoi(stored_hash.substr(pos1, pos2 - pos1));
    size_t pos3 = stored_hash.find('$', pos2 + 1);
    if (pos3 == std::string::npos) return false;

    std::string salt_hex = stored_hash.substr(pos2 + 1, pos3 - pos2 - 1);
    std::string expected_hash = stored_hash.substr(pos3 + 1);

    auto salt_bytes = hex_to_bytes(salt_hex);
    int iterations = 1 << cost;
    std::string computed_hash = pbkdf2_hash(password, salt_bytes.data(), salt_bytes.size(), iterations);

    return computed_hash == expected_hash;
}

} // namespace bsfchat
