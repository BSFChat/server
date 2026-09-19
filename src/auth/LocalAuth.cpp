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

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>

// The single-SHA-256 storage of access tokens in this file is only sound
// because the tokens are high-entropy: see hash_access_token() in the header.
// They were not. generate_access_token() drew from an mt19937 seeded with one
// 32-bit value, so every token the server ever issued was one of 2^32 strings
// — about 1.3 core-hours to enumerate — and hashing them changed nothing about
// that.
//
// The fix lives in the protocol library. This guard exists because the server
// does not always build against the protocol checkout sitting next to it: with
// no local copy present, CMake fetches protocol `main` from GitHub, so a green
// build is not evidence of which version went in. Fail here instead of
// shipping a server that issues guessable bearer tokens under a comment
// promising 256 bits.
#ifndef BSFCHAT_PROTOCOL_CSPRNG_IDENTIFIERS
#error "This server requires a protocol library whose identifier generators use the CSPRNG. \
Update the bsfchat-protocol dependency: before that change, access and refresh tokens had \
32 bits of entropy regardless of their length."
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string_view>
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

const std::string& dummy_password_hash(int cost) {
    static std::mutex cache_mutex;
    static std::map<int, std::string> cache;

    std::lock_guard lock(cache_mutex);
    if (auto it = cache.find(cost); it != cache.end()) return it->second;

    // Random, not a constant: a fixed string in the binary would let anyone
    // with a copy of the server recognise the dummy hash. Nothing ever needs
    // to verify against it, so it is discarded the moment it is hashed.
    unsigned char noise[32];
    if (RAND_bytes(noise, sizeof(noise)) != 1) {
        throw std::runtime_error("Failed to generate dummy password material");
    }
    auto hashed = hash_password(
        std::string(reinterpret_cast<const char*>(noise), sizeof(noise)), cost);
    return cache.emplace(cost, std::move(hashed)).first->second;
}

std::optional<std::string> password_policy_error(const std::string& password,
                                                 const std::string& localpart) {
    if (password.size() < limits::kMinPasswordLength) {
        return "Password must be at least " + std::to_string(limits::kMinPasswordLength) +
               " characters";
    }

    const auto lower = [](std::string v) {
        std::transform(v.begin(), v.end(), v.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return v;
    };
    const std::string pw = lower(password);
    const std::string user = lower(localpart);

    // Anything built around the username. The length floor is what keeps this
    // proportionate: a two-letter username would otherwise veto a large share
    // of perfectly good passwords for containing those two letters in a row.
    if (!user.empty() && pw == user) {
        return "Password must not be your username";
    }
    if (user.size() >= 4 && pw.find(user) != std::string::npos) {
        return "Password must not contain your username";
    }

    // The head of every credential-stuffing list, filtered to entries that can
    // actually reach this check — the 8-character minimum has already refused
    // "123456", "qwerty" and the rest of the short classics, so listing them
    // would be decoration. Kept deliberately short: past the first few hundred
    // guesses the lockout and rate limits are the control that matters, and a
    // longer list here buys less than it costs to carry.
    static constexpr std::array<std::string_view, 40> kCommon{{
        "password", "password1", "password123", "passw0rd", "p@ssw0rd", "password!",
        "12345678", "123456789", "1234567890", "87654321", "11111111", "00000000",
        "qwerty123", "qwertyui", "qwertyuiop", "1q2w3e4r", "1qaz2wsx", "zaq12wsx",
        "asdfghjk", "asdfghjkl", "abcd1234", "1234abcd", "aaaaaaaa", "abc12345",
        "iloveyou", "princess", "sunshine", "football", "baseball", "superman",
        "starwars", "whatever", "computer", "trustno1", "letmein1", "welcome1",
        "admin123", "changeme", "monkey123", "dragon123",
    }};
    if (std::find(kCommon.begin(), kCommon.end(), pw) != kCommon.end()) {
        return "That password is one of the most common in use; choose another";
    }

    // The product's own name is to this server what "password" is to the
    // world: the first thing a human reaches for and the first thing an
    // attacker tries against THIS deployment specifically.
    if (pw.find("bsfchat") != std::string::npos || pw.find("gamechat") != std::string::npos) {
        return "Password must not contain the name of this service";
    }

    return std::nullopt;
}

std::optional<std::string> device_id_error(const std::string& device_id) {
    // Empty is not an error at the call sites — they substitute a generated id
    // — but an explicitly empty string is a client bug worth naming rather
    // than silently treating as "not supplied".
    if (device_id.empty()) {
        return "device_id must not be empty";
    }
    if (device_id.size() > kMaxDeviceIdLength) {
        return "device_id must be at most " + std::to_string(kMaxDeviceIdLength) +
               " characters";
    }
    for (unsigned char c : device_id) {
        // Control characters only. NOT a charset allowlist: a device id is an
        // opaque client-chosen string, and a client that already persisted one
        // containing, say, a non-ASCII character would be unable to log in at
        // all if this were stricter. Newlines are the part that matters — they
        // are what let a device id forge additional lines in the server log.
        if (c < 0x20 || c == 0x7F) {
            return "device_id must not contain control characters";
        }
    }
    return std::nullopt;
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
