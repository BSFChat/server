#pragma once

#include <optional>
#include <string>

namespace bsfchat {

// Password hashing using PBKDF2-HMAC-SHA256.
// Stored format: $pbkdf2$<cost>$<salt_hex>$<hash_hex>, where the iteration
// count is 2^cost. The cost travels with the hash, so raising the default
// leaves every existing hash verifiable; AuthHandler re-hashes at the next
// successful login when a stored hash is below the configured cost.

// `cost` is a power of two: iterations = 2^cost. 19 => 524,288, in line with
// current OWASP guidance. The old default of 12 gave 4,096.
std::string hash_password(const std::string& password, int cost = 19);
bool verify_password(const std::string& password, const std::string& hash);

// Cost factor recorded in a stored hash, or nullopt if it isn't a hash this
// module produced. Used to decide whether to transparently upgrade it.
std::optional<int> password_hash_cost(const std::string& stored_hash);

// Digest used to store access/refresh tokens at rest, as lowercase hex.
//
// Tokens are bearer secrets: a database dump used to hand an attacker a live
// session for every logged-in user, forever. They are now only ever stored
// hashed.
//
// A single unsalted SHA-256 — NOT the PBKDF2 used for passwords — is
// deliberate, and the reasoning matters:
//   * generate_access_token() returns 43 base64 characters of CSPRNG output
//     (~256 bits). There is no low-entropy secret to brute-force, so the
//     iteration count that protects a human-chosen password buys nothing here.
//   * the digest is computed on EVERY authenticated request and is the primary
//     key we look tokens up by. A 500k-iteration KDF per request would be a
//     self-inflicted denial of service, and a per-row salt would make the
//     lookup a full table scan instead of an index probe.
// Unsalted is safe for the same reason: identical tokens never occur, so
// there is nothing for a precomputed table to attack.
std::string hash_access_token(const std::string& token);

} // namespace bsfchat
