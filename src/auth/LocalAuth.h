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

// A PBKDF2 hash at `cost` of a value nobody can supply — 32 CSPRNG bytes,
// generated once and never written down.
//
// Exists so that "no such user" costs the same as "wrong password". Without
// it, /login short-circuits before verify_password whenever get_password_hash
// returns nothing, so a request for an account that does not exist comes back
// in microseconds while a request for one that does spends half a second in
// PBKDF2 at cost 19. That difference is not subtle and does not need
// statistics to read: it is a remote account-enumeration oracle sitting behind
// an endpoint whose error message was carefully written not to be one.
//
// Verify a submitted password against this when the account is missing (or has
// no usable hash) and throw the result away. The cost must be the one real
// accounts are hashed at, or the timings still differ.
//
// Cached per cost: building it is itself a PBKDF2, and doing that per request
// would hand back an even louder signal than the one being closed.
const std::string& dummy_password_hash(int cost);

// Password rules beyond the length minimum, applied identically at
// registration and at password change. Returns the message to send the user,
// or nullopt when the password is acceptable.
//
// `localpart` is the account's own username, because the single most likely
// password for account "mike" is some arrangement of "mike". Deliberately
// small and dependency-free: a real breach-corpus check (HIBP's k-anonymity
// API, or a multi-megabyte local list) is a different kind of change, with a
// network dependency or a data file to ship and update. This catches the
// passwords that a credential-stuffing list tries in its first few hundred
// guesses, which is the population that the per-account lockout alone does not
// protect — a sprayer trying ONE common password against many accounts never
// trips a per-account counter.
std::optional<std::string> password_policy_error(const std::string& password,
                                                 const std::string& localpart);

// Generous: the shipped client sends "DEVICE_" plus 10 characters. This is a
// storage bound, not a format rule.
inline constexpr size_t kMaxDeviceIdLength = 255;

// Validates a client-supplied device id before it reaches storage. Returns the
// rejection message, or nullopt when it is usable.
//
// device_id arrives straight from the request body and went to the database
// unexamined: unbounded length (a row per login, kept for the token's 90-day
// life) and any bytes at all, including the newlines that let a device id
// forge extra lines in the server log. Bounded and stripped of control
// characters; everything else a real client might send still passes, because
// rejecting a device id a client already persisted would lock that client out
// of logging in at all.
std::optional<std::string> device_id_error(const std::string& device_id);

} // namespace bsfchat
