#pragma once

#include <string>

namespace bsfchat {

// Simple password hashing using OpenSSL's SHA-256 with salt.
// In production, use bcrypt/argon2 — this is a lightweight MVP substitute.

std::string hash_password(const std::string& password, int cost = 12);
bool verify_password(const std::string& password, const std::string& hash);

} // namespace bsfchat
