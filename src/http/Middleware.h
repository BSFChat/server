#pragma once

#include <optional>
#include <string>

namespace bsfchat {

class SqliteStore;

// Extract access token from Authorization header
// Returns the token string if present, or nullopt
std::optional<std::string> extract_access_token(const std::string& auth_header);

// Validate an access token and return the associated user_id
// Returns nullopt if the token is invalid
std::optional<std::string> authenticate(SqliteStore& store, const std::string& auth_header);

} // namespace bsfchat
