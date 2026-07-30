#pragma once

#include <bsfchat/ErrorCodes.h>

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

// The 401 body to send when authenticate() failed.
//
// Distinguishes "no token was supplied" (M_MISSING_TOKEN) from "a token was
// supplied but is not valid" (M_UNKNOWN_TOKEN). Every handler used to answer
// M_MISSING_TOKEN for both, which was merely untidy while tokens lived forever
// — now that they expire and can be revoked, it is the difference between a
// client knowing it must re-authenticate and a client retrying a dead token
// forever. The desktop client already reasons about M_UNKNOWN_TOKEN
// specifically (see client SyncBackoff::indicatesRejectedSinceToken).
MatrixError auth_error(const std::string& auth_header);

} // namespace bsfchat
