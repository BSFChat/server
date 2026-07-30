#include "http/Middleware.h"
#include "store/SqliteStore.h"

namespace bsfchat {

std::optional<std::string> extract_access_token(const std::string& auth_header) {
    const std::string prefix = "Bearer ";
    if (auth_header.size() > prefix.size() &&
        auth_header.substr(0, prefix.size()) == prefix) {
        return auth_header.substr(prefix.size());
    }
    return std::nullopt;
}

std::optional<std::string> authenticate(SqliteStore& store, const std::string& auth_header) {
    auto token = extract_access_token(auth_header);
    if (!token) return std::nullopt;
    return store.get_user_by_token(*token);
}

MatrixError auth_error(const std::string& auth_header) {
    if (extract_access_token(auth_header)) {
        return MatrixError::unknown_token("Access token is invalid or has expired");
    }
    return MatrixError::missing_token();
}

} // namespace bsfchat
