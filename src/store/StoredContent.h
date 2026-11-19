#pragma once

#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>

#include <vector>

namespace bsfchat {

// Readers for STORED documents, which may predate the shape checks on write
// (audit 3, fix-first #3). The protocol's from_json(ServerRole) reads fields
// with json::value(), which throws on a wrong type; one bad role in a legacy
// bsfchat.server.roles row used to throw out of every permission check on the
// server. Here a role that does not parse is skipped and the rest survive.
[[nodiscard]] inline std::vector<ServerRole> parse_server_roles_lenient(
    const nlohmann::json& doc) {
    std::vector<ServerRole> roles;
    if (!doc.is_object()) return roles;
    const auto it = doc.find("roles");
    if (it == doc.end() || !it->is_array()) return roles;
    for (const auto& rj : *it) {
        if (!rj.is_object()) continue;
        try {
            ServerRole role;
            from_json(rj, role);
            roles.push_back(std::move(role));
        } catch (const nlohmann::json::exception&) {
        }
    }
    return roles;
}

} // namespace bsfchat
