#pragma once

#include <bsfchat/Constants.h>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace bsfchat::permission_input {

// ── Permission values in a request body, checked BEFORE from_json ─────────
//
// Audit 2026-11-15 P-1: the protocol library's from_json for ServerRole
// (`permissions`) and ChannelPermissionOverride (`allow`, `deny`) tests
// is_number_integer() and then reads get<uint64_t>(), so `-1` parses as all
// ones — every permission, ADMINISTRATOR included. A string it cannot parse
// reads as 0, so a typo silently strips a role. The fix belongs in protocol;
// until it ships, every server path that hands a CLIENT's JSON to those
// from_json overloads checks the shape here first and answers 400.
//
// Accepted: a non-negative JSON integer, or "0x"/"0X" (optional) followed by
// 1-16 hex digits and nothing else — the form flags_to_hex writes.
inline bool is_strict_hex_flags(std::string_view v) {
    if (v.size() >= 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) v.remove_prefix(2);
    if (v.empty() || v.size() > 16) return false;
    for (const char c : v) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

inline bool is_permission_value(const nlohmann::json& v) {
    if (v.is_number_unsigned()) return true;
    if (v.is_string()) return is_strict_hex_flags(v.get_ref<const std::string&>());
    return false;
}

// For a bsfchat.server.roles document. Also checks the fields whose wrong type
// would make from_json throw or narrow silently (an out-of-int position wraps
// into range), so the caller can say which field was wrong rather than
// "Malformed role list".
inline std::optional<std::string> role_document_error(const nlohmann::json& content) {
    if (!content.is_object()) return "The role list must be a JSON object";
    if (!content.contains("roles")) return std::nullopt;
    const auto& roles = content["roles"];
    if (!roles.is_array()) return "roles must be an array";
    for (const auto& r : roles) {
        if (!r.is_object()) return "Each role must be a JSON object";
        if (r.contains("permissions") && !is_permission_value(r["permissions"])) {
            return "permissions must be a hex string or a non-negative integer";
        }
        if (r.contains("position")) {
            const auto& p = r["position"];
            if (!p.is_number_integer() || p.get<std::int64_t>() < 0 ||
                p.get<std::int64_t>() > limits::kMaxRolePosition) {
                return "position must be an integer from 0 to " +
                       std::to_string(limits::kMaxRolePosition);
            }
        }
    }
    return std::nullopt;
}

// For a bsfchat.channel.permissions override.
inline std::optional<std::string> channel_override_error(const nlohmann::json& content) {
    if (!content.is_object()) return "A channel permission override must be a JSON object";
    for (const char* key : {"allow", "deny"}) {
        if (content.contains(key) && !is_permission_value(content[key])) {
            return std::string(key) + " must be a hex string or a non-negative integer";
        }
    }
    return std::nullopt;
}

} // namespace bsfchat::permission_input
