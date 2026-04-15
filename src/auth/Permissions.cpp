#include "auth/Permissions.h"

#include "core/Config.h"
#include "store/SqliteStore.h"

#include <algorithm>
#include <limits>

namespace bsfchat {

namespace {

bool is_server_actor(const std::string& user_id, const Config& config) {
    // Internal writes from the server go through this synthetic user; grant
    // ADMINISTRATOR unconditionally so bootstrap/migration events succeed.
    return user_id == "@server:" + config.server_name;
}

// Sort roles the user has, by position ascending (low → high). The effective
// permissions are then computed by OR'ing left-to-right (order doesn't matter
// for the base OR, but overrides are applied in this order).
std::vector<ServerRole> resolve_user_roles(
    const std::vector<ServerRole>& all_roles,
    const std::vector<std::string>& user_role_ids) {
    std::vector<ServerRole> out;
    out.reserve(user_role_ids.size() + 1);
    // @everyone is implicit — always applied first, regardless of membership.
    auto everyone = std::find_if(all_roles.begin(), all_roles.end(),
        [](const ServerRole& r) { return r.id == permission::role_id::kEveryone; });
    if (everyone != all_roles.end()) out.push_back(*everyone);

    for (const auto& id : user_role_ids) {
        if (id == permission::role_id::kEveryone) continue;
        auto it = std::find_if(all_roles.begin(), all_roles.end(),
            [&](const ServerRole& r) { return r.id == id; });
        if (it != all_roles.end()) out.push_back(*it);
    }

    std::sort(out.begin(), out.end(), [](const ServerRole& a, const ServerRole& b) {
        return a.position < b.position;
    });
    return out;
}

} // namespace

PermissionsEngine::PermissionsEngine(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {}

permission::Flags PermissionsEngine::compute(const std::string& user_id, const std::string& room_id) {
    if (is_server_actor(user_id, config_)) return permission::kAllFlags;

    auto all_roles = store_.get_server_roles();
    auto user_role_ids = store_.get_member_role_ids(user_id);
    auto user_roles = resolve_user_roles(all_roles, user_role_ids);

    // Base = OR of all role permission bitfields.
    permission::Flags base = 0;
    for (const auto& r : user_roles) base |= r.permissions;

    // Administrator short-circuit.
    if (permission::has(base, permission::kAdministrator)) return permission::kAllFlags;

    if (room_id.empty()) return base; // server-level check, no channel context

    auto overrides = store_.get_channel_overrides(room_id);

    auto apply = [&](const std::string& key) {
        auto it = overrides.find(key);
        if (it == overrides.end()) return;
        base = (base & ~it->second.deny) | it->second.allow;
    };

    // 1. @everyone override.
    apply(std::string("role:") + permission::role_id::kEveryone);
    // 2. Each role's override, in position order (low → high).
    for (const auto& r : user_roles) {
        if (r.id == permission::role_id::kEveryone) continue;
        apply("role:" + r.id);
    }
    // 3. User-specific override.
    apply("user:" + user_id);

    return base;
}

int PermissionsEngine::highest_role_position(const std::string& user_id) {
    if (is_server_actor(user_id, config_)) return std::numeric_limits<int>::max();

    auto all_roles = store_.get_server_roles();
    auto ids = store_.get_member_role_ids(user_id);
    int highest = 0;
    for (const auto& id : ids) {
        auto it = std::find_if(all_roles.begin(), all_roles.end(),
            [&](const ServerRole& r) { return r.id == id; });
        if (it != all_roles.end() && it->position > highest) highest = it->position;
    }
    return highest;
}

bool PermissionsEngine::outranks(const std::string& actor_id, const std::string& target_id) {
    if (is_server_actor(actor_id, config_)) return true;
    return highest_role_position(actor_id) > highest_role_position(target_id);
}

} // namespace bsfchat
