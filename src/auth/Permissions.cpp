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

const std::vector<ServerRole>& PermissionsEngine::server_roles() {
    if (!server_roles_cache_) server_roles_cache_ = store_.get_server_roles();
    return *server_roles_cache_;
}

const std::vector<std::string>& PermissionsEngine::member_role_ids(const std::string& user_id) {
    auto it = member_roles_cache_.find(user_id);
    if (it != member_roles_cache_.end()) return it->second;
    auto [inserted, _] = member_roles_cache_.emplace(user_id, store_.get_member_role_ids(user_id));
    return inserted->second;
}

bool PermissionsEngine::is_direct_room(const std::string& room_id) {
    auto it = direct_room_cache_.find(room_id);
    if (it != direct_room_cache_.end()) return it->second;
    auto [inserted, _] = direct_room_cache_.emplace(room_id, store_.is_direct_room(room_id));
    return inserted->second;
}

permission::Flags PermissionsEngine::compute(const std::string& user_id, const std::string& room_id) {
    if (is_server_actor(user_id, config_)) return permission::kAllFlags;

    const auto& all_roles = server_roles();
    const auto& user_role_ids = member_role_ids(user_id);

    // Fallback: if the server hasn't been bootstrapped yet (no roles at all
    // and no member.roles events), grant the default @everyone permissions
    // so a fresh deployment still lets users see and send messages.
    if (all_roles.empty() && user_role_ids.empty()) {
        return permission::kEveryoneDefault;
    }

    auto user_roles = resolve_user_roles(all_roles, user_role_ids);

    // Base = OR of all role permission bitfields.
    permission::Flags base = 0;
    for (const auto& r : user_roles) base |= r.permissions;

    // Administrator short-circuit.
    if (permission::has(base, permission::kAdministrator)) return permission::kAllFlags;

    if (room_id.empty()) return base; // server-level check, no channel context

    auto overrides = store_.get_channel_overrides(room_id);

    // A DM has no channel access control, so it has no channel overrides —
    // enforced here rather than assumed. Its access control is that exactly two
    // people are in it and nobody is ever force-joined into one, which is what
    // lets m.direct be derived straight from membership and left unfiltered
    // (docs/membership-vs-visibility.md). An override on a DM is a second,
    // contradictory rule: a VIEW_CHANNEL deny would hide the room from
    // /joined_rooms and /sync while m.direct kept listing it.
    //
    // handle_set_state now refuses to WRITE one, which stops new ones. This is
    // the other half, and it is not belt-and-braces: a DM that already carries
    // an override from a build without that refusal could not be repaired once
    // it landed, because clearing an override means writing an empty one
    // through the route that now refuses. Enforcing the invariant where it is
    // READ makes every consumer — sync, listing, reading, voice, typing —
    // agree at once, instead of each one remembering the DM case.
    //
    // Ordered after get_channel_overrides so the extra lookup only happens for
    // a room that has overrides at all — which a DM never does once this holds,
    // and an ordinary public channel or a category never does either. A private
    // channel does, and pays one memoised indexed read per engine.
    if (!overrides.empty() && is_direct_room(room_id)) overrides.clear();

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

    const auto& all_roles = server_roles();
    const auto& ids = member_role_ids(user_id);
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

namespace {

const ServerRole* find_role(const std::vector<ServerRole>& roles, const std::string& id) {
    auto it = std::find_if(roles.begin(), roles.end(),
        [&](const ServerRole& r) { return r.id == id; });
    return it == roles.end() ? nullptr : &*it;
}

bool same_role(const ServerRole& a, const ServerRole& b) {
    return a.position == b.position && a.permissions == b.permissions;
}

} // namespace

PermissionsEngine::RoleChangeVerdict PermissionsEngine::may_assign_roles(
    const std::string& actor_id, const std::string& target_id,
    const std::vector<std::string>& new_role_ids) {
    if (is_server_actor(actor_id, config_)) return {};
    if (can(actor_id, std::string(), permission::kAdministrator)) return {};

    const int actor_pos = highest_role_position(actor_id);

    // You cannot rewrite the roles of someone who ranks at or above you.
    // Editing your OWN assignment is allowed, but only downward — the role
    // checks below are what stop it being a promotion.
    if (actor_id != target_id && !outranks(actor_id, target_id)) {
        return {false, "You cannot change the roles of a user ranked at or above you"};
    }

    const auto& all = server_roles();

    // Nothing at or above your own rank may be granted...
    for (const auto& id : new_role_ids) {
        if (id == permission::role_id::kEveryone) continue;
        const ServerRole* role = find_role(all, id);
        if (!role) return {false, "Unknown role: " + id};
        if (role->position >= actor_pos) {
            return {false, "You cannot assign a role ranked at or above your own"};
        }
    }

    // ...nor taken away. Otherwise a moderator could strip the owner's admin
    // role, which is the same escalation wearing a different hat.
    const auto& current = member_role_ids(target_id);
    for (const auto& id : current) {
        if (id == permission::role_id::kEveryone) continue;
        if (std::find(new_role_ids.begin(), new_role_ids.end(), id) != new_role_ids.end())
            continue;
        const ServerRole* role = find_role(all, id);
        if (role && role->position >= actor_pos) {
            return {false, "You cannot remove a role ranked at or above your own"};
        }
    }

    return {};
}

PermissionsEngine::RoleChangeVerdict PermissionsEngine::may_edit_role_definitions(
    const std::string& actor_id, const std::vector<ServerRole>& proposed) {
    if (is_server_actor(actor_id, config_)) return {};
    if (can(actor_id, std::string(), permission::kAdministrator)) return {};

    const int actor_pos = highest_role_position(actor_id);
    const auto& current = server_roles();

    for (const auto& role : proposed) {
        const ServerRole* existing = find_role(current, role.id);

        // Granting ADMINISTRATOR is granting everything, including the power
        // to undo this check. Only an administrator may do it.
        if (permission::has(role.permissions, permission::kAdministrator)
            && (!existing || !permission::has(existing->permissions, permission::kAdministrator))) {
            return {false, "Only an administrator may grant the Administrator permission"};
        }

        // A role at or above your own rank may exist, but you may not touch
        // it — and you may not mint a new one there either.
        if (role.position >= actor_pos) {
            if (!existing) {
                return {false, "You cannot create a role ranked at or above your own"};
            }
            if (!same_role(role, *existing)) {
                return {false, "You cannot modify a role ranked at or above your own"};
            }
        }
    }

    // Deleting the role above you is as good as modifying it.
    for (const auto& role : current) {
        if (role.position < actor_pos) continue;
        if (!find_role(proposed, role.id)) {
            return {false, "You cannot delete a role ranked at or above your own"};
        }
    }

    return {};
}

} // namespace bsfchat
