#include "auth/Permissions.h"

#include "core/Config.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>

#include <algorithm>
#include <limits>
#include <set>
#include <string>

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
        if (it == all_roles.end()) continue;
        // A role anyone may take confers no rank — see the header. Without
        // this, an opt-in role positioned anywhere above @everyone would be a
        // one-click immunity from moderation for every member of the server.
        if (it->self_assignable) continue;
        if (it->position > highest) highest = it->position;
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

// Is `a` the same role as `b` in every respect that CONFERS POWER?
//
// This is the predicate that decides whether an edit to a role above your own
// rank is a no-op you may submit (because you are echoing back a document you
// are not allowed to change) or a modification you may not. So it has to name
// every field that matters, and `self_assignable` matters most of all: without
// it here, a delegated MANAGE_ROLES holder could flip that one flag on the
// Admin role, leave its position and permissions untouched so this returned
// true, and turn "become an administrator" into a button every member has.
// Cosmetic fields (name, color, hoist, mentionable) are deliberately left out —
// they confer nothing, and treating a rename of a senior role as an escalation
// would only teach people to work around this check.
bool same_role(const ServerRole& a, const ServerRole& b) {
    return a.position == b.position && a.permissions == b.permissions
        && a.self_assignable == b.self_assignable;
}

// The permission bits @everyone carries, which is the ceiling a self-assignable
// role may reach. Absent @everyone, the ceiling is nothing: a document with no
// @everyone role is already broken, and the safe reading of a broken document
// is that no opt-in role may confer anything.
permission::Flags everyone_permissions(const std::vector<ServerRole>& roles) {
    const ServerRole* everyone = find_role(roles, permission::role_id::kEveryone);
    return everyone ? everyone->permissions : 0;
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

PermissionsEngine::RoleChangeVerdict PermissionsEngine::validate_role_document(
    const std::vector<ServerRole>& proposed) {
    if (proposed.size() > limits::kMaxRoles) {
        return {false, "A server may define at most " + std::to_string(limits::kMaxRoles)
                           + " roles"};
    }

    std::set<std::string> seen;
    for (const auto& role : proposed) {
        if (role.id.empty()) return {false, "A role must have an id"};
        if (!seen.insert(role.id).second) {
            return {false, "Duplicate role id: " + role.id};
        }
        if (role.name.size() > limits::kMaxRoleNameLength) {
            return {false, "Role name is too long"};
        }
        if (role.position < 0 || role.position > limits::kMaxRolePosition) {
            return {false, "Role position out of range"};
        }
    }

    // Every permission evaluation on the server reads @everyone, and the
    // containment rule below measures against it, so a document without one is
    // not a document with one fewer role — it is a server where nobody has any
    // default permission and every opt-in role's ceiling silently becomes zero.
    if (!find_role(proposed, permission::role_id::kEveryone)) {
        return {false, "The role list must contain the @everyone role; it cannot be deleted"};
    }

    // The containment rule. See the header: this is what makes `self_assignable`
    // safe to hand to a bot, and it binds administrators too.
    const permission::Flags ceiling = everyone_permissions(proposed);
    for (const auto& role : proposed) {
        if (!role.self_assignable) continue;
        if (role.id == permission::role_id::kEveryone) {
            // @everyone is not opt-in; every member already has it and nobody
            // may shed it. Marking it self-assignable would advertise a "leave
            // @everyone" button that, if the claim path ever honoured it, would
            // drop the holder out of every permission the server grants by
            // default.
            return {false, "The @everyone role cannot be self-assignable"};
        }
        const permission::Flags extra = role.permissions & ~ceiling;
        if (extra != 0) {
            return {false,
                    "A self-assignable role cannot grant permissions @everyone does not "
                    "already have (role '" + role.id + "' adds "
                        + permission::flags_to_hex(extra) + ")"};
        }
    }

    return {};
}

PermissionsEngine::RoleChangeVerdict PermissionsEngine::may_self_assign_role(
    const std::string& actor_id, const std::string& role_id) {
    const auto& all = server_roles();
    const ServerRole* role = find_role(all, role_id);
    if (!role) return {false, "Unknown role: " + role_id};

    if (role_id == permission::role_id::kEveryone) {
        return {false, "The @everyone role is not opt-in"};
    }
    if (!role->self_assignable) {
        return {false, "That role is not self-assignable"};
    }

    // Re-checked against the document AS IT STANDS, not trusted from the write
    // that created the role. The two checks answer different questions:
    // validate_role_document asks whether a document may be stored,
    // this asks whether a role may be handed out RIGHT NOW. They come apart
    // whenever @everyone is narrowed after the opt-in role was created, and
    // they would also come apart if a future path ever wrote the role document
    // without going through may_edit_role_definitions. The second reason is why
    // this is not redundant belt-and-braces: it is the check that is actually
    // standing between a member and a dangerous role, and it is one line.
    const permission::Flags extra = role->permissions & ~everyone_permissions(all);
    if (extra != 0) {
        return {false,
                "That role grants permissions beyond @everyone and cannot be self-assigned"};
    }

    return {};
}

PermissionsEngine::RoleChangeVerdict PermissionsEngine::may_edit_role_definitions(
    const std::string& actor_id, const std::vector<ServerRole>& proposed) {
    // FIRST, and before any exemption: the rules about what a role document may
    // say bind everyone who can write one.
    if (auto verdict = validate_role_document(proposed); !verdict) return verdict;

    if (is_server_actor(actor_id, config_)) return {};
    if (can(actor_id, std::string(), permission::kAdministrator)) return {};

    const int actor_pos = highest_role_position(actor_id);
    const auto& current = server_roles();
    // What the actor themselves may do, at server scope. A channel override
    // must have no say here; this is a question about the whole server.
    const permission::Flags actor_perms = compute(actor_id, std::string());

    for (const auto& role : proposed) {
        const ServerRole* existing = find_role(current, role.id);

        // Granting ADMINISTRATOR is granting everything, including the power
        // to undo this check. Only an administrator may do it.
        if (permission::has(role.permissions, permission::kAdministrator)
            && (!existing || !permission::has(existing->permissions, permission::kAdministrator))) {
            return {false, "Only an administrator may grant the Administrator permission"};
        }

        // YOU CANNOT PUT A PERMISSION ON A ROLE THAT YOU DO NOT HOLD YOURSELF.
        //
        // Without this, MANAGE_ROLES was a slower path to every other flag on
        // the server: a "builder" at position 10 holding nothing but
        // MANAGE_ROLES could define a role at position 9 carrying BAN_MEMBERS,
        // then assign it to themselves — may_assign_roles permits assigning
        // your own roles downward, and position 9 is below 10, so every check
        // on that path passes. The rank system was never the thing stopping
        // this; nothing was. The ADMINISTRATOR clause above is the same
        // sentence said about one bit, and it was the only bit it protected.
        //
        // Scoped to what the edit ADDS, so echoing back a role you may not
        // touch stays legal, and so does removing a permission from a role
        // (taking power away is not escalation).
        const permission::Flags before = existing ? existing->permissions : 0;
        const permission::Flags added = role.permissions & ~before;
        if ((added & ~actor_perms) != 0) {
            return {false, "You cannot grant a role a permission you do not hold yourself ("
                               + permission::flags_to_hex(added & ~actor_perms) + ")"};
        }

        // A role at or above your own rank may exist, but you may not touch
        // it — and you may not mint a new one there either.
        //
        // BOTH positions are checked, the proposed one and the one the role
        // holds today. Looking only at the proposed position left demotion
        // wide open: an actor at 10 could move the Admin role from 100 down to
        // 1, which took the `role.position >= actor_pos` branch out of play
        // entirely, and having demoted it they then outranked every
        // administrator and could strip the role off them. "You cannot delete
        // the role above you" was already written below for exactly this
        // reason; moving it is the same act performed gradually.
        const int effective_pos = existing ? std::max(role.position, existing->position)
                                           : role.position;
        if (effective_pos >= actor_pos) {
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
