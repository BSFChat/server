#include "auth/Permissions.h"

#include "core/Config.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>

#include <algorithm>
#include <cstring>
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
//
// `implicit_everyone` is permission::inherits_everyone_role() for the account
// being evaluated — false for a bot, which does not get the server's default
// role handed to it. See that predicate for the whole argument. Here it changes
// exactly one thing: whether @everyone is added whatever the assignment says, or
// only when the assignment NAMES it. A bot given @everyone explicitly resolves
// it through the ordinary loop below and comes out identical to a member, which
// is what makes the upgrade invisible — every bot on a running server already
// holds it, written by bootstrap_roles at creation.
std::vector<ServerRole> resolve_user_roles(
    const std::vector<ServerRole>& all_roles,
    const std::vector<std::string>& user_role_ids,
    bool implicit_everyone) {
    std::vector<ServerRole> out;
    out.reserve(user_role_ids.size() + 1);
    // @everyone is implicit — always applied first, regardless of membership.
    if (implicit_everyone) {
        auto everyone = std::find_if(all_roles.begin(), all_roles.end(),
            [](const ServerRole& r) { return r.id == permission::role_id::kEveryone; });
        if (everyone != all_roles.end()) out.push_back(*everyone);
    }

    for (const auto& id : user_role_ids) {
        // Skipped only because it is already there. When it is not implicit,
        // an assignment naming @everyone resolves it like any other role.
        if (implicit_everyone && id == permission::role_id::kEveryone) continue;
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

    // Does the server's default role apply to this account at all? False for a
    // bot — see permission::inherits_everyone_role() for why, and note that it
    // is asked ONCE and used in both branches below. The fallback is not an
    // exception to the rule: it is the rule's most dangerous corner, because it
    // hands out kEveryoneDefault with no document to read it out of, which is
    // exactly the grant a scoped bot was not given.
    const bool implicit_everyone = permission::inherits_everyone_role(user_id);

    // Fallback: if the server hasn't been bootstrapped yet (no roles at all
    // and no member.roles events), grant the default @everyone permissions
    // so a fresh deployment still lets users see and send messages.
    if (all_roles.empty() && user_role_ids.empty()) {
        return implicit_everyone ? permission::kEveryoneDefault : 0;
    }

    auto user_roles = resolve_user_roles(all_roles, user_role_ids, implicit_everyone);

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

const std::vector<std::string>& PermissionsEngine::override_rooms() {
    if (!override_rooms_cache_) override_rooms_cache_ = store_.rooms_with_channel_overrides();
    return *override_rooms_cache_;
}

permission::Flags PermissionsEngine::channel_access_excess(const std::string& subject_id,
                                                           const std::string& actor_id) {
    // A SHORT-CIRCUIT FOR COST, NOT FOR CORRECTNESS, and worth labelling as
    // such so nobody defends it with a test that cannot exist. compute()
    // already returns kAllFlags for an administrator and for @server in every
    // room, so the loop below would reach zero on its own for both — these two
    // lines only stop it asking the database first. Deleting them changes no
    // answer, which is exactly why tests/e2e/mutate_containment.py does not
    // carry a mutation for them.
    if (is_server_actor(actor_id, config_)) return 0;
    if (can(actor_id, std::string(), permission::kAdministrator)) return 0;

    // The ROLE half of the difference, which this function is not about — see
    // the header. Subtracting it is what keeps "a moderator holding
    // KICK_MEMBERS may moderate a member holding MANAGE_MESSAGES" true, which
    // is the arrangement `position` exists to express.
    const permission::Flags role_gap =
        compute(subject_id, std::string()) & ~compute(actor_id, std::string());

    permission::Flags excess = 0;
    for (const auto& room_id : override_rooms()) {
        excess |= (compute(subject_id, room_id) & ~compute(actor_id, room_id)) & ~role_gap;
        // Nothing below can retract a bit, so stop as soon as every flag the
        // server defines is already accounted for. Mostly this just means the
        // common answer — a scoped bot with one channel — costs one query.
        if (excess == permission::kAllFlags) break;
    }
    return excess;
}

bool PermissionsEngine::outranks(const std::string& actor_id, const std::string& target_id) {
    if (is_server_actor(actor_id, config_)) return true;
    // The role half first: it is two in-memory lookups against data this
    // engine has almost certainly already read, and it is the half that
    // refuses most often. The channel half costs one query per configured
    // channel, so it is only asked once the cheap answer is "yes".
    if (highest_role_position(actor_id) <= highest_role_position(target_id)) return false;
    return channel_access_excess(target_id, actor_id) == 0;
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
//
// `mentionable` IS IN THIS LIST, and the reason is that it stopped being
// cosmetic. It used to be a flag nothing read, so listing it here would have
// been superstition; it is now the gate on who may ping a role
// (EventHandler.cpp, above MentionSet). Flipping it on a role above your rank
// grants no permission to anybody, which is why it looks like it belongs with
// name and color — but it removes a protection FROM A ROLE YOU MAY NOT TOUCH,
// which is the exact thing this predicate exists to prevent. Concretely: a
// delegated MANAGE_ROLES holder sets mentionable on @Admins, leaves everything
// else alone, and every member on the server can now ping the administrators
// at will. "Confers no permission" and "is safe for someone below the rank line
// to change" are different questions, and this check is asking the second one.
//
// Genuinely cosmetic fields (name, color, hoist) stay out: they confer nothing
// AND take nothing away, and treating a rename of a senior role as an
// escalation would only teach people to work around this check. Note this is
// not a tax on the delta endpoints — a caller not changing `mentionable` echoes
// the same value back and this still returns true. Only an actual flip is
// refused.
bool same_role(const ServerRole& a, const ServerRole& b) {
    return a.position == b.position && a.permissions == b.permissions
        && a.self_assignable == b.self_assignable
        && a.mentionable == b.mentionable;
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
    const std::string& actor_id, const std::string& role_id, bool adding) {
    // A BOT MAY NOT HAND ITSELF A ROLE, in either direction.
    //
    // This is the one path on the server that grants a role with no rank check
    // and no MANAGE_ROLES — deliberately, because an ordinary member sits at
    // position 0 and could otherwise never be given anything. It pays for that
    // bypass with the containment rule: a self-assignable role's permissions
    // are a subset of @everyone's. For a person that is exactly the right
    // trade. For a bot it is the whole of its scoping, because @everyone's
    // permissions are precisely the set a scoped bot was NOT given — so one
    // request against an opt-in role would take a bot from "may see three
    // channels" back to "may see and post in every channel on the server",
    // using nothing but the token it already holds.
    //
    // Refused by account kind rather than by making opt-in roles bot-proof,
    // because the roles are not the problem: a server is entitled to offer
    // "@announcements" to its members. What has no meaning is a bot opting in.
    // There is no human behind the token to click it, so every such request is
    // either a misconfigured integration or an attempt to grow.
    //
    // Removal is refused too, for the reason the header already gives about
    // removal generally: a role can carry channel DENY overrides, so "muted" is
    // a role, and a bot that could shed roles could unmute itself.
    if (bot::is_bot_user_id(actor_id)) {
        return {false, "A bot account cannot assign roles to itself; ask an administrator"};
    }

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
    //
    // ...and only when TAKING the role. Dropping one cannot grant anything, so
    // enforcing containment on removal only strands whoever already holds a
    // role that drifted — with no other way out, since self-assignment is the
    // only path that moves it.
    const permission::Flags extra = role->permissions & ~everyone_permissions(all);
    if (adding && extra != 0) {
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

PermissionsEngine::RoleChangeVerdict PermissionsEngine::may_write_channel_override(
    const std::string& actor_id, const std::string& room_id, const std::string& state_key,
    const ChannelPermissionOverride& before, const ChannelPermissionOverride& proposed) {
    // FIRST, and before any exemption — the two rules about what an override
    // is ALLOWED TO SAY, which bind administrators and the synthetic @server
    // actor as well, in the same way and for the same reason
    // validate_role_document binds them.

    // 1. It has to name somebody. compute() applies exactly two key shapes,
    //    "role:<id>" and "user:<id>", so anything else is a row that is stored,
    //    mirrored to every client through /sync, shown in the audit log as a
    //    permission change, and read by nothing. This route already refuses an
    //    unlisted EVENT TYPE rather than storing attacker-shaped state it does
    //    not understand; an unlisted STATE KEY on the one event whose whole
    //    content is a permission grant deserves the same closed table.
    if (state_key.rfind("user:", 0) != 0 && state_key.rfind("role:", 0) != 0) {
        return {false, "A channel override must name a user (\"user:<id>\") or a role "
                       "(\"role:<id>\")"};
    }

    // 2. ADMINISTRATOR is not a thing a channel can say. compute() takes the
    //    administrator short-circuit from the ROLE BASE, before a single
    //    override is applied, so the bit is inert here whoever writes it — its
    //    presence in an override is always either a misunderstanding of the
    //    model or somebody probing it. Refused only when the write ADDS it, so
    //    an override stored by an older build can still be edited or cleared
    //    and no channel is left unfixable.
    if (permission::has(proposed.allow, permission::kAdministrator) &&
        !permission::has(before.allow, permission::kAdministrator)) {
        return {false, "A channel override cannot grant the Administrator permission; it is a "
                       "role-level flag and a channel has no say over it"};
    }

    if (is_server_actor(actor_id, config_)) return {};
    if (can(actor_id, std::string(), permission::kAdministrator)) return {};

    // The gate the caller has already applied, applied again. Deliberate
    // duplication: this function is THE authority for a channel override (see
    // the header), and an authority that trusts its caller to have done the
    // first half is an authority that loses the first half the day a second
    // caller appears. It is one memoised comparison.
    if (!can(actor_id, room_id, permission::kManageRoles)) {
        return {false, "You need Manage Roles in this channel to change its permissions"};
    }

    // ── Rule 1: containment ──
    //
    // Every bit this write TOUCHES, in either direction, measured against what
    // the actor holds in this very channel. See the header for why it is a
    // symmetric difference and not "what the edit adds": removing a deny is a
    // grant wearing a removal's clothes, and it was the one of the four edits
    // most likely to be missed.
    const permission::Flags held = compute(actor_id, room_id);
    const permission::Flags changed =
        (proposed.allow ^ before.allow) | (proposed.deny ^ before.deny);
    if (const permission::Flags beyond = changed & ~held; beyond != 0) {
        return {false, "You cannot change a permission you do not hold in this channel ("
                           + permission::flags_to_hex(beyond) + ")"};
    }

    // ── Rule 2: rank ──
    //
    // Only for the direction that takes access away. Handing a principal MORE
    // access in a channel takes nothing from anybody and is what this route is
    // for; refusing it on rank would stop a channel's own manager from letting
    // their own administrators in.
    const permission::Flags taken =
        (proposed.deny & ~before.deny) | (before.allow & ~proposed.allow);
    if (taken == 0) return {};

    if (state_key.rfind("user:", 0) == 0) {
        const std::string target = state_key.substr(std::strlen("user:"));
        // The same test may_assign_roles applies to rewriting this person's
        // roles and handle_put_nickname applies to relabelling them. A DENY is
        // a moderation action against a named account — muting somebody is not
        // a lesser act than kicking them — so it answers to the same rule.
        if (!outranks(actor_id, target)) {
            return {false, "You cannot take permissions away from a user ranked at or above "
                           "you in this channel"};
        }
        return {};
    }

    const std::string role_id = state_key.substr(std::strlen("role:"));
    // @everyone is the floor rather than a principal above anyone, and
    // "@everyone DENY VIEW_CHANNEL" is literally how a private channel is made
    // on this server (docs/membership-vs-visibility.md) — a rank test here
    // would refuse the feature. Containment above still binds it, which is the
    // half that matters: you cannot deny a channel a permission you do not
    // hold in it.
    if (role_id == permission::role_id::kEveryone) return {};

    const ServerRole* role = find_role(server_roles(), role_id);
    // An override naming a role that no longer exists confers and removes
    // nothing — resolve_user_roles cannot match it — so it is treated as
    // rankless rather than refused, exactly as highest_role_position treats an
    // assignment naming one.
    const int role_pos = role ? role->position : 0;
    if (role_pos >= highest_role_position(actor_id)) {
        return {false, "You cannot take permissions away from a role ranked at or above your "
                       "own"};
    }
    return {};
}

} // namespace bsfchat
