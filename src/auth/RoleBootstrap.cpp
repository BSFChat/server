#include "auth/RoleBootstrap.h"

#include "core/Config.h"
#include "core/Logger.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>
#include <chrono>

namespace bsfchat {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string server_actor(const Config& config) {
    return "@server:" + config.server_name;
}

// Pick the room we write server-wide state into. Prefer a category room,
// fall back to any room. Returns empty if no rooms exist yet.
std::string pick_canonical_room(SqliteStore& store) {
    auto non_cat = store.list_all_non_category_rooms();
    // The difference between the full room list and non_cat gives us categories.
    // But we don't have a direct "list categories" helper; use sqlite directly
    // via a simpler path: get_joined_rooms across any user won't work either.
    // Easiest: just pick the first non-category if categories are absent.
    // For now, prefer the lowest-stream-position room (oldest).
    // Actually we don't have that helper either — just return first non-cat.
    if (!non_cat.empty()) return non_cat.front();
    return {};
}

ServerRolesContent default_roles() {
    ServerRolesContent c;
    ServerRole everyone;
    everyone.id = permission::role_id::kEveryone;
    everyone.name = "@everyone";
    everyone.color = "#99aab5";
    everyone.position = 0;
    everyone.permissions = permission::kEveryoneDefault;
    everyone.mentionable = false;
    everyone.hoist = false;
    c.roles.push_back(everyone);

    ServerRole mod;
    mod.id = permission::role_id::kModerator;
    mod.name = "Moderator";
    mod.color = "#43b581";
    mod.position = 10;
    mod.permissions =
        permission::kEveryoneDefault |
        permission::kManageMessages |
        permission::kKickMembers |
        permission::kMentionEveryone;
    mod.mentionable = true;
    mod.hoist = true;
    c.roles.push_back(mod);

    ServerRole admin;
    admin.id = permission::role_id::kAdmin;
    admin.name = "Admin";
    admin.color = "#f04747";
    admin.position = 100;
    admin.permissions = permission::kAllFlags;
    admin.mentionable = true;
    admin.hoist = true;
    c.roles.push_back(admin);

    return c;
}

void write_server_roles(SqliteStore& store, SyncEngine& sync_engine,
                        const Config& config, const std::string& room_id) {
    nlohmann::json j;
    to_json(j, default_roles());
    auto event_id = generate_event_id(config.server_name);
    store.insert_event(event_id, room_id, server_actor(config),
                       std::string(event_type::kServerRoles),
                       std::string(""), j.dump(), now_ms());
    get_logger()->info("Seeded default server roles in room {}", room_id);
}

void write_member_roles(SqliteStore& store, const Config& config,
                        const std::string& room_id, const std::string& user_id,
                        const std::vector<std::string>& role_ids) {
    MemberRolesContent c;
    c.role_ids = role_ids;
    nlohmann::json j;
    to_json(j, c);
    auto event_id = generate_event_id(config.server_name);
    store.insert_event(event_id, room_id, server_actor(config),
                       std::string(event_type::kMemberRoles),
                       user_id, j.dump(), now_ms());
}

} // namespace

void bootstrap_roles(SqliteStore& store, SyncEngine& sync_engine, const Config& config) {
    auto canonical = pick_canonical_room(store);
    if (canonical.empty()) {
        get_logger()->info("bootstrap_roles: no rooms yet, skipping");
        return;
    }

    // 1. Seed default server roles if missing OR if the existing event is
    // legacy-shape (pre-permissions, i.e. name/level/color only). Detect the
    // legacy shape by "no role has any permission bits set" — a legacy event
    // deserializes with permissions=0 for every role, which would lock every
    // user out of VIEW_CHANNEL.
    auto existing = store.get_server_roles();
    bool needs_seed = existing.empty();
    if (!needs_seed) {
        bool any_perms = false;
        for (const auto& r : existing) {
            if (r.permissions != 0) { any_perms = true; break; }
        }
        if (!any_perms) {
            get_logger()->info("bootstrap_roles: existing server.roles event is legacy-shape, upgrading");
            needs_seed = true;
        }
    }
    if (needs_seed) {
        write_server_roles(store, sync_engine, config, canonical);
    }

    // 2. Ensure every user has a member.roles event. First-registered user
    // (oldest created_at) gets Admin; everyone else gets @everyone only.
    auto users = store.list_users_with_created_at();
    if (users.empty()) {
        sync_engine.notify_new_event();
        return;
    }

    const std::string& owner_id = users.front().first;
    int wrote = 0;
    for (const auto& [user_id, _ts] : users) {
        auto current = store.get_member_role_ids(user_id);
        if (!current.empty()) continue; // already assigned, leave alone

        std::vector<std::string> ids = { std::string(permission::role_id::kEveryone) };
        if (user_id == owner_id) ids.push_back(std::string(permission::role_id::kAdmin));
        write_member_roles(store, config, canonical, user_id, ids);
        ++wrote;
    }
    if (wrote > 0) {
        get_logger()->info("bootstrap_roles: assigned default roles to {} user(s); owner={}", wrote, owner_id);
    }
    sync_engine.notify_new_event();
}

} // namespace bsfchat
