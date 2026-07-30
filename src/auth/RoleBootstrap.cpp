#include "auth/RoleBootstrap.h"

#include "audit/AuditLog.h"
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

// Room to MIRROR server-wide state into so clients pick it up on sync.
//
// This used to be where server-wide state actually LIVED, chosen as
// list_all_non_category_rooms().front() — an unordered SQLite result. Since
// delete_room hard-deletes every event in a room, deleting whichever channel
// happened to come back first destroyed every role definition and assignment
// server-wide. Authority now lives in the server_state table
// (SqliteStore::set_server_state); this mirror is presentation only, and it
// being absent or deleted costs nothing.
std::string pick_mirror_room(SqliteStore& store) {
    auto non_cat = store.list_all_non_category_rooms();
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

void write_server_roles(SqliteStore& store, const Config& config,
                        const std::string& mirror_room) {
    nlohmann::json j;
    to_json(j, default_roles());
    write_server_scoped_state(store, config, std::string(event_type::kServerRoles),
                              std::string(""), j.dump(), mirror_room);
    get_logger()->info("Seeded default server roles");
}

void write_member_roles(SqliteStore& store, const Config& config,
                        const std::string& mirror_room, const std::string& user_id,
                        const std::vector<std::string>& role_ids) {
    MemberRolesContent c;
    c.role_ids = role_ids;
    nlohmann::json j;
    to_json(j, c);
    write_server_scoped_state(store, config, std::string(event_type::kMemberRoles),
                              user_id, j.dump(), mirror_room);
}

} // namespace

void write_server_scoped_state(SqliteStore& store, const Config& config,
                                const std::string& evt_type, const std::string& state_key,
                                const std::string& content_json,
                                const std::string& mirror_room,
                                const std::string& sender) {
    const std::string actor = sender.empty() ? server_actor(config) : sender;

    // Authoritative write — survives deletion of every room on the server. The
    // content it replaced comes back from the same locked write, so the audit
    // record below cannot name a "before" that a concurrent role edit had already
    // overwritten.
    auto previous = store.set_server_state(evt_type, state_key, actor, content_json);

    // Audited HERE rather than in the handler, because this is the one choke point
    // every role definition and role assignment write passes through — the
    // permission handler, the startup bootstrap, and anything added later. A new
    // call site cannot introduce an unaudited role change by forgetting to log.
    // Bootstrap writes are recorded too, under the synthetic @server actor: "the
    // server granted the first account Admin at bootstrap" is exactly the kind of
    // thing an owner asking "how did they get admin?" needs to be able to see.
    audit_server_scoped_change(store, actor, evt_type, state_key, previous, content_json);

    // Best-effort mirror so clients, which learn about roles from sync state
    // events, still see the change. Purely a delivery mechanism: no read path
    // consults these events any more.
    if (!mirror_room.empty() && store.room_exists(mirror_room)) {
        auto event_id = generate_event_id(config.server_name);
        store.insert_event(event_id, mirror_room, actor,
                           evt_type, state_key, content_json, now_ms());
    }
}

void bootstrap_roles(SqliteStore& store, SyncEngine& sync_engine, const Config& config) {
    // Note: no longer bails out when the server has no rooms. Role bootstrap
    // used to require a room to write into, which deadlocked a fresh
    // deployment now that channel creation itself requires MANAGE_CHANNELS —
    // no rooms meant no roles, no roles meant nobody could create the first
    // room. Server-wide state has its own home now, so this always works.
    auto canonical = pick_mirror_room(store);

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
        write_server_roles(store, config, canonical);
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
