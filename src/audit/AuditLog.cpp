#include "audit/AuditLog.h"

#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace bsfchat {

using json = nlohmann::json;

namespace {

// Role definitions keyed by role id, from a bsfchat.server.roles content blob.
// `ok` is false when the blob was not parseable as a roles list at all, which the
// caller must distinguish from "no roles": diffing an unparseable side against a
// good one would invent creations or deletions that never happened.
struct RoleSnapshot {
    std::map<std::string, ServerRole> by_id;
    bool ok = false;
};

RoleSnapshot parse_roles(const std::optional<std::string>& content_json) {
    RoleSnapshot snap;
    if (!content_json) {
        // Absent state is a legitimate empty snapshot — this is the first write.
        snap.ok = true;
        return snap;
    }
    auto parsed = json::parse(*content_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) return snap;
    ServerRolesContent content;
    from_json(parsed, content);
    for (const auto& role : content.roles) {
        if (role.id.empty()) continue;
        snap.by_id[role.id] = role;
    }
    snap.ok = true;
    return snap;
}

// The payload recorded for one role. Serialised through the protocol's own
// to_json so `permissions` is the same hex string the wire and the client use —
// an operator reading the audit log sees exactly the bitfield format they set.
std::string role_payload(const ServerRole& role) {
    json j;
    to_json(j, role);
    return j.dump();
}

std::vector<std::string> parse_role_ids(const std::optional<std::string>& content_json) {
    if (!content_json) return {};
    auto parsed = json::parse(*content_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) return {};
    MemberRolesContent content;
    from_json(parsed, content);
    return content.role_ids;
}

ChannelPermissionOverride parse_override(const std::optional<std::string>& content_json) {
    ChannelPermissionOverride ov;
    if (!content_json) return ov; // absent == nothing allowed and nothing denied
    auto parsed = json::parse(*content_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) return ov;
    from_json(parsed, ov);
    return ov;
}

std::string override_payload(const ChannelPermissionOverride& ov) {
    return json{{"allow", permission::flags_to_hex(ov.allow)},
                {"deny", permission::flags_to_hex(ov.deny)}}
        .dump();
}

// The latest content of a room state event, or nullopt.
std::optional<json> room_state_content(SqliteStore& store, const std::string& room_id,
                                      std::string_view evt_type) {
    auto ev = store.get_state_event(room_id, std::string(evt_type), "");
    if (!ev) return std::nullopt;
    return ev->content.data;
}

// Records one role definition change.
void append_role_record(SqliteStore& store, const std::string& actor, const char* action,
                        const std::string& role_id, const std::string& before,
                        const std::string& after) {
    SqliteStore::AuditRecord record;
    record.actor = actor;
    record.action = action;
    record.target_key = role_id;
    record.before_json = before;
    record.after_json = after;
    store.append_audit_record(record);
}

void audit_role_definitions(SqliteStore& store, const std::string& actor,
                            const std::optional<std::string>& before_json,
                            const std::string& after_json) {
    auto before = parse_roles(before_json);
    auto after = parse_roles(std::optional<std::string>(after_json));

    if (!before.ok || !after.ok) {
        // One side is unreadable, so a per-role diff would be fiction. Record the
        // fact that the whole role list was rewritten, with both raw blobs, rather
        // than nothing at all — an unparseable role write is itself worth seeing.
        append_role_record(store, actor, audit_action::kRoleUpdate, "",
                           before_json.value_or(std::string()), after_json);
        return;
    }

    // Deterministic order: both sides are ordered maps, so walking their union
    // gives the same record order for the same change every time.
    std::set<std::string> ids;
    for (const auto& [id, _] : before.by_id) ids.insert(id);
    for (const auto& [id, _] : after.by_id) ids.insert(id);

    for (const auto& id : ids) {
        auto b = before.by_id.find(id);
        auto a = after.by_id.find(id);
        const bool had = b != before.by_id.end();
        const bool has = a != after.by_id.end();

        if (!had && has) {
            append_role_record(store, actor, audit_action::kRoleCreate, id, "",
                               role_payload(a->second));
        } else if (had && !has) {
            append_role_record(store, actor, audit_action::kRoleDelete, id,
                               role_payload(b->second), "");
        } else if (had && has) {
            auto before_payload = role_payload(b->second);
            auto after_payload = role_payload(a->second);
            // An unchanged role records nothing. Role writes carry the entire
            // list, so without this every edit to one role would also log a
            // no-op record for every other role on the server — and the
            // idempotent bootstrap re-seed would log the whole list on each
            // startup, burying the changes that matter.
            if (before_payload != after_payload) {
                append_role_record(store, actor, audit_action::kRoleUpdate, id,
                                   before_payload, after_payload);
            }
        }
    }
}

void audit_role_assignment(SqliteStore& store, const std::string& actor,
                           const std::string& target_user,
                           const std::optional<std::string>& before_json,
                           const std::string& after_json) {
    auto before_ids = parse_role_ids(before_json);
    auto after_ids = parse_role_ids(std::optional<std::string>(after_json));

    // Compared as sets: the order a client happens to send role ids in is not a
    // change in what the user can do, and logging it as one would make the log
    // noisier without making it more truthful.
    const std::set<std::string> before_set(before_ids.begin(), before_ids.end());
    const std::set<std::string> after_set(after_ids.begin(), after_ids.end());
    if (before_set == after_set) return;

    std::vector<std::string> added;
    std::vector<std::string> removed;
    for (const auto& id : after_set) {
        if (!before_set.count(id)) added.push_back(id);
    }
    for (const auto& id : before_set) {
        if (!after_set.count(id)) removed.push_back(id);
    }

    SqliteStore::AuditRecord record;
    record.actor = actor;
    record.action = audit_action::kRoleAssign;
    record.target_user = target_user;
    record.before_json = json{{"role_ids", before_ids}}.dump();
    // `added`/`removed` are redundant with the before/after pair but are what a
    // reader actually wants to see ("granted admin"), and computing them here
    // means every consumer does not have to.
    record.after_json =
        json{{"role_ids", after_ids}, {"added", added}, {"removed", removed}}.dump();
    store.append_audit_record(record);
}

} // namespace

std::string membership_audit_action(const std::string& before_membership,
                                   const std::string& after_membership) {
    if (after_membership == membership::kBan) return audit_action::kMemberBan;
    if (after_membership == membership::kLeave) {
        return before_membership == membership::kBan ? audit_action::kMemberUnban
                                                     : audit_action::kMemberKick;
    }
    return audit_action::kMemberMembershipSet;
}

void audit_membership_change(SqliteStore& store, const std::string& actor,
                            const std::string& room_id, const std::string& target_user,
                            const std::string& before_membership,
                            const std::string& after_membership,
                            const std::string& reason) {
    SqliteStore::AuditRecord record;
    record.actor = actor;
    record.action = membership_audit_action(before_membership, after_membership);
    record.target_user = target_user;
    record.target_room = room_id;
    record.reason = reason;
    // The transition, not just the end state: "banned" and "banned a user who was
    // already banned" are different facts, and so are "kicked" and "un-invited".
    record.before_json = json{{"membership", before_membership}}.dump();
    record.after_json = json{{"membership", after_membership}}.dump();
    store.append_audit_record(record);
}

void audit_nickname_change(SqliteStore& store, const std::string& actor,
                          const std::string& target_user,
                          const std::optional<std::string>& before,
                          const std::optional<std::string>& after) {
    // An unchanged value is not an event. Without this a client resubmitting the
    // same nickname would pad the log with records that record nothing.
    if (before == after) return;

    // nullopt is recorded as JSON null, not as "", so "cleared the nickname" and
    // "set the nickname to an empty string" cannot be confused by a reader — the
    // second is not something the API permits, and the log should not imply it is.
    const auto as_json = [](const std::optional<std::string>& v) {
        return (v ? json(*v) : json(nullptr));
    };

    SqliteStore::AuditRecord record;
    record.actor = actor;
    record.action = audit_action::kMemberNicknameSet;
    record.target_user = target_user;
    // No target_room: a nickname is server-wide, so naming one room would be
    // arbitrary and would make the record look narrower than the change was.
    record.before_json = json{{"nickname", as_json(before)}}.dump();
    record.after_json = json{{"nickname", as_json(after)}}.dump();
    store.append_audit_record(record);
}

void audit_bot_lifecycle(SqliteStore& store, const std::string& actor,
                         const std::string& action, const std::string& bot_user_id,
                         const std::string& after_json) {
    SqliteStore::AuditRecord record;
    record.actor = actor;
    record.action = action;
    // The bot goes in target_user, not in a field of its own. It IS a user, and
    // an investigator filtering the log by a user id must get both "what this
    // account did" and "what was done to this account" from the same query —
    // which is exactly what the partial index v16 installed on target_user
    // serves. A bespoke `target_bot` would split that answer in two and index
    // neither half.
    record.target_user = bot_user_id;
    // No target_room: the bot lifecycle is server-wide, and naming a room would
    // make the record look narrower than the action was.
    record.after_json = after_json;
    store.append_audit_record(record);
}

void audit_room_deletion(SqliteStore& store, const std::string& actor,
                         const std::string& room_id) {
    std::string room_type = "text";
    if (auto type_content = room_state_content(store, room_id, event_type::kRoomType)) {
        room_type = type_content->value("type", room_type);
    }

    std::string name;
    if (auto name_content = room_state_content(store, room_id, event_type::kRoomName)) {
        name = name_content->value("name", "");
    }

    std::string parent_id;
    if (auto cat_content = room_state_content(store, room_id, event_type::kRoomCategory)) {
        parent_id = cat_content->value("parent_id", "");
    }

    SqliteStore::AuditRecord record;
    record.actor = actor;
    record.action = room_type == "category" ? audit_action::kCategoryDelete
                                            : audit_action::kChannelDelete;
    record.target_room = room_id;
    // Everything below is read while the room still exists. A record that only
    // held the room id would be almost useless the instant the deletion landed:
    // nothing else in the database would still be able to say what "!abc:host"
    // had been called.
    record.before_json = json{
        {"name", name},
        {"type", room_type},
        {"parent_id", parent_id},
        {"is_direct", store.is_direct_room(room_id)},
        {"members", store.get_room_members(room_id).size()},
    }.dump();
    // No after: the room is about to stop existing.
    store.append_audit_record(record);
}

void audit_channel_override_change(SqliteStore& store, const std::string& actor,
                                   const std::string& room_id, const std::string& state_key,
                                   const std::optional<std::string>& before_json,
                                   const std::string& after_json) {
    auto before = parse_override(before_json);
    auto after = parse_override(std::optional<std::string>(after_json));
    if (before.allow == after.allow && before.deny == after.deny) return;

    SqliteStore::AuditRecord record;
    record.actor = actor;
    record.action = audit_action::kChannelPermissionsSet;
    record.target_room = room_id;
    record.target_key = state_key;
    // A "user:@bob:host" override is a thing done TO a user, so it is also filed
    // under that user — otherwise "what has been done to Bob" would miss the
    // per-channel permission changes aimed squarely at him.
    constexpr std::string_view kUserPrefix = "user:";
    if (state_key.rfind(kUserPrefix, 0) == 0) {
        record.target_user = state_key.substr(kUserPrefix.size());
    }
    record.before_json = override_payload(before);
    record.after_json = override_payload(after);
    store.append_audit_record(record);
}

void audit_server_scoped_change(SqliteStore& store, const std::string& actor,
                                const std::string& evt_type, const std::string& state_key,
                                const std::optional<std::string>& before_json,
                                const std::string& after_json) {
    if (evt_type == std::string(event_type::kServerRoles)) {
        audit_role_definitions(store, actor, before_json, after_json);
        return;
    }
    if (evt_type == std::string(event_type::kMemberRoles)) {
        // state_key is the user whose assignments changed.
        audit_role_assignment(store, actor, state_key, before_json, after_json);
        return;
    }
    // No other server-scoped type exists; a new one is a deliberate decision
    // about whether it belongs in the audit log, not something to guess at here.
}

} // namespace bsfchat
