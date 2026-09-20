#include "api/RoleHandler.h"

#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace bsfchat {

using json = nlohmann::json;

namespace {

// Server scope for PermissionsEngine — the empty room id. See RoleHandler.h.
const std::string kServerScope;

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

void send_json(httplib::Response& res, const json& body, int status = 200) {
    res.status = status;
    res.set_content(body.dump(), "application/json");
}

std::optional<json> parse_object_body(const httplib::Request& req, httplib::Response& res) {
    auto parsed = json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        send_error(res, 400, MatrixError::bad_json("Request body must be a JSON object"));
        return std::nullopt;
    }
    return parsed;
}

// "#RRGGBB", or empty for "no colour set". Validated because it is echoed to
// every client and dropped straight into a stylesheet by the desktop role list.
bool valid_color(const std::string& c) {
    if (c.empty()) return true;
    if (c.size() != 7 || c[0] != '#') return false;
    return std::all_of(c.begin() + 1, c.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    });
}

// Permissions arrive as the same hex string the wire uses everywhere else, or
// as a plain integer for a client that has not been updated. Returns nullopt
// for a field that is present but is neither.
std::optional<permission::Flags> read_permissions(const json& j) {
    if (j.is_string()) {
        return permission::flags_from_hex(j.get<std::string>());
    }
    if (j.is_number_unsigned()) {
        return j.get<permission::Flags>();
    }
    return std::nullopt;
}

json role_json(const ServerRole& role) {
    json j;
    to_json(j, role);
    return j;
}

json roles_json(const std::vector<ServerRole>& roles) {
    json arr = json::array();
    for (const auto& r : roles) arr.push_back(role_json(r));
    return json{{"roles", arr}};
}

// Reads the mutable fields of a role out of a request body, leaving anything
// the body does not mention exactly as it was. `role` is updated in place.
//
// Undefined bits are MASKED OFF rather than refused. A client built against a
// newer protocol than this server would otherwise have every role edit
// rejected for a bit this build has never heard of, and — worse — storing an
// unknown bit means storing a permission whose meaning nothing here can check,
// including validate_role_document's containment rule.
std::optional<MatrixError> apply_role_fields(ServerRole& role, const json& body) {
    if (body.contains("name")) {
        if (!body["name"].is_string()) return MatrixError::bad_json("name must be a string");
        role.name = body["name"].get<std::string>();
    }
    if (body.contains("color")) {
        if (!body["color"].is_string()) return MatrixError::bad_json("color must be a string");
        role.color = body["color"].get<std::string>();
        if (!valid_color(role.color)) {
            return MatrixError::invalid_param("color must be \"#RRGGBB\"");
        }
    }
    if (body.contains("position")) {
        if (!body["position"].is_number_integer()) {
            return MatrixError::bad_json("position must be an integer");
        }
        const int64_t pos = body["position"].get<int64_t>();
        if (pos < 0 || pos > limits::kMaxRolePosition) {
            return MatrixError::invalid_param("position out of range");
        }
        role.position = static_cast<int>(pos);
    }
    if (body.contains("permissions")) {
        auto flags = read_permissions(body["permissions"]);
        if (!flags) {
            return MatrixError::bad_json("permissions must be a hex string or an integer");
        }
        role.permissions = *flags & permission::kAllFlags;
    }
    if (body.contains("hoist")) {
        if (!body["hoist"].is_boolean()) return MatrixError::bad_json("hoist must be a boolean");
        role.hoist = body["hoist"].get<bool>();
    }
    if (body.contains("mentionable")) {
        if (!body["mentionable"].is_boolean()) {
            return MatrixError::bad_json("mentionable must be a boolean");
        }
        role.mentionable = body["mentionable"].get<bool>();
    }
    if (body.contains("self_assignable")) {
        if (!body["self_assignable"].is_boolean()) {
            return MatrixError::bad_json("self_assignable must be a boolean");
        }
        role.self_assignable = body["self_assignable"].get<bool>();
    }
    if (role.name.empty()) return MatrixError::invalid_param("A role must have a name");
    if (role.name.size() > limits::kMaxRoleNameLength) {
        return MatrixError::invalid_param("Role name is too long");
    }
    return std::nullopt;
}

} // namespace

RoleHandler::RoleHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

std::string RoleHandler::mirror_room() {
    return pick_server_state_mirror_room(store_);
}

std::optional<std::string> RoleHandler::authorize_role_admin(const httplib::Request& req,
                                                             httplib::Response& res) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        send_error(res, 401, auth_error(req.get_header_value("Authorization")));
        return std::nullopt;
    }
    PermissionsEngine perms(store_, config_);
    if (!perms.can(*actor, kServerScope, permission::kManageRoles)) {
        send_error(res, 403, MatrixError::forbidden("Insufficient permissions to manage roles"));
        return std::nullopt;
    }
    return actor;
}

bool RoleHandler::commit_roles(const std::string& actor, const std::vector<ServerRole>& proposed,
                               httplib::Response& res) {
    PermissionsEngine perms(store_, config_);
    auto verdict = perms.may_edit_role_definitions(actor, proposed);
    if (!verdict) {
        get_logger()->warn("Refused role-document change by {}: {}", actor, verdict.reason);
        send_error(res, 403, MatrixError::forbidden(verdict.reason));
        return false;
    }

    ServerRolesContent content;
    content.roles = proposed;
    json j;
    to_json(j, content);
    // Same choke point as the wholesale PUT and the bootstrap: this is where the
    // authoritative write, the audit diff and the sync mirror all happen, so
    // none of the three had to be reimplemented here and none can be forgotten.
    write_server_scoped_state(store_, config_, std::string(event_type::kServerRoles),
                              std::string(), j.dump(), mirror_room(), actor);
    sync_engine_.notify_new_event();
    return true;
}

void RoleHandler::handle_list_roles(const httplib::Request& req, httplib::Response& res) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        send_error(res, 401, auth_error(req.get_header_value("Authorization")));
        return;
    }
    send_json(res, roles_json(store_.get_server_roles()));
}

void RoleHandler::handle_create_role(const httplib::Request& req, httplib::Response& res) {
    auto actor = authorize_role_admin(req, res);
    if (!actor) return;

    auto body = parse_object_body(req, res);
    if (!body) return;

    ServerRole role;
    // Server-minted, never caller-chosen. A caller-chosen id could collide with
    // a role above the caller's rank — which may_edit_role_definitions would
    // then read as an EDIT of that role rather than a creation — or squat a
    // well-known id ("everyone", "admin") that other code matches by string.
    // The prefix keeps a minted id visibly distinct from those three forever.
    role.id = "role_" + generate_media_id();
    role.position = 0;
    role.permissions = 0;
    if (auto err = apply_role_fields(role, *body)) {
        send_error(res, 400, *err);
        return;
    }

    auto proposed = store_.get_server_roles();
    proposed.push_back(role);
    if (!commit_roles(*actor, proposed, res)) return;

    send_json(res, json{{"role", role_json(role)}}, 201);
}

void RoleHandler::handle_update_role(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route(std::string(api_path::kRoles) + "/{roleId}", req.path);
    if (!match.matched) {
        send_error(res, 404, MatrixError::not_found("Unknown endpoint"));
        return;
    }
    const std::string role_id = match.params["roleId"];

    auto actor = authorize_role_admin(req, res);
    if (!actor) return;

    auto body = parse_object_body(req, res);
    if (!body) return;

    auto proposed = store_.get_server_roles();
    auto it = std::find_if(proposed.begin(), proposed.end(),
                           [&](const ServerRole& r) { return r.id == role_id; });
    if (it == proposed.end()) {
        send_error(res, 404, MatrixError::not_found("No such role"));
        return;
    }
    if (auto err = apply_role_fields(*it, *body)) {
        send_error(res, 400, *err);
        return;
    }

    const ServerRole updated = *it;
    if (!commit_roles(*actor, proposed, res)) return;

    send_json(res, json{{"role", role_json(updated)}});
}

void RoleHandler::handle_delete_role(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route(std::string(api_path::kRoles) + "/{roleId}", req.path);
    if (!match.matched) {
        send_error(res, 404, MatrixError::not_found("Unknown endpoint"));
        return;
    }
    const std::string role_id = match.params["roleId"];

    auto actor = authorize_role_admin(req, res);
    if (!actor) return;

    // Refused before the permission machinery gets a chance to phrase it as a
    // rank problem: @everyone is not deletable by anyone, including an
    // administrator, because every permission evaluation on the server reads it.
    if (role_id == permission::role_id::kEveryone) {
        send_error(res, 403, MatrixError::forbidden("The @everyone role cannot be deleted"));
        return;
    }

    auto current = store_.get_server_roles();
    auto it = std::find_if(current.begin(), current.end(),
                           [&](const ServerRole& r) { return r.id == role_id; });
    if (it == current.end()) {
        send_error(res, 404, MatrixError::not_found("No such role"));
        return;
    }

    std::vector<ServerRole> proposed;
    proposed.reserve(current.size() - 1);
    for (const auto& r : current) {
        if (r.id != role_id) proposed.push_back(r);
    }
    if (!commit_roles(*actor, proposed, res)) return;

    // Now strip the dead id from everyone who held it. Ordered AFTER the
    // definition write, so a refusal above leaves assignments untouched, and
    // so a crash in between leaves stale ids rather than members still holding
    // a role that no longer exists — stale ids are inert in compute(), the
    // other way round is not a state this code can produce at all.
    const std::string mirror = mirror_room();
    int stripped = 0;
    for (const auto& [user_id, _created] : store_.list_users_with_created_at()) {
        auto ids = store_.get_member_role_ids(user_id);
        auto removed = std::remove(ids.begin(), ids.end(), role_id);
        if (removed == ids.end()) continue;
        ids.erase(removed, ids.end());
        MemberRolesContent assignment;
        assignment.role_ids = ids;
        json j;
        to_json(j, assignment);
        write_server_scoped_state(store_, config_, std::string(event_type::kMemberRoles),
                                  user_id, j.dump(), mirror, *actor);
        ++stripped;
    }
    if (stripped > 0) {
        sync_engine_.notify_new_event();
        get_logger()->info("Role {} deleted by {}; stripped from {} member(s)", role_id, *actor,
                           stripped);
    }

    send_json(res, json::object());
}

void RoleHandler::handle_add_self_role(const httplib::Request& req, httplib::Response& res) {
    change_self_role(req, res, /*add=*/true);
}

void RoleHandler::handle_remove_self_role(const httplib::Request& req, httplib::Response& res) {
    change_self_role(req, res, /*add=*/false);
}

void RoleHandler::change_self_role(const httplib::Request& req, httplib::Response& res, bool add) {
    auto match = match_route(std::string(api_path::kSelfRoles) + "/{roleId}", req.path);
    if (!match.matched) {
        send_error(res, 404, MatrixError::not_found("Unknown endpoint"));
        return;
    }
    const std::string role_id = match.params["roleId"];

    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        send_error(res, 401, auth_error(req.get_header_value("Authorization")));
        return;
    }

    PermissionsEngine perms(store_, config_);
    auto verdict = perms.may_self_assign_role(*actor, role_id);
    if (!verdict) {
        // 404 for an id that does not exist, 403 for one that does but is not
        // on offer. There is nothing to leak by distinguishing them: the role
        // list is readable by every authenticated user.
        const bool unknown = verdict.reason.rfind("Unknown role", 0) == 0;
        send_error(res, unknown ? 404 : 403,
                   unknown ? MatrixError::not_found(verdict.reason)
                           : MatrixError::forbidden(verdict.reason));
        return;
    }

    auto ids = store_.get_member_role_ids(*actor);
    const bool held = std::find(ids.begin(), ids.end(), role_id) != ids.end();
    if (add == held) {
        // Already in the requested state. Writing anyway would append an audit
        // record and wake every client's sync for a change that did not happen,
        // which a picker that re-sends its whole state on every open would do
        // constantly.
        send_json(res, json{{"role_ids", ids}});
        return;
    }

    if (add) {
        // @everyone is implicit in compute() but is written into the
        // assignment by bootstrap, so a member whose list somehow lacks it does
        // not acquire one here — this endpoint only ever touches `role_id`.
        ids.push_back(role_id);
    } else {
        ids.erase(std::remove(ids.begin(), ids.end(), role_id), ids.end());
    }

    MemberRolesContent assignment;
    assignment.role_ids = ids;
    json j;
    to_json(j, assignment);
    // Attributed to the member, not to the server: "who gave you that role" has
    // a real answer here and the audit log should carry it.
    write_server_scoped_state(store_, config_, std::string(event_type::kMemberRoles), *actor,
                              j.dump(), mirror_room(), *actor);
    sync_engine_.notify_new_event();

    send_json(res, json{{"role_ids", ids}});
}

} // namespace bsfchat
