#include "api/RoleHandler.h"

#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/JsonIo.h"
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
    auto parsed = parse_request_json_or_discarded(req.body.empty() ? "{}" : req.body);
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

// A server-scoped document and THE EXACT BYTES it was parsed from, read once.
//
// Two reads — get_server_state() for the bytes and get_server_roles() for the
// parsed list — would straddle a concurrent write and produce a proposal whose
// compare-and-swap expectation names a document it was not built from. That is
// the exact bug the expectation exists to catch, reintroduced inside the
// machinery that catches it, and it would be invisible because the CAS would
// then pass. So there is one read, and everything else is derived from it.
template <typename T>
struct VersionedDocument {
    SqliteStore::ExpectedServerState raw;  // nullopt when the key is unset
    T parsed{};
};

// Mirrors SqliteStore::get_server_roles() exactly, including its "unparseable
// content reads as no roles" behaviour — a document this cannot parse is one
// nothing else on the server can either, and refusing to write over it would
// leave the deployment with no way back.
VersionedDocument<std::vector<ServerRole>> read_role_document(SqliteStore& store) {
    VersionedDocument<std::vector<ServerRole>> doc;
    doc.raw = store.get_server_state(std::string(event_type::kServerRoles), std::string());
    if (!doc.raw) return doc;
    auto j = json::parse(*doc.raw, nullptr, false);
    if (j.is_discarded()) return doc;
    ServerRolesContent content;
    from_json(j, content);
    doc.parsed = std::move(content.roles);
    return doc;
}

// The same, for one member's assignment. Mirrors
// SqliteStore::get_member_role_ids().
VersionedDocument<std::vector<std::string>> read_member_roles(SqliteStore& store,
                                                              const std::string& user_id) {
    VersionedDocument<std::vector<std::string>> doc;
    doc.raw = store.get_server_state(std::string(event_type::kMemberRoles), user_id);
    if (!doc.raw) return doc;
    auto j = json::parse(*doc.raw, nullptr, false);
    if (j.is_discarded()) return doc;
    MemberRolesContent content;
    from_json(j, content);
    doc.parsed = std::move(content.role_ids);
    return doc;
}

// May `permissions` be disclosed for this role to a caller who cannot edit
// roles? See handle_list_roles for the whole argument; the rule itself is two
// cases, and both are cases where the bitfield tells the reader nothing they do
// not already hold.
//
//   @everyone       — every human account on the server has these bits, and the
//                     self-assignable ceiling is measured against them, so a
//                     client cannot do the arithmetic below without this one.
//   self_assignable — validate_role_document refuses to STORE such a role whose
//                     permissions are not a subset of @everyone's, and
//                     may_self_assign_role refuses to HAND ONE OUT if that ever
//                     stops holding. So its bits are, by construction, bits the
//                     reader could take for themselves in one request anyway.
//
// Every other role's bitfield is withheld. That is the part of the document
// that is a map of who can do what, and it is the part no member-facing feature
// reads.
bool permissions_are_public(const ServerRole& role) {
    return role.id == permission::role_id::kEveryone || role.self_assignable;
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

void RoleHandler::send_conflict(httplib::Response& res) {
    // M_LIMIT_EXCEEDED, and 429 rather than 409, because the only thing a
    // caller can usefully do with this is wait a moment and repeat the request
    // — which is exactly the handling every client already has for this code.
    // Reaching it takes kMaxCommitAttempts consecutive losses on one document,
    // so minting a bsfchat-specific errcode (and a client branch to understand
    // it) would be protocol surface for a path that needs four simultaneous
    // role editors to appear at all.
    send_error(res, 429,
               MatrixError::limit_exceeded(
                   "The role document changed while this edit was being prepared; retry",
                   /*retry_after_ms=*/100));
}

RoleHandler::Commit RoleHandler::commit_roles(const std::string& actor,
                                              const std::vector<ServerRole>& proposed,
                                              const SqliteStore::ExpectedServerState& expected,
                                              httplib::Response& res) {
    PermissionsEngine perms(store_, config_);
    auto verdict = perms.may_edit_role_definitions(actor, proposed);
    if (!verdict) {
        get_logger()->warn("Refused role-document change by {}: {}", actor, verdict.reason);
        send_error(res, 403, MatrixError::forbidden(verdict.reason));
        return Commit::Refused;
    }

    ServerRolesContent content;
    content.roles = proposed;
    json j;
    to_json(j, content);
    // Same choke point as the wholesale PUT and the bootstrap: this is where the
    // authoritative write, the audit diff and the sync mirror all happen, so
    // none of the three had to be reimplemented here and none can be forgotten.
    //
    // Under a compare-and-swap against the document `proposed` was built from.
    // Note that `perms` above is a FRESH engine and therefore re-read the
    // document itself, so without this the authorisation and the proposal can
    // be computed from two different documents — which is not just a lost edit
    // but a reverted one, because the containment test measures what the
    // proposal ADDS relative to whatever it reads. Permissions audit F8.
    const bool applied =
        write_server_scoped_state(store_, config_, std::string(event_type::kServerRoles),
                                  std::string(), j.dump(), mirror_room(), actor, &expected);
    if (!applied) return Commit::Conflict;

    sync_engine_.notify_new_event();
    return Commit::Ok;
}

void RoleHandler::handle_list_roles(const httplib::Request& req, httplib::Response& res) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        send_error(res, 401, auth_error(req.get_header_value("Authorization")));
        return;
    }

    // Two views of one document. See RoleHandler.h for why the read is not
    // gated at all, and why it must not become gated; this is the narrower
    // question of what the ungated view contains.
    //
    // THE INVARIANT: anybody who can WRITE the role document can READ it in
    // full, and nobody else gets the permission bitfields. That holds because
    // both halves ask the identical question — kManageRoles at SERVER scope —
    // of the identical engine. Every route that can change a role definition
    // (the three delta endpoints here, and bsfchat.server.roles through
    // handle_set_state, which is server-scoped) is behind that same test, so
    // there is no caller that can write the document and would read it
    // truncated. That matters for more than tidiness: a bot doing
    // read-modify-write against a truncated document would write permissions=0
    // onto every role it echoed back, and the invariant is what makes that
    // combination unreachable rather than merely unlikely.
    //
    // WHY NARROW IT AT ALL, given the document is also mirrored into a channel
    // and delivered by /sync. Because the justification recorded in the header
    // — "the role list already reaches every client through the sync mirror, so
    // gating the read would hide nothing" — is true of a member in the mirror
    // room and false of two callers it did not consider (permissions audit F7,
    // September 2026):
    //
    //   * A SCOPED BOT. Bots are excluded from channel auto-join and the mirror
    //     is one pinned room (RoleBootstrap.h), so a bot granted one channel by
    //     override receives no server.roles event at all. Its token bought it
    //     the complete escalation map of a server it was deliberately scoped
    //     out of: which role carries ADMINISTRATOR, and where each one sits.
    //   * A MEMBER DENIED kViewChannel ON THE MIRROR ROOM. SyncEngine filters
    //     delivered rooms through can_view_room, so that member never receives
    //     the document either — which is also why the read stays ungated: this
    //     endpoint is the only thing making their client correct.
    //
    // WHAT IS WITHHELD is one field, `permissions`, and only on roles where it
    // carries information — see permissions_are_public(). Everything a member's
    // client renders survives: id, name, colour, position, hoist, mentionable
    // and self_assignable are all present for every role, so the member list,
    // the hoisting groups, role mentions and the opt-in picker all still work,
    // and the picker's client-side containment arithmetic still has the two
    // bitfields it needs (SelfRoleModel.h). `position` stays because it is the
    // sort order of a member list that every client already draws.
    //
    // The alternative the audit also offered — gate the whole document on
    // kManageRoles — was rejected: it would break the opt-in role picker for
    // every ordinary member (who holds no role permission by definition), and
    // it would take away the one authoritative role read a scoped bot has,
    // which is the direction RoleBootstrap.h is explicitly travelling in
    // ("the server.roles half is already covered by GET /bsfchat/roles").
    PermissionsEngine perms(store_, config_);
    const bool may_edit = perms.can(*actor, kServerScope, permission::kManageRoles);

    const auto roles = store_.get_server_roles();
    json arr = json::array();
    for (const auto& r : roles) {
        json j = role_json(r);
        if (!may_edit && !permissions_are_public(r)) {
            // ERASED, not zeroed. A caller that checks for the key can tell
            // "withheld" from "this role grants nothing", and ServerRole's
            // from_json leaves the field at its default for either — so the
            // honest encoding costs a careless reader nothing extra and tells a
            // careful one the truth.
            j.erase("permissions");
        }
        arr.push_back(std::move(j));
    }
    send_json(res, json{{"roles", std::move(arr)}});
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

    // Read-check-write under a compare-and-swap, re-reading whenever another
    // writer lands in between. The RETRY, rather than a 409 straight back at
    // the caller, is the point of these endpoints: this file exists because
    // making the caller perform the read-modify-write is what lost edits and
    // forced a delegated MANAGE_ROLES holder to reproduce roles it may not
    // touch (see the header). Handing the loop back would undo that.
    //
    // The id is minted ABOVE the loop, so a retry re-proposes the same role
    // rather than leaving a trail of ids behind on a contended document.
    for (int attempt = 0; attempt < kMaxCommitAttempts; ++attempt) {
        auto doc = read_role_document(store_);
        auto proposed = doc.parsed;
        proposed.push_back(role);
        switch (commit_roles(*actor, proposed, doc.raw, res)) {
            case Commit::Ok:
                send_json(res, json{{"role", role_json(role)}}, 201);
                return;
            case Commit::Refused:
                return;
            case Commit::Conflict:
                break;
        }
    }
    send_conflict(res);
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

    // Everything below is re-derived on each attempt, and it has to be: this
    // endpoint's contract is that an omitted key keeps its CURRENT value, and
    // "current" means the value in the document this write is about to
    // supersede. Applying the delta once and resubmitting it would quietly
    // convert a partial update into a wholesale one carrying stale fields — the
    // very thing the partial semantics exist to prevent.
    for (int attempt = 0; attempt < kMaxCommitAttempts; ++attempt) {
        auto doc = read_role_document(store_);
        auto proposed = std::move(doc.parsed);
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
        switch (commit_roles(*actor, proposed, doc.raw, res)) {
            case Commit::Ok:
                send_json(res, json{{"role", role_json(updated)}});
                return;
            case Commit::Refused:
                return;
            case Commit::Conflict:
                break;
        }
    }
    send_conflict(res);
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

    bool deleted = false;
    for (int attempt = 0; attempt < kMaxCommitAttempts && !deleted; ++attempt) {
        auto doc = read_role_document(store_);
        const auto& current = doc.parsed;
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
        switch (commit_roles(*actor, proposed, doc.raw, res)) {
            case Commit::Ok:
                deleted = true;
                break;
            case Commit::Refused:
                return;
            case Commit::Conflict:
                break;
        }
    }
    if (!deleted) {
        send_conflict(res);
        return;
    }

    // Now strip the dead id from everyone who held it. Ordered AFTER the
    // definition write, so a refusal above leaves assignments untouched, and
    // so a crash in between leaves stale ids rather than members still holding
    // a role that no longer exists — stale ids are inert in compute(), the
    // other way round is not a state this code can produce at all.
    //
    // Each member's assignment is its own row and its own read-modify-write, so
    // each gets its own compare-and-swap for the same reason the document above
    // does: a member who is granted an unrelated role while this sweep is
    // running must not have that grant erased by a proposal built before it.
    // Losing every attempt on one member leaves a stale id, which is the
    // failure mode this ordering was already chosen to prefer — inert in
    // compute(), and logged here so it is not silent.
    const std::string mirror = mirror_room();
    int stripped = 0;
    for (const auto& [user_id, _created] : store_.list_users_with_created_at()) {
        bool done = false;
        for (int attempt = 0; attempt < kMaxCommitAttempts && !done; ++attempt) {
            auto doc = read_member_roles(store_, user_id);
            auto ids = std::move(doc.parsed);
            auto removed = std::remove(ids.begin(), ids.end(), role_id);
            if (removed == ids.end()) {
                done = true;
                break;
            }
            ids.erase(removed, ids.end());
            MemberRolesContent assignment;
            assignment.role_ids = ids;
            json j;
            to_json(j, assignment);
            if (write_server_scoped_state(store_, config_, std::string(event_type::kMemberRoles),
                                          user_id, j.dump(), mirror, *actor, &doc.raw)) {
                ++stripped;
                done = true;
            }
        }
        if (!done) {
            get_logger()->warn(
                "Role {} deleted, but {}'s assignment kept being overwritten; the dead id is "
                "still on it. Harmless — compute() ignores unknown ids — but their next "
                "wholesale member.roles PUT will be refused with \"Unknown role\" until it is "
                "removed",
                role_id, user_id);
        }
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

    // THE ONE INSTANCE OF THIS RACE AN ATTACKER CAN DRIVE, which is why it is
    // written out here rather than left to the reader of commit_roles.
    //
    // This endpoint is callable by any member, against their own assignment,
    // at line rate, and the row it read-modify-writes is the same row a
    // moderator's demotion writes. Without the compare-and-swap below, a member
    // who is being demoted can revert it: spam a self-assignable role on and
    // off, and whichever request read the assignment before the demotion landed
    // writes the pre-demotion list back — role and all. The moderator sees 200
    // and believes the revocation took. Permissions audit F8, September 2026.
    //
    // The whole body loops, including the verdict: may_self_assign_role is a
    // question about the ROLE DOCUMENT (is this still self-assignable, is it
    // still inside @everyone's ceiling), which is a different row that a
    // concurrent admin may also have just moved. Re-asking it per attempt costs
    // one indexed lookup and means the answer that is finally acted on is the
    // one the write lands next to, not one from a document that no longer
    // exists. Note that this is NOT re-treading may_self_assign_role's own
    // hardening — that check already re-reads the document "as it stands"; what
    // is new is only that the WRITE cannot now be built on a stale assignment.
    for (int attempt = 0; attempt < kMaxCommitAttempts; ++attempt) {
        PermissionsEngine perms(store_, config_);
        auto verdict = perms.may_self_assign_role(*actor, role_id, add);
        if (!verdict) {
            // 404 for an id that does not exist, 403 for one that does but is
            // not on offer. There is nothing to leak by distinguishing them:
            // every authenticated caller can read the role list, and the two
            // fields this decision turns on — `self_assignable` and, for the
            // containment ceiling, @everyone's bits — are both in the narrowed
            // view GET /bsfchat/roles hands a member (see handle_list_roles).
            const bool unknown = verdict.reason.rfind("Unknown role", 0) == 0;
            send_error(res, unknown ? 404 : 403,
                       unknown ? MatrixError::not_found(verdict.reason)
                               : MatrixError::forbidden(verdict.reason));
            return;
        }

        auto doc = read_member_roles(store_, *actor);
        auto ids = std::move(doc.parsed);
        const bool held = std::find(ids.begin(), ids.end(), role_id) != ids.end();
        if (add == held) {
            // Already in the requested state. Writing anyway would append an
            // audit record and wake every client's sync for a change that did
            // not happen, which a picker that re-sends its whole state on every
            // open would do constantly.
            send_json(res, json{{"role_ids", ids}});
            return;
        }

        if (add) {
            // @everyone is implicit in compute() but is written into the
            // assignment by bootstrap, so a member whose list somehow lacks it
            // does not acquire one here — this endpoint only ever touches
            // `role_id`.
            ids.push_back(role_id);
        } else {
            ids.erase(std::remove(ids.begin(), ids.end(), role_id), ids.end());
        }

        MemberRolesContent assignment;
        assignment.role_ids = ids;
        json j;
        to_json(j, assignment);
        // Attributed to the member, not to the server: "who gave you that role"
        // has a real answer here and the audit log should carry it.
        if (write_server_scoped_state(store_, config_, std::string(event_type::kMemberRoles),
                                      *actor, j.dump(), mirror_room(), *actor, &doc.raw)) {
            sync_engine_.notify_new_event();
            send_json(res, json{{"role_ids", ids}});
            return;
        }
    }
    send_conflict(res);
}

} // namespace bsfchat
