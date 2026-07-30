#include "api/AuditHandler.h"

#include "auth/Permissions.h"
#include "core/Config.h"
#include "http/Middleware.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <string>

namespace bsfchat {

using json = nlohmann::json;

namespace {

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// Stored payloads are JSON text. Hand them back as JSON so a client does not have
// to parse a string out of a string; fall back to the raw text if a record
// somehow holds something unparseable, because dropping it would be worse.
json payload_or_raw(const std::string& stored) {
    auto parsed = json::parse(stored, nullptr, false);
    if (parsed.is_discarded()) return stored;
    return parsed;
}

json record_to_json(const SqliteStore::AuditRecord& r) {
    json out = {
        {"id", r.id},
        {"created_at", r.created_at},
        {"actor", r.actor},
        {"action", r.action},
    };
    // Empty means "not applicable to this action" — omit rather than emit "" and
    // make every consumer decide what an empty target id means.
    if (!r.target_user.empty()) out["target_user"] = r.target_user;
    if (!r.target_room.empty()) out["target_room"] = r.target_room;
    if (!r.target_key.empty()) out["target_key"] = r.target_key;
    if (!r.reason.empty()) out["reason"] = r.reason;
    if (!r.before_json.empty()) out["before"] = payload_or_raw(r.before_json);
    if (!r.after_json.empty()) out["after"] = payload_or_raw(r.after_json);
    return out;
}

} // namespace

AuditHandler::AuditHandler(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {}

void AuditHandler::handle_get_audit_log(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    // SERVER-scope permission check. The empty room_id is the whole point: with a
    // room_id, PermissionsEngine::compute applies that channel's allow/deny
    // overrides, and a MANAGE_SERVER override inside one channel would then unlock
    // the server-wide audit log. ADMINISTRATOR still passes here — compute()
    // short-circuits it to every flag before any override is considered.
    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, "", permission::kManageServer)) {
        return send_error(res, 403, MatrixError::forbidden(
            "Insufficient permissions to read the moderation audit log"));
    }

    int limit = limits::kDefaultAuditLimit;
    if (req.has_param("limit")) {
        try {
            limit = std::clamp(std::stoi(req.get_param_value("limit")), 1,
                               limits::kMaxAuditLimit);
        } catch (const std::exception&) {
            return send_error(res, 400, MatrixError::invalid_param("limit must be an integer"));
        }
    }

    std::optional<int64_t> before_id;
    if (req.has_param("from")) {
        // Rejected rather than silently ignored. A malformed cursor treated as
        // "start again from the newest" would hand a paginating caller the first
        // page forever while looking like progress — on an audit log, that is a
        // reader who believes they have seen everything and has not.
        try {
            before_id = std::stoll(req.get_param_value("from"));
        } catch (const std::exception&) {
            return send_error(res, 400, MatrixError::invalid_param("from must be an integer"));
        }
        if (*before_id < 0) {
            return send_error(res, 400, MatrixError::invalid_param("from must not be negative"));
        }
    }

    auto page = store_.list_audit_records(limit, before_id);

    json records = json::array();
    for (const auto& record : page.records) records.push_back(record_to_json(record));

    json out = {
        {"records", std::move(records)},
        // Total rows in the table. Retention is deliberately unbounded (see
        // SqliteStore::append_audit_record), so the number an operator would need
        // in order to revisit that decision is surfaced rather than buried.
        {"total", page.total},
    };
    if (page.next_from) out["next_from"] = *page.next_from;

    res.set_content(out.dump(), "application/json");
}

} // namespace bsfchat
