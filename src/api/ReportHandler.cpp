#include "api/ReportHandler.h"
#include "api/InputLimits.h"

#include "audit/AuditLog.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/JsonIo.h"
#include "http/Middleware.h"
#include "http/RateLimitResponse.h"
#include "http/Router.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>

namespace bsfchat {

using json = nlohmann::json;

namespace {

constexpr const char* kReportEventRoute =
    "/_matrix/client/v3/rooms/{roomId}/report/{eventId}";
constexpr const char* kReportUserRoute = "/_matrix/client/v3/users/{userId}/report";
constexpr const char* kListReportsRoute = "/_matrix/client/v3/bsfchat/reports";

// Page sizes for the administrator's queue. Local rather than in the protocol's
// limits:: for the reason the route literals above are local — adding constants
// there moves this change into a second repository that has to merge first.
constexpr int kDefaultReportLimit = 50;
constexpr int kMaxReportLimit = 500;

// Matrix's severity hint: -100 is "most offensive", 0 is "inoffensive". The
// range is the spec's, and it is enforced rather than clamped because a client
// sending 50 has misunderstood the sign convention, and silently storing it as
// 0 would file every one of that client's reports as harmless.
constexpr int kMinScore = -100;
constexpr int kMaxScore = 0;

// Server scope for PermissionsEngine — the empty room id. See ReportHandler.h
// for why reading the queue must be evaluated with it, and AuditHandler.h for
// the escalation shape it prevents.
const std::string kServerScope;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// `reason` and `score` out of a report body, or the 400 to send.
//
// Both are optional in the Matrix spec and both are optional here. A report
// with no reason is still a report — the event id and the sender are the
// substance, and requiring prose would mean a client either nagging the user or
// inventing filler that an administrator then has to read past.
struct ReportBody {
    std::string reason;
    int score = 0;
    std::optional<MatrixError> error;
};

ReportBody parse_report_body(const std::string& raw, bool scored) {
    ReportBody out;

    // An empty body is `{}`. httplib hands an empty string for a POST with no
    // body at all, and json::parse throws on it; a report with neither field is
    // legitimate, so it must not be a 400.
    json body = json::object();
    if (!raw.empty()) {
        try {
            body = parse_request_json(raw);
        } catch (...) {
            out.error = MatrixError::bad_json();
            return out;
        }
    }
    if (!body.is_object()) {
        out.error = MatrixError::bad_json();
        return out;
    }

    if (auto it = body.find("reason"); it != body.end() && !it->is_null()) {
        if (!it->is_string()) {
            out.error = MatrixError::invalid_param("reason must be a string");
            return out;
        }
        out.reason = it->get<std::string>();
        // The same ceiling a kick or ban reason gets, and for the same reason:
        // it is caller text that is stored and later read by a person.
        if (auto err = oversize_field("reason", out.reason, input_limits::kMaxReasonBytes)) {
            out.error = *err;
            return out;
        }
    }

    if (scored) {
        if (auto it = body.find("score"); it != body.end() && !it->is_null()) {
            if (!it->is_number_integer()) {
                out.error = MatrixError::invalid_param("score must be an integer");
                return out;
            }
            const auto score = it->get<int64_t>();
            if (score < kMinScore || score > kMaxScore) {
                out.error = MatrixError::invalid_param(
                    "score must be between " + std::to_string(kMinScore) + " and " +
                    std::to_string(kMaxScore));
                return out;
            }
            out.score = static_cast<int>(score);
        }
    }

    return out;
}

// The bounded copy of a reported event kept with the report.
//
// The whole content object, not just `body`: a report about an image is about
// the `url`, one about a formatted message may be about markup the plain body
// does not show, and an administrator reading the queue months later has no
// other way to see what it was. Truncated on a byte boundary with a marker,
// because what this defends against is somebody posting a large message and
// having it reported many times (input_limits::kMaxReportSnapshotBytes).
std::string snapshot_of(const RoomEvent& event) {
    std::string dumped = event.content.data.dump();
    if (dumped.size() <= input_limits::kMaxReportSnapshotBytes) return dumped;
    dumped.resize(input_limits::kMaxReportSnapshotBytes);
    // The marker matters: a silently truncated JSON document looks like a
    // malformed one, and an administrator should be able to tell "the server
    // cut this" from "this arrived broken".
    dumped += "…[truncated]";
    return dumped;
}

json report_to_json(const SqliteStore::ContentReport& r) {
    json out = {
        {"id", r.id},
        {"created_at", r.created_at},
        {"reporter", r.reporter},
        {"score", r.score},
    };
    // Empty means "not applicable to this kind of report" — a user-level report
    // has no room or event. Omitted rather than emitted as "", so no consumer
    // has to decide what an empty room id means.
    if (!r.target_user.empty()) out["target_user"] = r.target_user;
    if (!r.room_id.empty()) out["room_id"] = r.room_id;
    if (!r.event_id.empty()) out["event_id"] = r.event_id;
    if (!r.event_sender.empty()) out["event_sender"] = r.event_sender;
    if (!r.reason.empty()) out["reason"] = r.reason;
    if (!r.event_snapshot.empty()) {
        // Handed back as JSON when it parses, as text when it does not — which
        // is what a truncated snapshot always is. Same shape AuditHandler uses
        // for a stored payload, so an operator's tooling reads both the same
        // way.
        auto parsed = json::parse(r.event_snapshot, nullptr, false);
        out["event_content"] = parsed.is_discarded() ? json(r.event_snapshot) : parsed;
    }
    return out;
}

} // namespace

ReportHandler::ReportHandler(SqliteStore& store, const Config& config, LimiterClock clock)
    : store_(store), config_(config), limits_(config.send_limits, std::move(clock)) {}

void ReportHandler::handle_report_event(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto match = match_route(kReportEventRoute, req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }
    const auto& room_id = match.params["roomId"];
    const auto& event_id = match.params["eventId"];

    // Charged before anything is read or parsed, for the reason every limiter
    // in this server is charged first: the budget bounds work, and a lookup is
    // work. It is also charged on a report that goes on to be REFUSED, which is
    // deliberate — otherwise the endpoint is a free, unlimited probe and only
    // the successful half of it is bounded.
    if (const auto wait = limits_.acquire(SendLimiter::Bucket::kReport, *user_id)) {
        return send_rate_limited(res, wait,
                                 SendLimiter::message_for(SendLimiter::Bucket::kReport));
    }

    // ── ONE REFUSAL FOR EVERY WAY THIS CAN FAIL TO NAME A VISIBLE EVENT ───
    //
    // 404 M_NOT_FOUND, identically, for: no such event; an event in a room the
    // caller is not in; an event in a room the caller's roles cannot view; and
    // an event that exists in a DIFFERENT room from the one named in the path.
    //
    // They have to be indistinguishable. This endpoint takes an arbitrary event
    // id from an unprivileged caller and is reachable by every account on the
    // server, so any refusal that told the four apart would turn it into an
    // existence oracle over every event on the deployment — "is $abc a real
    // event", then "is it in !secret", answered one request at a time. The
    // report rate limit slows that down; it is not what stops it.
    //
    // Membership AND VIEW_CHANNEL, in that order, and kViewChannel asked
    // directly rather than through can_view_room(): that helper exempts
    // categories because the sidebar must render a container it cannot open,
    // which is a rule about LISTING a room. This is a read of something inside
    // one, so it gets the reading rule. Same reasoning as /messages and
    // /read_marker, which are the two other places this distinction is argued.
    const auto refuse_unknown = [&res] {
        send_error(res, 404, MatrixError::not_found("Event not found"));
    };

    if (!store_.is_room_member(room_id, *user_id)) {
        return refuse_unknown();
    }
    {
        PermissionsEngine perms(store_, config_);
        if (!perms.can(*user_id, room_id, permission::kViewChannel)) {
            return refuse_unknown();
        }
    }

    auto event = store_.get_event_by_id(event_id);
    // The room check is not redundant with the membership check above: without
    // it, a member of ANY channel could report an event id belonging to a
    // channel they cannot see and have its content copied into a report — which
    // would make this endpoint a read path for arbitrary events, wearing a
    // write endpoint's clothes.
    if (!event || event->room_id != room_id) {
        return refuse_unknown();
    }

    auto parsed = parse_report_body(req.body, /*scored=*/true);
    if (parsed.error) {
        return send_error(res, 400, *parsed.error);
    }

    SqliteStore::ContentReport report;
    report.created_at = now_ms();
    report.reporter = *user_id;
    // THE SENDER FROM THE EVENT, never a user id from the request. A reporter
    // says what they are reporting; they do not get to say whose record it
    // lands on. Nothing in the body is read into this field, and there is no
    // field in the body for it.
    report.target_user = event->sender;
    report.event_sender = event->sender;
    report.room_id = room_id;
    report.event_id = event_id;
    report.event_snapshot = snapshot_of(*event);
    report.score = parsed.score;
    report.reason = parsed.reason;

    const int64_t id = store_.add_content_report(report);
    audit_content_report(store_, *user_id, report.target_user, room_id, event_id,
                         report.score, report.reason);

    // Logged so an operator watching the server learns about a report without
    // polling the queue. No reason and no content: the line goes to a file an
    // operator tails, the reason is a person's words about another person, and
    // the queue is where both belong.
    get_logger()->info("Content report #{} filed by {} against {} in room {} (score {})",
                       id, *user_id, report.target_user, room_id, report.score);

    // 200 {} whatever else is true — including when this is the tenth identical
    // report of the same event by the same account. Duplicates are not refused
    // and not deduplicated: telling a reporter "already reported" would say
    // that somebody else reported it, which is somebody else's business, and
    // refusing their own repeat would leave them unsure it was filed at all.
    // The administrator sees the count, which is information.
    res.set_content("{}", "application/json");
}

void ReportHandler::handle_report_user(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto match = match_route(kReportUserRoute, req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }
    const auto& target = match.params["userId"];

    if (const auto wait = limits_.acquire(SendLimiter::Bucket::kReport, *user_id)) {
        return send_rate_limited(res, wait,
                                 SendLimiter::message_for(SendLimiter::Bucket::kReport));
    }

    if (!UserId::is_valid(target)) {
        return send_error(res, 400, MatrixError::invalid_param("Invalid user id"));
    }
    // Reporting yourself is refused rather than stored. It is always either a
    // client bug or a test, and neither belongs in a queue a person reads.
    if (target == *user_id) {
        return send_error(res, 400, MatrixError::invalid_param("You cannot report yourself"));
    }

    // Existence is checked, and answering 404 for an account that does not
    // exist does disclose existence to an authenticated caller. That is
    // acceptable here and it is worth saying why rather than leaving it to be
    // found: GET /profile/{userId} already answers the same question for the
    // same callers, so this adds no oracle that is not already there, and it is
    // behind the tightest rate limit in the server. The alternative — accepting
    // reports about ids nobody holds — fills the moderation queue with typos
    // and with an attacker's fabricated names, which is a real cost paid to
    // withhold nothing.
    //
    // NO CO-MEMBERSHIP REQUIREMENT, deliberately. The conduct a user-level
    // report exists for is exactly the conduct that has already made the
    // reporter leave: the DM they backed out of, the channel they stopped
    // opening. Requiring a shared room would refuse the reports most worth
    // having.
    if (!store_.user_exists(target)) {
        return send_error(res, 404, MatrixError::not_found("User not found"));
    }

    // `scored=false`: the Matrix user-report endpoint carries no score, and
    // accepting one here would mean the two kinds of report sorted differently
    // in the same queue for no reason a reader could see.
    auto parsed = parse_report_body(req.body, /*scored=*/false);
    if (parsed.error) {
        return send_error(res, 400, *parsed.error);
    }

    SqliteStore::ContentReport report;
    report.created_at = now_ms();
    report.reporter = *user_id;
    report.target_user = target;
    report.reason = parsed.reason;

    const int64_t id = store_.add_content_report(report);
    audit_content_report(store_, *user_id, target, "", "", 0, report.reason);

    get_logger()->info("User report #{} filed by {} against {}", id, *user_id, target);

    res.set_content("{}", "application/json");
}

void ReportHandler::handle_list_reports(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto match = match_route(kListReportsRoute, req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    // SERVER scope. kServerScope is the empty room id and it is the whole check
    // — see ReportHandler.h and AuditHandler.h. It is the FIRST thing this
    // handler does after routing, ahead of the cursor and the page size, so no
    // parameter can reach around it.
    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, kServerScope, permission::kManageServer)) {
        return send_error(res, 403, MatrixError::forbidden(
            "Insufficient permissions to read content reports"));
    }

    int limit = kDefaultReportLimit;
    if (req.has_param("limit")) {
        try {
            limit = std::clamp(std::stoi(req.get_param_value("limit")), 1, kMaxReportLimit);
        } catch (const std::exception&) {
            return send_error(res, 400, MatrixError::invalid_param("limit must be an integer"));
        }
    }

    std::optional<int64_t> before_id;
    if (req.has_param("from")) {
        // Refused rather than silently ignored, exactly as the audit log
        // refuses a malformed cursor: a bad cursor read as "start from the
        // newest" hands a paginating reader the first page forever while
        // looking like progress, and on a moderation queue that is somebody who
        // believes they have triaged everything and has not.
        try {
            before_id = std::stoll(req.get_param_value("from"));
        } catch (const std::exception&) {
            return send_error(res, 400, MatrixError::invalid_param("from must be an integer"));
        }
        if (*before_id < 0) {
            return send_error(res, 400, MatrixError::invalid_param("from must not be negative"));
        }
    }

    auto page = store_.list_content_reports(limit, before_id);

    json reports = json::array();
    for (const auto& r : page.reports) reports.push_back(report_to_json(r));

    json out = {
        {"reports", std::move(reports)},
        {"total", page.total},
    };
    if (page.next_from) out["next_from"] = *page.next_from;

    // Lenient dump: this response carries OTHER accounts' message content, and
    // the strict dump() throws on invalid UTF-8 anywhere in it. One bad byte in
    // one snapshot must not be able to take the whole moderation queue down —
    // which is the shape of audit S1, on the one endpoint whose job is to show
    // an administrator content that somebody has already flagged as hostile.
    res.set_content(dump_response_json(out), "application/json");
}

} // namespace bsfchat
