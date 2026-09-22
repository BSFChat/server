#pragma once

#include "core/SendLimiter.h"

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
struct Config;

// Content and user reporting.
//
//   POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}   {score, reason}
//   POST /_matrix/client/v3/users/{userId}/report             {reason}
//   GET  /_matrix/client/v3/bsfchat/reports                   (administrators)
//
// The first two are Matrix spec paths and are spec-shaped down to the field
// names, so a conventional client's report button works against this server
// without knowing anything about it. The third is bsfchat.* because Matrix has
// no read path for reports at all — the spec assumes an out-of-band moderation
// tool — and this deployment is one server with one owner, who has no such
// tool. Same precedent as the audit-log and bot routes.
//
// ── What a report is, and what it deliberately is not ─────────────────────
//
// A report changes NOTHING. It does not redact the event, mute the sender,
// hide anything from anybody, or notify the reported account. It is a row and
// an audit record, and every effect it has happens later, by hand, through the
// moderation routes that already exist. That is the whole design, and it is
// what keeps the endpoint safe to expose to every account on the server: an
// endpoint with no consequence cannot be turned into a weapon by filing enough
// of them, and the one resource it does consume — an administrator's
// attention — is bounded by the rate limit.
//
// A user who wants an effect right now wants the BLOCK (AccountDataHandler),
// which is instant, private and needs nobody's help. The two are a pair and a
// client should offer them together: block to stop it, report to have it dealt
// with.
//
// ── The reported party learns nothing ─────────────────────────────────────
//
// Nothing here writes an event, wakes a sync, or changes any response the
// reported account receives. A report is invisible to its subject for the same
// reason a block is: the person most likely to retaliate is the one being
// reported, and a reporting feature that tips them off is one people learn not
// to use.
//
// ── Reading the queue is gated exactly like the audit log ─────────────────
//
// MANAGE_SERVER evaluated at SERVER SCOPE — PermissionsEngine::can with an
// EMPTY room_id. The empty room id is load-bearing and is the same detail
// AuditHandler.h explains at length: per-channel allow/deny overrides are only
// consulted when a room_id is supplied, so an override granting the flag inside
// one unimportant channel must not unlock a server-wide queue. ADMINISTRATOR
// passes, because compute() short-circuits it before any override.
//
// And, as with the audit log, the RECORDS ARE NOT THEN FILTERED against the
// reader's VIEW_CHANNEL. A report names the channel it came from, so a reader
// learns that a private channel exists. That is the point: the report an
// administrator most needs to see is the one from the channel they were not
// watching, and a queue with holes in it and no marks where the holes are is
// worse than no queue, because it reads as complete. See audit/AuditLog.h for
// the full argument — it is the same one, and if it is ever revisited it must
// be revisited in both places or the two will disagree about the same rooms.
class ReportHandler {
public:
    ReportHandler(SqliteStore& store, const Config& config,
                  LimiterClock clock = limiter_steady_now_ms);

    // POST /rooms/{roomId}/report/{eventId}. 200 {} on success.
    //
    // Requires membership AND VIEW_CHANNEL on the room, and answers the same
    // 404 for "no such event", "an event in a room you cannot see" and "an
    // event in a different room" — reporting must not become an event-existence
    // oracle over the whole server, which is exactly what it would be if the
    // refusals were distinguishable.
    void handle_report_event(const httplib::Request& req, httplib::Response& res);

    // POST /users/{userId}/report. 200 {} on success.
    //
    // For conduct that is not one event: a display name, an avatar, a pattern
    // across a conversation, a DM the reporter has since left. Accepted for any
    // user id that EXISTS, with no requirement that the reporter share a room
    // with them — see the .cpp for why that is not an enumeration oracle here
    // and what bounds it.
    void handle_report_user(const httplib::Request& req, httplib::Response& res);

    // GET /bsfchat/reports. Newest first, paginated on a monotonic id with the
    // same cursor shape as the audit log.
    void handle_list_reports(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    const Config& config_;
    SendLimiter limits_;
};

} // namespace bsfchat
