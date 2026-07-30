#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
struct Config;

// GET /_matrix/client/v3/bsfchat/audit_log — read the moderation audit log.
//
// The only read path to the audit log, and the only reason it is worth writing
// one: before this, nothing could tell a server owner who kicked whom, who
// rewrote a role's permissions, or who deleted a category.
//
// Gated on MANAGE_SERVER evaluated at SERVER scope — the permission engine is
// called with an EMPTY room_id, which is the load-bearing detail. Per-channel
// allow/deny overrides are only consulted when a room_id is supplied, so an
// override granting a flag inside one unimportant channel cannot reach a
// server-wide log. That precise escalation shape (a per-channel override
// unlocking a server-wide capability) was a real bug in the role-write path, and
// this endpoint must not reintroduce it. ADMINISTRATOR still passes, because
// compute() short-circuits it to every flag before any override is applied.
//
// Paginated newest-first over a strictly monotonic id. Records are never
// modified, never deleted and never renumbered, so a cursor of "older than id N"
// stays exactly as valid as when it was issued, however many inserts land in
// between.
class AuditHandler {
public:
    AuditHandler(SqliteStore& store, const Config& config);

    void handle_get_audit_log(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    const Config& config_;
};

} // namespace bsfchat
