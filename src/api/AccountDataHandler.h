#pragma once

#include "core/SendLimiter.h"

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

// Matrix per-account key/value storage, and the block list it carries.
//
//   GET /_matrix/client/v3/user/{userId}/account_data/{type}
//   PUT /_matrix/client/v3/user/{userId}/account_data/{type}
//
// This server had no account data at all. It is added here because blocking
// needs it: Matrix stores a user's block list as the `m.ignored_user_list`
// account-data document, and a client that speaks the protocol will look for it
// there. Inventing a bsfchat.* blocking endpoint instead would have worked
// exactly as well and been wrong for the reason the notify_level route is
// namespaced and this one is not — there IS a spec path here, and claiming a
// different one makes every conventional client's block button do nothing.
//
// ── userId must be the caller, always ─────────────────────────────────────
//
// Both verbs refuse a userId that is not the authenticated account, with 403
// M_FORBIDDEN, and this is the whole access-control story for the endpoint:
// account data is private per-account storage with no sharing model, no
// moderator read, and no admin read. There is deliberately no permission that
// unlocks somebody else's.
//
// That matters more here than it would for an arbitrary key/value store,
// because of what is in it. THE BLOCK LIST IS THE ONE PIECE OF STATE ON THIS
// SERVER WHOSE VALUE IS THAT ITS SUBJECT CANNOT SEE IT. A blocked account that
// could read the list learns it has been blocked, by whom, and — since the
// block is what stops the harassment — exactly which account to come back at
// from a second one. Every refusal on this endpoint is that rule.
//
// ── It reaches the account's other devices now ────────────────────────────
//
// When this endpoint was added, /sync carried no account data, so a block made
// on a phone never reached the desktop and the header said so. It does now: a
// write claims a stream position and every one of the account's /sync polls
// picks it up against the token it already holds (see
// server/docs/read-state.md). The PUT wakes them rather than letting them time
// out first.
//
// ── Global account data only ──────────────────────────────────────────────
//
// Matrix also defines room-scoped account data
// (/user/{u}/rooms/{r}/account_data/{t}). It is not here, deliberately: on this
// server membership is not visibility, so a room-scoped write needs a
// VIEW_CHANNEL gate of its own and a decision about what happens to the rows
// when the channel is deleted. Nothing needs it yet, and a half-considered
// version would be a second place for that gate to be got wrong. Add it with
// its first caller. Until then the route is absent and httplib answers 404,
// which is what a client should see for something the server does not
// implement.
class AccountDataHandler {
public:
    AccountDataHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config,
                       LimiterClock clock = limiter_steady_now_ms);

    // 200 with the stored document, or 404 M_NOT_FOUND when this account has
    // never written one — the shape the Matrix spec defines, and what lets a
    // client tell "no block list" from "an empty block list".
    void handle_get_account_data(const httplib::Request& req, httplib::Response& res);

    // 200 {} on success. The body must be a JSON object; a bare array, string or
    // number is 400 M_BAD_JSON.
    //
    // For m.ignored_user_list the document is additionally VALIDATED rather
    // than stored blind — every key must be a syntactically valid user id, the
    // list has a ceiling (input_limits::kMaxIgnoredUsers), and the caller may
    // not ignore themselves. It is the one type whose contents this server acts
    // on, so it is the one type that cannot be allowed to contain nonsense: a
    // malformed entry stored happily and silently enforcing nothing is a block
    // the user believes they have and does not.
    void handle_put_account_data(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    // A successful PUT wakes parked /sync polls: since schema v30 the account's
    // OTHER devices learn about the write from /sync, and the whole value of
    // that is not waiting out a poll timeout for it.
    SyncEngine& sync_engine_;
    const Config& config_;
    SendLimiter limits_;
};

} // namespace bsfchat
