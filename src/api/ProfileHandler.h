#pragma once

#include "core/SendLimiter.h"

#include <httplib.h>
#include <string>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

class ProfileHandler {
public:
    // `clock` drives the profile rate limiter only; it is a parameter so a test
    // can outlive a window without sleeping through it. Limiter sizes come from
    // config.send_limits, read here once.
    ProfileHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config,
                   LimiterClock clock = limiter_steady_now_ms);

    void handle_get_profile(const httplib::Request& req, httplib::Response& res);
    void handle_get_displayname(const httplib::Request& req, httplib::Response& res);
    void handle_put_displayname(const httplib::Request& req, httplib::Response& res);
    void handle_get_avatar_url(const httplib::Request& req, httplib::Response& res);
    void handle_put_avatar_url(const httplib::Request& req, httplib::Response& res);

    // Per-server nickname. Unlike displayname/avatar_url, which are strictly
    // self-service, this endpoint accepts a target other than the caller —
    // setting your own needs CHANGE_NICKNAME, setting anybody else's needs
    // MANAGE_NICKNAMES plus the same rank check kick and ban apply. Both are
    // evaluated at SERVER scope: a nickname is one value for the whole server, so
    // a per-channel override must not be able to grant it.
    void handle_get_nickname(const httplib::Request& req, httplib::Response& res);
    void handle_put_nickname(const httplib::Request& req, httplib::Response& res);

private:
    // Re-emit m.room.member in every joined room with the updated
    // displayname/avatar so all connected clients see the change.
    void broadcastMemberUpdate(const std::string& user_id);

    // Charges one profile write to `user_id`'s budget and, when that budget is
    // spent, writes the 429 and returns true — so a caller reads as
    // `if (profile_flood(*user_id, res)) return;`.
    //
    // The limit exists because of what broadcastMemberUpdate costs, not because
    // of what this endpoint stores: one request is one m.room.member insert per
    // joined channel plus a server-wide /sync wake, so an unlimited loop from a
    // single ordinary account is tens of thousands of event rows a second
    // through the store's one mutex and a sync-latency collapse for everybody
    // else. It is charged against the ACCOUNT BEING CHANGED, not the caller: the
    // fan-out is over that account's channels, and a moderator renaming other
    // people must not be able to spend one budget on many amplifiers.
    bool profile_flood(const std::string& user_id, httplib::Response& res);

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    SendLimiter limits_;
};

} // namespace bsfchat
