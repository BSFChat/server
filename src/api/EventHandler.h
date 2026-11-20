#pragma once

#include "core/SendLimiter.h"

#include <httplib.h>

#include <mutex>
#include <vector>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
class PushService;
struct Config;

class EventHandler {
public:
    // `push` may be null — the handler then simply records no notifications.
    // Push evaluation only ever enqueues rows, so this path never blocks on
    // outbound HTTP regardless.
    // `clock` is injectable so tests can move time instead of sleeping out a
    // rate-limit window, matching how AuthHandler's limiters are tested.
    EventHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config,
                 PushService* push = nullptr,
                 LimiterClock clock = limiter_steady_now_ms);

    void handle_send_event(const httplib::Request& req, httplib::Response& res);
    void handle_room_messages(const httplib::Request& req, httplib::Response& res);
    void handle_read_marker(const httplib::Request& req, httplib::Response& res);
    void handle_redact(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    PushService* push_ = nullptr;
    // Per-account ceiling on writes to a room. Held by the handler because the
    // counters have to outlive a request; Server.cpp builds exactly one
    // EventHandler and shares it across every worker thread, which is what
    // makes one account's budget one budget.
    SendLimiter limits_;
    // The /sync token key, so /messages can accept a next_batch as `from`.
    // Derived the way SyncEngine derives its own (same secret, same server
    // name, so the same key), lazily for the same reason.
    const std::vector<unsigned char>& sync_token_key();
    std::once_flag sync_key_once_;
    std::vector<unsigned char> sync_key_;
};

} // namespace bsfchat
