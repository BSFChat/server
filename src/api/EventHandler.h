#pragma once

#include <httplib.h>

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
    EventHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config,
                 PushService* push = nullptr);

    void handle_send_event(const httplib::Request& req, httplib::Response& res);
    void handle_room_messages(const httplib::Request& req, httplib::Response& res);
    void handle_read_marker(const httplib::Request& req, httplib::Response& res);
    void handle_redact(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    PushService* push_ = nullptr;
};

} // namespace bsfchat
