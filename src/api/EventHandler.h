#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

class EventHandler {
public:
    EventHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

    void handle_send_event(const httplib::Request& req, httplib::Response& res);
    void handle_room_messages(const httplib::Request& req, httplib::Response& res);
    void handle_read_marker(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
