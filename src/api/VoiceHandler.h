#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

class VoiceHandler {
public:
    VoiceHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

    void handle_voice_join(const httplib::Request& req, httplib::Response& res);
    void handle_voice_leave(const httplib::Request& req, httplib::Response& res);
    void handle_voice_members(const httplib::Request& req, httplib::Response& res);
    void handle_voice_state(const httplib::Request& req, httplib::Response& res);
    void handle_turn_server(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
