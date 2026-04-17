#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

class ProfileHandler {
public:
    ProfileHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

    void handle_get_profile(const httplib::Request& req, httplib::Response& res);
    void handle_get_displayname(const httplib::Request& req, httplib::Response& res);
    void handle_put_displayname(const httplib::Request& req, httplib::Response& res);
    void handle_get_avatar_url(const httplib::Request& req, httplib::Response& res);
    void handle_put_avatar_url(const httplib::Request& req, httplib::Response& res);

private:
    // Re-emit m.room.member in every joined room with the updated
    // displayname/avatar so all connected clients see the change.
    void broadcastMemberUpdate(const std::string& user_id);

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
