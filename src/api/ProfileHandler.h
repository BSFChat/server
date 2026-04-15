#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
struct Config;

class ProfileHandler {
public:
    ProfileHandler(SqliteStore& store, const Config& config);

    void handle_get_profile(const httplib::Request& req, httplib::Response& res);
    void handle_get_displayname(const httplib::Request& req, httplib::Response& res);
    void handle_put_displayname(const httplib::Request& req, httplib::Response& res);
    void handle_get_avatar_url(const httplib::Request& req, httplib::Response& res);
    void handle_put_avatar_url(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    const Config& config_;
};

} // namespace bsfchat
