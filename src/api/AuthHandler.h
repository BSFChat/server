#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class OidcAuth;
class SyncEngine;
struct Config;

class AuthHandler {
public:
    AuthHandler(SqliteStore& store, SyncEngine& sync_engine,
                const Config& config, OidcAuth* oidc_auth = nullptr);

    void handle_versions(const httplib::Request& req, httplib::Response& res);
    void handle_login_flows(const httplib::Request& req, httplib::Response& res);
    void handle_login(const httplib::Request& req, httplib::Response& res);
    void handle_register(const httplib::Request& req, httplib::Response& res);
    void handle_logout(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    OidcAuth* oidc_auth_ = nullptr;
};

} // namespace bsfchat
