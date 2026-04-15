#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class OidcAuth;
struct Config;

class AuthHandler {
public:
    AuthHandler(SqliteStore& store, const Config& config, OidcAuth* oidc_auth = nullptr);

    void handle_versions(const httplib::Request& req, httplib::Response& res);
    void handle_login_flows(const httplib::Request& req, httplib::Response& res);
    void handle_login(const httplib::Request& req, httplib::Response& res);
    void handle_register(const httplib::Request& req, httplib::Response& res);
    void handle_logout(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    const Config& config_;
    OidcAuth* oidc_auth_ = nullptr;
};

} // namespace bsfchat
