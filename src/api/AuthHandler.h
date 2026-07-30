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
    // POST /_matrix/client/v3/logout/all — revokes every session for the
    // account, including the calling one.
    void handle_logout_all(const httplib::Request& req, httplib::Response& res);
    void handle_whoami(const httplib::Request& req, httplib::Response& res);
    // POST /_matrix/client/v3/account/password — authenticated password change.
    // Requires the current password (a valid access token is not enough) and
    // revokes the account's other sessions unless logout_devices is false.
    void handle_password_change(const httplib::Request& req, httplib::Response& res);
    // POST /_matrix/client/v3/refresh — exchanges a refresh token for a fresh
    // access/refresh pair, rotating both.
    void handle_refresh(const httplib::Request& req, httplib::Response& res);

private:
    // Configured access-token lifetime, in milliseconds.
    [[nodiscard]] int64_t token_lifetime_ms() const;

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    OidcAuth* oidc_auth_ = nullptr;
};

} // namespace bsfchat
