#include "api/AuthHandler.h"
#include "auth/AutoJoin.h"
#include "auth/LocalAuth.h"
#include "auth/OidcAuth.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>
#include <algorithm>

namespace bsfchat {

using json = nlohmann::json;

AuthHandler::AuthHandler(SqliteStore& store, SyncEngine& sync_engine,
                         const Config& config, OidcAuth* oidc_auth)
    : store_(store), sync_engine_(sync_engine), config_(config), oidc_auth_(oidc_auth) {}

void AuthHandler::handle_versions(const httplib::Request&, httplib::Response& res) {
    json resp = {
        {"versions", {std::string(spec::kVersion)}},
    };
    res.set_content(resp.dump(), "application/json");
}

void AuthHandler::handle_login_flows(const httplib::Request&, httplib::Response& res) {
    auto flows = json::array();

    // Always include password login unless identity is required and local accounts are disabled
    if (!config_.identity || !config_.identity->required || config_.identity->allow_local_accounts) {
        flows.push_back({{"type", "m.login.password"}});
    }

    // Include token login if OIDC is configured
    if (oidc_auth_) {
        json token_flow = {{"type", "m.login.token"}};
        if (config_.identity) {
            token_flow["identity_provider"] = config_.identity->provider_url;
        }
        flows.push_back(token_flow);
    }

    json resp = {{"flows", flows}};
    res.set_content(resp.dump(), "application/json");
}

void AuthHandler::handle_login(const httplib::Request& req, httplib::Response& res) {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    LoginRequest login_req;
    try {
        from_json(body, login_req);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing required fields").to_json().dump(), "application/json");
        return;
    }

    if (login_req.type == "m.login.password") {
        std::string user_id = login_req.identifier.user;
        // If user provided just a localpart, construct the full user_id
        if (!user_id.empty() && user_id[0] != '@') {
            user_id = "@" + user_id + ":" + config_.server_name;
        }

        auto hash = store_.get_password_hash(user_id);
        if (!hash || !verify_password(login_req.password, *hash)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden("Invalid username or password").to_json().dump(), "application/json");
            return;
        }

        auto access_token = generate_access_token();
        auto device_id = login_req.device_id.value_or(generate_device_id());
        store_.store_access_token(access_token, user_id, device_id);

        LoginResponse login_resp{
            .user_id = user_id,
            .access_token = access_token,
            .device_id = device_id,
        };

        json resp;
        to_json(resp, login_resp);
        res.set_content(resp.dump(), "application/json");

        get_logger()->info("User logged in: {}", user_id);

    } else if (login_req.type == "m.login.token") {
        if (!oidc_auth_) {
            res.status = 400;
            res.set_content(MatrixError::unknown("Token login is not configured").to_json().dump(), "application/json");
            return;
        }

        auto claims = oidc_auth_->validate_token(login_req.token);
        if (!claims) {
            res.status = 403;
            res.set_content(MatrixError::forbidden("Invalid identity token").to_json().dump(), "application/json");
            return;
        }

        // Build user_id from OIDC subject
        std::string user_id = "@oidc_" + claims->sub + ":" + config_.server_name;

        // Create user if they don't exist (OIDC-only user with empty password hash)
        bool newly_created = !store_.user_exists(user_id);
        if (newly_created) {
            store_.create_user(user_id, ""); // empty hash — cannot log in with password
        }

        // Set display name from claims if available
        if (claims->name) {
            store_.set_display_name(user_id, *claims->name);
        }

        auto access_token = generate_access_token();
        auto device_id = login_req.device_id.value_or(generate_device_id());
        store_.store_access_token(access_token, user_id, device_id);

        if (newly_created) {
            auto_join_public_rooms(store_, sync_engine_, config_, user_id);
        }

        LoginResponse login_resp{
            .user_id = user_id,
            .access_token = access_token,
            .device_id = device_id,
        };

        json resp;
        to_json(resp, login_resp);
        res.set_content(resp.dump(), "application/json");

        get_logger()->info("OIDC user logged in: {} (sub: {})", user_id, claims->sub);

    } else {
        res.status = 400;
        res.set_content(MatrixError::unknown("Unsupported login type").to_json().dump(), "application/json");
        return;
    }
}

void AuthHandler::handle_register(const httplib::Request& req, httplib::Response& res) {
    if (!config_.registration_enabled) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Registration is disabled").to_json().dump(), "application/json");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    RegisterRequest reg_req;
    try {
        from_json(body, reg_req);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing username or password").to_json().dump(), "application/json");
        return;
    }

    // Validate username
    auto& username = reg_req.username;
    if (username.empty() || username.size() > limits::kMaxUsernameLength) {
        res.status = 400;
        res.set_content(MatrixError::invalid_username("Username must be 1-64 characters").to_json().dump(), "application/json");
        return;
    }
    if (!std::all_of(username.begin(), username.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        })) {
        res.status = 400;
        res.set_content(MatrixError::invalid_username("Username may only contain lowercase letters, digits, ., _, -").to_json().dump(), "application/json");
        return;
    }

    if (reg_req.password.size() < limits::kMinPasswordLength) {
        res.status = 400;
        res.set_content(MatrixError::invalid_param("Password must be at least 8 characters").to_json().dump(), "application/json");
        return;
    }

    std::string user_id = "@" + username + ":" + config_.server_name;

    if (store_.user_exists(user_id)) {
        res.status = 400;
        res.set_content(MatrixError::user_in_use().to_json().dump(), "application/json");
        return;
    }

    auto password_hash = hash_password(reg_req.password, config_.password_hash_cost);
    if (!store_.create_user(user_id, password_hash)) {
        res.status = 500;
        res.set_content(MatrixError::unknown("Failed to create user").to_json().dump(), "application/json");
        return;
    }

    auto access_token = generate_access_token();
    auto device_id = reg_req.device_id.value_or(generate_device_id());
    store_.store_access_token(access_token, user_id, device_id);

    // Auto-join all existing public channels so new users immediately see the server's content
    auto_join_public_rooms(store_, sync_engine_, config_, user_id);

    LoginResponse login_resp{
        .user_id = user_id,
        .access_token = access_token,
        .device_id = device_id,
    };

    json resp;
    to_json(resp, login_resp);
    res.status = 200;
    res.set_content(resp.dump(), "application/json");

    get_logger()->info("User registered: {}", user_id);
}

void AuthHandler::handle_logout(const httplib::Request& req, httplib::Response& res) {
    auto token = extract_access_token(req.get_header_value("Authorization"));
    if (!token) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    store_.delete_access_token(*token);
    res.set_content("{}", "application/json");
}

} // namespace bsfchat
