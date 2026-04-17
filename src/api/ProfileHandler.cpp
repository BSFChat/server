#include "api/ProfileHandler.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>

#include <nlohmann/json.hpp>
#include <chrono>

namespace bsfchat {

using json = nlohmann::json;

namespace {
int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
} // namespace

ProfileHandler::ProfileHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void ProfileHandler::handle_get_profile(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& user_id = match.params.at("userId");

    if (!store_.user_exists(user_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("User not found").to_json().dump(), "application/json");
        return;
    }

    json resp;
    auto display_name = store_.get_display_name(user_id);
    auto avatar_url = store_.get_avatar_url(user_id);

    if (display_name) resp["displayname"] = *display_name;
    if (avatar_url) resp["avatar_url"] = *avatar_url;

    res.set_content(resp.dump(), "application/json");
}

void ProfileHandler::handle_get_displayname(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/displayname", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& user_id = match.params.at("userId");

    if (!store_.user_exists(user_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("User not found").to_json().dump(), "application/json");
        return;
    }

    json resp;
    auto display_name = store_.get_display_name(user_id);
    if (display_name) resp["displayname"] = *display_name;

    res.set_content(resp.dump(), "application/json");
}

void ProfileHandler::handle_put_displayname(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/displayname", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& target_user_id = match.params.at("userId");

    // Authenticate
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    // Only allow updating own profile
    if (*user_id != target_user_id) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot set displayname for other users").to_json().dump(), "application/json");
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

    if (!body.contains("displayname") || !body["displayname"].is_string()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing displayname field").to_json().dump(), "application/json");
        return;
    }

    store_.set_display_name(*user_id, body["displayname"].get<std::string>());
    broadcastMemberUpdate(*user_id);

    get_logger()->info("User {} updated display name", *user_id);
    res.set_content("{}", "application/json");
}

void ProfileHandler::handle_get_avatar_url(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/avatar_url", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& user_id = match.params.at("userId");

    if (!store_.user_exists(user_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("User not found").to_json().dump(), "application/json");
        return;
    }

    json resp;
    auto avatar_url = store_.get_avatar_url(user_id);
    if (avatar_url) resp["avatar_url"] = *avatar_url;

    res.set_content(resp.dump(), "application/json");
}

void ProfileHandler::handle_put_avatar_url(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/avatar_url", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& target_user_id = match.params.at("userId");

    // Authenticate
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    // Only allow updating own profile
    if (*user_id != target_user_id) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot set avatar_url for other users").to_json().dump(), "application/json");
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

    if (!body.contains("avatar_url") || !body["avatar_url"].is_string()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing avatar_url field").to_json().dump(), "application/json");
        return;
    }

    store_.set_avatar_url(*user_id, body["avatar_url"].get<std::string>());
    broadcastMemberUpdate(*user_id);

    get_logger()->info("User {} updated avatar URL", *user_id);
    res.set_content("{}", "application/json");
}

void ProfileHandler::broadcastMemberUpdate(const std::string& user_id)
{
    // Re-emit m.room.member state event in every joined room with the
    // current profile so all connected clients see the name/avatar change
    // on their next sync.
    auto rooms = store_.get_joined_rooms(user_id);
    auto dn = store_.get_display_name(user_id);
    auto av = store_.get_avatar_url(user_id);

    for (const auto& room_id : rooms) {
        json content = {{"membership", membership::kJoin}};
        if (dn) content["displayname"] = *dn;
        if (av) content["avatar_url"] = *av;

        auto event_id = generate_event_id(config_.server_name);
        store_.insert_event(event_id, room_id, user_id,
                            std::string(event_type::kRoomMember),
                            user_id, content.dump(), now_ms());
    }
    if (!rooms.empty()) sync_engine_.notify_new_event();
}

} // namespace bsfchat
