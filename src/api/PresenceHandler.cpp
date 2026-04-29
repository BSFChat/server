#include "api/PresenceHandler.h"

#include "core/Config.h"
#include "http/Middleware.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/ErrorCodes.h>

#include <nlohmann/json.hpp>

namespace bsfchat {

using json = nlohmann::json;

PresenceHandler::PresenceHandler(SqliteStore& store,
                                  SyncEngine& sync_engine,
                                  const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void PresenceHandler::handle_put_presence(const httplib::Request& req,
                                           httplib::Response& res) {
    auto user_id = authenticate(store_,
        req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(),
                        "application/json");
        return;
    }

    // /presence/{userId}/status — the userId in the URL must match
    // the authenticated user. Setting another user's presence is
    // forbidden (matches Matrix spec §10.5).
    auto target_user_id = req.matches[1].str();
    if (*user_id != target_user_id) {
        res.status = 403;
        res.set_content(MatrixError::forbidden(
            "Cannot set presence for another user").to_json().dump(),
            "application/json");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(),
                        "application/json");
        return;
    }

    // Whitelist the presence values — accept Matrix's three
    // canonical states and reject anything else so a malicious
    // client can't sneak markup or arbitrary tokens in.
    std::string presence = body.value("presence", "");
    if (presence != "online" && presence != "unavailable"
        && presence != "offline") {
        res.status = 400;
        res.set_content(MatrixError::bad_json(
            "presence must be online|unavailable|offline").to_json().dump(),
            "application/json");
        return;
    }
    std::string status_msg = body.value("status_msg", "");

    // Cap status length to keep clients honest. 80 chars matches
    // Discord's status field.
    if (status_msg.size() > 80) status_msg.resize(80);

    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard lock(mutex_);
        auto& e = entries_[*user_id];
        e.presence = std::move(presence);
        e.status_msg = std::move(status_msg);
        e.updated_at = now;
        e.last_active_at = now;
    }

    // Wake any longpolling /sync waiters so other clients see
    // the new presence quickly.
    sync_engine_.notify_new_event();

    res.status = 200;
    res.set_content("{}", "application/json");
}

std::optional<PresenceHandler::Entry>
PresenceHandler::get_for(const std::string& user_id) const {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(user_id);
    if (it == entries_.end()) return std::nullopt;
    return it->second;
}

void PresenceHandler::touch(const std::string& user_id) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(mutex_);
    auto& e = entries_[user_id];
    if (e.presence.empty()) e.presence = "online"; // never seen
    e.last_active_at = now;
}

} // namespace bsfchat
