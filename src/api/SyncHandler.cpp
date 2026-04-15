#include "api/SyncHandler.h"
#include "api/TypingHandler.h"
#include "http/Middleware.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>

namespace bsfchat {

using json = nlohmann::json;

SyncHandler::SyncHandler(SqliteStore& store, SyncEngine& sync_engine)
    : store_(store), sync_engine_(sync_engine) {}

void SyncHandler::handle_sync(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    std::string since;
    if (req.has_param("since")) since = req.get_param_value("since");

    int timeout = limits::kDefaultSyncTimeoutMs;
    if (req.has_param("timeout")) {
        timeout = std::stoi(req.get_param_value("timeout"));
    }

    auto response = sync_engine_.handle_sync(*user_id, since, timeout);

    // Inject typing indicators into joined rooms
    if (typing_handler_) {
        // Add typing info to rooms already in the response
        for (auto& [room_id, joined] : response.rooms.join) {
            auto typing_users = typing_handler_->get_typing_users(room_id);
            if (!typing_users.empty()) {
                RoomEvent typing_event;
                typing_event.type = std::string(event_type::kTyping);
                typing_event.content.data = {{"user_ids", typing_users}};
                joined.ephemeral = EphemeralEvents{};
                joined.ephemeral->events.push_back(std::move(typing_event));
            }
        }

        // Also add rooms where someone is typing but no timeline events occurred
        auto joined_rooms = store_.get_joined_rooms(*user_id);
        for (const auto& room_id : joined_rooms) {
            if (response.rooms.join.count(room_id)) continue; // already handled
            auto typing_users = typing_handler_->get_typing_users(room_id);
            if (!typing_users.empty()) {
                JoinedRoom joined;
                RoomEvent typing_event;
                typing_event.type = std::string(event_type::kTyping);
                typing_event.content.data = {{"user_ids", typing_users}};
                joined.ephemeral = EphemeralEvents{};
                joined.ephemeral->events.push_back(std::move(typing_event));
                response.rooms.join[room_id] = std::move(joined);
            }
        }
    }

    json resp;
    to_json(resp, response);
    res.set_content(resp.dump(), "application/json");
}

} // namespace bsfchat
