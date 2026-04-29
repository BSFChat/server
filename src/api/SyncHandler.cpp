#include "api/SyncHandler.h"
#include "api/TypingHandler.h"
#include "api/PresenceHandler.h"
#include "http/Middleware.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <set>

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

    // Inject presence events for every user the requester shares a
    // room with. Matrix delivers presence at the top level (not
    // per-room) and the client folds it into a global user→state
    // map, so we collect distinct user-ids across all joined rooms
    // and emit one m.presence event per known peer.
    if (presence_handler_) {
        std::set<std::string> seen;
        auto joined_rooms = store_.get_joined_rooms(*user_id);
        for (const auto& room_id : joined_rooms) {
            auto members = store_.get_room_members(room_id);
            for (const auto& [m_uid, _state] : members) {
                if (m_uid == *user_id) continue;
                seen.insert(m_uid);
            }
        }
        // Touch ourselves so other peers see us as recently-active
        // simply by virtue of having opened a sync stream.
        presence_handler_->touch(*user_id);
        seen.insert(*user_id);

        PresenceEvents pe;
        for (const auto& uid : seen) {
            auto entry = presence_handler_->get_for(uid);
            if (!entry) continue;
            RoomEvent ev;
            ev.type = std::string(event_type::kPresence);
            ev.sender = uid;
            json content = {{"presence", entry->presence}};
            if (!entry->status_msg.empty()) {
                content["status_msg"] = entry->status_msg;
            }
            // Optional last_active_ago in ms — clients use this to
            // render "5 min ago" hints. We compute against the
            // entry's last_active_at in the steady_clock domain.
            auto ago = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - entry->last_active_at).count();
            if (ago >= 0) content["last_active_ago"] = ago;
            ev.content.data = std::move(content);
            pe.events.push_back(std::move(ev));
        }
        if (!pe.events.empty()) response.presence = std::move(pe);
    }

    json resp;
    to_json(resp, response);
    res.set_content(resp.dump(), "application/json");
}

} // namespace bsfchat
