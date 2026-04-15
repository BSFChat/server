#include "sync/SyncEngine.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Permissions.h>

#include <set>
#include <unordered_map>

namespace bsfchat {

namespace {

bool is_category_room(SqliteStore& store, const std::string& room_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kRoomType), "");
    if (!ev) return false;
    return ev->content.data.value("type", "") == "category";
}

} // namespace

SyncEngine::SyncEngine(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {
    current_position_ = store_.get_current_stream_position();
}

void SyncEngine::notify_new_event() {
    current_position_ = store_.get_current_stream_position();
    new_event_cv_.notify_all();
}

SyncResponse SyncEngine::handle_sync(const std::string& user_id,
                                      const std::string& since_token,
                                      int timeout_ms) {
    if (since_token.empty()) {
        return build_initial_sync(user_id);
    }

    int64_t since_pos = 0;
    if (since_token.size() > 1 && since_token[0] == 's') {
        since_pos = std::stoll(since_token.substr(1));
    }

    auto response = build_incremental_sync(user_id, since_pos);
    if (!response.rooms.join.empty()) {
        return response;
    }

    if (timeout_ms > 0) {
        timeout_ms = std::min(timeout_ms, limits::kMaxSyncTimeoutMs);
        std::unique_lock lock(wait_mutex_);
        new_event_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
            return current_position_.load() > since_pos;
        });

        response = build_incremental_sync(user_id, since_pos);
    }

    return response;
}

SyncResponse SyncEngine::build_initial_sync(const std::string& user_id) {
    SyncResponse response;
    PermissionsEngine perms(store_, config_);

    auto rooms = store_.get_joined_rooms(user_id);
    for (const auto& room_id : rooms) {
        // Categories bypass VIEW_CHANNEL so the sidebar can still show the
        // container node even when individual child channels are hidden.
        if (!is_category_room(store_, room_id) &&
            !perms.can(user_id, room_id, permission::kViewChannel)) {
            continue;
        }

        JoinedRoom joined;
        joined.state.events = store_.get_state_events(room_id);
        joined.timeline.events = store_.get_room_events(room_id, limits::kDefaultTimelineLimit, "b");
        std::reverse(joined.timeline.events.begin(), joined.timeline.events.end());
        joined.timeline.limited = true;

        response.rooms.join[room_id] = std::move(joined);
    }

    for (auto& [room_id, joined] : response.rooms.join) {
        joined.unread_count = store_.count_unread(user_id, room_id);
    }

    response.next_batch = "s" + std::to_string(store_.get_current_stream_position());
    return response;
}

SyncResponse SyncEngine::build_incremental_sync(const std::string& user_id, int64_t since_pos) {
    SyncResponse response;
    PermissionsEngine perms(store_, config_);

    auto events = store_.get_events_since(user_id, since_pos);

    std::set<std::string> newly_joined_rooms;
    // Cache VIEW_CHANNEL decisions so we don't recompute for every event in
    // the same room (hot path during bursts).
    std::unordered_map<std::string, bool> view_cache;
    auto can_view = [&](const std::string& room_id) -> bool {
        auto it = view_cache.find(room_id);
        if (it != view_cache.end()) return it->second;
        bool ok = is_category_room(store_, room_id) ||
                  perms.can(user_id, room_id, permission::kViewChannel);
        view_cache.emplace(room_id, ok);
        return ok;
    };

    for (auto& event : events) {
        if (!can_view(event.room_id)) continue;

        if (event.type == std::string(event_type::kRoomMember)
            && event.state_key.has_value()
            && *event.state_key == user_id) {
            auto membership = event.content.data.value("membership", "");
            if (membership == "join") {
                newly_joined_rooms.insert(event.room_id);
            }
        }

        auto& joined = response.rooms.join[event.room_id];
        if (event.state_key.has_value()) {
            joined.state.events.push_back(event);
        }
        joined.timeline.events.push_back(std::move(event));
    }

    for (const auto& room_id : newly_joined_rooms) {
        if (!can_view(room_id)) continue;
        auto state = store_.get_state_events(room_id);
        auto& joined = response.rooms.join[room_id];
        joined.state.events = std::move(state);
    }

    for (auto& [room_id, joined] : response.rooms.join) {
        joined.unread_count = store_.count_unread(user_id, room_id);
    }

    int64_t max_pos = since_pos;
    if (!events.empty()) {
        max_pos = store_.get_current_stream_position();
    }
    response.next_batch = "s" + std::to_string(max_pos);
    return response;
}

} // namespace bsfchat
