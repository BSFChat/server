#include "sync/SyncEngine.h"
#include "store/SqliteStore.h"
#include "core/Logger.h"

#include <bsfchat/Constants.h>

#include <set>

namespace bsfchat {

SyncEngine::SyncEngine(SqliteStore& store)
    : store_(store) {
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

    // Parse "s{position}" token
    int64_t since_pos = 0;
    if (since_token.size() > 1 && since_token[0] == 's') {
        since_pos = std::stoll(since_token.substr(1));
    }

    // Check for new events immediately
    auto response = build_incremental_sync(user_id, since_pos);
    if (!response.rooms.join.empty()) {
        return response;
    }

    // No new events — long-poll
    if (timeout_ms > 0) {
        timeout_ms = std::min(timeout_ms, limits::kMaxSyncTimeoutMs);
        std::unique_lock lock(wait_mutex_);
        new_event_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
            return current_position_.load() > since_pos;
        });

        // Re-check after wake
        response = build_incremental_sync(user_id, since_pos);
    }

    return response;
}

SyncResponse SyncEngine::build_initial_sync(const std::string& user_id) {
    SyncResponse response;

    auto rooms = store_.get_joined_rooms(user_id);
    for (const auto& room_id : rooms) {
        JoinedRoom joined;

        // Get current state
        joined.state.events = store_.get_state_events(room_id);

        // Get recent timeline
        joined.timeline.events = store_.get_room_events(room_id, limits::kDefaultTimelineLimit, "b");
        // Reverse to chronological order (get_room_events returns newest first in "b" direction)
        std::reverse(joined.timeline.events.begin(), joined.timeline.events.end());
        joined.timeline.limited = true;

        response.rooms.join[room_id] = std::move(joined);
    }

    response.next_batch = "s" + std::to_string(store_.get_current_stream_position());
    return response;
}

SyncResponse SyncEngine::build_incremental_sync(const std::string& user_id, int64_t since_pos) {
    SyncResponse response;

    auto events = store_.get_events_since(user_id, since_pos);

    // Track rooms where this user just got joined in this batch — they need full state
    // because earlier state events (name, topic, type, etc.) are older than since_pos.
    std::set<std::string> newly_joined_rooms;

    // Group events by room
    for (auto& event : events) {
        // Detect our own membership=join event on a room we haven't seen before
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

    // For each newly-joined room, inject the full current state.
    // This gives the client the room name, topic, type, power levels, etc. that
    // existed before the user joined.
    for (const auto& room_id : newly_joined_rooms) {
        auto state = store_.get_state_events(room_id);
        auto& joined = response.rooms.join[room_id];
        // Replace state events (they're a superset of what we already collected)
        joined.state.events = std::move(state);
    }

    int64_t max_pos = since_pos;
    if (!events.empty()) {
        max_pos = store_.get_current_stream_position();
    }
    response.next_batch = "s" + std::to_string(max_pos);
    return response;
}

} // namespace bsfchat
