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
    auto pos = store_.get_current_stream_position();
    {
        // Must be held while publishing the new position: a waiter evaluates
        // its predicate under this same lock, and a notify slipping in between
        // that evaluation and the wait would otherwise be lost entirely.
        std::lock_guard lock(wait_mutex_);
        current_position_ = pos;
    }
    new_event_cv_.notify_all();
}

void SyncEngine::notify_ephemeral() {
    {
        std::lock_guard lock(wait_mutex_);
        ++ephemeral_seq_;
    }
    new_event_cv_.notify_all();
}

SyncResponse SyncEngine::handle_sync(const std::string& user_id,
                                      const std::string& since_token,
                                      int timeout_ms) {
    // A banned user sees nothing, whatever their membership rows say.
    //
    // The ban projection already sets every room_members row to "ban", so this is
    // belt and braces — but it is the cheap kind: one primary-key lookup at the
    // top of the one endpoint a client polls continuously, and it fails closed for
    // any room whose projection was missed (a crash between the ban-list write and
    // the projection, or a row written by some future code path). It also returns
    // immediately rather than long-polling, so a banned client stops holding a
    // request thread open.
    if (store_.is_server_banned(user_id)) {
        SyncResponse response;
        response.next_batch = "s" + std::to_string(store_.get_current_stream_position());
        return response;
    }

    if (since_token.empty()) {
        return build_initial_sync(user_id);
    }

    int64_t since_pos = 0;
    if (since_token.size() > 1 && since_token[0] == 's') {
        // A malformed token used to throw std::invalid_argument /
        // std::out_of_range straight out of the handler.
        try {
            since_pos = std::stoll(since_token.substr(1));
        } catch (const std::exception&) {
            since_pos = 0;
        }
        if (since_pos < 0) since_pos = 0;
    }

    // Snapshot the ephemeral counter BEFORE building, so typing/presence
    // changes that land while we're querying still count as "something
    // happened" and don't get swallowed by the wait.
    const uint64_t edu_at_entry = ephemeral_seq_.load();

    auto response = build_incremental_sync(user_id, since_pos);
    if (!response.rooms.join.empty()) {
        return response;
    }

    if (timeout_ms > 0) {
        timeout_ms = std::min(timeout_ms, limits::kMaxSyncTimeoutMs);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

        // The condition variable is global: notify_new_event() wakes every
        // waiter on the server, whatever room the event landed in. Returning
        // straight after the first wake therefore ended a client's poll because
        // somebody else posted in a channel it cannot even see.
        //
        // That is not just wasted work. Such a reply carries no timeline events
        // AND no advance in next_batch, and the desktop client reads a fast
        // reply that did not move next_batch as a broken endpoint: it answers
        // with SyncBackoff's escalating no-progress delay, 1s then 2s, 4s, 8s,
        // up to a minute. So a busy unrelated channel could walk an idle
        // client's poll interval out to 60s, and the next message genuinely
        // addressed to it then waited that long with no request even in flight.
        //
        // Re-check instead, and go back to sleep on a wake that turned out to
        // hold nothing for this user. `checked_pos` is what makes that
        // terminate: the raw predicate stays true forever once the global head
        // has passed since_pos, so it has to advance to the head we have
        // already looked at.
        int64_t checked_pos = since_pos;
        for (;;) {
            bool signalled = false;
            {
                std::unique_lock lock(wait_mutex_);
                // Read under the lock: current_position_ is only published
                // under it, so sampling it here cannot miss a notification
                // that lands between this and the wait.
                checked_pos = std::max(checked_pos, current_position_.load());
                signalled = new_event_cv_.wait_until(lock, deadline, [&] {
                    return current_position_.load() > checked_pos ||
                           ephemeral_seq_.load() != edu_at_entry;
                });
            }
            if (!signalled) break; // deadline passed with nothing for us

            response = build_incremental_sync(user_id, since_pos);
            // Real events, or an ephemeral change the caller injects typing and
            // presence from — either is worth returning immediately.
            if (!response.rooms.join.empty() ||
                ephemeral_seq_.load() != edu_at_entry) {
                return response;
            }
            // Woken for an event this user cannot see. Keep the poll parked.
        }

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
        // Use the paginated variant so we can set `prev_batch` to the
        // token the client needs for back-pagination. `next_pos` here is
        // the stream_position of the oldest row in the returned batch; the
        // client passes it back as `from` to /rooms/{id}/messages to fetch
        // events strictly older than this batch.
        auto [timeline_events, next_pos] = store_.get_room_events_paginated(
            room_id, limits::kDefaultTimelineLimit, "b");
        joined.timeline.events = std::move(timeline_events);
        std::reverse(joined.timeline.events.begin(), joined.timeline.events.end());
        // `limited` is true when more history exists beyond this batch; the
        // probe-row trick in get_room_events_paginated sets next_pos iff so.
        joined.timeline.limited = next_pos.has_value();
        if (next_pos) {
            joined.timeline.prev_batch = "s" + std::to_string(*next_pos);
        }

        response.rooms.join[room_id] = std::move(joined);
    }

    // One grouped query for mentions across every room, rather than one per
    // room inside the loop — each store call serialises behind the store's
    // single global mutex, and an initial sync visits every joined channel.
    auto mentions = store_.get_unread_mention_counts(user_id);
    for (auto& [room_id, joined] : response.rooms.join) {
        joined.unread_count = store_.count_unread(user_id, room_id);
        auto it = mentions.find(room_id);
        joined.highlight_count = it == mentions.end() ? 0 : it->second;
    }

    response.next_batch = "s" + std::to_string(store_.get_current_stream_position());
    return response;
}

SyncResponse SyncEngine::build_incremental_sync(const std::string& user_id, int64_t since_pos) {
    SyncResponse response;
    PermissionsEngine perms(store_, config_);

    // `delivered_max` is the highest stream position actually scanned. It is
    // what next_batch must be built from: the old code fetched at most `limit`
    // events and then set next_batch to the GLOBAL stream head, so anything
    // past the limit — or anything inserted between the fetch and the head
    // read — was skipped permanently.
    int64_t delivered_max = since_pos;
    constexpr int kScanLimit = 1000;
    auto events = store_.get_events_since(user_id, since_pos, delivered_max, kScanLimit);

    // When the scan was not cut short by the limit, this user has been offered
    // everything on the stream, so their token can jump to the global head even
    // though most of those rows were other people's rooms. Leaving it pinned to
    // the highest VISIBLE row meant a client in a quiet channel re-scanned the
    // same widening range on every poll, and — worse — came back from any
    // spurious wake with next_batch unchanged, which the desktop client treats
    // as a no-progress reply and punishes with an escalating backoff.
    //
    // Only safe when the scan was complete: if it hit the limit there are
    // certainly rows past `delivered_max` this user still needs, and skipping
    // to the head would drop them permanently.
    if (static_cast<int>(events.size()) < kScanLimit) {
        delivered_max = std::max(delivered_max, store_.get_current_stream_position());
    }

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

    auto mentions = store_.get_unread_mention_counts(user_id);
    for (auto& [room_id, joined] : response.rooms.join) {
        joined.unread_count = store_.count_unread(user_id, room_id);
        auto it = mentions.find(room_id);
        joined.highlight_count = it == mentions.end() ? 0 : it->second;
    }

    response.next_batch = "s" + std::to_string(delivered_max);
    return response;
}

} // namespace bsfchat
