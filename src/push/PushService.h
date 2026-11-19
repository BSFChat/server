#pragma once

#include "core/Config.h"
#include "store/SqliteStore.h"

#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <thread>
#include <vector>

namespace bsfchat {

class PermissionsEngine;

// Server-side push notifications.
//
// Split deliberately in two halves that never touch each other's concerns:
//
//   evaluate_message()  runs on the request thread, inside the send path. It
//                       decides who should be notified and writes push_queue
//                       rows. It performs NO network I/O, so a send (or a
//                       /sync that unblocks because of it) can never be held up
//                       by a slow or dead push gateway.
//
//   the worker thread   drains push_queue and POSTs to each pusher's gateway
//                       URL. It is the only thing here that talks to the
//                       network, and it never holds the store's global mutex
//                       across a request: every store call it makes returns
//                       before the HTTP client is constructed.
//
// The wire format is the Matrix push-gateway notify shape
// (POST <pusher url> {"notification": {...}}), so the server stays
// provider-agnostic: FCM/APNs credentials belong to the gateway a deployment
// runs, not here.
class PushService {
public:
    PushService(SqliteStore& store, const Config& config);
    ~PushService();

    PushService(const PushService&) = delete;
    PushService& operator=(const PushService&) = delete;

    // Notification levels a user can set per room.
    static constexpr const char* kLevelAll = "all";
    static constexpr const char* kLevelMentions = "mentions";
    static constexpr const char* kLevelNone = "none";
    static bool is_valid_level(const std::string& level);

    // What a message did that might deserve a push. Built by the send path,
    // which is the only place that knows the validated mention set.
    struct MessageNotification {
        std::string event_id;
        std::string room_id;
        std::string sender;
        std::string event_type;
        // Users mentioned directly (already validated). May contain
        // kRoomMentionSentinel for a room-wide mention.
        std::vector<std::string> mentioned;
        // Roles the message mentioned, already through the mentionable /
        // MENTION_EVERYONE gate. Role IDS, not sentinels and not expanded to
        // members: evaluate_message() is already iterating the room's pusher
        // candidates and checks each one's roles as it goes, so expanding here
        // would build a member list only to intersect it back down again.
        std::vector<std::string> mentioned_role_ids;
        bool room_wide_mention = false;
        // Message content, forwarded to the gateway unless the pusher asked for
        // `format: "event_id_only"`.
        nlohmann::json content;
    };

    // Decides recipients and enqueues. Returns the number of queue rows written.
    // Cheap and non-blocking; safe to call while handling a request.
    //
    // `perms` is the request's PermissionsEngine so VIEW_CHANNEL decisions reuse
    // its memoised role reads: a user who cannot see the channel is never pushed.
    int evaluate_message(const MessageNotification& notification, PermissionsEngine& perms);

    // A read marker moved for `user_id` in `room_id` (audit 3, 2026-11-19).
    // When that leaves the room with no unread messages AND this server has
    // pushed the account a count for the room since it was last cleared, a
    // COUNT-ONLY notification goes to each of the account's pushers:
    //   {"notification": {"room_id": ..., "prio": "low",
    //                     "counts": {"unread": 0}, "devices": [...]}}
    // with no event_id, which push gateways (Sygnal) treat as a badge update
    // and nothing else — so a phone's badge clears when the room is read on
    // another device instead of staying lit until the next message.
    //
    // Throttled by construction: at most one clear per room per run of pushed
    // notifications, never one per marker move (the desktop client posts a
    // marker for every batch of messages that arrives in the open room). The
    // "was pushed" record is in memory, so a restart forgets it and the first
    // read after one sends no clear; that costs one stale badge, not a storm.
    //
    // Returns the number of queue rows written. No network I/O.
    int notify_read(const std::string& user_id, const std::string& room_id);

    void start();
    void stop();

    // Runs one drain pass synchronously. Exposed for tests, which must not race
    // a background thread; the worker loop calls exactly this.
    // Returns {delivered, failed}.
    struct DrainResult {
        int delivered = 0;
        int failed = 0;
    };
    DrainResult drain_once();

    // Overrides the HTTP transport. Tests use this to assert delivery behaviour
    // (and that the insert path never waited on it) without standing up a
    // gateway. Must be set before start().
    struct GatewayResponse {
        bool transport_ok = false;         // did we get an HTTP response at all
        int status = 0;
        std::vector<std::string> rejected; // pushkeys the gateway disowned
    };
    using Transport = std::function<GatewayResponse(const std::string& url,
                                                    const std::string& body)>;
    void set_transport(Transport transport);

private:
    GatewayResponse post_to_gateway(const std::string& url, const std::string& body) const;
    void worker_loop();
    // Backoff for attempt N (0-based), capped by config.
    [[nodiscard]] int64_t backoff_for(int attempts) const;

    SqliteStore& store_;
    const Config& config_;

    Transport transport_;

    std::thread worker_;
    std::atomic<bool> running_{false};
    std::mutex wake_mutex_;
    std::condition_variable wake_cv_;
    // Bumped by evaluate_message() so the worker picks up new work immediately
    // instead of waiting out its poll interval.
    std::atomic<uint64_t> wake_seq_{0};

    void wake_worker();
    // (user, room) pairs this server has pushed a nonzero count for since the
    // badge was last cleared; see notify_read(). Bounded: cleared wholesale
    // past kMaxBadged, which costs at most one missed clear per entry.
    static constexpr std::size_t kMaxBadged = 1u << 17;
    std::mutex badged_mutex_;
    std::set<std::pair<std::string, std::string>> badged_;
};

} // namespace bsfchat
