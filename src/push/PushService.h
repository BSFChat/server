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
#include <string>
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
};

} // namespace bsfchat
