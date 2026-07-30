#include "push/PushService.h"

#include "auth/Permissions.h"
#include "core/Logger.h"

#include <bsfchat/Constants.h>

#include <httplib.h>

#include <algorithm>
#include <chrono>
#include <set>

namespace bsfchat {

using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Splits "https://host:port/path" into a client origin and a request path, the
// way httplib::Client wants it. Mirrors the parsing OidcAuth already does for
// the JWKS URI.
bool split_url(const std::string& url, std::string& origin, std::string& path) {
    auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) return false;
    auto host_start = scheme_end + 3;
    if (host_start >= url.size()) return false;
    auto path_start = url.find('/', host_start);
    if (path_start == std::string::npos) {
        origin = url;
        path = "/";
    } else {
        origin = url.substr(0, path_start);
        path = url.substr(path_start);
    }
    return !origin.empty();
}

} // namespace

bool PushService::is_valid_level(const std::string& level) {
    return level == kLevelAll || level == kLevelMentions || level == kLevelNone;
}

PushService::PushService(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {
    transport_ = [this](const std::string& url, const std::string& body) {
        return post_to_gateway(url, body);
    };
}

PushService::~PushService() {
    stop();
}

void PushService::set_transport(Transport transport) {
    if (transport) transport_ = std::move(transport);
}

// ── Evaluation (request thread; no network I/O) ────────────────────────────

int PushService::evaluate_message(const MessageNotification& n, PermissionsEngine& perms) {
    if (!config_.push.enabled) return 0;
    if (n.event_type != std::string(event_type::kRoomMessage)) return 0;

    // One query, bounded by "members of this room who registered a pusher"
    // rather than by room size, and already excluding the sender — nobody should
    // be notified about their own message.
    auto candidates = store_.list_room_pusher_candidates(n.room_id, n.sender);
    if (candidates.empty()) return 0;

    const bool is_dm = store_.is_direct_room(n.room_id);
    auto levels = store_.get_room_notify_levels(n.room_id);

    std::set<std::string> mentioned(n.mentioned.begin(), n.mentioned.end());
    mentioned.erase(kRoomMentionSentinel); // room-wide is tracked separately

    // Cached per user because a user may have several pushers.
    std::map<std::string, bool> notify_cache;
    auto should_notify = [&](const std::string& user_id) -> bool {
        auto cached = notify_cache.find(user_id);
        if (cached != notify_cache.end()) return cached->second;

        bool decision = [&] {
            // A user who cannot see the channel must never be told about its
            // messages, whatever their notification level says. This is the same
            // gate /sync applies, so push can't become a side channel that leaks
            // the existence or content of a hidden channel.
            if (!perms.can(user_id, n.room_id, permission::kViewChannel)) return false;

            const bool is_mentioned =
                n.room_wide_mention || mentioned.count(user_id) > 0;

            // Default: everything in a DM (there is no such thing as an
            // uninteresting message in a two-person conversation), mentions only
            // in a channel (so joining a busy server doesn't mean a phone
            // buzzing all day).
            std::string level = is_dm ? kLevelAll : kLevelMentions;
            auto it = levels.find(user_id);
            if (it != levels.end() && is_valid_level(it->second)) level = it->second;

            if (level == kLevelNone) return false;
            if (level == kLevelAll) return true;
            return is_mentioned; // kLevelMentions
        }();

        notify_cache.emplace(user_id, decision);
        return decision;
    };

    std::vector<SqliteStore::QueuedPush> queue;
    queue.reserve(candidates.size());
    for (const auto& pusher : candidates) {
        if (!should_notify(pusher.user_id)) continue;

        // Matrix push-gateway notify shape. One device per row: retry and
        // rejection accounting are per-pushkey, and a single failing device
        // must not hold up or duplicate delivery to the others.
        json device = {
            {"app_id", pusher.app_id},
            {"pushkey", pusher.pushkey},
        };
        auto data = json::parse(pusher.data_json, nullptr, false);
        if (!data.is_discarded() && data.is_object()) device["data"] = std::move(data);
        if (n.room_wide_mention || mentioned.count(pusher.user_id) > 0) {
            device["tweaks"] = {{"sound", "default"}};
        }

        json notification = {
            {"event_id", n.event_id},
            {"room_id", n.room_id},
            {"type", n.event_type},
            {"sender", n.sender},
            {"prio", (n.room_wide_mention || mentioned.count(pusher.user_id) > 0 || is_dm)
                         ? "high" : "low"},
            {"counts", {{"unread", store_.count_unread(pusher.user_id, n.room_id)}}},
            {"devices", json::array({std::move(device)})},
        };
        // `event_id_only` is the spec's privacy mode: the gateway (and whatever
        // third-party provider sits behind it) is told only that something
        // happened, never what was said. Honour it.
        if (pusher.format != "event_id_only") {
            notification["content"] = n.content;
            if (auto name = store_.get_display_name(n.sender)) {
                notification["sender_display_name"] = *name;
            }
        }

        SqliteStore::QueuedPush q;
        q.user_id = pusher.user_id;
        q.app_id = pusher.app_id;
        q.pushkey = pusher.pushkey;
        q.url = pusher.url;
        q.payload = json{{"notification", std::move(notification)}}.dump();
        queue.push_back(std::move(q));
    }

    if (queue.empty()) return 0;
    // A local INSERT and nothing more. Delivery happens on the worker thread.
    store_.enqueue_pushes(queue);
    {
        std::lock_guard lock(wake_mutex_);
        ++wake_seq_;
    }
    wake_cv_.notify_all();
    return static_cast<int>(queue.size());
}

// ── Delivery (worker thread) ───────────────────────────────────────────────

int64_t PushService::backoff_for(int attempts) const {
    int64_t delay = config_.push.base_backoff_ms;
    // Shift rather than pow, and stop doubling well before overflow.
    for (int i = 0; i < attempts && i < 20; ++i) {
        delay *= 2;
        if (delay >= config_.push.max_backoff_ms) break;
    }
    return std::min(delay, config_.push.max_backoff_ms);
}

PushService::GatewayResponse PushService::post_to_gateway(const std::string& url,
                                                          const std::string& body) const {
    GatewayResponse out;
    std::string origin;
    std::string path;
    if (!split_url(url, origin, path)) {
        get_logger()->warn("Push: pusher URL is not a valid absolute URL, dropping: {}", url);
        // Treat as a permanent failure by reporting a 4xx: retrying a malformed
        // URL forever accomplishes nothing.
        out.transport_ok = true;
        out.status = 400;
        return out;
    }

    httplib::Client client(origin);
    client.set_connection_timeout(config_.push.connect_timeout_s);
    client.set_read_timeout(config_.push.request_timeout_s);
    client.set_write_timeout(config_.push.request_timeout_s);
    client.set_follow_location(false);

    auto res = client.Post(path, body, "application/json");
    if (!res) return out; // transport failure — retryable

    out.transport_ok = true;
    out.status = res->status;

    // The gateway reports devices it could not deliver to. A rejected pushkey
    // means the device is gone for good (app uninstalled, token revoked), so the
    // pusher is removed rather than retried.
    auto parsed = json::parse(res->body, nullptr, false);
    if (!parsed.is_discarded() && parsed.is_object()) {
        auto it = parsed.find("rejected");
        if (it != parsed.end() && it->is_array()) {
            for (const auto& entry : *it) {
                if (entry.is_string()) out.rejected.push_back(entry.get<std::string>());
            }
        }
    }
    return out;
}

PushService::DrainResult PushService::drain_once() {
    DrainResult result;

    // Claim under the store lock, then release it. Everything below this line
    // runs with NO store mutex held — the whole reason the queue exists is that
    // the server serialises all DB access, so holding that lock across an
    // outbound HTTP request would stall every other request in the process.
    auto batch = store_.claim_due_pushes(now_ms(), config_.push.batch_size,
                                         config_.push.lease_ms);
    if (batch.empty()) return result;

    for (const auto& item : batch) {
        auto response = transport_(item.url, item.payload);

        if (!response.rejected.empty()) {
            for (const auto& pushkey : response.rejected) {
                int removed = store_.delete_pushers_by_pushkey(pushkey);
                if (removed > 0) {
                    get_logger()->info(
                        "Push: gateway rejected pushkey; removed {} pusher(s) for it", removed);
                }
            }
        }

        const bool rejected_this =
            std::find(response.rejected.begin(), response.rejected.end(), item.pushkey) !=
            response.rejected.end();

        // A 2xx (or an explicit rejection, which is a definitive answer) retires
        // the row. Anything else is retried with backoff: 5xx and transport
        // failures because the gateway may recover, 4xx because retrying a
        // handful of times before giving up is cheaper than losing a
        // notification to a transient misconfiguration.
        const bool done = rejected_this || (response.transport_ok && response.status >= 200 &&
                                            response.status < 300);
        if (done) {
            store_.delete_queued_push(item.id);
            ++result.delivered;
            continue;
        }

        ++result.failed;
        const int64_t next_at = now_ms() + backoff_for(item.attempts);
        if (!store_.reschedule_queued_push(item.id, config_.push.max_attempts, next_at)) {
            get_logger()->warn(
                "Push: giving up on notification for {} after {} attempts (last status {})",
                item.user_id, config_.push.max_attempts, response.status);
        }
    }
    return result;
}

void PushService::worker_loop() {
    while (running_.load()) {
        DrainResult result;
        try {
            result = drain_once();
        } catch (const std::exception& e) {
            // Never let the worker die: a dead worker means notifications stop
            // silently and the queue grows without bound.
            get_logger()->error("Push: delivery pass failed: {}", e.what());
        }

        // Something was delivered this pass, so there may be more due right now.
        if (result.delivered > 0 || result.failed > 0) continue;

        const uint64_t seen = wake_seq_.load();
        std::unique_lock lock(wake_mutex_);
        wake_cv_.wait_for(lock, std::chrono::milliseconds(config_.push.worker_poll_ms),
                          [&] { return !running_.load() || wake_seq_.load() != seen; });
    }
}

void PushService::start() {
    if (!config_.push.enabled) {
        get_logger()->info("Push notifications disabled (push.enabled = false)");
        return;
    }
    if (running_.exchange(true)) return;
    worker_ = std::thread([this] { worker_loop(); });
    get_logger()->info(
        "Push delivery worker started (gateway-agnostic; {} queued notification(s) pending)",
        store_.count_queued_pushes());
}

void PushService::stop() {
    if (!running_.exchange(false)) return;
    wake_cv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

} // namespace bsfchat
