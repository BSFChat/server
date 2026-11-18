#pragma once

#include <httplib.h>

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

// Tracks user presence + free-form status messages and serves the
// PUT /_matrix/client/v3/presence/{userId}/status endpoint. Keeps
// state in memory keyed by user_id; the SyncHandler injects
// per-user presence events into the top-level `presence` block of
// each /sync response for everyone the requesting user shares a
// room with.
//
// "online" / "unavailable" / "offline" are the standard Matrix
// values. We also forward whatever string the user puts in
// `status_msg` verbatim — clients render it under the user's
// display name.
class PresenceHandler {
public:
    PresenceHandler(SqliteStore& store, SyncEngine& sync_engine,
                    const Config& config);

    void handle_put_presence(const httplib::Request& req,
                              httplib::Response& res);

    struct Entry {
        std::string presence;       // online | unavailable | offline
        std::string status_msg;     // optional, may be empty
        std::chrono::steady_clock::time_point updated_at;
        // Last time this user wrote anything we observed (presence,
        // typing, message). Used to compute last_active_ago for the
        // sync payload so other clients can render "5 min ago".
        std::chrono::steady_clock::time_point last_active_at;
        // The store's stream head when what a client renders from this entry
        // (presence, status_msg, or its coming online) last changed. See
        // live_for_sync(). last_active_at moving is not a change.
        int64_t changed_at_pos = 0;
    };

    // Look up by user; nullopt if we've never seen them, or if their
    // entry has gone stale (treated as "not online" by callers).
    std::optional<Entry> get_for(const std::string& user_id) const;

    // The live entries a /sync presence pass shows (audit 2-2026-11-18,
    // S2-4): `self`'s, whenever it is live, and each of `peers` (sorted
    // ascending, as SyncHandler's peer list is) whose entry changed at or
    // after `since_pos` — or every live peer when `since_pos` < 0, the full
    // restatement.
    //
    // Restating every peer on every delivered poll made each woken /sync
    // O(peers), so one message to N parked polls cost O(N²). A peer's entry
    // is only news to a poll if it changed after that poll's token was minted:
    // an entry stamped below the token was already live when the response
    // carrying that token ran its own presence pass (the pass runs after the
    // scan that saw the head reach the token, and the stamp is taken under
    // the same lock as the change), so it was delivered then, or earlier.
    // `>=` rather than `>` because a change while the head stood still is
    // stamped with the very position a poll may already hold.
    std::vector<std::pair<std::string, Entry>> live_for_sync(
        const std::vector<std::string>& peers, const std::string& self,
        int64_t since_pos) const;

    // Bump last_active_at for a user — invoked by other handlers
    // (message send, typing, etc.) so presence implicitly reflects
    // recent activity even if the user hasn't called PUT /presence.
    void touch(const std::string& user_id);

    // Drops entries whose last_active_at is older than kExpiry. Without
    // this, entries_ was an unbounded in-memory map and a user who ever
    // set "online" stayed online forever — until the process restarted.
    // Every /sync touches the requester, so a live client is refreshed
    // well inside the window.
    void sweep_expired();

    // A client that has stopped syncing is considered gone after this.
    // Comfortably longer than the 30s default long-poll so a slow or
    // briefly-disconnected client isn't flapped offline.
    static constexpr std::chrono::seconds kExpiry{150};

    // status_msg ceiling, in code points (never bytes; see the .cpp).
    static constexpr std::size_t kMaxStatusMsgCodepoints = 80;

private:
    // Caller must hold mutex_.
    bool is_expired_locked(const Entry& e,
                            std::chrono::steady_clock::time_point now) const;

    mutable std::mutex mutex_;
    std::map<std::string, Entry> entries_;
    // Guarded by mutex_. See sweep_expired().
    std::chrono::steady_clock::time_point last_sweep_{};
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
