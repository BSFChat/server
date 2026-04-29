#pragma once

#include <httplib.h>

#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <string>
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
    };

    // Look up by user; nullopt if we've never seen them.
    std::optional<Entry> get_for(const std::string& user_id) const;

    // Bump last_active_at for a user — invoked by other handlers
    // (message send, typing, etc.) so presence implicitly reflects
    // recent activity even if the user hasn't called PUT /presence.
    void touch(const std::string& user_id);

private:
    mutable std::mutex mutex_;
    std::map<std::string, Entry> entries_;
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
