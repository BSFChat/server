#pragma once

#include "core/SendLimiter.h"

#include <httplib.h>

#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

class TypingHandler {
public:
    TypingHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

    void handle_typing(const httplib::Request& req, httplib::Response& res);

    // Get currently typing users for a room (called by sync)
    std::vector<std::string> get_typing_users(const std::string& room_id);

    // The same, as `viewer` should see it: anyone `viewer` ignores is left out
    // (audit 3). This is the call /sync should make when it builds a room's
    // m.typing for a particular reader.
    std::vector<std::string> get_typing_users_for(const std::string& room_id,
                                                  const std::string& viewer);

private:
    struct TypingEntry {
        std::string user_id;
        std::chrono::steady_clock::time_point expires_at;
    };

    std::mutex mutex_;
    std::map<std::string, std::vector<TypingEntry>> typing_; // room_id -> entries
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    SendLimiter limits_;  // Bucket::kTyping, per account

    void cleanup_expired(const std::string& room_id);
};

} // namespace bsfchat
