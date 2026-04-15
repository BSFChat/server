#pragma once

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

    void cleanup_expired(const std::string& room_id);
};

} // namespace bsfchat
