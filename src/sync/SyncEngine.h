#pragma once

#include <bsfchat/MatrixTypes.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>

namespace bsfchat {

class SqliteStore;
struct Config;

class SyncEngine {
public:
    SyncEngine(SqliteStore& store, const Config& config);

    // Notify that a new event was inserted. Wakes all waiting sync requests.
    void notify_new_event();

    // Handle a /sync request. Blocks up to timeout_ms if no new events.
    // since_token: "s{stream_position}" or empty for initial sync.
    SyncResponse handle_sync(const std::string& user_id,
                              const std::string& since_token,
                              int timeout_ms);

private:
    SyncResponse build_initial_sync(const std::string& user_id);
    SyncResponse build_incremental_sync(const std::string& user_id, int64_t since_pos);

    SqliteStore& store_;
    const Config& config_;
    std::mutex wait_mutex_;
    std::condition_variable new_event_cv_;
    std::atomic<int64_t> current_position_{0};
};

} // namespace bsfchat
