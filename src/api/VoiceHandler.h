#pragma once

#include <httplib.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

class VoiceHandler {
public:
    VoiceHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);
    ~VoiceHandler();

    void handle_voice_join(const httplib::Request& req, httplib::Response& res);
    void handle_voice_leave(const httplib::Request& req, httplib::Response& res);
    void handle_voice_members(const httplib::Request& req, httplib::Response& res);
    void handle_voice_state(const httplib::Request& req, httplib::Response& res);
    void handle_turn_server(const httplib::Request& req, httplib::Response& res);

    // Ghost-participant reaper. Clients in voice heartbeat via GET
    // voice/members (and voice/join / voice/state); a background thread
    // marks active members inactive when their heartbeat goes stale.
    void start_reaper();
    void stop_reaper();

    // Record a liveness heartbeat for a voice member. `now` is injectable
    // so tests can drive the reaper deterministically.
    void record_heartbeat(const std::string& room_id, const std::string& user_id,
                          std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    // Single reaper pass: emits active:false for every active m.call.member
    // whose last heartbeat is older than kHeartbeatTtl. Active members never
    // seen before (e.g. after a server restart) are seeded with a fresh
    // heartbeat instead of being reaped. Returns the number of members reaped.
    size_t reap_stale_members(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    static constexpr std::chrono::seconds kHeartbeatTtl{30};
    static constexpr std::chrono::seconds kReapInterval{10};

private:
    void clear_heartbeat(const std::string& room_id, const std::string& user_id);

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;

    // Serializes check-then-emit sections across HTTP worker threads:
    // the max_participants check in handle_voice_join and the
    // read-modify-write in handle_voice_state.
    std::mutex voice_state_mutex_;

    // (room_id, user_id) -> last heartbeat. Guarded by heartbeat_mutex_.
    std::mutex heartbeat_mutex_;
    std::map<std::pair<std::string, std::string>, std::chrono::steady_clock::time_point> heartbeats_;

    // Reaper thread lifecycle.
    std::thread reaper_thread_;
    std::mutex reaper_mutex_;
    std::condition_variable reaper_cv_;
    bool reaper_stop_ = false;
};

} // namespace bsfchat
