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

    // POST /_matrix/client/v3/rooms/{roomId}/voice/livekit_token
    //
    // Issues a LiveKit join token for the authenticated user on this voice
    // channel. Gated on room membership, the channel's m.room.voice being
    // enabled, AND permission::kViewChannel — a user who cannot see the
    // channel must never receive a token that lets them into its SFU room.
    void handle_livekit_token(const httplib::Request& req, httplib::Response& res);

    // POST /_matrix/client/v3/rooms/{roomId}/voice/livekit_rekey
    //
    // Rotates this channel's media key. Requires permission::kManageChannels
    // on top of everything handle_livekit_token requires — rotating ejects
    // every participant currently decrypting with the old key until they
    // re-fetch, so it is a moderation action, not a user action.
    //
    // This is the ONLY way to revoke a departed member's ability to decrypt.
    // See LiveKitConfig::room_encryption for why the ratchet cannot do it.
    void handle_livekit_rekey(const httplib::Request& req, httplib::Response& res);

    // Per-room media key, derived rather than stored.
    //
    // key = HKDF-SHA256(ikm  = livekit.key_material(),
    //                   salt = "bsfchat/livekit-room-key/v1",
    //                   info = server_name || 0x00 || room_id || 0x00 || generation)
    //
    // Derivation instead of a CSPRNG-generated row in the database, for two
    // reasons. The practical one: the store and its migrations are being
    // changed concurrently by other work, and a key table would collide.
    // The better one: derived keys survive a restart. A generated key held
    // only in memory would change on every server bounce and silently break
    // every call in progress; persisting it would put long-lived media keys
    // in the database, which is a worse place for them than a KDF over a
    // secret that already has to be protected.
    //
    // The output is indistinguishable from random to anyone without
    // key_material(), which is the property that matters. Distinct rooms and
    // distinct generations give unrelated keys: the length-prefixed info
    // string means no two (room, generation) pairs can produce the same
    // input, so a room id ending in a digit cannot collide with a
    // generation bump.
    //
    // Returns 32 raw bytes. Never log this, never put it in a URL.
    // Exposed (and static) so tests can assert determinism and separation.
    static std::vector<unsigned char> livekit_room_key(const std::string& key_material,
                                                       const std::string& server_name,
                                                       const std::string& room_id,
                                                       uint64_t generation);

    // Maps a Matrix room id to the LiveKit room name.
    //
    // Hashed rather than sanitised on purpose. Room ids contain characters
    // ('!', ':') whose safety in a LiveKit room name is not guaranteed, and any
    // character-replacement scheme collides — "!a:b" and "!a-b" would both
    // become "-a-b" and share one SFU room, which is a cross-channel audio
    // leak. SHA-256 cannot collide by accident. server_name is mixed in so the
    // mapping differs between deployments sharing one LiveKit instance.
    //
    // Exposed (and static) so tests can assert determinism and separation.
    static std::string livekit_room_name(const std::string& server_name,
                                         const std::string& room_id);

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

    // room_id -> media-key generation. Absent means generation 0.
    //
    // In memory on purpose. A generation is not a secret and holds no value
    // across a restart: after a bounce every room is back at generation 0,
    // every client re-fetches on its next token request, and they all agree
    // again. The cost of a restart is therefore one rekey, not a broken
    // room. Rotations requested before the restart are forgotten, which is
    // the honest limitation — a departed member regains decryption of NEW
    // traffic after a server restart unless rekey is called again. That is
    // documented next to the endpoint and is why this design is described as
    // "encrypted to the relay" and never as end-to-end.
    std::mutex key_generation_mutex_;
    std::map<std::string, uint64_t> key_generations_;

    // Reaper thread lifecycle.
    std::thread reaper_thread_;
    std::mutex reaper_mutex_;
    std::condition_variable reaper_cv_;
    bool reaper_stop_ = false;
};

} // namespace bsfchat
