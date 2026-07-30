#include "api/VoiceHandler.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/JwtUtils.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <algorithm>
#include <chrono>
#include <exception>
#include <memory>
#include <stdexcept>
#include <vector>

namespace bsfchat {

using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string base64_encode(const unsigned char* data, size_t len) {
    std::string out((len + 2) / 3 * 4, '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data, static_cast<int>(len));
    out.resize(written > 0 ? static_cast<size_t>(written) : 0);
    return out;
}

void emit_state_event(SqliteStore& store, SyncEngine& sync_engine, const std::string& server_name,
                      const std::string& room_id, const std::string& sender,
                      const std::string& event_type, const std::string& state_key,
                      const json& content) {
    auto event_id = generate_event_id(server_name);
    store.insert_event(event_id, room_id, sender, event_type, state_key, content.dump(), now_ms());
    sync_engine.notify_new_event();
}

} // namespace

VoiceHandler::VoiceHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

VoiceHandler::~VoiceHandler() {
    stop_reaper();
}

void VoiceHandler::record_heartbeat(const std::string& room_id, const std::string& user_id,
                                    std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(heartbeat_mutex_);
    heartbeats_[{room_id, user_id}] = now;
}

void VoiceHandler::clear_heartbeat(const std::string& room_id, const std::string& user_id) {
    std::lock_guard<std::mutex> lock(heartbeat_mutex_);
    heartbeats_.erase({room_id, user_id});
}

size_t VoiceHandler::reap_stale_members(std::chrono::steady_clock::time_point now) {
    size_t reaped = 0;
    for (const auto& room_id : store_.list_all_non_category_rooms()) {
        auto state_events = store_.get_state_events(room_id);
        for (const auto& ev : state_events) {
            if (ev.type != std::string(event_type::kCallMember) || !ev.state_key) continue;
            if (!ev.content.data.value("active", false)) continue;

            const auto& member_id = *ev.state_key;
            bool stale = false;
            {
                std::lock_guard<std::mutex> lock(heartbeat_mutex_);
                auto key = std::make_pair(room_id, member_id);
                auto it = heartbeats_.find(key);
                if (it == heartbeats_.end()) {
                    // Active member with no recorded heartbeat (e.g. after a
                    // server restart): seed the map and grant a grace period
                    // instead of reaping on first sight.
                    heartbeats_[key] = now;
                } else if (now - it->second > kHeartbeatTtl) {
                    stale = true;
                    heartbeats_.erase(it);
                }
            }
            if (!stale) continue;

            VoiceMemberContent member;
            member.active = false;

            json member_json;
            to_json(member_json, member);
            emit_state_event(store_, sync_engine_, config_.server_name,
                             room_id, member_id, std::string(event_type::kCallMember), member_id, member_json);
            get_logger()->info("Voice reaper: expired ghost participant {} in room {}", member_id, room_id);
            reaped++;
        }
    }
    return reaped;
}

void VoiceHandler::start_reaper() {
    if (reaper_thread_.joinable()) return;
    {
        std::lock_guard<std::mutex> lock(reaper_mutex_);
        reaper_stop_ = false;
    }
    reaper_thread_ = std::thread([this] {
        std::unique_lock<std::mutex> lock(reaper_mutex_);
        while (!reaper_stop_) {
            reaper_cv_.wait_for(lock, kReapInterval, [this] { return reaper_stop_; });
            if (reaper_stop_) break;
            lock.unlock();
            try {
                reap_stale_members();
            } catch (const std::exception& e) {
                get_logger()->error("Voice reaper error: {}", e.what());
            }
            lock.lock();
        }
    });
}

void VoiceHandler::stop_reaper() {
    {
        std::lock_guard<std::mutex> lock(reaper_mutex_);
        reaper_stop_ = true;
    }
    reaper_cv_.notify_all();
    if (reaper_thread_.joinable()) reaper_thread_.join();
}

void VoiceHandler::handle_voice_join(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/join", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    // Check if room is voice-capable
    auto voice_state = store_.get_state_event(room_id, std::string(event_type::kRoomVoice), "");
    if (!voice_state) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Room is not voice-capable").to_json().dump(), "application/json");
        return;
    }

    VoiceChannelContent voice_channel;
    from_json(voice_state->content.data, voice_channel);
    if (!voice_channel.enabled) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Voice is disabled in this room").to_json().dump(), "application/json");
        return;
    }

    // Parse optional device_id from body
    std::string device_id;
    if (!req.body.empty()) {
        try {
            auto body = json::parse(req.body);
            device_id = body.value("device_id", "");
        } catch (...) {}
    }

    {
        // Serialize the participant-count check and the state emit so two
        // workers can't both pass the check and overfill the channel.
        std::lock_guard<std::mutex> lock(voice_state_mutex_);

        // Check max participants if set
        if (voice_channel.max_participants > 0) {
            // Count active members
            auto state_events = store_.get_state_events(room_id);
            int active_count = 0;
            for (const auto& ev : state_events) {
                if (ev.type == std::string(event_type::kCallMember)) {
                    if (ev.content.data.value("active", false)) {
                        active_count++;
                    }
                }
            }
            if (active_count >= voice_channel.max_participants) {
                res.status = 403;
                res.set_content(MatrixError::forbidden("Voice channel is full").to_json().dump(), "application/json");
                return;
            }
        }

        // Set the user's m.call.member state to active
        VoiceMemberContent member;
        member.active = true;
        member.muted = false;
        member.deafened = false;
        member.device_id = device_id;
        member.joined_at = now_ms();

        json member_json;
        to_json(member_json, member);
        emit_state_event(store_, sync_engine_, config_.server_name,
                         room_id, *user_id, std::string(event_type::kCallMember), *user_id, member_json);
    }

    record_heartbeat(room_id, *user_id);

    // Gather list of other active voice members
    auto state_events = store_.get_state_events(room_id);
    json members_arr = json::array();
    for (const auto& ev : state_events) {
        if (ev.type == std::string(event_type::kCallMember) && ev.state_key && *ev.state_key != *user_id) {
            if (ev.content.data.value("active", false)) {
                members_arr.push_back({
                    {"user_id", *ev.state_key},
                    {"muted", ev.content.data.value("muted", false)},
                    {"deafened", ev.content.data.value("deafened", false)},
                    {"screen_sharing", ev.content.data.value("screen_sharing", false)},
                    {"camera_on", ev.content.data.value("camera_on", false)},
                    {"device_id", ev.content.data.value("device_id", "")},
                });
            }
        }
    }

    res.set_content(json{{"members", members_arr}}.dump(), "application/json");
    get_logger()->info("User {} joined voice in room {}", *user_id, room_id);
}

void VoiceHandler::handle_voice_leave(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/leave", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    // Set the user's m.call.member state to inactive
    VoiceMemberContent member;
    member.active = false;

    json member_json;
    to_json(member_json, member);
    emit_state_event(store_, sync_engine_, config_.server_name,
                     room_id, *user_id, std::string(event_type::kCallMember), *user_id, member_json);
    clear_heartbeat(room_id, *user_id);

    res.set_content("{}", "application/json");
    get_logger()->info("User {} left voice in room {}", *user_id, room_id);
}

void VoiceHandler::handle_voice_members(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/members", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    auto state_events = store_.get_state_events(room_id);
    json members_arr = json::array();
    bool caller_active = false;
    for (const auto& ev : state_events) {
        if (ev.type == std::string(event_type::kCallMember) && ev.state_key) {
            if (ev.content.data.value("active", false)) {
                if (*ev.state_key == *user_id) caller_active = true;
                members_arr.push_back({
                    {"user_id", *ev.state_key},
                    {"muted", ev.content.data.value("muted", false)},
                    {"deafened", ev.content.data.value("deafened", false)},
                    {"screen_sharing", ev.content.data.value("screen_sharing", false)},
                    {"camera_on", ev.content.data.value("camera_on", false)},
                    {"device_id", ev.content.data.value("device_id", "")},
                    {"joined_at", ev.content.data.value("joined_at", int64_t(0))},
                });
            }
        }
    }

    // Members polling doubles as the caller's liveness heartbeat while they
    // are in voice; the reaper expires members whose heartbeat goes stale.
    if (caller_active) {
        record_heartbeat(room_id, *user_id);
    }

    res.set_content(json{{"members", members_arr}}.dump(), "application/json");
}

void VoiceHandler::handle_voice_state(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/state", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    {
        // Serialize the read-modify-write so concurrent updates from other
        // workers don't clobber each other's fields.
        std::lock_guard<std::mutex> lock(voice_state_mutex_);

        // Get current member state
        auto current = store_.get_state_event(room_id, std::string(event_type::kCallMember), *user_id);
        if (!current || !current->content.data.value("active", false)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden("Not in voice channel").to_json().dump(), "application/json");
            return;
        }

        // Update muted/deafened/screen_sharing/camera_on from request body,
        // keep other fields (omitted keys leave stored values unchanged)
        auto updated = current->content.data;
        if (body.contains("muted")) updated["muted"] = body["muted"].get<bool>();
        if (body.contains("deafened")) updated["deafened"] = body["deafened"].get<bool>();
        if (body.contains("screen_sharing")) updated["screen_sharing"] = body["screen_sharing"].get<bool>();
        if (body.contains("camera_on")) updated["camera_on"] = body["camera_on"].get<bool>();

        emit_state_event(store_, sync_engine_, config_.server_name,
                         room_id, *user_id, std::string(event_type::kCallMember), *user_id, updated);
    }

    record_heartbeat(room_id, *user_id);

    res.set_content("{}", "application/json");
}

void VoiceHandler::handle_turn_server(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    json uris = json::array();
    if (!config_.voice.stun_uri.empty()) {
        uris.push_back(config_.voice.stun_uri);
    }
    for (const auto& turn_uri : config_.voice.turn_uris) {
        if (!turn_uri.empty()) {
            uris.push_back(turn_uri);
        }
    }

    json resp;
    if (!config_.voice.turn_secret.empty()) {
        // coturn REST-API ephemeral credentials (use-auth-secret mode):
        // username = "<unix_expiry>:<user_id>",
        // credential = base64(HMAC-SHA1(turn_secret, username)).
        int64_t expiry = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() + config_.voice.turn_ttl;
        std::string username = std::to_string(expiry) + ":" + *user_id;

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        HMAC(EVP_sha1(),
             config_.voice.turn_secret.data(), static_cast<int>(config_.voice.turn_secret.size()),
             reinterpret_cast<const unsigned char*>(username.data()), username.size(),
             digest, &digest_len);

        resp = {
            {"username", username},
            {"password", base64_encode(digest, digest_len)},
            {"uris", uris},
            {"ttl", config_.voice.turn_ttl},
            {"allow_p2p", config_.voice.allow_peer_to_peer},
        };
    } else {
        // Static credentials never expire; ttl is just a refresh hint.
        resp = {
            {"username", config_.voice.turn_username},
            {"password", config_.voice.turn_password},
            {"uris", uris},
            {"ttl", config_.voice.turn_ttl},
            {"allow_p2p", config_.voice.allow_peer_to_peer},
        };
    }

    res.set_content(resp.dump(), "application/json");
}

std::vector<unsigned char> VoiceHandler::livekit_room_key(const std::string& key_material,
                                                          const std::string& server_name,
                                                          const std::string& room_id,
                                                          uint64_t generation) {
    // AES-GCM-256 to match livekit::EncryptionType::GCM, which is the SDK's
    // default and recommended mode.
    static constexpr size_t kKeyLen = 32;

    // Refuse to derive from nothing. An empty ikm would still produce
    // well-formed-looking bytes, and every deployment with an empty secret
    // would produce the SAME bytes for the same room — a shared "encryption"
    // key across unrelated servers. Fail loudly instead.
    if (key_material.empty()) {
        throw std::runtime_error("livekit_room_key: empty key material");
    }

    // Length-prefixed field packing. Plain concatenation would let
    // (room "a", generation 1) and (room "a1", generation "") collide once
    // the generation is rendered as text; prefixing each field with its
    // length makes the encoding injective, so distinct inputs cannot share a
    // derivation.
    std::string info;
    auto append_field = [&info](const std::string& s) {
        const uint32_t n = static_cast<uint32_t>(s.size());
        for (int i = 3; i >= 0; --i) {
            info.push_back(static_cast<char>((n >> (i * 8)) & 0xFF));
        }
        info += s;
    };
    append_field(server_name);
    append_field(room_id);
    for (int i = 7; i >= 0; --i) {
        info.push_back(static_cast<char>((generation >> (i * 8)) & 0xFF));
    }

    // Domain separation. If key_material is api_secret (the default when no
    // dedicated room_key_secret is set), this salt is what guarantees a room
    // key can never coincide with anything the JWT signer produces from the
    // same secret.
    static constexpr char kSalt[] = "bsfchat/livekit-room-key/v1";

    auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw std::runtime_error("livekit_room_key: HKDF context allocation failed");
    }

    std::vector<unsigned char> key(kKeyLen);
    size_t out_len = kKeyLen;
    if (EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(kSalt),
                                    static_cast<int>(sizeof(kSalt) - 1)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(),
                                   reinterpret_cast<const unsigned char*>(key_material.data()),
                                   static_cast<int>(key_material.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(info.data()),
                                    static_cast<int>(info.size())) <= 0 ||
        EVP_PKEY_derive(ctx.get(), key.data(), &out_len) <= 0 ||
        out_len != kKeyLen) {
        throw std::runtime_error("livekit_room_key: HKDF derivation failed");
    }
    return key;
}

std::string VoiceHandler::livekit_room_name(const std::string& server_name,
                                            const std::string& room_id) {
    // 0x1f (unit separator) cannot appear in either input, so the two fields
    // can't be confused for one another (a "\x1f"-free join would let
    // server="a", room="b!c" and server="a!b", room="c" hash identically).
    const std::string input = server_name + '\x1f' + room_id;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_Digest(input.data(), input.size(), digest, &digest_len, EVP_sha256(), nullptr);

    static constexpr char kHex[] = "0123456789abcdef";
    std::string out = "bsfchat-";
    // 16 bytes = 128 bits of the digest. Collision-free in practice, and short
    // enough to stay readable in LiveKit's own logs and dashboards.
    const unsigned int take = digest_len < 16 ? digest_len : 16;
    for (unsigned int i = 0; i < take; ++i) {
        out += kHex[digest[i] >> 4];
        out += kHex[digest[i] & 0x0F];
    }
    return out;
}

void VoiceHandler::handle_livekit_token(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/livekit_token", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }
    auto& room_id = match.params["roomId"];

    // Not configured is a 404, not a 500: on a mesh-only deployment this
    // endpoint simply does not exist, and that is how the client should read it
    // (fall back to mesh). Checked before any store access so an unconfigured
    // server does no work.
    if (!config_.voice.enabled || !config_.voice.livekit.configured()) {
        res.status = 404;
        res.set_content(
            MatrixError::not_found("LiveKit SFU is not configured on this server").to_json().dump(),
            "application/json");
        return;
    }

    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    // Same voice-capability gate as handle_voice_join: a token for a
    // non-voice or voice-disabled channel should not exist.
    auto voice_state = store_.get_state_event(room_id, std::string(event_type::kRoomVoice), "");
    if (!voice_state) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Room is not voice-capable").to_json().dump(), "application/json");
        return;
    }
    VoiceChannelContent voice_channel;
    from_json(voice_state->content.data, voice_channel);
    if (!voice_channel.enabled) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Voice is disabled in this room").to_json().dump(), "application/json");
        return;
    }

    // THE security gate. Room membership is server-wide in this data model
    // (channels are Matrix rooms, but a member of the server is a member of
    // its channels); visibility is what per-channel permissions control. A
    // user denied kViewChannel here can see neither the channel nor its
    // member list, so they must not be able to obtain a token that would put
    // them inside its SFU room and let them hear everyone in it.
    //
    // PermissionsEngine memoises per instance and is documented as
    // request-scoped — construct it here, do not cache it on the handler.
    PermissionsEngine perms(store_, config_);
    const permission::Flags flags = perms.compute(*user_id, room_id);
    if (!permission::has(flags, permission::kViewChannel)) {
        res.status = 403;
        res.set_content(
            MatrixError::forbidden("You do not have permission to view this channel").to_json().dump(),
            "application/json");
        return;
    }

    // Optional device_id, same body shape as voice/join.
    //
    // LiveKit identifies a participant solely by `sub`. Two connections with
    // the same identity are the same participant, and the SFU disconnects the
    // older one — so joining from a second device with a user-only identity
    // would silently kick the first. Suffixing the device keeps them distinct.
    // The user id is the part before the first '|', which never appears in a
    // Matrix user id, so the client can recover the owner unambiguously.
    std::string device_id;
    if (!req.body.empty()) {
        try {
            auto body = json::parse(req.body);
            device_id = body.value("device_id", "");
        } catch (...) {}
    }
    // '|' is our delimiter, so it must not survive from an attacker-chosen
    // device_id, or an identity could be forged to look like another user's.
    for (auto& c : device_id) {
        if (c == '|') c = '_';
    }
    std::string identity = *user_id;
    if (!device_id.empty()) {
        identity += '|';
        identity += device_id;
    }

    LiveKitGrants grants;
    grants.room = livekit_room_name(config_.server_name, room_id);
    grants.room_join = true;
    // Derived from the permission model as it exists today. There are no
    // voice-specific permission bits (no CONNECT/SPEAK/VIDEO), so publishing
    // mirrors the current mesh behaviour: any member who can view a voice
    // channel can talk, share screen and turn on camera in it. When voice
    // permission bits land, gate can_publish / can_publish_sources on them
    // here — this is the single place that decision is made.
    grants.can_publish = true;
    grants.can_subscribe = true;
    // Data messages are not part of the SFU migration yet; chat and
    // signalling stay on Matrix. Denying this keeps the token from being
    // usable as an unaudited side-channel between participants.
    grants.can_publish_data = false;
    grants.can_publish_sources = {"microphone", "camera", "screen_share", "screen_share_audio"};
    // Voice moderation (server-side mute, removing a participant) is gated on
    // the existing channel-management permission rather than a new bit.
    grants.room_admin = permission::has(flags, permission::kManageChannels);

    std::string token;
    try {
        token = livekit_token_sign(
            config_.voice.livekit.api_key,
            config_.voice.livekit.api_secret,
            identity,
            *user_id, // display name; the client resolves profiles itself
            grants,
            config_.voice.livekit.token_ttl);
    } catch (const std::exception& e) {
        // Never echo `e.what()` — the signer's messages are safe today, but
        // this is the one place an api_secret could reach a client.
        get_logger()->error("LiveKit token signing failed for room {}: {}", room_id, e.what());
        res.status = 500;
        res.set_content(MatrixError::unknown("Could not issue a voice token").to_json().dump(),
                        "application/json");
        return;
    }

    // A successful token request is also a liveness signal, exactly as
    // voice/join and voice/members are — otherwise a client that joins via
    // LiveKit and renews its token would still be reaped.
    record_heartbeat(room_id, *user_id);

    json body{
        {"url", config_.voice.livekit.url},
        {"token", token},
        {"room", grants.room},
        {"identity", identity},
        // Seconds. The client should re-request before this elapses if it
        // needs to be able to reconnect after a network drop.
        {"ttl", std::clamp<int64_t>(config_.voice.livekit.token_ttl, kLiveKitMinTtl, kLiveKitMaxTtl)},
    };

    // Media key. Reaching this point already required room membership, a
    // voice-enabled channel, and kViewChannel — the same gate as the token,
    // and deliberately so: the key is exactly as sensitive as the token,
    // because either one alone is useless and both together are what let a
    // participant hear the room.
    //
    // Delivered in the RESPONSE BODY over TLS, never in a URL. Query strings
    // land in access logs, proxy logs and browser history.
    if (config_.voice.livekit.room_encryption) {
        uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(key_generation_mutex_);
            auto it = key_generations_.find(room_id);
            if (it != key_generations_.end()) {
                generation = it->second;
            }
        }
        try {
            const auto key = livekit_room_key(config_.voice.livekit.key_material(),
                                              config_.server_name, room_id, generation);
            body["encryption"] = json{
                {"mode", "shared_key"},
                {"key", base64_encode(key.data(), key.size())},
                {"key_generation", generation},
            };
        } catch (const std::exception& e) {
            // Never echo e.what() to the client and never fall through to an
            // unencrypted response. A client that asked for an encrypted
            // session and silently got a plaintext one is the worst possible
            // outcome — it would believe it had a property it does not have.
            get_logger()->error("LiveKit room key derivation failed for room {}: {}",
                                room_id, e.what());
            res.status = 500;
            res.set_content(MatrixError::unknown("Could not issue a voice key").to_json().dump(),
                            "application/json");
            return;
        }
    }

    res.set_content(body.dump(), "application/json");
}

void VoiceHandler::handle_livekit_rekey(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/livekit_rekey", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }
    auto& room_id = match.params["roomId"];

    // Same "unconfigured is a 404" contract as the token endpoint. Also 404
    // when encryption is off: there is no key to rotate, and saying so
    // plainly beats pretending a rotation happened.
    if (!config_.voice.enabled || !config_.voice.livekit.configured() ||
        !config_.voice.livekit.room_encryption) {
        res.status = 404;
        res.set_content(
            MatrixError::not_found("LiveKit media encryption is not configured on this server")
                .to_json().dump(),
            "application/json");
        return;
    }

    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    auto voice_state = store_.get_state_event(room_id, std::string(event_type::kRoomVoice), "");
    if (!voice_state) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Room is not voice-capable").to_json().dump(), "application/json");
        return;
    }
    VoiceChannelContent voice_channel;
    from_json(voice_state->content.data, voice_channel);
    if (!voice_channel.enabled) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Voice is disabled in this room").to_json().dump(), "application/json");
        return;
    }

    // Rotating is a moderation action, not a user action: it interrupts
    // every participant still holding the old key until they re-fetch. Gate
    // it on channel management, the same bit that grants LiveKit roomAdmin.
    // kViewChannel is implied — the permission engine cannot grant
    // kManageChannels on a channel the user cannot see — but check it
    // explicitly anyway rather than relying on that.
    PermissionsEngine perms(store_, config_);
    const permission::Flags flags = perms.compute(*user_id, room_id);
    if (!permission::has(flags, permission::kViewChannel) ||
        !permission::has(flags, permission::kManageChannels)) {
        res.status = 403;
        res.set_content(
            MatrixError::forbidden("You do not have permission to rotate this channel's media key")
                .to_json().dump(),
            "application/json");
        return;
    }

    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(key_generation_mutex_);
        generation = ++key_generations_[room_id];
    }

    // The new key is NOT returned here. The caller re-fetches it from the
    // token endpoint like everyone else, so there is exactly one code path
    // that hands out key material and exactly one permission gate on it.
    res.set_content(json{
        {"key_generation", generation},
    }.dump(), "application/json");
}

} // namespace bsfchat
