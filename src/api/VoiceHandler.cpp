#include "api/VoiceHandler.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <chrono>

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
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
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
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
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
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
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
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
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
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
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

} // namespace bsfchat
