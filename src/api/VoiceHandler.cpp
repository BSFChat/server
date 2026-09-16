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
#include <openssl/rand.h>
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

// Opaque per-join token. 128 bits of CSPRNG output, hex encoded.
//
// It is not a secret and not a capability: every leave/state request is still
// authenticated as the user, and the token is published in the m.call.member
// content so a client can recognise its own session in a sync. Its only job is
// to let the server tell one join of a user from the next one, which a
// millisecond timestamp cannot do reliably when a client leaves and rejoins
// inside the same tick (V-H1).
std::string generate_session_id() {
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        // Falling back to a timestamp would silently reintroduce the
        // same-millisecond collision the token exists to rule out.
        throw std::runtime_error("RAND_bytes failed generating a voice session id");
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(sizeof(buf) * 2, '\0');
    for (size_t i = 0; i < sizeof(buf); ++i) {
        out[i * 2] = kHex[buf[i] >> 4];
        out[i * 2 + 1] = kHex[buf[i] & 0x0f];
    }
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
            // Identity of the row this sweep decided to look at. Re-checked
            // under the lock below; if it has moved on, a join landed in the
            // meantime and this sweep must not touch it.
            const auto snapshot_session = ev.content.data.value("session_id", std::string{});
            const auto snapshot_joined_at = ev.content.data.value("joined_at", int64_t(0));

            // The scan above is unsynchronised (it walks whole rooms and must
            // not hold a lock while doing so), so everything from here to the
            // emit runs under the same mutex handle_voice_join takes. Without
            // this a join that lands between the scan and the emit is reaped
            // by a sweep that never saw it: the member ends up active=false
            // with a live client, which is exactly the ghost the reaper is
            // supposed to prevent. Lock order is voice_state_mutex_ then
            // heartbeat_mutex_ everywhere.
            std::lock_guard<std::mutex> state_lock(voice_state_mutex_);

            auto current = store_.get_state_event(room_id, std::string(event_type::kCallMember), member_id);
            if (!current || !current->content.data.value("active", false)) continue;
            if (current->content.data.value("session_id", std::string{}) != snapshot_session ||
                current->content.data.value("joined_at", int64_t(0)) != snapshot_joined_at) {
                // A newer join replaced the row this sweep sampled. Its
                // heartbeat is fresh by construction (handle_voice_join
                // records it inside this same critical section), so leaving
                // it alone is correct and it will be considered next tick.
                continue;
            }

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
            // Echo the session being retracted so a client can tell "the
            // session I am running was reaped" from "an older session of mine
            // was cleaned up", which is what the client-side self-row
            // authority fix (V-H2) keys off.
            member_json["session_id"] = snapshot_session;
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

    std::string session_id;
    int64_t joined_at = 0;
    {
        // Serialize the participant-count check and the state emit so two
        // workers can't both pass the check and overfill the channel. The
        // reaper takes the same mutex around its check-and-emit.
        std::lock_guard<std::mutex> lock(voice_state_mutex_);

        auto existing = store_.get_state_event(room_id, std::string(event_type::kCallMember), *user_id);
        const bool was_active = existing && existing->content.data.value("active", false);

        // Check max participants if set
        if (voice_channel.max_participants > 0) {
            // Count active members
            auto state_events = store_.get_state_events(room_id);
            int active_count = 0;
            for (const auto& ev : state_events) {
                if (ev.type == std::string(event_type::kCallMember) && ev.state_key) {
                    // The caller's own stale row is about to be replaced, not
                    // added to, so it must not count against the cap.
                    // Otherwise rejoining after a crash into a full channel
                    // is refused because of the ghost the rejoin replaces.
                    if (*ev.state_key == *user_id) continue;
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

        // V-M6: joining over a row that is still active (second device, a
        // rejoin after a crash, a leave that never arrived) used to overwrite
        // it silently. Sitting mesh peers key their peer connection on the
        // active transition, so they never saw a reason to tear the old one
        // down and re-offer, and the rejoiner got silence. Retract the old
        // row explicitly first, then publish the new one.
        if (was_active) {
            VoiceMemberContent reset;
            reset.active = false;
            json reset_json;
            to_json(reset_json, reset);
            reset_json["session_id"] = existing->content.data.value("session_id", std::string{});
            emit_state_event(store_, sync_engine_, config_.server_name,
                             room_id, *user_id, std::string(event_type::kCallMember), *user_id, reset_json);
            get_logger()->info("User {} rejoined voice in room {} over a still-active session; "
                               "emitted a reset first", *user_id, room_id);
        }

        // Set the user's m.call.member state to active
        session_id = generate_session_id();
        joined_at = now_ms();

        VoiceMemberContent member;
        member.active = true;
        member.muted = false;
        member.deafened = false;
        member.device_id = device_id;
        member.joined_at = joined_at;

        json member_json;
        to_json(member_json, member);
        member_json["session_id"] = session_id;
        emit_state_event(store_, sync_engine_, config_.server_name,
                         room_id, *user_id, std::string(event_type::kCallMember), *user_id, member_json);

        // Inside the critical section on purpose: a reaper sweep must never be
        // able to observe the new active row without its heartbeat, which is
        // the "join in the same tick as the sweep" race.
        record_heartbeat(room_id, *user_id);
    }

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
                    {"joined_at", ev.content.data.value("joined_at", int64_t(0))},
                    {"session_id", ev.content.data.value("session_id", "")},
                });
            }
        }
    }

    // session_id is the token a client echoes back on leave/state so an
    // out-of-order request from a previous session cannot clobber this one
    // (V-H1). Clients that ignore it keep the pre-existing behaviour.
    res.set_content(json{
        {"members", members_arr},
        {"session_id", session_id},
        {"joined_at", joined_at},
    }.dump(), "application/json");
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

    // Optional session echo. A client that got a session_id from voice/join
    // should send it back here; joined_at is accepted as a weaker fallback for
    // clients that only kept the timestamp. Both are optional so clients
    // predating this change keep working.
    std::string claimed_session;
    int64_t claimed_joined_at = 0;
    bool has_claimed_joined_at = false;
    if (!req.body.empty()) {
        try {
            auto body = json::parse(req.body);
            if (body.is_object()) {
                if (body.contains("session_id") && body["session_id"].is_string()) {
                    claimed_session = body["session_id"].get<std::string>();
                }
                if (body.contains("joined_at") && body["joined_at"].is_number_integer()) {
                    claimed_joined_at = body["joined_at"].get<int64_t>();
                    has_claimed_joined_at = true;
                }
            }
        } catch (...) {}
    }

    std::string reason;
    {
        // Same mutex as join and the reaper: the decision below is a
        // check-then-emit and must not interleave with either.
        std::lock_guard<std::mutex> lock(voice_state_mutex_);

        auto current = store_.get_state_event(room_id, std::string(event_type::kCallMember), *user_id);
        const bool active = current && current->content.data.value("active", false);
        const auto stored_session =
            current ? current->content.data.value("session_id", std::string{}) : std::string{};
        const auto stored_joined_at =
            current ? current->content.data.value("joined_at", int64_t(0)) : int64_t(0);

        if (!active) {
            // Already inactive: a duplicate leave, a leave racing the reaper,
            // or a leave after a moderator action. Answering 200 with an
            // explicit no-op rather than 4xx keeps leave idempotent, which is
            // what a client tearing down on quit or on an error path needs;
            // re-emitting active=false would spam every peer's sync with a
            // state change that changes nothing.
            reason = "not_active";
        } else if (!claimed_session.empty() && !stored_session.empty() &&
                   claimed_session != stored_session) {
            // V-H1 server half: the leave belongs to a session that has
            // already been replaced by a newer join. Honouring it would mark
            // a live client inactive — the ghost participant that is audible,
            // unlisted and never heartbeats.
            reason = "stale_session";
        } else if (has_claimed_joined_at && stored_joined_at > claimed_joined_at) {
            // Same situation, detected from the weaker timestamp evidence.
            reason = "stale_session";
        }

        if (reason.empty()) {
            VoiceMemberContent member;
            member.active = false;

            json member_json;
            to_json(member_json, member);
            member_json["session_id"] = stored_session;
            emit_state_event(store_, sync_engine_, config_.server_name,
                             room_id, *user_id, std::string(event_type::kCallMember), *user_id, member_json);
            clear_heartbeat(room_id, *user_id);
        }
    }

    if (!reason.empty()) {
        get_logger()->info("Voice leave from {} in room {} ignored ({})", *user_id, room_id, reason);
        res.set_content(json{{"changed", false}, {"reason", reason}}.dump(), "application/json");
        return;
    }

    res.set_content(json{{"changed", true}}.dump(), "application/json");
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
                    {"session_id", ev.content.data.value("session_id", "")},
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
            // Deliberate: a state PUT never re-activates a member, including
            // one the reaper has just expired. Re-activating would make the
            // reaper unenforceable (any client that keeps PUTting mute every
            // few seconds would resurrect itself forever, which is precisely
            // the ghost participant the reaper exists to remove) and it would
            // let a state PUT stand in for a join, skipping the capacity
            // check and the join reset. A reaped client must re-POST
            // voice/join, which is what the client-side V-H2 fix does.
            res.status = 403;
            res.set_content(MatrixError::forbidden("Not in voice channel").to_json().dump(), "application/json");
            return;
        }

        // Reject a state PUT carrying a superseded session token for the same
        // reason leave rejects one: a mute/screen-share announcement queued by
        // a session that has already been replaced must not overwrite the
        // flags of the session running now.
        if (body.is_object() && body.contains("session_id") && body["session_id"].is_string()) {
            const auto stored_session = current->content.data.value("session_id", std::string{});
            if (!stored_session.empty() && body["session_id"].get<std::string>() != stored_session) {
                res.status = 403;
                res.set_content(MatrixError::forbidden("Voice session superseded").to_json().dump(),
                                "application/json");
                return;
            }
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
