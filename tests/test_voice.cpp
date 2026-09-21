#include <gtest/gtest.h>
#include "api/VoiceHandler.h"
#include "store/CallSignalling.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sqlite3.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <atomic>
#include <thread>
#include <vector>
#include <fstream>

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/JwtUtils.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

using namespace bsfchat;
using json = nlohmann::json;

// --- Protocol serialization tests ---

TEST(VoiceProtocol, VoiceMemberContentRoundTrip) {
    VoiceMemberContent member;
    member.active = true;
    member.muted = true;
    member.deafened = false;
    member.screen_sharing = true;
    member.camera_on = false;
    member.device_id = "ABCDEF";
    member.joined_at = 1700000000000;

    json j;
    to_json(j, member);

    EXPECT_TRUE(j["active"].get<bool>());
    EXPECT_TRUE(j["muted"].get<bool>());
    EXPECT_FALSE(j["deafened"].get<bool>());
    EXPECT_TRUE(j["screen_sharing"].get<bool>());
    EXPECT_FALSE(j["camera_on"].get<bool>());
    EXPECT_EQ(j["device_id"], "ABCDEF");
    EXPECT_EQ(j["joined_at"], 1700000000000);

    VoiceMemberContent parsed;
    from_json(j, parsed);

    EXPECT_EQ(parsed.active, member.active);
    EXPECT_EQ(parsed.muted, member.muted);
    EXPECT_EQ(parsed.deafened, member.deafened);
    EXPECT_EQ(parsed.screen_sharing, member.screen_sharing);
    EXPECT_EQ(parsed.camera_on, member.camera_on);
    EXPECT_EQ(parsed.device_id, member.device_id);
    EXPECT_EQ(parsed.joined_at, member.joined_at);

    // Legacy content without the media flags parses as false.
    j.erase("screen_sharing");
    j.erase("camera_on");
    VoiceMemberContent legacy;
    from_json(j, legacy);
    EXPECT_FALSE(legacy.screen_sharing);
    EXPECT_FALSE(legacy.camera_on);
}

TEST(VoiceProtocol, VoiceChannelContentRoundTrip) {
    VoiceChannelContent voice;
    voice.enabled = true;
    voice.max_participants = 10;

    json j;
    to_json(j, voice);

    EXPECT_TRUE(j["enabled"].get<bool>());
    EXPECT_EQ(j["max_participants"], 10);

    VoiceChannelContent parsed;
    from_json(j, parsed);

    EXPECT_EQ(parsed.enabled, voice.enabled);
    EXPECT_EQ(parsed.max_participants, voice.max_participants);
}

TEST(VoiceProtocol, CallInviteContentRoundTrip) {
    CallInviteContent invite;
    invite.call_id = "call-123";
    invite.lifetime = 30000;
    invite.offer.type = "offer";
    invite.offer.sdp = "v=0\r\no=- 12345 2 IN IP4 127.0.0.1\r\n";
    invite.version = 1;

    json j;
    to_json(j, invite);

    EXPECT_EQ(j["call_id"], "call-123");
    EXPECT_EQ(j["lifetime"], 30000);
    EXPECT_EQ(j["offer"]["type"], "offer");
    EXPECT_EQ(j["offer"]["sdp"], invite.offer.sdp);
    EXPECT_EQ(j["version"], 1);

    CallInviteContent parsed;
    from_json(j, parsed);

    EXPECT_EQ(parsed.call_id, invite.call_id);
    EXPECT_EQ(parsed.lifetime, invite.lifetime);
    EXPECT_EQ(parsed.offer.type, invite.offer.type);
    EXPECT_EQ(parsed.offer.sdp, invite.offer.sdp);
    EXPECT_EQ(parsed.version, invite.version);
}

TEST(VoiceProtocol, CallAnswerContentRoundTrip) {
    CallAnswerContent answer;
    answer.call_id = "call-123";
    answer.answer.type = "answer";
    answer.answer.sdp = "v=0\r\no=- 67890 2 IN IP4 127.0.0.1\r\n";
    answer.version = 1;

    json j;
    to_json(j, answer);

    CallAnswerContent parsed;
    from_json(j, parsed);

    EXPECT_EQ(parsed.call_id, answer.call_id);
    EXPECT_EQ(parsed.answer.type, answer.answer.type);
    EXPECT_EQ(parsed.answer.sdp, answer.answer.sdp);
}

TEST(VoiceProtocol, CallCandidatesContentRoundTrip) {
    CallCandidatesContent candidates;
    candidates.call_id = "call-123";
    candidates.version = 1;
    candidates.candidates.push_back({"candidate:1 1 UDP 2130706431 192.168.1.1 5000 typ host", "audio", 0});
    candidates.candidates.push_back({"candidate:2 1 UDP 1694498815 203.0.113.1 5001 typ srflx", "audio", 0});

    json j;
    to_json(j, candidates);

    EXPECT_EQ(j["candidates"].size(), 2u);
    EXPECT_EQ(j["candidates"][0]["sdpMid"], "audio");

    CallCandidatesContent parsed;
    from_json(j, parsed);

    EXPECT_EQ(parsed.call_id, candidates.call_id);
    EXPECT_EQ(parsed.candidates.size(), 2u);
    EXPECT_EQ(parsed.candidates[0].candidate, candidates.candidates[0].candidate);
    EXPECT_EQ(parsed.candidates[1].sdpMid, "audio");
}

TEST(VoiceProtocol, CallHangupContentRoundTrip) {
    CallHangupContent hangup;
    hangup.call_id = "call-123";
    hangup.reason = "user_hangup";
    hangup.version = 1;

    json j;
    to_json(j, hangup);

    CallHangupContent parsed;
    from_json(j, parsed);

    EXPECT_EQ(parsed.call_id, hangup.call_id);
    EXPECT_EQ(parsed.reason, hangup.reason);
    EXPECT_EQ(parsed.version, hangup.version);
}

// --- Voice channel store-level tests ---

class VoiceStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        sync_engine = std::make_unique<SyncEngine>(*store, config);

        store->create_user("@alice:test", hash_password("pass", 10));
        store->create_user("@bob:test", hash_password("pass", 10));
    }

    void create_voice_room(const std::string& room_id, const std::string& creator) {
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, "join");

        // Emit voice channel state
        auto eid = generate_event_id("test");
        json voice_content = {{"enabled", true}, {"max_participants", 0}};
        store->insert_event(eid, room_id, creator,
                           std::string(event_type::kRoomVoice), "", voice_content.dump(), 1000);
    }

    void join_voice(const std::string& room_id, const std::string& user_id) {
        auto eid = generate_event_id("test");
        json member = {{"active", true}, {"muted", false}, {"deafened", false}, {"device_id", ""}, {"joined_at", 1000}};
        store->insert_event(eid, room_id, user_id,
                           std::string(event_type::kCallMember), user_id, member.dump(), 1000);
    }

    void leave_voice(const std::string& room_id, const std::string& user_id) {
        auto eid = generate_event_id("test");
        json member = {{"active", false}, {"muted", false}, {"deafened", false}, {"device_id", ""}, {"joined_at", 0}};
        store->insert_event(eid, room_id, user_id,
                           std::string(event_type::kCallMember), user_id, member.dump(), 2000);
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
};

TEST_F(VoiceStoreTest, VoiceRoomHasVoiceState) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto voice_ev = store->get_state_event(room_id, std::string(event_type::kRoomVoice), "");
    ASSERT_TRUE(voice_ev.has_value());
    EXPECT_TRUE(voice_ev->content.data.value("enabled", false));
}

TEST_F(VoiceStoreTest, JoinAndLeaveVoice) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    join_voice(room_id, "@alice:test");

    auto member_ev = store->get_state_event(room_id, std::string(event_type::kCallMember), "@alice:test");
    ASSERT_TRUE(member_ev.has_value());
    EXPECT_TRUE(member_ev->content.data.value("active", false));

    leave_voice(room_id, "@alice:test");

    member_ev = store->get_state_event(room_id, std::string(event_type::kCallMember), "@alice:test");
    ASSERT_TRUE(member_ev.has_value());
    EXPECT_FALSE(member_ev->content.data.value("active", false));
}

TEST_F(VoiceStoreTest, ListVoiceMembers) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    store->set_membership(room_id, "@bob:test", "join");

    join_voice(room_id, "@alice:test");
    join_voice(room_id, "@bob:test");

    auto state_events = store->get_state_events(room_id);
    int active_count = 0;
    for (const auto& ev : state_events) {
        if (ev.type == std::string(event_type::kCallMember) && ev.state_key) {
            if (ev.content.data.value("active", false)) {
                active_count++;
            }
        }
    }
    EXPECT_EQ(active_count, 2);

    // Bob leaves
    leave_voice(room_id, "@bob:test");

    state_events = store->get_state_events(room_id);
    active_count = 0;
    for (const auto& ev : state_events) {
        if (ev.type == std::string(event_type::kCallMember) && ev.state_key) {
            if (ev.content.data.value("active", false)) {
                active_count++;
            }
        }
    }
    EXPECT_EQ(active_count, 1);
}

// --- TURN server config test ---

TEST(VoiceConfig, TurnServerResponseFormat) {
    Config cfg;
    cfg.voice.enabled = true;
    cfg.voice.stun_uri = "stun:stun.l.google.com:19302";
    cfg.voice.turn_uris = {"turn:turn.example.com:3478"};
    cfg.voice.turn_username = "user";
    cfg.voice.turn_password = "secret";

    // Build the response the same way VoiceHandler does
    json uris = json::array();
    if (!cfg.voice.stun_uri.empty()) uris.push_back(cfg.voice.stun_uri);
    for (const auto& turn_uri : cfg.voice.turn_uris) {
        if (!turn_uri.empty()) uris.push_back(turn_uri);
    }

    json resp = {
        {"username", cfg.voice.turn_username},
        {"password", cfg.voice.turn_password},
        {"uris", uris},
        {"ttl", cfg.voice.turn_ttl},
    };

    EXPECT_EQ(resp["username"], "user");
    EXPECT_EQ(resp["password"], "secret");
    EXPECT_EQ(resp["uris"].size(), 2u);
    EXPECT_EQ(resp["uris"][0], "stun:stun.l.google.com:19302");
    EXPECT_EQ(resp["uris"][1], "turn:turn.example.com:3478");
    EXPECT_EQ(resp["ttl"], 3600);
}

TEST(VoiceConfig, TurnUriAcceptsStringOrArray) {
    auto dir = std::filesystem::temp_directory_path();

    auto single = dir / "bsfchat_test_turn_single.toml";
    {
        std::ofstream out(single);
        out << "[voice]\nturn_uri = \"turn:one.example.com:3478\"\n"
            << "turn_secret = \"sekrit\"\nturn_ttl = 1200\n";
    }
    auto cfg1 = Config::load(single.string());
    ASSERT_EQ(cfg1.voice.turn_uris.size(), 1u);
    EXPECT_EQ(cfg1.voice.turn_uris[0], "turn:one.example.com:3478");
    EXPECT_EQ(cfg1.voice.turn_secret, "sekrit");
    EXPECT_EQ(cfg1.voice.turn_ttl, 1200);

    auto arr = dir / "bsfchat_test_turn_array.toml";
    {
        std::ofstream out(arr);
        out << "[voice]\nturn_uri = [\n"
            << "  \"turn:turn.example.com:3478?transport=udp\",\n"
            << "  \"turn:turn.example.com:3478?transport=tcp\",\n"
            << "]\n";
    }
    auto cfg2 = Config::load(arr.string());
    ASSERT_EQ(cfg2.voice.turn_uris.size(), 2u);
    EXPECT_EQ(cfg2.voice.turn_uris[0], "turn:turn.example.com:3478?transport=udp");
    EXPECT_EQ(cfg2.voice.turn_uris[1], "turn:turn.example.com:3478?transport=tcp");
    EXPECT_EQ(cfg2.voice.turn_ttl, 3600); // default

    std::filesystem::remove(single);
    std::filesystem::remove(arr);
}

namespace {

Config load_toml(const std::string& name, const std::string& body) {
    auto path = std::filesystem::temp_directory_path() / name;
    {
        std::ofstream out(path);
        out << body;
    }
    auto cfg = Config::load(path.string());
    std::filesystem::remove(path);
    return cfg;
}

} // namespace

TEST(VoiceConfig, LiveKitSubTableIsParsed) {
    auto cfg = load_toml("bsfchat_test_lk_ok.toml",
                         "[voice]\n"
                         "enabled = true\n"
                         "\n"
                         "[voice.livekit]\n"
                         "url = \"wss://sfu.example.com\"\n"
                         "api_key = \"APIabc\"\n"
                         "api_secret = \"shhh\"\n"
                         "token_ttl = 300\n");

    EXPECT_EQ(cfg.voice.livekit.url, "wss://sfu.example.com");
    EXPECT_EQ(cfg.voice.livekit.api_key, "APIabc");
    EXPECT_EQ(cfg.voice.livekit.api_secret, "shhh");
    EXPECT_EQ(cfg.voice.livekit.token_ttl, 300);
    EXPECT_TRUE(cfg.voice.livekit.configured());
    // The SFU config must not disturb the existing TURN settings.
    EXPECT_TRUE(cfg.voice.enabled);
    EXPECT_EQ(cfg.voice.turn_ttl, 3600);
}

TEST(VoiceConfig, LiveKitDefaultsToUnconfigured) {
    auto cfg = load_toml("bsfchat_test_lk_absent.toml", "[voice]\nenabled = true\n");
    EXPECT_FALSE(cfg.voice.livekit.configured());
    EXPECT_TRUE(cfg.voice.livekit.url.empty());
    EXPECT_EQ(cfg.voice.livekit.token_ttl, 600); // struct default
}

// This config is a TABLE, not flat keys. An earlier agent misparsed a table as
// flat keys on this project and silently migrated the owner's database, so
// pin the shape: flat `livekit_url = ...` under [voice] must be ignored
// outright rather than half-accepted.
TEST(VoiceConfig, LiveKitFlatKeysAreNotRecognised) {
    auto cfg = load_toml("bsfchat_test_lk_flat.toml",
                         "[voice]\n"
                         "livekit_url = \"wss://sfu.example.com\"\n"
                         "livekit_api_key = \"APIabc\"\n"
                         "livekit_api_secret = \"shhh\"\n");

    EXPECT_TRUE(cfg.voice.livekit.url.empty());
    EXPECT_TRUE(cfg.voice.livekit.api_key.empty());
    EXPECT_TRUE(cfg.voice.livekit.api_secret.empty());
    EXPECT_FALSE(cfg.voice.livekit.configured());
}

// A partially filled block must read as "not configured" so the server keeps
// serving mesh voice rather than trying to mint tokens with a missing secret.
TEST(VoiceConfig, PartialLiveKitConfigIsNotConfigured) {
    auto no_secret = load_toml("bsfchat_test_lk_partial.toml",
                               "[voice.livekit]\n"
                               "url = \"wss://sfu.example.com\"\n"
                               "api_key = \"APIabc\"\n");
    EXPECT_FALSE(no_secret.voice.livekit.configured());

    auto only_secret = load_toml("bsfchat_test_lk_partial2.toml",
                                 "[voice.livekit]\napi_secret = \"shhh\"\n");
    EXPECT_FALSE(only_secret.voice.livekit.configured());
}

// validate() clamps nothing itself (the signer does), but it must not reject
// or mangle an out-of-range ttl — the token endpoint still has to work.
TEST(VoiceConfig, LiveKitSurvivesAnOutOfRangeTokenTtl) {
    auto cfg = load_toml("bsfchat_test_lk_ttl.toml",
                         "[voice.livekit]\n"
                         "url = \"wss://sfu.example.com\"\n"
                         "api_key = \"APIabc\"\n"
                         "api_secret = \"shhh\"\n"
                         "token_ttl = 999999\n");
    EXPECT_TRUE(cfg.voice.livekit.configured());
    EXPECT_EQ(cfg.voice.livekit.token_ttl, 999999);
}

// --- Voice handler tests (reaper, leave membership check, TURN credentials) ---

class VoiceHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        sync_engine = std::make_unique<SyncEngine>(*store, config);
        handler = std::make_unique<VoiceHandler>(*store, *sync_engine, config);

        store->create_user("@alice:test", hash_password("pass", 10));
        store->create_user("@bob:test", hash_password("pass", 10));
        store->store_access_token("alice-token", "@alice:test", "DEV1");
        store->store_access_token("bob-token", "@bob:test", "DEV2");
    }

    void create_voice_room(const std::string& room_id, const std::string& creator) {
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, "join");

        auto eid = generate_event_id("test");
        json voice_content = {{"enabled", true}, {"max_participants", 0}};
        store->insert_event(eid, room_id, creator,
                           std::string(event_type::kRoomVoice), "", voice_content.dump(), 1000);
    }

    void join_voice(const std::string& room_id, const std::string& user_id) {
        auto eid = generate_event_id("test");
        json member = {{"active", true}, {"muted", false}, {"deafened", false}, {"device_id", ""}, {"joined_at", 1000}};
        store->insert_event(eid, room_id, user_id,
                           std::string(event_type::kCallMember), user_id, member.dump(), 1000);
    }

    bool is_active(const std::string& room_id, const std::string& user_id) {
        auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), user_id);
        return ev && ev->content.data.value("active", false);
    }

    // Handlers leave res.status untouched (-1) on success; httplib turns
    // that into 200 when sending. Normalize for assertions.
    static int status_of(const httplib::Response& res) {
        return res.status == -1 ? 200 : res.status;
    }

    // Drives the real join handler rather than inserting a row, so the
    // session token, the reset-on-rejoin and the heartbeat all happen.
    json real_join(const std::string& room_id, const std::string& token,
                   const std::string& body = "") {
        httplib::Response res;
        auto req = make_request("POST", "/_matrix/client/v3/rooms/" + room_id + "/voice/join", token, body);
        handler->handle_voice_join(req, res);
        EXPECT_EQ(status_of(res), 200) << res.body;
        return json::parse(res.body);
    }

    json real_leave(const std::string& room_id, const std::string& token,
                    const std::string& body = "") {
        httplib::Response res;
        auto req = make_request("POST", "/_matrix/client/v3/rooms/" + room_id + "/voice/leave", token, body);
        handler->handle_voice_leave(req, res);
        EXPECT_EQ(status_of(res), 200) << res.body;
        return json::parse(res.body);
    }

    // Every m.call.member event ever emitted for `user_id`, oldest first.
    // The roster is a state event, so the current row alone cannot show that
    // a rejoin emitted an inactive transition before the active one.
    std::vector<json> member_event_history(const std::string& room_id, const std::string& user_id) {
        std::vector<json> out;
        for (const auto& ev : store->get_room_events(room_id, 1000, "f")) {
            if (ev.type != std::string(event_type::kCallMember)) continue;
            if (!ev.state_key || *ev.state_key != user_id) continue;
            out.push_back(ev.content.data);
        }
        return out;
    }

    std::string stored_session(const std::string& room_id, const std::string& user_id) {
        auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), user_id);
        return ev ? ev->content.data.value("session_id", std::string{}) : std::string{};
    }

    static httplib::Request make_request(const std::string& method, const std::string& path,
                                         const std::string& token, const std::string& body = "") {
        httplib::Request req;
        req.method = method;
        req.path = path;
        req.set_header("Authorization", "Bearer " + token);
        req.body = body;
        return req;
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
    std::unique_ptr<VoiceHandler> handler;
};

TEST_F(VoiceHandlerTest, ReaperSeedsGracePeriodThenExpiresStaleMember) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    join_voice(room_id, "@alice:test");

    auto t0 = std::chrono::steady_clock::now();

    // First sight of an active member with no heartbeat (server-restart
    // scenario): seeded with a grace period, not reaped.
    EXPECT_EQ(handler->reap_stale_members(t0), 0u);
    EXPECT_TRUE(is_active(room_id, "@alice:test"));

    // Still within TTL: not reaped.
    EXPECT_EQ(handler->reap_stale_members(t0 + std::chrono::seconds(20)), 0u);
    EXPECT_TRUE(is_active(room_id, "@alice:test"));

    // Heartbeat older than 30s: reaped, active:false emitted.
    EXPECT_EQ(handler->reap_stale_members(t0 + std::chrono::seconds(31)), 1u);
    EXPECT_FALSE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, HeartbeatKeepsMemberAlive) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    join_voice(room_id, "@alice:test");

    auto t0 = std::chrono::steady_clock::now();
    handler->record_heartbeat(room_id, "@alice:test", t0);

    // Fresh heartbeat at t0+20s keeps the member alive past the original TTL.
    handler->record_heartbeat(room_id, "@alice:test", t0 + std::chrono::seconds(20));
    EXPECT_EQ(handler->reap_stale_members(t0 + std::chrono::seconds(31)), 0u);
    EXPECT_TRUE(is_active(room_id, "@alice:test"));

    // Once the heartbeats stop, the member is reaped.
    EXPECT_EQ(handler->reap_stale_members(t0 + std::chrono::seconds(51)), 1u);
    EXPECT_FALSE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, MembersPollRecordsHeartbeat) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    join_voice(room_id, "@alice:test");

    auto t0 = std::chrono::steady_clock::now();

    // Stale heartbeat, but a GET voice/members refreshes it.
    handler->record_heartbeat(room_id, "@alice:test", t0 - std::chrono::seconds(60));

    httplib::Response res;
    auto req = make_request("GET", "/_matrix/client/v3/rooms/" + room_id + "/voice/members", "alice-token");
    handler->handle_voice_members(req, res);
    EXPECT_EQ(status_of(res), 200);

    EXPECT_EQ(handler->reap_stale_members(t0 + std::chrono::seconds(5)), 0u);
    EXPECT_TRUE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, StaleHeartbeatWithoutPollGetsReaped) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    join_voice(room_id, "@alice:test");

    auto t0 = std::chrono::steady_clock::now();
    handler->record_heartbeat(room_id, "@alice:test", t0 - std::chrono::seconds(60));

    EXPECT_EQ(handler->reap_stale_members(t0 + std::chrono::seconds(5)), 1u);
    EXPECT_FALSE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, ReaperThreadStartsAndStopsPromptly) {
    handler->start_reaper();
    auto t0 = std::chrono::steady_clock::now();
    handler->stop_reaper();
    // The condition_variable must wake the thread immediately rather than
    // letting it sleep out the full reap interval.
    EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::seconds(2));
    // Idempotent.
    handler->stop_reaper();
}

TEST_F(VoiceHandlerTest, ScreenShareStateReflectedInMembers) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    join_voice(room_id, "@alice:test");

    // PUT voice/state announcing a screen share.
    httplib::Response put_res;
    auto put_req = make_request("PUT", "/_matrix/client/v3/rooms/" + room_id + "/voice/state",
                                "alice-token", json{{"screen_sharing", true}}.dump());
    handler->handle_voice_state(put_req, put_res);
    EXPECT_EQ(status_of(put_res), 200);

    // GET voice/members reflects it.
    httplib::Response get_res;
    auto get_req = make_request("GET", "/_matrix/client/v3/rooms/" + room_id + "/voice/members", "alice-token");
    handler->handle_voice_members(get_req, get_res);
    EXPECT_EQ(status_of(get_res), 200);

    auto members = json::parse(get_res.body)["members"];
    ASSERT_EQ(members.size(), 1u);
    EXPECT_EQ(members[0]["user_id"], "@alice:test");
    EXPECT_TRUE(members[0]["screen_sharing"].get<bool>());
    EXPECT_FALSE(members[0]["camera_on"].get<bool>());
}

TEST_F(VoiceHandlerTest, OmittedMediaKeysLeaveFlagsUnchanged) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    join_voice(room_id, "@alice:test");

    // Turn both media flags on.
    httplib::Response res1;
    auto req1 = make_request("PUT", "/_matrix/client/v3/rooms/" + room_id + "/voice/state",
                             "alice-token", json{{"screen_sharing", true}, {"camera_on", true}}.dump());
    handler->handle_voice_state(req1, res1);
    EXPECT_EQ(status_of(res1), 200);

    // A muted-toggle PUT that omits the media keys must not touch them.
    httplib::Response res2;
    auto req2 = make_request("PUT", "/_matrix/client/v3/rooms/" + room_id + "/voice/state",
                             "alice-token", json{{"muted", true}}.dump());
    handler->handle_voice_state(req2, res2);
    EXPECT_EQ(status_of(res2), 200);

    auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), "@alice:test");
    ASSERT_TRUE(ev.has_value());
    EXPECT_TRUE(ev->content.data.value("muted", false));
    EXPECT_TRUE(ev->content.data.value("screen_sharing", false));
    EXPECT_TRUE(ev->content.data.value("camera_on", false));

    // Explicitly turning one flag off leaves the other on.
    httplib::Response res3;
    auto req3 = make_request("PUT", "/_matrix/client/v3/rooms/" + room_id + "/voice/state",
                             "alice-token", json{{"screen_sharing", false}}.dump());
    handler->handle_voice_state(req3, res3);
    EXPECT_EQ(status_of(res3), 200);

    ev = store->get_state_event(room_id, std::string(event_type::kCallMember), "@alice:test");
    ASSERT_TRUE(ev.has_value());
    EXPECT_FALSE(ev->content.data.value("screen_sharing", false));
    EXPECT_TRUE(ev->content.data.value("camera_on", false));
}

TEST_F(VoiceHandlerTest, LeaveResetsMediaFlags) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    join_voice(room_id, "@alice:test");

    httplib::Response res1;
    auto req1 = make_request("PUT", "/_matrix/client/v3/rooms/" + room_id + "/voice/state",
                             "alice-token", json{{"screen_sharing", true}, {"camera_on", true}}.dump());
    handler->handle_voice_state(req1, res1);
    EXPECT_EQ(status_of(res1), 200);

    httplib::Response res2;
    auto req2 = make_request("POST", "/_matrix/client/v3/rooms/" + room_id + "/voice/leave", "alice-token");
    handler->handle_voice_leave(req2, res2);
    EXPECT_EQ(status_of(res2), 200);

    auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), "@alice:test");
    ASSERT_TRUE(ev.has_value());
    EXPECT_FALSE(ev->content.data.value("active", false));
    EXPECT_FALSE(ev->content.data.value("screen_sharing", false));
    EXPECT_FALSE(ev->content.data.value("camera_on", false));
}

TEST_F(VoiceHandlerTest, LeaveRequiresRoomMembership) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    // Bob is not a member of the room: 403.
    httplib::Response res;
    auto req = make_request("POST", "/_matrix/client/v3/rooms/" + room_id + "/voice/leave", "bob-token");
    handler->handle_voice_leave(req, res);
    EXPECT_EQ(res.status, 403);
    auto err = json::parse(res.body);
    EXPECT_EQ(err["errcode"], "M_FORBIDDEN");

    // Alice is a member: succeeds.
    httplib::Response res2;
    auto req2 = make_request("POST", "/_matrix/client/v3/rooms/" + room_id + "/voice/leave", "alice-token");
    handler->handle_voice_leave(req2, res2);
    EXPECT_EQ(status_of(res2), 200);
}

// --- V-M6 / V-H1: join and leave state checks ---
//
// Every test below drives the real handlers. The bug class they cover is
// "the server took an instruction at face value without asking what state
// the row was actually in", which only shows up when requests arrive out of
// the order the client sent them in.

TEST_F(VoiceHandlerTest, JoinMintsASessionTokenAndPublishesIt) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto joined = real_join(room_id, "alice-token");

    ASSERT_TRUE(joined.contains("session_id"));
    ASSERT_TRUE(joined.contains("joined_at"));
    EXPECT_EQ(joined["session_id"].get<std::string>().size(), 32u); // 128 bits, hex
    EXPECT_GT(joined["joined_at"].get<int64_t>(), 0);
    EXPECT_EQ(stored_session(room_id, "@alice:test"), joined["session_id"].get<std::string>());
    EXPECT_TRUE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, TwoJoinsMintDifferentSessionTokens) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto first = real_join(room_id, "alice-token")["session_id"].get<std::string>();
    auto second = real_join(room_id, "alice-token")["session_id"].get<std::string>();
    EXPECT_NE(first, second);
    EXPECT_EQ(stored_session(room_id, "@alice:test"), second);
}

TEST_F(VoiceHandlerTest, LeaveWithTheCurrentSessionDeactivates) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto session = real_join(room_id, "alice-token")["session_id"].get<std::string>();
    auto left = real_leave(room_id, "alice-token", json{{"session_id", session}}.dump());

    EXPECT_TRUE(left.value("changed", false));
    EXPECT_FALSE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, LeaveFromAnOlderSessionCannotFlipAFreshJoin) {
    // V-H1. The client sent leave then join on two connections; the server
    // saw the join first. Before the session token the late leave marked a
    // live client inactive: audible, unlisted, never heartbeating.
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto old_session = real_join(room_id, "alice-token")["session_id"].get<std::string>();
    auto fresh = real_join(room_id, "alice-token");
    auto fresh_session = fresh["session_id"].get<std::string>();

    auto ignored = real_leave(room_id, "alice-token", json{{"session_id", old_session}}.dump());

    EXPECT_FALSE(ignored.value("changed", true));
    EXPECT_EQ(ignored.value("reason", ""), "stale_session");
    EXPECT_TRUE(is_active(room_id, "@alice:test"));
    EXPECT_EQ(stored_session(room_id, "@alice:test"), fresh_session);

    // And the fresh session's own leave still works.
    EXPECT_TRUE(real_leave(room_id, "alice-token",
                           json{{"session_id", fresh_session}}.dump()).value("changed", false));
    EXPECT_FALSE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, LeaveWithAnOlderJoinedAtIsIgnored) {
    // Fallback evidence for a client that kept only the timestamp.
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto first = real_join(room_id, "alice-token");
    auto old_joined_at = first["joined_at"].get<int64_t>();

    // Force the replacement row to carry a strictly newer joined_at; two
    // joins inside one millisecond would otherwise make this ambiguous, which
    // is exactly why the session token exists as the primary check.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    real_join(room_id, "alice-token");

    auto ignored = real_leave(room_id, "alice-token", json{{"joined_at", old_joined_at}}.dump());
    EXPECT_FALSE(ignored.value("changed", true));
    EXPECT_EQ(ignored.value("reason", ""), "stale_session");
    EXPECT_TRUE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, LeaveWithoutASessionTokenStillWorks) {
    // Backwards compatibility: clients predating the token send an empty body.
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    real_join(room_id, "alice-token");
    EXPECT_TRUE(real_leave(room_id, "alice-token").value("changed", false));
    EXPECT_FALSE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, LeaveWhenAlreadyInactiveIsANoOpNotAnEvent) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    real_join(room_id, "alice-token");
    real_leave(room_id, "alice-token");
    auto after_first_leave = member_event_history(room_id, "@alice:test").size();

    auto second = real_leave(room_id, "alice-token");
    EXPECT_FALSE(second.value("changed", true));
    EXPECT_EQ(second.value("reason", ""), "not_active");
    EXPECT_FALSE(is_active(room_id, "@alice:test"));
    // The point of the no-op: no second active=false in everyone's /sync.
    EXPECT_EQ(member_event_history(room_id, "@alice:test").size(), after_first_leave);
}

TEST_F(VoiceHandlerTest, LeaveBeforeEverJoiningIsANoOp) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto res = real_leave(room_id, "alice-token");
    EXPECT_FALSE(res.value("changed", true));
    EXPECT_EQ(res.value("reason", ""), "not_active");
    EXPECT_TRUE(member_event_history(room_id, "@alice:test").empty());
}

TEST_F(VoiceHandlerTest, JoinOverAnActiveRowEmitsInactiveThenActive) {
    // V-M6. Sitting mesh peers key their peer connection on the active
    // transition. Overwriting one active row with another gave them no edge
    // to react to, so they held a dead connection and the rejoiner got
    // silence until a watchdog fired.
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto first = real_join(room_id, "alice-token");
    auto second = real_join(room_id, "alice-token");

    auto history = member_event_history(room_id, "@alice:test");
    ASSERT_EQ(history.size(), 3u) << "expected active, then inactive, then active";
    EXPECT_TRUE(history[0].value("active", false));
    EXPECT_EQ(history[0].value("session_id", ""), first["session_id"].get<std::string>());

    EXPECT_FALSE(history[1].value("active", true));
    EXPECT_EQ(history[1].value("session_id", ""), first["session_id"].get<std::string>())
        << "the reset must name the session it retracts, not the new one";

    EXPECT_TRUE(history[2].value("active", false));
    EXPECT_EQ(history[2].value("session_id", ""), second["session_id"].get<std::string>());
    EXPECT_TRUE(is_active(room_id, "@alice:test"));
}

TEST_F(VoiceHandlerTest, JoinOverAnInactiveRowEmitsOnlyTheActiveEvent) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    real_join(room_id, "alice-token");
    real_leave(room_id, "alice-token");
    auto before = member_event_history(room_id, "@alice:test").size();
    real_join(room_id, "alice-token");

    // No spurious reset when there was nothing live to reset.
    EXPECT_EQ(member_event_history(room_id, "@alice:test").size(), before + 1);
}

TEST_F(VoiceHandlerTest, RejoinIsNotRefusedByAFullChannel) {
    // The caller's own ghost row is replaced, not added to, so it must not
    // count against max_participants — otherwise a crash-and-rejoin into a
    // full channel is refused because of the ghost the rejoin would clear.
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test");
    store->set_membership(room_id, "@alice:test", "join");
    store->set_membership(room_id, "@bob:test", "join");
    store->insert_event(generate_event_id("test"), room_id, "@alice:test",
                        std::string(event_type::kRoomVoice), "",
                        json{{"enabled", true}, {"max_participants", 2}}.dump(), 1000);

    real_join(room_id, "alice-token");
    real_join(room_id, "bob-token");

    // Channel is at capacity with alice and bob. Alice rejoining is fine.
    auto rejoin = real_join(room_id, "alice-token");
    EXPECT_TRUE(is_active(room_id, "@alice:test"));
    EXPECT_TRUE(is_active(room_id, "@bob:test"));

    // Carol, a genuine third party, is still refused.
    store->create_user("@carol:test", hash_password("pass", 10));
    store->store_access_token("carol-token", "@carol:test", "DEV3");
    store->set_membership(room_id, "@carol:test", "join");
    httplib::Response res;
    auto req = make_request("POST", "/_matrix/client/v3/rooms/" + room_id + "/voice/join", "carol-token");
    handler->handle_voice_join(req, res);
    EXPECT_EQ(status_of(res), 403);
    EXPECT_NE(res.body.find("full"), std::string::npos);
}

TEST_F(VoiceHandlerTest, VoiceStateOnAReapedMemberIsRefusedAndDoesNotReactivate) {
    // Documented decision: a state PUT never re-activates a row. Allowing it
    // would make the reaper unenforceable (a client PUTting mute every few
    // seconds would resurrect itself indefinitely) and would let a state PUT
    // substitute for a join, skipping the capacity check and the reset.
    // A reaped client must re-POST voice/join.
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto joined = real_join(room_id, "alice-token");
    auto t0 = std::chrono::steady_clock::now();
    handler->record_heartbeat(room_id, "@alice:test", t0 - std::chrono::seconds(60));
    ASSERT_EQ(handler->reap_stale_members(t0), 1u);
    ASSERT_FALSE(is_active(room_id, "@alice:test"));
    auto after_reap = member_event_history(room_id, "@alice:test").size();

    httplib::Response res;
    auto req = make_request("PUT", "/_matrix/client/v3/rooms/" + room_id + "/voice/state", "alice-token",
                            json{{"muted", true}, {"session_id", joined["session_id"]}}.dump());
    handler->handle_voice_state(req, res);

    EXPECT_EQ(status_of(res), 403);
    EXPECT_NE(res.body.find("M_FORBIDDEN"), std::string::npos);
    EXPECT_FALSE(is_active(room_id, "@alice:test"));
    EXPECT_EQ(member_event_history(room_id, "@alice:test").size(), after_reap);

    // The prescribed recovery path works and mints a new session.
    auto rejoined = real_join(room_id, "alice-token");
    EXPECT_TRUE(is_active(room_id, "@alice:test"));
    EXPECT_NE(rejoined["session_id"], joined["session_id"]);
}

TEST_F(VoiceHandlerTest, ReapedRowNamesTheSessionItRetracted) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto joined = real_join(room_id, "alice-token");
    auto t0 = std::chrono::steady_clock::now();
    handler->record_heartbeat(room_id, "@alice:test", t0 - std::chrono::seconds(60));
    ASSERT_EQ(handler->reap_stale_members(t0), 1u);

    auto history = member_event_history(room_id, "@alice:test");
    ASSERT_FALSE(history.empty());
    EXPECT_FALSE(history.back().value("active", true));
    EXPECT_EQ(history.back().value("session_id", ""), joined["session_id"].get<std::string>());
}

TEST_F(VoiceHandlerTest, VoiceStateFromASupersededSessionIsRefused) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto old_session = real_join(room_id, "alice-token")["session_id"].get<std::string>();
    real_join(room_id, "alice-token");

    httplib::Response res;
    auto req = make_request("PUT", "/_matrix/client/v3/rooms/" + room_id + "/voice/state", "alice-token",
                            json{{"muted", true}, {"session_id", old_session}}.dump());
    handler->handle_voice_state(req, res);

    EXPECT_EQ(status_of(res), 403);
    auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), "@alice:test");
    ASSERT_TRUE(ev.has_value());
    EXPECT_FALSE(ev->content.data.value("muted", true)) << "a stale session must not mute the live one";
}

TEST_F(VoiceHandlerTest, VoiceStateWithTheCurrentSessionIsAccepted) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    auto session = real_join(room_id, "alice-token")["session_id"].get<std::string>();
    httplib::Response res;
    auto req = make_request("PUT", "/_matrix/client/v3/rooms/" + room_id + "/voice/state", "alice-token",
                            json{{"muted", true}, {"session_id", session}}.dump());
    handler->handle_voice_state(req, res);

    EXPECT_EQ(status_of(res), 200);
    auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), "@alice:test");
    ASSERT_TRUE(ev.has_value());
    EXPECT_TRUE(ev->content.data.value("muted", false));
    // The token survives a state update; it identifies the join, not the PUT.
    EXPECT_EQ(ev->content.data.value("session_id", ""), session);
}

TEST_F(VoiceHandlerTest, JoinInTheSameTickAsASweepIsNotReaped) {
    // The join's heartbeat is recorded inside the same critical section that
    // publishes the active row, so a sweep cannot observe one without the
    // other. Before that, a join landing between the reaper's scan and its
    // emit was marked inactive with a live client on the other end.
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    real_join(room_id, "alice-token");
    auto t0 = std::chrono::steady_clock::now();

    // Heartbeat is long stale: this member is due to be reaped.
    handler->record_heartbeat(room_id, "@alice:test", t0 - std::chrono::seconds(60));

    // ...but a fresh join lands first. It replaces the row AND the heartbeat.
    auto fresh = real_join(room_id, "alice-token");

    EXPECT_EQ(handler->reap_stale_members(t0), 0u);
    EXPECT_TRUE(is_active(room_id, "@alice:test"));
    EXPECT_EQ(stored_session(room_id, "@alice:test"), fresh["session_id"].get<std::string>());
}

TEST_F(VoiceHandlerTest, AJoinRacingASweepIsNeverLeftInactive) {
    // The deterministic test above cannot reach the interleaving that
    // actually bit: the sweep has already read the stale heartbeat and
    // decided to reap when the join lands, so it emits active=false over a
    // row that a live client just created. This runs the two against each
    // other with the reaper on a real clock, so every reap it performs is
    // one it was entitled to perform, and the only way the assertion can
    // fail is the check-then-emit window.
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");
    real_join(room_id, "alice-token");

    std::atomic<bool> stop{false};
    std::thread sweeper([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            handler->reap_stale_members(std::chrono::steady_clock::now());
            std::this_thread::yield();
        }
    });

    for (int i = 0; i < 300; ++i) {
        // Age the heartbeat so the sweep running alongside wants to reap,
        // then join. The join publishes the active row and records a fresh
        // heartbeat in one critical section, so once it has returned no sweep
        // on this clock has grounds to expire it.
        handler->record_heartbeat(room_id, "@alice:test",
                                  std::chrono::steady_clock::now() - std::chrono::seconds(60));
        real_join(room_id, "alice-token");

        auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), "@alice:test");
        ASSERT_TRUE(ev.has_value());
        ASSERT_TRUE(ev->content.data.value("active", false))
            << "a sweep expired a join it raced with, iteration " << i;
    }

    stop.store(true, std::memory_order_relaxed);
    sweeper.join();
}

TEST_F(VoiceHandlerTest, EphemeralTurnCredentials) {
    config.voice.stun_uri = "stun:stun.example.com:3478";
    config.voice.turn_uris = {"turn:turn.example.com:3478?transport=udp",
                              "turn:turn.example.com:3478?transport=tcp"};
    config.voice.turn_secret = "coturn-shared-secret";
    config.voice.turn_ttl = 600;

    auto before = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    httplib::Response res;
    auto req = make_request("GET", "/_matrix/client/v3/voip/turnServer", "alice-token");
    handler->handle_turn_server(req, res);
    EXPECT_EQ(status_of(res), 200);

    auto after = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto resp = json::parse(res.body);
    EXPECT_EQ(resp["ttl"], 600);
    ASSERT_EQ(resp["uris"].size(), 3u);
    EXPECT_EQ(resp["uris"][0], "stun:stun.example.com:3478");
    EXPECT_EQ(resp["uris"][1], "turn:turn.example.com:3478?transport=udp");
    EXPECT_EQ(resp["uris"][2], "turn:turn.example.com:3478?transport=tcp");

    // Username is "<unix_expiry>:<user_id>" with expiry = now + ttl.
    std::string username = resp["username"];
    auto colon = username.find(':');
    ASSERT_NE(colon, std::string::npos);
    int64_t expiry = std::stoll(username.substr(0, colon));
    EXPECT_GE(expiry, before + 600);
    EXPECT_LE(expiry, after + 600);
    EXPECT_EQ(username.substr(colon + 1), "@alice:test");

    // Credential is base64(HMAC-SHA1(turn_secret, username)) — verify
    // against an independently computed value.
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    HMAC(EVP_sha1(),
         config.voice.turn_secret.data(), static_cast<int>(config.voice.turn_secret.size()),
         reinterpret_cast<const unsigned char*>(username.data()), username.size(),
         digest, &digest_len);
    std::string expected((digest_len + 2) / 3 * 4, '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(expected.data()), digest, static_cast<int>(digest_len));
    expected.resize(written);

    EXPECT_EQ(resp["password"], expected);
}

TEST_F(VoiceHandlerTest, StaticTurnCredentialsWhenNoSecret) {
    config.voice.turn_uris = {"turn:turn.example.com:3478"};
    config.voice.turn_username = "static-user";
    config.voice.turn_password = "static-pass";

    httplib::Response res;
    auto req = make_request("GET", "/_matrix/client/v3/voip/turnServer", "alice-token");
    handler->handle_turn_server(req, res);
    EXPECT_EQ(status_of(res), 200);

    auto resp = json::parse(res.body);
    EXPECT_EQ(resp["username"], "static-user");
    EXPECT_EQ(resp["password"], "static-pass");
    EXPECT_EQ(resp["ttl"], config.voice.turn_ttl);
}

TEST(VoiceProtocol, EventTypeConstants) {
    EXPECT_EQ(event_type::kCallInvite, "m.call.invite");
    EXPECT_EQ(event_type::kCallAnswer, "m.call.answer");
    EXPECT_EQ(event_type::kCallCandidates, "m.call.candidates");
    EXPECT_EQ(event_type::kCallHangup, "m.call.hangup");
    EXPECT_EQ(event_type::kCallMember, "m.call.member");
    EXPECT_EQ(event_type::kRoomVoice, "m.room.voice");
}

// --- LiveKit join-token issuance -------------------------------------------
//
// The security-critical property here is that a token is only ever minted for
// a channel the caller is allowed to SEE. A LiveKit token is a bearer
// credential for an SFU room: whoever holds one can join that room and hear
// everyone in it, entirely outside this server's reach. So the permission gate
// has to hold on the issuing side — there is no second chance later.

namespace {

// Decodes the payload of a JWT without needing jwt-cpp (which is linked
// PRIVATE into bsfchat_protocol and so is not visible to tests).
json lk_payload(const std::string& token) {
    auto first = token.find('.');
    auto second = token.find('.', first + 1);
    auto bytes = base64url_decode(token.substr(first + 1, second - first - 1));
    return json::parse(std::string(bytes.begin(), bytes.end()));
}

ServerRole lk_role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

constexpr const char* kLkSecret = "test-livekit-api-secret-do-not-log";

} // namespace

class LiveKitTokenTest : public ::testing::Test {
protected:
    // Where this fixture's database lives. ":memory:" for everything that does
    // not care; LiveKitRekeyDurabilityTest overrides it with a real file,
    // because "does this survive a restart" cannot be asked of a database that
    // only exists inside the process being restarted.
    virtual std::string db_path() const { return ":memory:"; }

    void SetUp() override {
        store = std::make_unique<SqliteStore>(db_path());
        store->initialize();
        config = Config::defaults();
        config.server_name = "test";
        config.voice.enabled = true;
        config.voice.livekit.url = "wss://sfu.test";
        config.voice.livekit.api_key = "APItestkey";
        config.voice.livekit.api_secret = kLkSecret;
        config.voice.livekit.token_ttl = 600;

        sync_engine = std::make_unique<SyncEngine>(*store, config);
        handler = std::make_unique<VoiceHandler>(*store, *sync_engine, config);

        seed_roles();
        alice = add_user("alice");                                            // plain member
        mod = add_user("mod", {std::string(permission::role_id::kModerator)}); // MANAGE_CHANNELS
        outsider = add_user("outsider");                                      // not in the room

        room = add_voice_channel(alice);
        store->set_membership(room, mod, std::string(membership::kJoin));
        store->set_membership(room, outsider, std::string(membership::kLeave));
    }

    // Deliberately gives @everyone only kEveryoneDefault (which includes
    // kViewChannel) and moderator kManageChannels WITHOUT kAdministrator, so
    // the gate is exercised on its own flag rather than on the god-mode
    // short-circuit in PermissionsEngine::compute.
    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(lk_role(permission::role_id::kEveryone, 0,
                                        permission::kEveryoneDefault));
        content.roles.push_back(lk_role(permission::role_id::kModerator, 10,
                                        permission::kEveryoneDefault |
                                            permission::kManageChannels));
        content.roles.push_back(lk_role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test", j.dump());
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);

        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test", j.dump());
        return uid;
    }

    std::string add_voice_channel(const std::string& creator, bool enabled = true) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomVoice), std::string(""),
                            json{{"enabled", enabled}, {"max_participants", 0}}.dump(), 1000);
        return room_id;
    }

    void deny(const std::string& room_id, const std::string& target, permission::Flags flags) {
        ChannelPermissionOverride ov;
        ov.allow = 0;
        ov.deny = flags;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target, j.dump(), 1002);
    }

    // Marks a user as an active m.call.member, i.e. currently in the channel.
    void mark_in_voice(const std::string& room_id, const std::string& user_id) {
        store->insert_event(generate_event_id("test"), room_id, user_id,
                            std::string(event_type::kCallMember), user_id,
                            json{{"active", true}, {"muted", false}, {"deafened", false},
                                 {"device_id", ""}, {"joined_at", 1000}}.dump(), 1000);
    }

    bool is_active(const std::string& room_id, const std::string& user_id) {
        auto ev = store->get_state_event(room_id, std::string(event_type::kCallMember), user_id);
        return ev && ev->content.data.value("active", false);
    }

    // Old enough that a reap pass at "now" would expire it. Uses the real
    // steady clock because the handler's own record_heartbeat() defaults to it.
    static std::chrono::steady_clock::time_point stale_heartbeat_time() {
        return std::chrono::steady_clock::now() - VoiceHandler::kHeartbeatTtl -
               std::chrono::seconds(5);
    }

    static int status_of(const httplib::Response& res) { return res.status == -1 ? 200 : res.status; }

    httplib::Response request(const std::string& room_id, const std::string& token,
                              const std::string& body = "") {
        httplib::Request req;
        req.method = "POST";
        req.path = "/_matrix/client/v3/rooms/" + room_id + "/voice/livekit_token";
        if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
        req.body = body;
        httplib::Response res;
        handler->handle_livekit_token(req, res);
        return res;
    }

    // A channel with no bsfchat.room.voice event at all — an ordinary text
    // channel. The caller is joined, because membership is not visibility here
    // and the tests below are about what happens AFTER the membership check.
    std::string add_text_channel(const std::string& creator) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        return room_id;
    }

    httplib::Response join(const std::string& room_id, const std::string& token) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/_matrix/client/v3/rooms/" + room_id + "/voice/join";
        if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        handler->handle_voice_join(req, res);
        return res;
    }

    httplib::Response leave(const std::string& room_id, const std::string& token,
                            const std::string& body = "") {
        httplib::Request req;
        req.method = "POST";
        req.path = "/_matrix/client/v3/rooms/" + room_id + "/voice/leave";
        if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
        req.body = body;
        httplib::Response res;
        handler->handle_voice_leave(req, res);
        return res;
    }

    httplib::Response rekey(const std::string& room_id, const std::string& token) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/_matrix/client/v3/rooms/" + room_id + "/voice/livekit_rekey";
        if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        handler->handle_livekit_rekey(req, res);
        return res;
    }

    // The base64 media key from a token response, or "" when absent.
    static std::string key_of(const httplib::Response& res) {
        auto body = json::parse(res.body);
        if (!body.contains("encryption")) return "";
        return body["encryption"].value("key", "");
    }

    // The SFU room name from a token response. This is the string the token's
    // own `video.room` grant is signed over, so it is what LiveKit admits on.
    static std::string room_of(const httplib::Response& res) {
        return json::parse(res.body).value("room", "");
    }

    // The key generation from a token response, or 0 when absent.
    static uint64_t generation_of(const httplib::Response& res) {
        auto body = json::parse(res.body);
        if (!body.contains("encryption")) return 0;
        return body["encryption"].value("key_generation", uint64_t{0});
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
    std::unique_ptr<VoiceHandler> handler;
    std::string alice, mod, outsider, room;
};

// ---------------------------------------------------------------------------
// Media key issuance and rotation.
//
// What this feature is: the SFU relays media it cannot read, because the key
// comes from THIS server and never reaches LiveKit. What it is NOT: end-to-end
// encryption. The server holds the key, and a departed member keeps decrypting
// until rotation. The tests below pin both the property and its limits so
// neither drifts into an overstated claim.
// ---------------------------------------------------------------------------

TEST_F(LiveKitTokenTest, TokenResponseCarriesASharedMediaKey) {
    auto res = request(room, "token-alice");
    ASSERT_EQ(status_of(res), 200);
    auto body = json::parse(res.body);
    ASSERT_TRUE(body.contains("encryption"));
    EXPECT_EQ(body["encryption"]["mode"], "shared_key");
    // The generation is whatever this install's persisted baseline is, not a
    // literal: pinning a number here is what let the in-memory counter's
    // "always starts at 0" pass for correct.
    ASSERT_TRUE(body["encryption"].contains("key_generation"));
    EXPECT_TRUE(body["encryption"]["key_generation"].is_number_unsigned());
    // 32 raw bytes -> 44 base64 chars with one '=' of padding.
    EXPECT_EQ(key_of(res).size(), 44u);
}

TEST_F(LiveKitTokenTest, MediaKeyIsAes256Sized) {
    auto key = VoiceHandler::livekit_room_key(kLkSecret, "test", "!room:test", 0);
    EXPECT_EQ(key.size(), 32u);
}

TEST_F(LiveKitTokenTest, MediaKeyIsStableAcrossRequests) {
    // Two participants in the same room MUST derive the same bytes or they
    // cannot decode each other. This is the whole feature working.
    EXPECT_EQ(key_of(request(room, "token-alice")), key_of(request(room, "token-mod")));
}

TEST_F(LiveKitTokenTest, MediaKeyDiffersPerRoom) {
    auto other = add_voice_channel(alice);
    EXPECT_NE(key_of(request(room, "token-alice")), key_of(request(other, "token-alice")));
}

TEST_F(LiveKitTokenTest, MediaKeyDiffersPerServerName) {
    auto a = VoiceHandler::livekit_room_key(kLkSecret, "one.example", "!r:test", 0);
    auto b = VoiceHandler::livekit_room_key(kLkSecret, "two.example", "!r:test", 0);
    EXPECT_NE(a, b);
}

TEST_F(LiveKitTokenTest, MediaKeyDiffersPerSecret) {
    auto a = VoiceHandler::livekit_room_key("secret-one", "test", "!r:test", 0);
    auto b = VoiceHandler::livekit_room_key("secret-two", "test", "!r:test", 0);
    EXPECT_NE(a, b);
}

TEST_F(LiveKitTokenTest, MediaKeyDiffersPerGeneration) {
    auto a = VoiceHandler::livekit_room_key(kLkSecret, "test", "!r:test", 0);
    auto b = VoiceHandler::livekit_room_key(kLkSecret, "test", "!r:test", 1);
    EXPECT_NE(a, b);
}

// The info string is length-prefixed so field boundaries cannot be shifted.
// Without that, ("!r", gen) and ("!r" + gen-bytes, 0) could hash identically
// and two different rooms would share a key.
TEST_F(LiveKitTokenTest, MediaKeyFieldsCannotBeConfused) {
    auto a = VoiceHandler::livekit_room_key(kLkSecret, "ab", "c", 0);
    auto b = VoiceHandler::livekit_room_key(kLkSecret, "a", "bc", 0);
    EXPECT_NE(a, b);
}

// Deriving from nothing would give every deployment with an unset secret the
// same "encryption" key for the same room name.
TEST_F(LiveKitTokenTest, MediaKeyRefusesEmptyKeyMaterial) {
    EXPECT_THROW(VoiceHandler::livekit_room_key("", "test", "!r:test", 0), std::exception);
}

TEST_F(LiveKitTokenTest, DedicatedRoomKeySecretIsUsedWhenSet) {
    auto before = key_of(request(room, "token-alice"));
    config.voice.livekit.room_key_secret = "a-dedicated-room-key-secret";
    auto after = key_of(request(room, "token-alice"));
    EXPECT_NE(before, after);
}

// api_secret doubles as the default key material, so domain separation is the
// only thing keeping a media key from colliding with token-signing output.
TEST_F(LiveKitTokenTest, MediaKeyIsNotTheApiSecret) {
    auto res = request(room, "token-alice");
    ASSERT_EQ(status_of(res), 200);
    EXPECT_EQ(res.body.find(kLkSecret), std::string::npos);
    auto key = VoiceHandler::livekit_room_key(kLkSecret, "test", "!r:test", 0);
    const std::string key_str(key.begin(), key.end());
    EXPECT_NE(key_str, kLkSecret);
}

TEST_F(LiveKitTokenTest, NoMediaKeyWhenRoomEncryptionIsDisabled) {
    config.voice.livekit.room_encryption = false;
    auto res = request(room, "token-alice");
    ASSERT_EQ(status_of(res), 200);
    EXPECT_FALSE(json::parse(res.body).contains("encryption"));
}

// The key is exactly as sensitive as the token. Anyone the token gate refuses
// must not receive key material either — and since both ride the same
// response, that is structural rather than a second check.
TEST_F(LiveKitTokenTest, NoMediaKeyWithoutViewChannel) {
    deny(room, "user:" + alice, permission::kViewChannel);
    auto res = request(room, "token-alice");
    ASSERT_EQ(status_of(res), 403);
    EXPECT_EQ(res.body.find("encryption"), std::string::npos);
}

TEST_F(LiveKitTokenTest, NoMediaKeyForNonMember) {
    auto res = request(room, "token-outsider");
    ASSERT_EQ(status_of(res), 403);
    EXPECT_EQ(res.body.find("encryption"), std::string::npos);
}

TEST_F(LiveKitTokenTest, NoMediaKeyWithoutAuthentication) {
    auto res = request(room, "");
    ASSERT_EQ(status_of(res), 401);
    EXPECT_EQ(res.body.find("encryption"), std::string::npos);
}

// ---- rotation ----

TEST_F(LiveKitTokenTest, RekeyChangesTheIssuedKey) {
    const auto before = key_of(request(room, "token-alice"));
    const auto gen_before = generation_of(request(room, "token-alice"));
    auto rot = rekey(room, "token-mod"); // mod has kManageChannels
    ASSERT_EQ(status_of(rot), 200);
    EXPECT_GT(json::parse(rot.body)["key_generation"].get<uint64_t>(), gen_before);
    const auto after = key_of(request(room, "token-alice"));
    EXPECT_NE(before, after);
}

TEST_F(LiveKitTokenTest, RekeyAdvancesGenerationMonotonically) {
    const auto first = json::parse(rekey(room, "token-mod").body)["key_generation"].get<uint64_t>();
    const auto second = json::parse(rekey(room, "token-mod").body)["key_generation"].get<uint64_t>();
    EXPECT_GT(second, first);
    // The token endpoint reports the same generation the rotation returned;
    // a client that re-fetches gets the key the moderator just minted.
    EXPECT_EQ(generation_of(request(room, "token-alice")), second);
}

TEST_F(LiveKitTokenTest, RekeyIsScopedToOneChannel) {
    auto other = add_voice_channel(alice);
    const auto other_before = key_of(request(other, "token-alice"));
    const auto other_room_before = room_of(request(other, "token-alice"));
    ASSERT_EQ(status_of(rekey(room, "token-mod")), 200);
    EXPECT_EQ(key_of(request(other, "token-alice")), other_before);
    // Rotating one channel must not move a bystanding channel's call to a new
    // SFU room and drop everyone in it.
    EXPECT_EQ(room_of(request(other, "token-alice")), other_room_before);
}

// Rotation interrupts everyone still holding the old key, so it is a
// moderation action. A plain member must not be able to trigger it.
TEST_F(LiveKitTokenTest, RekeyRequiresManageChannels) {
    auto res = rekey(room, "token-alice");
    EXPECT_EQ(status_of(res), 403);
}

TEST_F(LiveKitTokenTest, RekeyDeniedWithoutViewChannel) {
    deny(room, "user:" + mod, permission::kViewChannel);
    EXPECT_EQ(status_of(rekey(room, "token-mod")), 403);
}

TEST_F(LiveKitTokenTest, RekeyDeniedForNonMember) {
    EXPECT_EQ(status_of(rekey(room, "token-outsider")), 403);
}

TEST_F(LiveKitTokenTest, RekeyRequiresAuthentication) {
    EXPECT_EQ(status_of(rekey(room, "")), 401);
}

TEST_F(LiveKitTokenTest, RekeyNotFoundWhenLiveKitIsUnconfigured) {
    config.voice.livekit.api_secret.clear();
    EXPECT_EQ(status_of(rekey(room, "token-mod")), 404);
}

TEST_F(LiveKitTokenTest, RekeyNotFoundWhenEncryptionIsDisabled) {
    config.voice.livekit.room_encryption = false;
    EXPECT_EQ(status_of(rekey(room, "token-mod")), 404);
}

// A failed rotation must not silently succeed: no generation bump, so the
// key everyone is using stays valid rather than half the room rotating.
TEST_F(LiveKitTokenTest, DeniedRekeyDoesNotBumpTheGeneration) {
    const auto before = key_of(request(room, "token-alice"));
    ASSERT_EQ(status_of(rekey(room, "token-alice")), 403);
    EXPECT_EQ(key_of(request(room, "token-alice")), before);
}

// Rotation never returns key material. One code path hands out keys, with one
// permission gate on it.
TEST_F(LiveKitTokenTest, RekeyResponseCarriesNoKeyMaterial) {
    auto res = rekey(room, "token-mod");
    ASSERT_EQ(status_of(res), 200);
    auto body = json::parse(res.body);
    EXPECT_FALSE(body.contains("key"));
    EXPECT_FALSE(body.contains("encryption"));
    EXPECT_EQ(res.body.find(kLkSecret), std::string::npos);
}

// ---- rotation retires tokens already in circulation ----
//
// A join token is a signed JWT: this server mints it, the SFU admits on it,
// and nothing we hold is consulted in between. There is no registry to revoke
// it from, so a departed member holding an unexpired one could walk into the
// channel's SFU room — unable to decrypt after a rotation, but present, on the
// participant list, for up to token_ttl. What a token does name is one room,
// so a rotation moves the channel to a new one and leaves the old token
// pointing at a room the conversation has left.

TEST_F(LiveKitTokenTest, RekeyMovesTheChannelToADifferentSfuRoom) {
    const auto before = room_of(request(room, "token-alice"));
    ASSERT_FALSE(before.empty());
    ASSERT_EQ(status_of(rekey(room, "token-mod")), 200);
    EXPECT_NE(room_of(request(room, "token-alice")), before);
}

// The enforcement point is the token's own grant, which LiveKit checks — not
// any bookkeeping of ours. So the assertion is on the signed claim.
TEST_F(LiveKitTokenTest, TokenMintedBeforeARotationGrantsOnlyTheAbandonedRoom) {
    auto kept = request(room, "token-alice"); // the token a departing member keeps
    ASSERT_EQ(status_of(kept), 200);
    const auto kept_grant =
        lk_payload(json::parse(kept.body)["token"])["video"].value("room", "");
    ASSERT_EQ(kept_grant, room_of(kept));

    ASSERT_EQ(status_of(rekey(room, "token-mod")), 200);

    // The kept token still verifies — nothing can un-sign it — but the room it
    // admits to is no longer the one the channel is in.
    EXPECT_NE(kept_grant, room_of(request(room, "token-alice")));
}

// The guard against this going too far — an unrotated channel's members must
// still land in ONE room, and re-fetching must not move anyone — is
// SfuRoomNameIsStableAndPerChannel below, which predates this and still holds.

// A rotation is a moderation action with a durable consequence, so it must
// leave a durable record. Without one, an operator who restores a backup has
// no way to learn that a rotation they are about to lose ever happened.
TEST_F(LiveKitTokenTest, RekeyIsRecordedInTheAuditLog) {
    const auto before = generation_of(request(room, "token-alice"));
    ASSERT_EQ(status_of(rekey(room, "token-mod")), 200);

    auto page = store->list_audit_records(10, std::nullopt, {});
    ASSERT_EQ(page.records.size(), 1u);
    const auto& rec = page.records[0];
    // The literal rather than audit_action::kVoiceRekey: action names are a
    // stable part of the read API, so the test pins the string an operator
    // greps for, not the constant that happens to spell it today.
    EXPECT_EQ(rec.action, "voice.rekey");
    EXPECT_EQ(rec.actor, mod);
    EXPECT_EQ(rec.target_room, room);
    ASSERT_FALSE(rec.before_json.empty());
    ASSERT_FALSE(rec.after_json.empty());
    EXPECT_EQ(json::parse(rec.before_json).value("key_generation", uint64_t{0}), before);
    EXPECT_GT(json::parse(rec.after_json).value("key_generation", uint64_t{0}), before);
}

TEST_F(LiveKitTokenTest, DeniedRekeyIsNotAudited) {
    ASSERT_EQ(status_of(rekey(room, "token-alice")), 403);
    EXPECT_TRUE(store->list_audit_records(10, std::nullopt, {}).records.empty());
}

// ---------------------------------------------------------------------------
// Rotation durability — audit A finding 4.
//
// The generation the media key is derived from used to live in a std::map on
// this handler that defaulted to 0 for any room it had not seen. Every restart
// therefore undid every rotation ever performed: the key reverted to the
// generation-0 key and everyone a moderator had rotated out could decrypt
// again, silently, with the endpoint still reporting success. Server.cpp
// advertises this endpoint as "the only way to stop a departed member
// decrypting", so what follows is the guarantee itself, not a detail.
//
// A real file rather than ":memory:": "does this survive the process" cannot
// be asked of a database that only exists inside it.
// ---------------------------------------------------------------------------
class LiveKitRekeyDurabilityTest : public LiveKitTokenTest {
protected:
    LiveKitRekeyDurabilityTest() {
        // The pid matters: ctest runs each test as its own process, in
        // parallel, so a name built only from a clock and a per-process
        // counter collides and the two runs stamp on each other's database.
        static std::atomic<int> counter{0};
        path_ = (std::filesystem::temp_directory_path() /
                 ("bsfchat-rekey-" + std::to_string(::getpid()) + "-" +
                  std::to_string(counter++) + ".db")).string();
        backup_ = path_ + ".backup";
        remove_db(path_);
        remove_db(backup_);
    }

    std::string db_path() const override { return path_; }

    void TearDown() override {
        close_server();
        remove_db(path_);
        remove_db(backup_);
    }

    // Everything the process was holding goes away and comes back against the
    // same file, exactly as `docker compose up -d` does. Whatever was only in
    // memory is gone — which is the whole question.
    void restart() {
        close_server();
        open_server();
    }

    // The operator's nightly backup: a copy of the database taken while the
    // server is down, so there is no WAL to reconcile.
    void snapshot() {
        close_server();
        std::filesystem::copy_file(path_, backup_,
                                   std::filesystem::copy_options::overwrite_existing);
        open_server();
    }

    // ...and the restore. Everything written since the snapshot is gone.
    void restore_snapshot() {
        close_server();
        remove_db(path_);
        std::filesystem::copy_file(backup_, path_);
        open_server();
    }

    // Hand the process the shape a pre-v19 deployment has: no generation
    // table, no baseline, user_version back where it was. Same approach as the
    // v17 test — the data half is what the migration acts on.
    void rewind_below_v19() {
        close_server();
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path_.c_str(), &db), SQLITE_OK);
        auto run = [&](const char* sql) {
            char* err = nullptr;
            ASSERT_EQ(sqlite3_exec(db, sql, nullptr, nullptr, &err), SQLITE_OK) << (err ? err : "");
            sqlite3_free(err);
        };
        run("DROP TABLE IF EXISTS voice_key_generations");
        run("DELETE FROM server_meta WHERE key = 'voice.key_generation_baseline'");
        run("PRAGMA user_version = 18");
        sqlite3_close(db);
        open_server();
    }

    // Any wall clock a real deployment could have. Generations at or above this
    // cannot collide with anything the old in-memory counter reached, because
    // that counter started at 0 and stepped by one per rotation.
    static constexpr uint64_t kAnyPlausibleClock = 1'600'000'000'000ull; // Sept 2020, ms

private:
    void close_server() {
        handler.reset();
        sync_engine.reset();
        store.reset();
    }

    void open_server() {
        store = std::make_unique<SqliteStore>(path_);
        store->initialize();
        sync_engine = std::make_unique<SyncEngine>(*store, config);
        handler = std::make_unique<VoiceHandler>(*store, *sync_engine, config);
    }

    static void remove_db(const std::string& path) {
        std::error_code ec;
        for (const char* suffix : {"", "-wal", "-shm"}) {
            std::filesystem::remove(path + suffix, ec);
        }
    }

    std::string path_;
    std::string backup_;
};

// THE test for this finding. Bob keeps the key he was handed, a moderator
// rotates him out, the server restarts — and Bob's key must stay dead.
TEST_F(LiveKitRekeyDurabilityTest, RotationSurvivesARestart) {
    const auto departed_key = key_of(request(room, "token-alice"));
    ASSERT_EQ(status_of(rekey(room, "token-mod")), 200);
    const auto rotated_key = key_of(request(room, "token-alice"));
    ASSERT_NE(rotated_key, departed_key);

    restart();

    const auto after_restart = key_of(request(room, "token-alice"));
    EXPECT_NE(after_restart, departed_key)
        << "a restart handed the departed member's key back";
    EXPECT_EQ(after_restart, rotated_key)
        << "a restart changed the key out from under everyone still in the channel";
}

TEST_F(LiveKitRekeyDurabilityTest, GenerationSurvivesARestart) {
    const auto rotated = json::parse(rekey(room, "token-mod").body)["key_generation"].get<uint64_t>();
    restart();
    EXPECT_EQ(generation_of(request(room, "token-alice")), rotated);
}

// Rotating twice across a restart must keep climbing rather than restart the
// sequence — otherwise the second rotation re-issues the first one's key.
TEST_F(LiveKitRekeyDurabilityTest, GenerationKeepsClimbingAcrossARestart) {
    const auto first = json::parse(rekey(room, "token-mod").body)["key_generation"].get<uint64_t>();
    restart();
    const auto second = json::parse(rekey(room, "token-mod").body)["key_generation"].get<uint64_t>();
    EXPECT_GT(second, first);
}

// A room nobody ever rotated must keep the same key across a restart too: a
// restart is not a rotation, and rotating everyone on every deploy would break
// every call in progress.
TEST_F(LiveKitRekeyDurabilityTest, UnrotatedRoomKeepsItsKeyAcrossARestart) {
    const auto before = key_of(request(room, "token-alice"));
    restart();
    EXPECT_EQ(key_of(request(room, "token-alice")), before);
}

// Same guard for the SFU room, which is derived from the same generation: a
// deploy must not scatter a live call across two LiveKit rooms.
TEST_F(LiveKitRekeyDurabilityTest, UnrotatedRoomKeepsItsSfuRoomAcrossARestart) {
    const auto before = room_of(request(room, "token-alice"));
    restart();
    EXPECT_EQ(room_of(request(room, "token-alice")), before);
}

// The two halves of this package meeting: a rotation retires outstanding
// tokens by moving the channel, and a restart must not move it back.
TEST_F(LiveKitRekeyDurabilityTest, TheAbandonedSfuRoomIsNotReoccupiedAfterARestart) {
    const auto abandoned = room_of(request(room, "token-alice"));
    ASSERT_EQ(status_of(rekey(room, "token-mod")), 200);
    const auto rotated = room_of(request(room, "token-alice"));
    ASSERT_NE(rotated, abandoned);

    restart();

    EXPECT_EQ(room_of(request(room, "token-alice")), rotated);
    EXPECT_NE(room_of(request(room, "token-alice")), abandoned)
        << "a restart moved the channel back into the room a departed member's "
           "token still grants entry to";
}

// Upgrading a deployment that rotated keys in memory. Those generations are
// lost — they were never written down — so the migration must land every
// existing channel somewhere the old counter could never have reached, or the
// upgrade itself silently re-admits whoever the last rotation removed.
TEST_F(LiveKitRekeyDurabilityTest, UpgradeLandsExistingChannelsAboveAnyInMemoryGeneration) {
    rewind_below_v19();

    const auto generation = generation_of(request(room, "token-alice"));
    EXPECT_GE(generation, kAnyPlausibleClock)
        << "an upgraded channel came back at a generation the old in-memory "
           "counter could have reached, so a pre-upgrade key may still be live";
    // Distinct generations give distinct keys (MediaKeyDiffersPerGeneration),
    // so a generation no old counter could reach is a key no old client holds.
    for (uint64_t legacy = 0; legacy <= 64; ++legacy) {
        ASSERT_NE(generation, legacy);
    }
}

// Rolling the database back to a backup loses the record of any rotation made
// since — that is what a rollback is, and no design inside that same database
// can prevent it. What it must NOT do is let the sequence walk back over
// generations that were already live, because re-issuing one hands a departed
// member a key they kept. Generations are floored at the wall clock, which a
// restore cannot rewind, so the next rotation lands above every generation
// ever issued on this install.
TEST_F(LiveKitRekeyDurabilityTest, RestoredBackupNeverReissuesARotatedGeneration) {
    snapshot();
    ASSERT_EQ(status_of(rekey(room, "token-mod")), 200);
    const auto rotated = generation_of(request(room, "token-alice"));
    const auto rotated_key = key_of(request(room, "token-alice"));

    restore_snapshot();

    // The floor is wall-clock based, so the guarantee is "the clock moved on",
    // and the test moves it on rather than racing the millisecond.
    std::this_thread::sleep_for(std::chrono::milliseconds(3));

    ASSERT_EQ(status_of(rekey(room, "token-mod")), 200);
    EXPECT_GT(generation_of(request(room, "token-alice")), rotated);
    EXPECT_NE(key_of(request(room, "token-alice")), rotated_key)
        << "a rotation after a restore re-issued a key that was already retired";
}

TEST_F(LiveKitTokenTest, IssuesTokenForPermittedMember) {
    auto res = request(room, "token-alice");
    ASSERT_EQ(status_of(res), 200) << res.body;

    auto body = json::parse(res.body);
    EXPECT_EQ(body.value("url", ""), "wss://sfu.test");
    EXPECT_EQ(body.value("room", ""),
              VoiceHandler::livekit_room_name("test", room, store->get_voice_key_generation(room)));
    EXPECT_EQ(body.value("identity", ""), "@alice:test");
    EXPECT_EQ(body.value("ttl", int64_t{0}), 600);
    ASSERT_TRUE(body.contains("token"));

    auto p = lk_payload(body["token"]);
    EXPECT_EQ(p.value("iss", ""), "APItestkey");
    EXPECT_EQ(p.value("sub", ""), "@alice:test");
    EXPECT_EQ(p["video"].value("room", ""), body.value("room", ""));
    EXPECT_TRUE(p["video"].value("roomJoin", false));
    EXPECT_TRUE(p["video"].value("canPublish", false));
    EXPECT_TRUE(p["video"].value("canSubscribe", false));
    // Chat and signalling stay on Matrix; the SFU token is not a side-channel.
    EXPECT_FALSE(p["video"].value("canPublishData", true));
}

// THE test. A per-channel deny of VIEW_CHANNEL must stop token issuance dead.
TEST_F(LiveKitTokenTest, DeniedWhenViewChannelRevokedForUser) {
    deny(room, "user:" + alice, permission::kViewChannel);

    auto res = request(room, "token-alice");
    EXPECT_EQ(status_of(res), 403);
    // No token may leak in the error body.
    EXPECT_EQ(res.body.find("token"), std::string::npos) << res.body;
}

// Same property via the @everyone channel override rather than a user override,
// because those are two different code paths in PermissionsEngine.
TEST_F(LiveKitTokenTest, DeniedWhenViewChannelRevokedForEveryone) {
    deny(room, "role:" + std::string(permission::role_id::kEveryone), permission::kViewChannel);

    EXPECT_EQ(status_of(request(room, "token-alice")), 403);
    EXPECT_EQ(status_of(request(room, "token-mod")), 403);
}

// Revoking an unrelated permission must NOT block voice — otherwise the gate
// is just "deny anything" and the test above proves nothing specific.
TEST_F(LiveKitTokenTest, StillIssuedWhenAnUnrelatedPermissionIsRevoked) {
    deny(room, "user:" + alice, permission::kSendMessages | permission::kAttachFiles);
    EXPECT_EQ(status_of(request(room, "token-alice")), 200);
}

TEST_F(LiveKitTokenTest, DeniedForNonMemberOfTheRoom) {
    auto res = request(room, "token-outsider");
    EXPECT_EQ(status_of(res), 403);
    EXPECT_EQ(res.body.find("token"), std::string::npos);
}

TEST_F(LiveKitTokenTest, RequiresAuthentication) {
    EXPECT_EQ(status_of(request(room, "")), 401);
    EXPECT_EQ(status_of(request(room, "not-a-real-token")), 401);
}

TEST_F(LiveKitTokenTest, NotFoundWhenLiveKitIsUnconfigured) {
    config.voice.livekit = LiveKitConfig{};
    auto res = request(room, "token-alice");
    EXPECT_EQ(status_of(res), 404);
    EXPECT_EQ(res.body.find("token"), std::string::npos);
}

// A half-filled config must behave exactly like no config: never mint a token
// with a missing secret, and never report itself as available.
TEST_F(LiveKitTokenTest, NotFoundWhenLiveKitIsPartiallyConfigured) {
    config.voice.livekit.api_secret.clear();
    EXPECT_EQ(status_of(request(room, "token-alice")), 404);

    config.voice.livekit.api_secret = kLkSecret;
    config.voice.livekit.api_key.clear();
    EXPECT_EQ(status_of(request(room, "token-alice")), 404);

    config.voice.livekit.api_key = "APItestkey";
    config.voice.livekit.url.clear();
    EXPECT_EQ(status_of(request(room, "token-alice")), 404);
}

TEST_F(LiveKitTokenTest, NotFoundWhenVoiceIsGloballyDisabled) {
    config.voice.enabled = false;
    EXPECT_EQ(status_of(request(room, "token-alice")), 404);
}

TEST_F(LiveKitTokenTest, DeniedWhenChannelIsNotVoiceCapable) {
    auto text_room = generate_room_id("test");
    store->create_room(text_room, alice);
    store->set_membership(text_room, alice, std::string(membership::kJoin));

    auto res = request(text_room, "token-alice");
    EXPECT_EQ(status_of(res), 403);
    EXPECT_EQ(res.body.find("token"), std::string::npos);
}

TEST_F(LiveKitTokenTest, DeniedWhenVoiceIsDisabledInTheChannel) {
    auto off = add_voice_channel(alice, /*enabled=*/false);
    EXPECT_EQ(status_of(request(off, "token-alice")), 403);
}

// roomAdmin is what lets a client drive LiveKit-side moderation (server mute,
// removing a participant), so it must track a real permission rather than
// being handed to everyone.
TEST_F(LiveKitTokenTest, RoomAdminGrantFollowsManageChannels) {
    auto plain = lk_payload(json::parse(request(room, "token-alice").body)["token"]);
    EXPECT_FALSE(plain["video"].value("roomAdmin", true));

    auto moderator = lk_payload(json::parse(request(room, "token-mod").body)["token"]);
    EXPECT_TRUE(moderator["video"].value("roomAdmin", false));
}

// LiveKit treats one identity as one participant and disconnects the older
// connection, so a second device must not evict the first.
TEST_F(LiveKitTokenTest, IdentityIsScopedToTheDeviceWhenSupplied) {
    auto res = request(room, "token-alice", json{{"device_id", "DEV1"}}.dump());
    ASSERT_EQ(status_of(res), 200);
    auto body = json::parse(res.body);
    EXPECT_EQ(body.value("identity", ""), "@alice:test|DEV1");
    EXPECT_EQ(lk_payload(body["token"]).value("sub", ""), "@alice:test|DEV1");

    auto other = json::parse(request(room, "token-alice", json{{"device_id", "DEV2"}}.dump()).body);
    EXPECT_NE(body.value("identity", ""), other.value("identity", ""));
}

// '|' is the user/device delimiter, so it must not survive from a
// client-supplied device_id — otherwise a device_id could forge an identity
// that parses as a different user.
TEST_F(LiveKitTokenTest, DeviceIdCannotForgeAnotherIdentity) {
    auto body = json::parse(
        request(room, "token-alice", json{{"device_id", "x|@mod:test"}}.dump()).body);
    EXPECT_EQ(body.value("identity", ""), "@alice:test|x_@mod:test");
    // The user part is still unambiguously alice.
    const std::string identity = body.value("identity", "");
    EXPECT_EQ(identity.substr(0, identity.find('|')), "@alice:test");
}

TEST_F(LiveKitTokenTest, MalformedBodyIsToleratedAsNoDeviceId) {
    auto res = request(room, "token-alice", "{not json");
    ASSERT_EQ(status_of(res), 200);
    EXPECT_EQ(json::parse(res.body).value("identity", ""), "@alice:test");
}

// Distinct channels must never share one SFU room, and the mapping must be
// stable across calls or participants would land in different rooms.
// Also the guard on rotation-derived room names: without a rotation in
// between, two members and two requests must agree on one room, or a token
// refresh would scatter a live call across LiveKit rooms.
TEST_F(LiveKitTokenTest, SfuRoomNameIsStableAndPerChannel) {
    auto second = add_voice_channel(alice);

    auto a1 = json::parse(request(room, "token-alice").body).value("room", "");
    auto a2 = json::parse(request(room, "token-mod").body).value("room", "");
    auto b1 = json::parse(request(second, "token-alice").body).value("room", "");

    EXPECT_EQ(a1, a2);
    EXPECT_NE(a1, b1);
    EXPECT_TRUE(a1.starts_with("bsfchat-"));
    // The raw Matrix room id must not appear verbatim — the name is a digest.
    EXPECT_EQ(a1.find(room), std::string::npos);
}

TEST_F(LiveKitTokenTest, SfuRoomNameIsScopedToTheServerName) {
    EXPECT_NE(VoiceHandler::livekit_room_name("a.example", "!r:a.example", 0),
              VoiceHandler::livekit_room_name("b.example", "!r:a.example", 0));
    // And the three fields cannot be confused for one another.
    EXPECT_NE(VoiceHandler::livekit_room_name("a", "b!c", 0),
              VoiceHandler::livekit_room_name("a!b", "c", 0));
    // Including the generation, which is rendered as digits and so would run
    // into a room id ending in digits under a plain join.
    EXPECT_NE(VoiceHandler::livekit_room_name("a", "b", 12),
              VoiceHandler::livekit_room_name("a", "b1", 2));
}

TEST_F(LiveKitTokenTest, ApiSecretNeverReachesTheClient) {
    auto res = request(room, "token-alice");
    ASSERT_EQ(status_of(res), 200);
    EXPECT_EQ(res.body.find(kLkSecret), std::string::npos);
    // Nor inside the token's own claims.
    EXPECT_EQ(lk_payload(json::parse(res.body)["token"]).dump().find(kLkSecret),
              std::string::npos);
}

// A client that joins over LiveKit renews its token instead of calling
// voice/join repeatedly; without a heartbeat here the reaper would mark it a
// ghost mid-call.
//
// This pair has to be read together. The assertion "nothing was reaped" is
// only meaningful next to a control showing the same stale heartbeat IS reaped
// when no token is requested — otherwise the test passes whether or not the
// handler records anything. (It did exactly that in its first form, and a
// mutation removing record_heartbeat went undetected.)
TEST_F(LiveKitTokenTest, TokenRequestCountsAsALivenessHeartbeat) {
    mark_in_voice(room, alice);
    handler->record_heartbeat(room, alice, stale_heartbeat_time());

    ASSERT_EQ(status_of(request(room, "token-alice")), 200);

    // The request must have refreshed the heartbeat to ~now.
    EXPECT_EQ(handler->reap_stale_members(), 0u);
    EXPECT_TRUE(is_active(room, alice));
}

TEST_F(LiveKitTokenTest, ControlStaleMemberIsReapedWithoutATokenRequest) {
    mark_in_voice(room, alice);
    handler->record_heartbeat(room, alice, stale_heartbeat_time());

    EXPECT_EQ(handler->reap_stale_members(), 1u);
    EXPECT_FALSE(is_active(room, alice));
}

TEST_F(LiveKitTokenTest, TokenTtlIsClampedAndReportedConsistently) {
    config.voice.livekit.token_ttl = 5; // below the floor
    auto res = request(room, "token-alice");
    ASSERT_EQ(status_of(res), 200);
    auto body = json::parse(res.body);
    EXPECT_EQ(body.value("ttl", int64_t{0}), kLiveKitMinTtl);

    auto p = lk_payload(body["token"]);
    // The advertised ttl must match the token's actual lifetime, or a client
    // renewing on schedule would still be refused at reconnect.
    EXPECT_EQ(p.value("exp", int64_t{0}) - p.value("nbf", int64_t{0}), kLiveKitMinTtl);
}

// --- Audit data-path finding 19: PUT /rooms/{id}/voice/state is a write path
// --- with no membership and no VIEW_CHANNEL check.
//
// The gate on voice/join was argued to cover this endpoint transitively: join
// is "the only endpoint that makes someone an active call member", so an
// active row implies the join gate was passed. That reasoning holds only at
// the instant of the join. Authorization here is evaluated once and then
// cached in a row, and both of its inputs can change afterwards — a user can
// be removed from the room, and VIEW_CHANNEL can be revoked.
//
// The reaper does not close the window either, and that is the part the audit
// under-stated: handle_voice_state calls record_heartbeat() on its way out, so
// each PUT refreshes the very liveness the reaper expires on. A revoked user
// who keeps announcing screen_sharing every few seconds holds an active roster
// entry, visible to everyone in the channel, indefinitely rather than for one
// reap interval.
TEST_F(LiveKitTokenTest, VoiceStateRefusedAfterViewChannelIsRevoked) {
    mark_in_voice(room, alice);
    deny(room, "user:" + alice, permission::kViewChannel);

    httplib::Request req;
    req.method = "PUT";
    req.path = "/_matrix/client/v3/rooms/" + room + "/voice/state";
    req.set_header("Authorization", "Bearer token-alice");
    req.body = json{{"screen_sharing", true}}.dump();
    httplib::Response res;
    handler->handle_voice_state(req, res);

    EXPECT_EQ(status_of(res), 403);
    // The flag must not have been written on the way to the refusal.
    auto ev = store->get_state_event(room, std::string(event_type::kCallMember), alice);
    ASSERT_TRUE(ev.has_value());
    EXPECT_FALSE(ev->content.data.value("screen_sharing", false));
}

// The refusal must be specific to VIEW_CHANNEL, not "any deny at all", or the
// test above would pass against a gate that refuses everybody.
TEST_F(LiveKitTokenTest, VoiceStateStillAcceptedWhenAnUnrelatedPermissionIsRevoked) {
    mark_in_voice(room, alice);
    deny(room, "user:" + alice, permission::kSendMessages | permission::kAttachFiles);

    httplib::Request req;
    req.method = "PUT";
    req.path = "/_matrix/client/v3/rooms/" + room + "/voice/state";
    req.set_header("Authorization", "Bearer token-alice");
    req.body = json{{"screen_sharing", true}}.dump();
    httplib::Response res;
    handler->handle_voice_state(req, res);

    EXPECT_EQ(status_of(res), 200) << res.body;
    auto ev = store->get_state_event(room, std::string(event_type::kCallMember), alice);
    ASSERT_TRUE(ev.has_value());
    EXPECT_TRUE(ev->content.data.value("screen_sharing", false));
}

// A user who left the room entirely. `outsider` has a 'leave' row, so this is
// the plain membership half of the same gap.
TEST_F(LiveKitTokenTest, VoiceStateRefusedForANonMemberOfTheRoom) {
    mark_in_voice(room, outsider);

    httplib::Request req;
    req.method = "PUT";
    req.path = "/_matrix/client/v3/rooms/" + room + "/voice/state";
    req.set_header("Authorization", "Bearer token-outsider");
    req.body = json{{"camera_on", true}}.dump();
    httplib::Response res;
    handler->handle_voice_state(req, res);

    EXPECT_EQ(status_of(res), 403);
    auto ev = store->get_state_event(room, std::string(event_type::kCallMember), outsider);
    ASSERT_TRUE(ev.has_value());
    EXPECT_FALSE(ev->content.data.value("camera_on", false));
}

// The heartbeat is the reason the window is unbounded rather than one reap
// interval, so the refusal has to stop short of record_heartbeat() too. If it
// did not, a revoked user could still keep their ghost alive by PUTting into
// a 403.
TEST_F(LiveKitTokenTest, RefusedVoiceStateDoesNotRefreshTheHeartbeat) {
    mark_in_voice(room, alice);
    handler->record_heartbeat(room, alice, stale_heartbeat_time());
    deny(room, "user:" + alice, permission::kViewChannel);

    httplib::Request req;
    req.method = "PUT";
    req.path = "/_matrix/client/v3/rooms/" + room + "/voice/state";
    req.set_header("Authorization", "Bearer token-alice");
    req.body = json{{"muted", true}}.dump();
    httplib::Response res;
    handler->handle_voice_state(req, res);
    ASSERT_EQ(status_of(res), 403);

    EXPECT_EQ(handler->reap_stale_members(), 1u);
    EXPECT_FALSE(is_active(room, alice));
}

// --- Audit data-path finding 23: the startup sweep that never ran ---
//
// CallSignalling.h says the two-minute retention "deliberately does NOT
// survive a restart in any useful sense — the sweep runs at startup as well".
// It did not. The prune rides the voice reaper thread, and that loop waits out
// a full kReapInterval before its first pass, so every restart left whatever
// was in the table at shutdown readable for another ten seconds.
//
// Small in wall-clock terms, and the reason to fix it is not the ten seconds:
// it is that a header comment describing a retention guarantee was false, and
// the cheapest way to make it true is to run the pass the comment promises.
TEST_F(VoiceHandlerTest, ReaperPrunesExpiredSignallingImmediatelyAtStartup) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto expired = generate_event_id("test");
    store->insert_event(expired, room_id, "@alice:test",
                        std::string(event_type::kCallCandidates), std::nullopt,
                        json{{"to", "@bob:test"},
                             {"candidate", "10.0.0.7 51000 typ host"}}.dump(),
                        now - limits::kCallSignallingTtlMs - 1000);
    ASSERT_TRUE(store->get_event_by_id(expired).has_value());

    handler->start_reaper();
    // Well inside kReapInterval (10 s): if the sweep only happens on the
    // timer, nothing has been removed by the time this gives up.
    bool gone = false;
    for (int i = 0; i < 40 && !gone; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        gone = !store->get_event_by_id(expired).has_value();
    }
    handler->stop_reaper();

    EXPECT_TRUE(gone) << "expired signalling survived server startup for a full reap interval";
}

// The startup pass must not be a licence to delete anything else: fresh
// signalling is still inside its TTL and has to survive the restart, which is
// the case the retention window exists for.
TEST_F(VoiceHandlerTest, StartupSweepLeavesFreshSignallingAlone) {
    auto room_id = generate_room_id("test");
    create_voice_room(room_id, "@alice:test");

    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto fresh = generate_event_id("test");
    store->insert_event(fresh, room_id, "@alice:test",
                        std::string(event_type::kCallCandidates), std::nullopt,
                        json{{"to", "@bob:test"},
                             {"candidate", "10.0.0.8 51001 typ host"}}.dump(), now);

    handler->start_reaper();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    handler->stop_reaper();

    EXPECT_TRUE(store->get_event_by_id(fresh).has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// Permissions audit, September 2026 — the voice findings (F9, F11).
//
// docs/audit-permissions-2026-09.md raised three things about this file and
// left all three "reasoned" rather than proven, so these are the proofs. F10
// (roomAdmin without a rank check) is answered in a comment at the grant site
// in VoiceHandler.cpp and by the existing RoomAdminGrantFollowsManageChannels
// above; it needed no behaviour change and therefore no new test.
// ═══════════════════════════════════════════════════════════════════════════

// ── F11: pre-permission refusals leaked channel voice configuration ────────
//
// handle_voice_join, handle_livekit_token and handle_livekit_rekey each used to
// answer "is this room voice-capable?" and "is its voice switched on?" BEFORE
// asking whether the caller may see the room at all. Those two refusals are
// distinguishable from each other and from the visibility one, so a caller
// holding nothing but a room id could read a private channel's voice
// configuration straight out of the error bodies.
//
// Small — it is two bits about a channel, not its contents — and still a read
// of exactly the state a DENY VIEW_CHANNEL override exists to withhold. The
// server already holds itself to the opposite standard where two refusals could
// be told apart: see PermissionsHandler's kRefusal, one body for "no such
// account", "not visible to you" and "not a member of anything you share".
//
// The fix is ordering and nothing else, so the tests are written as an
// INDISTINGUISHABILITY property rather than as "assert the new message": the
// three refusals must be byte-identical for a caller who cannot see the
// channel. An implementation that merely reworded one message cannot satisfy
// that by accident, and a future reordering that reintroduces the leak fails
// here rather than somewhere subtle.

TEST_F(LiveKitTokenTest, JoinRefusalSaysNothingAboutAnUnseenChannelsVoiceConfig) {
    auto text = add_text_channel(alice);            // not voice-capable at all
    auto disabled = add_voice_channel(alice, false); // voice-capable, switched off
    for (const auto& r : {room, text, disabled}) {
        deny(r, "user:" + alice, permission::kViewChannel);
    }

    auto seen = join(room, "token-alice");
    ASSERT_EQ(status_of(seen), 403) << seen.body;

    // Precondition: alice IS a member of all three, so the membership check
    // above is not what any of these refusals are.
    for (const auto& r : {room, text, disabled}) {
        ASSERT_TRUE(store->is_room_member(r, alice));
    }

    EXPECT_EQ(status_of(join(text, "token-alice")), 403);
    EXPECT_EQ(join(text, "token-alice").body, seen.body)
        << "a caller who cannot see the channel learned it is not a voice channel";
    EXPECT_EQ(status_of(join(disabled, "token-alice")), 403);
    EXPECT_EQ(join(disabled, "token-alice").body, seen.body)
        << "a caller who cannot see the channel learned its voice is switched off";
}

// The same property on the SFU token endpoint. Worth its own test rather than a
// loop: the "LiveKit is not configured" 404 sits above all of this and is
// deliberately NOT part of the property — it is a fact about the deployment,
// identical for every room and every caller.
TEST_F(LiveKitTokenTest, LiveKitTokenRefusalSaysNothingAboutAnUnseenChannelsVoiceConfig) {
    auto text = add_text_channel(alice);
    auto disabled = add_voice_channel(alice, false);
    for (const auto& r : {room, text, disabled}) {
        deny(r, "user:" + alice, permission::kViewChannel);
    }

    auto seen = request(room, "token-alice");
    ASSERT_EQ(status_of(seen), 403) << seen.body;
    EXPECT_EQ(request(text, "token-alice").body, seen.body);
    EXPECT_EQ(request(disabled, "token-alice").body, seen.body);
}

TEST_F(LiveKitTokenTest, RekeyRefusalSaysNothingAboutAnUnseenChannelsVoiceConfig) {
    config.voice.livekit.room_encryption = true;
    auto text = add_text_channel(alice);
    auto disabled = add_voice_channel(alice, false);

    // alice holds no kManageChannels anywhere, so she is refused by the rekey
    // gate whatever else is true — which is the point. Before the reordering
    // the two capability answers were handed to her in front of that refusal.
    auto seen = rekey(room, "token-alice");
    ASSERT_EQ(status_of(seen), 403) << seen.body;
    EXPECT_EQ(rekey(text, "token-alice").body, seen.body);
    EXPECT_EQ(rekey(disabled, "token-alice").body, seen.body);
}

// The reordering must not have cost the answers a legitimate caller needs. A
// member who CAN see the channel still gets the two capability refusals told
// apart, and deliberately so: they already receive bsfchat.room.voice for it
// through /sync, so there is nothing to withhold, and the client needs to tell
// "this is a text channel" from "the owner turned voice off".
TEST_F(LiveKitTokenTest, AMemberWhoCanSeeTheChannelStillLearnsWhyVoiceIsUnavailable) {
    auto text = add_text_channel(alice);
    auto disabled = add_voice_channel(alice, false);

    auto not_capable = join(text, "token-alice");
    auto switched_off = join(disabled, "token-alice");
    ASSERT_EQ(status_of(not_capable), 403);
    ASSERT_EQ(status_of(switched_off), 403);
    EXPECT_NE(not_capable.body, switched_off.body);
    EXPECT_NE(not_capable.body.find("not voice-capable"), std::string::npos) << not_capable.body;
    EXPECT_NE(switched_off.body.find("disabled"), std::string::npos) << switched_off.body;
}

// ── F9: voice/leave is gated on membership alone, and stays that way ───────
//
// This is the regression guard for a DECLINED finding, which is why it asserts
// that leaving still WORKS rather than that it is refused. The audit found no
// escalation through this endpoint and recommended adding the kViewChannel
// check anyway, for symmetry with its four siblings. Declined: leaving is the
// one voice act that takes access away, it only ever clears the caller's own
// row, and the gate would strand exactly the user a revocation has just
// created. The full argument is at handle_voice_leave.
//
// Without a test, the next reader sees four gated endpoints and one ungated one
// and "fixes" it. With one, they have to argue with a red build.

TEST_F(LiveKitTokenTest, AMemberLockedOutMidCallCanStillLeaveIt) {
    ASSERT_EQ(status_of(join(room, "token-alice")), 200);
    ASSERT_TRUE(is_active(room, alice));

    deny(room, "user:" + alice, permission::kViewChannel);

    // Precondition: the revocation really did land. If joining were still
    // permitted this test would prove nothing about the ungated leave.
    ASSERT_EQ(status_of(join(room, "token-alice")), 403);

    auto res = leave(room, "token-alice");
    EXPECT_EQ(status_of(res), 200) << res.body;
    EXPECT_TRUE(json::parse(res.body).value("changed", false));
    EXPECT_FALSE(is_active(room, alice))
        << "a user who has just been locked out of a channel is still listed in its call";
}

// And the other half of why the missing gate costs nothing: for a caller who
// cannot see the channel and was never in the call, the answer is a constant.
// It is the same "not_active" whether the channel is busy, empty, voice-capable
// or a text channel, and no row is written on the way out — so there is nothing
// here for an unprivileged caller to difference.
TEST_F(LiveKitTokenTest, LeavingAChannelYouCannotSeeIsAConstantAnswerAndNoSideEffect) {
    deny(room, "user:" + alice, permission::kViewChannel);

    // Somebody else is genuinely in the call, so a leak-by-timing or a
    // leak-by-roster would have something to reveal.
    mark_in_voice(room, mod);

    auto text = add_text_channel(alice);
    deny(text, "user:" + alice, permission::kViewChannel);

    auto busy = leave(room, "token-alice");
    auto plain = leave(text, "token-alice");
    EXPECT_EQ(status_of(busy), 200);
    EXPECT_EQ(busy.body, plain.body);
    EXPECT_FALSE(json::parse(busy.body).value("changed", true));
    EXPECT_EQ(json::parse(busy.body).value("reason", ""), "not_active");

    EXPECT_FALSE(is_active(room, alice));
    EXPECT_TRUE(is_active(room, mod)) << "leave touched a row that was not the caller's";
}
