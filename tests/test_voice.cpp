#include <gtest/gtest.h>
#include "api/VoiceHandler.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <chrono>
#include <filesystem>
#include <fstream>

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>

using namespace bsfchat;
using json = nlohmann::json;

// --- Protocol serialization tests ---

TEST(VoiceProtocol, VoiceMemberContentRoundTrip) {
    VoiceMemberContent member;
    member.active = true;
    member.muted = true;
    member.deafened = false;
    member.device_id = "ABCDEF";
    member.joined_at = 1700000000000;

    json j;
    to_json(j, member);

    EXPECT_TRUE(j["active"].get<bool>());
    EXPECT_TRUE(j["muted"].get<bool>());
    EXPECT_FALSE(j["deafened"].get<bool>());
    EXPECT_EQ(j["device_id"], "ABCDEF");
    EXPECT_EQ(j["joined_at"], 1700000000000);

    VoiceMemberContent parsed;
    from_json(j, parsed);

    EXPECT_EQ(parsed.active, member.active);
    EXPECT_EQ(parsed.muted, member.muted);
    EXPECT_EQ(parsed.deafened, member.deafened);
    EXPECT_EQ(parsed.device_id, member.device_id);
    EXPECT_EQ(parsed.joined_at, member.joined_at);
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
