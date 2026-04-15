#include <gtest/gtest.h>
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"

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
        sync_engine = std::make_unique<SyncEngine>(*store);

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
    cfg.voice.turn_uri = "turn:turn.example.com:3478";
    cfg.voice.turn_username = "user";
    cfg.voice.turn_password = "secret";

    // Build the response the same way VoiceHandler does
    json uris = json::array();
    if (!cfg.voice.stun_uri.empty()) uris.push_back(cfg.voice.stun_uri);
    if (!cfg.voice.turn_uri.empty()) uris.push_back(cfg.voice.turn_uri);

    json resp = {
        {"username", cfg.voice.turn_username},
        {"password", cfg.voice.turn_password},
        {"uris", uris},
        {"ttl", 86400},
    };

    EXPECT_EQ(resp["username"], "user");
    EXPECT_EQ(resp["password"], "secret");
    EXPECT_EQ(resp["uris"].size(), 2u);
    EXPECT_EQ(resp["uris"][0], "stun:stun.l.google.com:19302");
    EXPECT_EQ(resp["uris"][1], "turn:turn.example.com:3478");
    EXPECT_EQ(resp["ttl"], 86400);
}

TEST(VoiceProtocol, EventTypeConstants) {
    EXPECT_EQ(event_type::kCallInvite, "m.call.invite");
    EXPECT_EQ(event_type::kCallAnswer, "m.call.answer");
    EXPECT_EQ(event_type::kCallCandidates, "m.call.candidates");
    EXPECT_EQ(event_type::kCallHangup, "m.call.hangup");
    EXPECT_EQ(event_type::kCallMember, "m.call.member");
    EXPECT_EQ(event_type::kRoomVoice, "m.room.voice");
}
