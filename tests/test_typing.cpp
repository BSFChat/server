#include <gtest/gtest.h>
#include "api/TypingHandler.h"

#include <regex>
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"

#include <bsfchat/Constants.h>
#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>
#include <thread>
#include <chrono>

using namespace bsfchat;
using json = nlohmann::json;

class TypingTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = Config::defaults();
        config.server_name = "test";

        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync_engine = std::make_unique<SyncEngine>(*store, config);
        handler = std::make_unique<TypingHandler>(*store, *sync_engine, config);

        // Create test users
        store->create_user("@alice:test", hash_password("pass123"));
        store->create_user("@bob:test", hash_password("pass123"));

        // Create a room and join both users
        room_id = store->create_room("!room1:test", "@alice:test");
        store->set_membership(room_id, "@alice:test", "join");
        store->set_membership(room_id, "@bob:test", "join");
    }

    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync_engine;
    std::unique_ptr<TypingHandler> handler;
    std::string room_id;
};

TEST_F(TypingTest, GetTypingUsersEmptyByDefault) {
    auto users = handler->get_typing_users(room_id);
    EXPECT_TRUE(users.empty());
}

TEST_F(TypingTest, GetTypingUsersNonexistentRoom) {
    auto users = handler->get_typing_users("!nonexistent:test");
    EXPECT_TRUE(users.empty());
}

// Test typing state via the public get_typing_users API
// Since handle_typing requires httplib::Request with matches, we test
// the typing handler state management through a simulated flow.
// For proper integration testing, we'd use a full HTTP test harness.

TEST_F(TypingTest, SyncResponseIncludesEphemeral) {
    // Verify that the protocol types support ephemeral events
    SyncResponse response;
    JoinedRoom joined;

    RoomEvent typing_event;
    typing_event.type = std::string(event_type::kTyping);
    typing_event.content.data = {{"user_ids", std::vector<std::string>{"@alice:test", "@bob:test"}}};

    joined.ephemeral = EphemeralEvents{};
    joined.ephemeral->events.push_back(std::move(typing_event));

    response.rooms.join[room_id] = std::move(joined);
    response.next_batch = "s1";

    // Serialize
    json j;
    to_json(j, response);

    // Verify ephemeral is present
    ASSERT_TRUE(j["rooms"]["join"].contains(room_id));
    auto& room_json = j["rooms"]["join"][room_id];
    ASSERT_TRUE(room_json.contains("ephemeral"));
    ASSERT_TRUE(room_json["ephemeral"].contains("events"));
    ASSERT_EQ(room_json["ephemeral"]["events"].size(), 1);
    EXPECT_EQ(room_json["ephemeral"]["events"][0]["type"], "m.typing");

    auto user_ids = room_json["ephemeral"]["events"][0]["content"]["user_ids"];
    ASSERT_EQ(user_ids.size(), 2);
    EXPECT_EQ(user_ids[0], "@alice:test");
    EXPECT_EQ(user_ids[1], "@bob:test");

    // Round-trip
    SyncResponse parsed;
    from_json(j, parsed);

    ASSERT_TRUE(parsed.rooms.join.count(room_id));
    auto& parsed_room = parsed.rooms.join[room_id];
    ASSERT_TRUE(parsed_room.ephemeral.has_value());
    ASSERT_EQ(parsed_room.ephemeral->events.size(), 1);
    EXPECT_EQ(parsed_room.ephemeral->events[0].type, "m.typing");

    auto parsed_ids = parsed_room.ephemeral->events[0].content.data["user_ids"];
    ASSERT_EQ(parsed_ids.size(), 2);
    EXPECT_EQ(parsed_ids[0], "@alice:test");
    EXPECT_EQ(parsed_ids[1], "@bob:test");
}

TEST_F(TypingTest, SyncResponseNoEphemeralWhenEmpty) {
    SyncResponse response;
    JoinedRoom joined;
    response.rooms.join[room_id] = std::move(joined);
    response.next_batch = "s1";

    json j;
    to_json(j, response);

    auto& room_json = j["rooms"]["join"][room_id];
    EXPECT_FALSE(room_json.contains("ephemeral"));
}

TEST_F(TypingTest, EphemeralEventsRoundTrip) {
    // Test EphemeralEvents struct directly
    EphemeralEvents ephemeral;
    RoomEvent ev;
    ev.type = "m.typing";
    ev.content.data = {{"user_ids", json::array({"@user1:test"})}};
    ephemeral.events.push_back(std::move(ev));

    ASSERT_EQ(ephemeral.events.size(), 1);
    EXPECT_EQ(ephemeral.events[0].type, "m.typing");
}

// PUT typing is rate limited per account (audit 2026-11-15 S-8): every write
// wakes the room's long-polls.
TEST_F(TypingTest, TypingIsRateLimitedPerAccount) {
    config.send_limits.typing_limit = 2;
    TypingHandler limited(*store, *sync_engine, config);
    store->store_access_token("alice-token", "@alice:test", "DEV1");
    store->store_access_token("bob-token", "@bob:test", "DEV2");

    const auto put = [&](const std::string& user, const std::string& token) {
        static const std::regex re(R"(/_matrix/client/v3/rooms/([^/]+)/typing/(.+))");
        httplib::Request req;
        req.path = "/_matrix/client/v3/rooms/" + room_id + "/typing/" + user;
        req.body = json{{"typing", true}, {"timeout", 30000}}.dump();
        req.set_header("Authorization", "Bearer " + token);
        EXPECT_TRUE(std::regex_match(req.path, req.matches, re));
        httplib::Response res;
        limited.handle_typing(req, res);
        return res.status == -1 ? 200 : res.status;
    };
    EXPECT_NE(put("@alice:test", "alice-token"), 429);
    EXPECT_NE(put("@alice:test", "alice-token"), 429);
    EXPECT_EQ(put("@alice:test", "alice-token"), 429);
    EXPECT_NE(put("@bob:test", "bob-token"), 429);
}

// Audit 2-2026-11-18 S2-3: `typing` of any type but boolean (and a non-number
// `timeout`) used to throw out of json::value() as a 500. Now a 400.
TEST_F(TypingTest, WrongTypedFieldsAreBadJsonNotAServerError) {
    store->store_access_token("alice-token", "@alice:test", "DEV1");
    const auto put = [&](const std::string& body) {
        static const std::regex re(R"(/_matrix/client/v3/rooms/([^/]+)/typing/(.+))");
        httplib::Request req;
        req.path = "/_matrix/client/v3/rooms/" + room_id + "/typing/@alice:test";
        req.body = body;
        req.set_header("Authorization", "Bearer alice-token");
        EXPECT_TRUE(std::regex_match(req.path, req.matches, re));
        httplib::Response res;
        EXPECT_NO_THROW(handler->handle_typing(req, res)) << body;
        return res.status == -1 ? 200 : res.status;
    };
    EXPECT_EQ(put(R"({"typing": "yes"})"), 400);
    EXPECT_EQ(put(R"({"typing": 1})"), 400);
    EXPECT_EQ(put(R"({"typing": true, "timeout": "30000"})"), 400);
    EXPECT_EQ(put(R"([true])"), 400);
    EXPECT_TRUE(handler->get_typing_users(room_id).empty());

    // Well-typed bodies still work, including an absurd timeout (clamped).
    EXPECT_EQ(put(R"({"typing": true, "timeout": 1e300})"), 200);
    EXPECT_EQ(handler->get_typing_users(room_id).size(), 1u);
    EXPECT_EQ(put(R"({"typing": false})"), 200);
    EXPECT_TRUE(handler->get_typing_users(room_id).empty());
}
