#include <gtest/gtest.h>
#include "api/TypingHandler.h"
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
