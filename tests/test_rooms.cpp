#include <gtest/gtest.h>
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "core/Config.h"
#include "auth/LocalAuth.h"

#include <bsfchat/Identifiers.h>
#include <bsfchat/Constants.h>

#include <nlohmann/json.hpp>

using namespace bsfchat;
using json = nlohmann::json;

class RoomTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        sync_engine = std::make_unique<SyncEngine>(*store, config);

        // Create a test user
        store->create_user("@alice:test", hash_password("pass", 10));
        store->create_user("@bob:test", hash_password("pass", 10));
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
};

TEST_F(RoomTest, CreateRoom) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test");

    EXPECT_TRUE(store->room_exists(room_id));
    EXPECT_FALSE(store->room_exists("!nonexistent:test"));
}

TEST_F(RoomTest, Membership) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test");

    store->set_membership(room_id, "@alice:test", "join");
    EXPECT_TRUE(store->is_room_member(room_id, "@alice:test"));
    EXPECT_FALSE(store->is_room_member(room_id, "@bob:test"));

    auto rooms = store->get_joined_rooms("@alice:test");
    EXPECT_EQ(rooms.size(), 1u);
    EXPECT_EQ(rooms[0], room_id);
}

TEST_F(RoomTest, LeaveRoom) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test");
    store->set_membership(room_id, "@alice:test", "join");

    EXPECT_TRUE(store->is_room_member(room_id, "@alice:test"));

    store->set_membership(room_id, "@alice:test", "leave");
    EXPECT_FALSE(store->is_room_member(room_id, "@alice:test"));

    auto rooms = store->get_joined_rooms("@alice:test");
    EXPECT_TRUE(rooms.empty());
}

TEST_F(RoomTest, MultipleMembers) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test");
    store->set_membership(room_id, "@alice:test", "join");
    store->set_membership(room_id, "@bob:test", "join");

    auto members = store->get_room_members(room_id);
    EXPECT_EQ(members.size(), 2u);
}

TEST_F(RoomTest, InsertAndGetEvents) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test");
    store->set_membership(room_id, "@alice:test", "join");

    // Insert some events
    auto eid1 = generate_event_id("test");
    store->insert_event(eid1, room_id, "@alice:test", "m.room.message", std::nullopt,
                        json{{"msgtype", "m.text"}, {"body", "Hello"}}.dump(), 1000);

    auto eid2 = generate_event_id("test");
    store->insert_event(eid2, room_id, "@alice:test", "m.room.message", std::nullopt,
                        json{{"msgtype", "m.text"}, {"body", "World"}}.dump(), 2000);

    auto events = store->get_room_events(room_id, 10, "b");
    EXPECT_EQ(events.size(), 2u);
    // "b" direction: newest first
    EXPECT_EQ(events[0].content.data["body"], "World");
    EXPECT_EQ(events[1].content.data["body"], "Hello");
}

TEST_F(RoomTest, StateEvents) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test");
    store->set_membership(room_id, "@alice:test", "join");

    // Insert state events
    auto eid1 = generate_event_id("test");
    store->insert_event(eid1, room_id, "@alice:test", "m.room.name",
                        std::string(""), json{{"name", "Test Room"}}.dump(), 1000);

    auto eid2 = generate_event_id("test");
    store->insert_event(eid2, room_id, "@alice:test", "m.room.topic",
                        std::string(""), json{{"topic", "A test room"}}.dump(), 2000);

    auto state = store->get_state_events(room_id);
    EXPECT_EQ(state.size(), 2u);

    auto name_event = store->get_state_event(room_id, "m.room.name", "");
    ASSERT_TRUE(name_event.has_value());
    EXPECT_EQ(name_event->content.data["name"], "Test Room");
}

TEST_F(RoomTest, StateEventOverwrite) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test");

    // Set name twice — latest should win
    auto eid1 = generate_event_id("test");
    store->insert_event(eid1, room_id, "@alice:test", "m.room.name",
                        std::string(""), json{{"name", "Old Name"}}.dump(), 1000);

    auto eid2 = generate_event_id("test");
    store->insert_event(eid2, room_id, "@alice:test", "m.room.name",
                        std::string(""), json{{"name", "New Name"}}.dump(), 2000);

    auto name_event = store->get_state_event(room_id, "m.room.name", "");
    ASSERT_TRUE(name_event.has_value());
    EXPECT_EQ(name_event->content.data["name"], "New Name");
}

// ── Audit data-path finding 26: m.direct's peer side is deliberately unfiltered ─
//
// The audit recommends `AND peer.membership = 'join'` here and calls the change
// cosmetic. It is not cosmetic, and it is the wrong direction. get_direct_rooms
// is the ONLY thing that tells /sync a room is a DM: attach_direct_rooms turns
// each (room, peer) pair into `m.direct[peer] = [room]`, so a pair that is
// filtered out does not become a DM with a missing name — the room stops being
// a DM at all and the client files the conversation under channels.
//
// Dropping the peer therefore makes a DM whose other side left or was banned
// vanish from the DM list, taking its history with it as far as the sidebar is
// concerned. A conversation you had with someone who has since left is still
// your conversation, which is what SqliteStore.h has said about this function
// since it was written. Declined; these tests pin the behaviour so a later
// reader does not "fix" it from the audit line alone.
TEST_F(RoomTest, DirectRoomSurvivesThePeerLeaving) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test", /*is_direct=*/true);
    store->set_membership(room_id, "@alice:test", "join");
    store->set_membership(room_id, "@bob:test", "join");

    ASSERT_EQ(store->get_direct_rooms("@alice:test").size(), 1u);

    store->set_membership(room_id, "@bob:test", "leave");
    auto direct = store->get_direct_rooms("@alice:test");
    ASSERT_EQ(direct.size(), 1u)
        << "filtering the peer would delete the conversation from m.direct entirely";
    EXPECT_EQ(direct[0].first, room_id);
    EXPECT_EQ(direct[0].second, "@bob:test");
}

// The caller's OWN side is filtered, and must stay filtered: a DM the caller
// left is not theirs to be shown.
TEST_F(RoomTest, DirectRoomsDropTheCallersOwnLeftRooms) {
    auto room_id = generate_room_id("test");
    store->create_room(room_id, "@alice:test", /*is_direct=*/true);
    store->set_membership(room_id, "@alice:test", "join");
    store->set_membership(room_id, "@bob:test", "join");

    store->set_membership(room_id, "@alice:test", "leave");
    EXPECT_TRUE(store->get_direct_rooms("@alice:test").empty());
}
