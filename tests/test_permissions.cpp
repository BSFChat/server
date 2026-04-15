#include <gtest/gtest.h>
#include "auth/PowerLevels.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "core/Config.h"
#include "auth/LocalAuth.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>

using namespace bsfchat;
using json = nlohmann::json;

// ============================================================
// PowerLevelChecker unit tests
// ============================================================

class PowerLevelCheckerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default power levels: creator @alice at 100, everyone else at 0
        levels.users_default = 0;
        levels.events_default = 0;
        levels.state_default = 50;
        levels.ban = 50;
        levels.kick = 50;
        levels.invite = 0;
        levels.redact = 50;
        levels.users["@alice:test"] = 100;
        levels.users["@mod:test"] = 50;
    }

    PowerLevelsContent levels;
};

TEST_F(PowerLevelCheckerTest, UserPowerLevels) {
    PowerLevelChecker checker(levels);

    EXPECT_EQ(checker.getUserPowerLevel("@alice:test"), 100);
    EXPECT_EQ(checker.getUserPowerLevel("@mod:test"), 50);
    EXPECT_EQ(checker.getUserPowerLevel("@bob:test"), 0);
    EXPECT_EQ(checker.getUserPowerLevel("@unknown:test"), 0);
}

TEST_F(PowerLevelCheckerTest, CanSendRegularEvents) {
    PowerLevelChecker checker(levels);

    // events_default = 0, so everyone can send regular events
    EXPECT_TRUE(checker.canSendEvent("@alice:test", "m.room.message"));
    EXPECT_TRUE(checker.canSendEvent("@mod:test", "m.room.message"));
    EXPECT_TRUE(checker.canSendEvent("@bob:test", "m.room.message"));
}

TEST_F(PowerLevelCheckerTest, CanSendStateEvents) {
    PowerLevelChecker checker(levels);

    // state_default = 50, so only mod and admin can send state events
    EXPECT_TRUE(checker.canSendEvent("@alice:test", "m.room.name", true));
    EXPECT_TRUE(checker.canSendEvent("@mod:test", "m.room.name", true));
    EXPECT_FALSE(checker.canSendEvent("@bob:test", "m.room.name", true));
}

TEST_F(PowerLevelCheckerTest, PerEventTypeOverride) {
    // Set a custom requirement for a specific event type
    levels.events["m.room.topic"] = 75;
    PowerLevelChecker checker(levels);

    EXPECT_TRUE(checker.canSendEvent("@alice:test", "m.room.topic", true));
    EXPECT_FALSE(checker.canSendEvent("@mod:test", "m.room.topic", true));
    EXPECT_FALSE(checker.canSendEvent("@bob:test", "m.room.topic", true));

    // Non-overridden event types still use defaults
    EXPECT_TRUE(checker.canSendEvent("@mod:test", "m.room.name", true));
}

TEST_F(PowerLevelCheckerTest, CanKick) {
    PowerLevelChecker checker(levels);

    EXPECT_TRUE(checker.canKick("@alice:test"));
    EXPECT_TRUE(checker.canKick("@mod:test"));
    EXPECT_FALSE(checker.canKick("@bob:test"));
}

TEST_F(PowerLevelCheckerTest, CanBan) {
    PowerLevelChecker checker(levels);

    EXPECT_TRUE(checker.canBan("@alice:test"));
    EXPECT_TRUE(checker.canBan("@mod:test"));
    EXPECT_FALSE(checker.canBan("@bob:test"));
}

TEST_F(PowerLevelCheckerTest, CanInvite) {
    PowerLevelChecker checker(levels);

    // invite = 0, so everyone can invite
    EXPECT_TRUE(checker.canInvite("@alice:test"));
    EXPECT_TRUE(checker.canInvite("@mod:test"));
    EXPECT_TRUE(checker.canInvite("@bob:test"));
}

TEST_F(PowerLevelCheckerTest, CanInviteRestricted) {
    levels.invite = 50;
    PowerLevelChecker checker(levels);

    EXPECT_TRUE(checker.canInvite("@alice:test"));
    EXPECT_TRUE(checker.canInvite("@mod:test"));
    EXPECT_FALSE(checker.canInvite("@bob:test"));
}

TEST_F(PowerLevelCheckerTest, CanRedact) {
    PowerLevelChecker checker(levels);

    EXPECT_TRUE(checker.canRedact("@alice:test"));
    EXPECT_TRUE(checker.canRedact("@mod:test"));
    EXPECT_FALSE(checker.canRedact("@bob:test"));
}

TEST_F(PowerLevelCheckerTest, DefaultPowerLevels) {
    // Test with entirely default PowerLevelsContent (no user overrides)
    PowerLevelsContent defaults;
    PowerLevelChecker checker(defaults);

    EXPECT_EQ(checker.getUserPowerLevel("@anyone:test"), 0);
    EXPECT_TRUE(checker.canSendEvent("@anyone:test", "m.room.message"));
    EXPECT_FALSE(checker.canSendEvent("@anyone:test", "m.room.name", true));
    EXPECT_FALSE(checker.canKick("@anyone:test"));
    EXPECT_FALSE(checker.canBan("@anyone:test"));
    EXPECT_TRUE(checker.canInvite("@anyone:test"));
    EXPECT_FALSE(checker.canRedact("@anyone:test"));
}

// ============================================================
// PowerLevelsContent JSON serialization
// ============================================================

TEST(PowerLevelsSerializationTest, RoundTrip) {
    PowerLevelsContent original;
    original.users_default = 0;
    original.events_default = 0;
    original.state_default = 50;
    original.ban = 50;
    original.kick = 50;
    original.invite = 0;
    original.redact = 50;
    original.users["@alice:test"] = 100;
    original.users["@mod:test"] = 50;
    original.events["m.room.topic"] = 75;

    json j;
    to_json(j, original);

    PowerLevelsContent restored;
    from_json(j, restored);

    EXPECT_EQ(restored.users_default, original.users_default);
    EXPECT_EQ(restored.events_default, original.events_default);
    EXPECT_EQ(restored.state_default, original.state_default);
    EXPECT_EQ(restored.ban, original.ban);
    EXPECT_EQ(restored.kick, original.kick);
    EXPECT_EQ(restored.invite, original.invite);
    EXPECT_EQ(restored.redact, original.redact);
    EXPECT_EQ(restored.users, original.users);
    EXPECT_EQ(restored.events, original.events);
}

TEST(PowerLevelsSerializationTest, FromJsonDefaults) {
    json j = json::object();  // empty object
    PowerLevelsContent pl;
    from_json(j, pl);

    EXPECT_EQ(pl.users_default, 0);
    EXPECT_EQ(pl.events_default, 0);
    EXPECT_EQ(pl.state_default, 50);
    EXPECT_EQ(pl.ban, 50);
    EXPECT_EQ(pl.kick, 50);
    EXPECT_EQ(pl.invite, 0);
    EXPECT_EQ(pl.redact, 50);
    EXPECT_TRUE(pl.users.empty());
    EXPECT_TRUE(pl.events.empty());
}

// ============================================================
// Integration: room creation sets power levels
// ============================================================

class PermissionIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        sync_engine = std::make_unique<SyncEngine>(*store, config);

        store->create_user("@alice:test", hash_password("pass", 10));
        store->create_user("@bob:test", hash_password("pass", 10));
    }

    // Helper to simulate room creation with power levels set
    std::string create_room_with_power_levels(const std::string& creator) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, "join");

        // Emit power levels like handle_create_room does
        PowerLevelsContent pl;
        pl.users[creator] = 100;
        json pl_json;
        to_json(pl_json, pl);

        auto eid = generate_event_id("test");
        store->insert_event(eid, room_id, creator, std::string(event_type::kRoomPowerLevels),
                            std::string(""), pl_json.dump(),
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count());

        return room_id;
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync_engine;
};

TEST_F(PermissionIntegrationTest, RoomCreatorHasPowerLevel100) {
    auto room_id = create_room_with_power_levels("@alice:test");

    auto pl_event = store->get_state_event(room_id, std::string(event_type::kRoomPowerLevels), "");
    ASSERT_TRUE(pl_event.has_value());

    PowerLevelsContent pl;
    from_json(pl_event->content.data, pl);

    PowerLevelChecker checker(pl);
    EXPECT_EQ(checker.getUserPowerLevel("@alice:test"), 100);
    EXPECT_EQ(checker.getUserPowerLevel("@bob:test"), 0);
}

TEST_F(PermissionIntegrationTest, CreatorCanDoEverything) {
    auto room_id = create_room_with_power_levels("@alice:test");

    auto pl_event = store->get_state_event(room_id, std::string(event_type::kRoomPowerLevels), "");
    ASSERT_TRUE(pl_event.has_value());

    PowerLevelsContent pl;
    from_json(pl_event->content.data, pl);
    PowerLevelChecker checker(pl);

    EXPECT_TRUE(checker.canSendEvent("@alice:test", "m.room.message"));
    EXPECT_TRUE(checker.canSendEvent("@alice:test", "m.room.name", true));
    EXPECT_TRUE(checker.canKick("@alice:test"));
    EXPECT_TRUE(checker.canBan("@alice:test"));
    EXPECT_TRUE(checker.canInvite("@alice:test"));
    EXPECT_TRUE(checker.canRedact("@alice:test"));
}

TEST_F(PermissionIntegrationTest, RegularUserCannotModerate) {
    auto room_id = create_room_with_power_levels("@alice:test");
    store->set_membership(room_id, "@bob:test", "join");

    auto pl_event = store->get_state_event(room_id, std::string(event_type::kRoomPowerLevels), "");
    ASSERT_TRUE(pl_event.has_value());

    PowerLevelsContent pl;
    from_json(pl_event->content.data, pl);
    PowerLevelChecker checker(pl);

    // Bob can send regular messages but not moderate
    EXPECT_TRUE(checker.canSendEvent("@bob:test", "m.room.message"));
    EXPECT_FALSE(checker.canSendEvent("@bob:test", "m.room.name", true));
    EXPECT_FALSE(checker.canKick("@bob:test"));
    EXPECT_FALSE(checker.canBan("@bob:test"));
    EXPECT_TRUE(checker.canInvite("@bob:test")); // invite default is 0
    EXPECT_FALSE(checker.canRedact("@bob:test"));
}

TEST_F(PermissionIntegrationTest, EventTypeSpecificPermission) {
    auto room_id = create_room_with_power_levels("@alice:test");
    store->set_membership(room_id, "@bob:test", "join");

    // Update power levels to require level 50 for m.room.message
    PowerLevelsContent pl;
    pl.users["@alice:test"] = 100;
    pl.events["m.room.message"] = 50;
    json pl_json;
    to_json(pl_json, pl);

    auto eid = generate_event_id("test");
    store->insert_event(eid, room_id, "@alice:test", std::string(event_type::kRoomPowerLevels),
                        std::string(""), pl_json.dump(),
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());

    auto pl_event = store->get_state_event(room_id, std::string(event_type::kRoomPowerLevels), "");
    ASSERT_TRUE(pl_event.has_value());

    PowerLevelsContent restored;
    from_json(pl_event->content.data, restored);
    PowerLevelChecker checker(restored);

    // Bob (level 0) cannot send m.room.message when it requires 50
    EXPECT_FALSE(checker.canSendEvent("@bob:test", "m.room.message"));
    // Alice (level 100) still can
    EXPECT_TRUE(checker.canSendEvent("@alice:test", "m.room.message"));
}
