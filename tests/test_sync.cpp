#include <gtest/gtest.h>
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "core/Config.h"
#include "auth/LocalAuth.h"

#include <bsfchat/Identifiers.h>

#include <nlohmann/json.hpp>
#include <chrono>
#include <thread>

using namespace bsfchat;
using json = nlohmann::json;

class SyncTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        sync = std::make_unique<SyncEngine>(*store, config);

        store->create_user("@alice:test", hash_password("pass", 10));

        // Create a room and join alice
        room_id = generate_room_id("test");
        store->create_room(room_id, "@alice:test");
        store->set_membership(room_id, "@alice:test", "join");

        // Insert a state event
        auto eid = generate_event_id("test");
        store->insert_event(eid, room_id, "@alice:test", "m.room.name",
                            std::string(""), json{{"name", "Test"}}.dump(), 1000);
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync;
    std::string room_id;
};

TEST_F(SyncTest, InitialSync) {
    auto resp = sync->handle_sync("@alice:test", "", 0);

    EXPECT_FALSE(resp.next_batch.empty());
    ASSERT_EQ(resp.rooms.join.count(room_id), 1u);

    auto& room = resp.rooms.join[room_id];
    EXPECT_FALSE(room.state.events.empty());
}

TEST_F(SyncTest, IncrementalSync) {
    // First do an initial sync to get a token
    auto initial = sync->handle_sync("@alice:test", "", 0);
    auto since = initial.next_batch;

    // Insert a new message
    auto eid = generate_event_id("test");
    store->insert_event(eid, room_id, "@alice:test", "m.room.message", std::nullopt,
                        json{{"msgtype", "m.text"}, {"body", "Hello"}}.dump(), 2000);
    sync->notify_new_event();

    // Incremental sync should only return the new message
    auto resp = sync->handle_sync("@alice:test", since, 0);

    ASSERT_EQ(resp.rooms.join.count(room_id), 1u);
    auto& timeline = resp.rooms.join[room_id].timeline.events;
    ASSERT_EQ(timeline.size(), 1u);
    EXPECT_EQ(timeline[0].content.data["body"], "Hello");
}

TEST_F(SyncTest, IncrementalSyncNoNewEvents) {
    auto initial = sync->handle_sync("@alice:test", "", 0);

    // Incremental sync with no new events and 0 timeout — should return immediately
    auto resp = sync->handle_sync("@alice:test", initial.next_batch, 0);
    EXPECT_TRUE(resp.rooms.join.empty());
    EXPECT_EQ(resp.next_batch, initial.next_batch);
}

// This test is named for the WAKE, but for a long time it could not see one.
// It asserted only that the event came back, and the idle-timeout path at the
// bottom of handle_sync does a final build_incremental_sync before it
// returns — so a build with notify_new_event()'s notify_all() removed
// entirely still passed it, in 5044 ms, having sat out the whole timeout
// holding an event that was committed the entire time. That is precisely the
// regression this is here for, and the content assertions are blind to it.
//
// The fix is not a tight budget. It is a timeout so long that the two
// outcomes cannot be confused: a signalled poll returns in ~100 ms, an
// unsignalled one returns at kTimeoutMs. Half of that is the dividing line,
// and there is nothing the code can do that lands in between — the condition
// variable is either notified or it is not. 15 s of slack for a ~100 ms
// operation is not a budget the machine can fail; a busy box makes the wake
// take 300 ms instead of 100 ms, not 15 000 ms.
//
// It also makes the healthy case FASTER: this used to always cost its full
// 5 s timeout when the wake was broken, and now a broken wake is what is slow.
TEST_F(SyncTest, LongPollWakeUp) {
    auto initial = sync->handle_sync("@alice:test", "", 0);
    auto since = initial.next_batch;

    constexpr int kTimeoutMs = 30000;

    // Start a sync in a thread with a long timeout
    SyncResponse resp;
    const auto started = std::chrono::steady_clock::now();
    std::thread sync_thread([&]() {
        resp = sync->handle_sync("@alice:test", since, kTimeoutMs);
    });

    // Wait a bit, then insert an event
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto eid = generate_event_id("test");
    store->insert_event(eid, room_id, "@alice:test", "m.room.message", std::nullopt,
                        json{{"msgtype", "m.text"}, {"body", "Wake up!"}}.dump(), 3000);
    sync->notify_new_event();

    sync_thread.join();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    // Should have woken up and returned the event
    ASSERT_EQ(resp.rooms.join.count(room_id), 1u);
    EXPECT_EQ(resp.rooms.join[room_id].timeline.events.size(), 1u);

    // ...and should have been WOKEN to do it, not answered by its own
    // deadline. Without this, removing the notify_all() outright is green.
    EXPECT_LT(elapsed_ms, kTimeoutMs / 2)
        << "the poll returned the event only when its " << kTimeoutMs
        << " ms timeout expired, not when the commit notified it: the "
           "condition-variable wake in notify_new_event() is not reaching "
           "the waiter in handle_sync()";
}

// Was "the token parses as s<N> and N > 0". It no longer does, and that is the
// point: next_batch is opaque, because the integer it used to be was the global
// stream head and therefore a volume-and-timing oracle over every room on the
// server (finding 10, docs/audit-data-2026-09.md). What survives from the old
// test is the behaviour it was really checking — the token is non-empty, it
// round-trips, and it names a real position. See test_sync_token.cpp for the
// opacity properties themselves.
TEST_F(SyncTest, StreamPositionToken) {
    auto resp1 = sync->handle_sync("@alice:test", "", 0);
    EXPECT_FALSE(resp1.next_batch.empty());
    EXPECT_FALSE(resp1.next_batch.starts_with("s"))
        << "next_batch is still the raw stream position: " << resp1.next_batch;

    // It round-trips: polling with it returns nothing new and hands back the
    // identical string, which is what "it names the position we are at" means
    // once the number is no longer readable.
    auto resp2 = sync->handle_sync("@alice:test", resp1.next_batch, 0);
    EXPECT_TRUE(resp2.rooms.join.empty());
    EXPECT_EQ(resp2.next_batch, resp1.next_batch);
}
