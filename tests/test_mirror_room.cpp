// The room server-scoped state is MIRRORED into, and the fact that it used to
// move on its own.
//
// Role definitions and per-member assignments live authoritatively in the
// server_state table; the mirror is delivery only, so that clients — which
// learn roles from /sync state events and from nowhere else — see a change.
// pick_server_state_mirror_room() chooses that room.
//
// THE BUG. It used to choose list_all_non_category_rooms().front() on every
// single write. That query has no ORDER BY, so "front" is whatever SQLite
// returned; delete a channel, or change the plan, and the mirror silently moves
// to a different room. New role events then land somewhere a given client may
// not be, while the events in the old room sit there unchanged and still look
// current. That client keeps a stale role document indefinitely: the desktop
// client's latest-wins guards compare origin_server_ts, which cannot help when
// the newer event is never delivered at all.
//
// The properties under test:
//   1. The choice is pinned after the first call and does not follow the room
//      list around.
//   2. Upgrading pins the room the server was ALREADY using, so installing this
//      build performs no migration of its own.
//   3. It moves only when the pinned room actually stops existing.
//   4. A server with no channels still has no mirror room, and says so with an
//      empty string rather than inventing one.

#include <gtest/gtest.h>

#include "auth/RoleBootstrap.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

constexpr const char* kMirrorRoomKey = "server_state.mirror_room";

struct Fixture {
    std::string db_path;
    std::unique_ptr<SqliteStore> store;

    explicit Fixture(const std::string& name) {
        db_path = (std::filesystem::temp_directory_path() /
                   ("bsfchat-mirror-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
        remove_db();
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
    }

    ~Fixture() {
        store.reset();
        remove_db();
    }

    void remove_db() {
        std::filesystem::remove(db_path);
        std::filesystem::remove(db_path + "-wal");
        std::filesystem::remove(db_path + "-shm");
    }

    std::string add_channel(const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, "@owner:test");
        store->insert_event(generate_event_id("test"), room_id, "@owner:test",
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, "@owner:test",
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "text"}}.dump(), 1001);
        return room_id;
    }

    // Converts a channel into a category, which drops it out of
    // list_all_non_category_rooms() WITHOUT deleting the room. That is the one
    // way a test can move the unpinned expression's answer deterministically —
    // the ordering of that query is exactly what is not under a test's control.
    void make_category(const std::string& room_id) {
        store->insert_event(generate_event_id("test"), room_id, "@owner:test",
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "category"}}.dump(), 2000);
    }
};

} // namespace

// Installing this build must not itself move the mirror. The first call pins
// whatever the old expression would have answered, so an existing deployment
// carries on writing into the room its clients are already reading.
TEST(ServerStateMirrorRoom, TheFirstCallPinsTheRoomTheServerWasAlreadyUsing) {
    Fixture f("upgrade");
    f.add_channel("general");
    f.add_channel("random");
    const std::string legacy_answer = f.store->list_all_non_category_rooms().front();

    EXPECT_EQ(pick_server_state_mirror_room(*f.store), legacy_answer);
    EXPECT_EQ(f.store->get_meta(kMirrorRoomKey).value_or(""), legacy_answer);
}

// The property itself: once pinned, the answer stops following the room list.
TEST(ServerStateMirrorRoom, ThePinnedRoomDoesNotFollowTheRoomList) {
    Fixture f("pinned");
    auto first = f.add_channel("general");
    f.add_channel("random");
    ASSERT_EQ(pick_server_state_mirror_room(*f.store), first)
        << "this test assumes the first channel is what the scan returns first";

    // The room still exists, but the unpinned expression would now answer a
    // different room. Before the pin, every subsequent role write would have
    // gone there instead, stranding every client that is not in it.
    f.make_category(first);
    ASSERT_NE(f.store->list_all_non_category_rooms().front(), first)
        << "the unpinned expression must actually have moved, or this proves nothing";

    EXPECT_EQ(pick_server_state_mirror_room(*f.store), first);
}

// It does move when it has to, and records the new choice rather than
// recomputing it forever after.
TEST(ServerStateMirrorRoom, TheMirrorMovesOnlyWhenThePinnedRoomIsDeleted) {
    Fixture f("deleted");
    auto first = f.add_channel("general");
    auto second = f.add_channel("random");
    ASSERT_EQ(pick_server_state_mirror_room(*f.store), first);

    f.store->delete_room(first);
    EXPECT_EQ(pick_server_state_mirror_room(*f.store), second);
    EXPECT_EQ(f.store->get_meta(kMirrorRoomKey).value_or(""), second);

    // And the new choice is itself pinned — a move must not leave the server
    // recomputing again.
    f.make_category(second);
    EXPECT_EQ(pick_server_state_mirror_room(*f.store), second);
}

// A fresh deployment has no channels and therefore no mirror. It must answer
// empty rather than invent one: bootstrap_roles runs before any room exists,
// and write_server_scoped_state treats an empty mirror as "authoritative write
// only", which is correct. Nothing is pinned in that state either, or the next
// call would find a pin naming a room that never existed.
TEST(ServerStateMirrorRoom, AServerWithNoChannelsHasNoMirrorRoom) {
    Fixture f("empty");
    EXPECT_EQ(pick_server_state_mirror_room(*f.store), "");
    EXPECT_FALSE(f.store->get_meta(kMirrorRoomKey).has_value());

    auto room = f.add_channel("general");
    EXPECT_EQ(pick_server_state_mirror_room(*f.store), room);
}
