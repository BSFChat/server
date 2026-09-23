// Cross-device read state, and the /sync account_data section that carries it.
//
// The complaint: "I read the channel on my phone and the dot is still lit on
// the desktop." The capability simply did not exist. /sync had no account_data
// section at all, so nothing a user stored about themselves — their read
// markers, their block list — ever reached their other devices. The unread
// COUNT cleared, because the server derives it from the read marker, but the
// client's dot is arithmetic on a timestamp it persisted locally and nothing
// ever corrected it.
//
// These tests pin the four things that have to hold for that to work:
//
//   1. A document written by one device reaches the account's other devices,
//      once, and is not restated on every poll afterwards.
//   2. A read marker set on device A clears the unread state on device B —
//      the count AND the m.fully_read marker its dot needs.
//   3. A device that has been offline cannot drag the marker backwards.
//   4. A parked long poll is woken for both, rather than riding out its
//      timeout. Latency budget and method follow test_sync_latency.cpp.
//
// And the invariant that cuts across all of them: membership is not
// visibility. Account data is per-user, but a read marker names a ROOM, and a
// room the reader may not see must not be named to them even by their own row.

#include <gtest/gtest.h>

#include "api/AccountDataHandler.h"
#include "api/EventHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;
using clk = std::chrono::steady_clock;

namespace {

// The same budget test_sync_latency.cpp uses, for the same reason: ~3x the
// measured wake on loopback, and two orders of magnitude below the 30s a poll
// that is never woken takes to come back.
constexpr int64_t kMaxWakeMs = 200;

int64_t ms_since(clk::time_point t0) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - t0).count();
}

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-readstate-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

template <typename Handler, typename Method>
httplib::Response call(Handler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
}

ServerRole role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

struct Fixture {
    std::string db_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    int64_t ts = 1000;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        seed_roles();
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 4));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    void state(const std::string& room_id, const std::string& sender, std::string_view type,
               const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ++ts);
    }

    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        state(room_id, user_id, event_type::kRoomMember, user_id,
              json{{"membership", membership::kJoin}});
    }

    std::string say(const std::string& room_id, const std::string& sender,
                    const std::string& body) {
        auto event_id = generate_event_id("test");
        store->insert_event(event_id, room_id, sender, std::string(event_type::kRoomMessage),
                            std::nullopt, json{{"msgtype", "m.text"}, {"body", body}}.dump(),
                            ++ts);
        return event_id;
    }

    void deny_view(const std::string& room_id, const std::string& user_id) {
        ChannelPermissionOverride ov;
        ov.allow = 0;
        ov.deny = permission::kViewChannel;
        json j;
        to_json(j, ov);
        state(room_id, "@server:test", event_type::kChannelPermissions, "user:" + user_id, j);
    }
};

std::string account_data_path(const std::string& user_id, const std::string& type) {
    return "/_matrix/client/v3/user/" + user_id + "/account_data/" + type;
}

std::string read_marker_path(const std::string& room_id) {
    return "/_matrix/client/v3/rooms/" + room_id + "/read_marker";
}

std::string ignore_document(const std::vector<std::string>& users) {
    json ignored = json::object();
    for (const auto& u : users) ignored[u] = json::object();
    return json{{account_data_type::kIgnoredUsersKey, ignored}}.dump();
}

// The one account-data document of `type` in a response, or nullopt.
std::optional<json> document(const SyncResponse& response, std::string_view type) {
    for (const auto& doc : response.account_data) {
        if (doc.type == type) return doc.content;
    }
    return std::nullopt;
}

// The m.fully_read marker a response carries for `room`, or nullopt.
std::optional<json> read_marker(const SyncResponse& response, const std::string& room) {
    auto it = response.rooms.join.find(room);
    if (it == response.rooms.join.end()) return std::nullopt;
    for (const auto& doc : it->second.account_data) {
        if (doc.type == event_type::kFullyRead) return doc.content;
    }
    return std::nullopt;
}

} // namespace

// ── 1. Account data reaches the account's other devices ──────────────────

// The gap PR #3 left behind, stated as a test: a block made on one device is
// delivered to the other through /sync rather than never.
TEST(AccountDataSync, ADocumentWrittenOnOneDeviceReachesASecondDevice) {
    Fixture f("second-device");
    auto alice = f.add_user("alice");
    f.add_user("spammer");

    // Device B is up to date and holds a token.
    const std::string since = f.sync->handle_sync(alice, "", 0).next_batch;

    AccountDataHandler account_data(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(account_data, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, std::string(account_data_type::kIgnoredUserList)),
                          "token-alice", ignore_document({"@spammer:test"}))));

    auto second = f.sync->handle_sync(alice, since, 0);
    auto doc = document(second, account_data_type::kIgnoredUserList);
    ASSERT_TRUE(doc.has_value())
        << "a block made on another device did not reach this one through /sync";
    EXPECT_EQ(doc->at(std::string(account_data_type::kIgnoredUsersKey))
                  .count("@spammer:test"),
              1u);

    // And it is a DELTA, not a restatement: the token that carried it puts it
    // below the next poll's range. A section that reappeared on every poll
    // would be bytes per client per 30 seconds forever, and a client could not
    // tell a change from an echo.
    auto third = f.sync->handle_sync(alice, second.next_batch, 0);
    EXPECT_FALSE(document(third, account_data_type::kIgnoredUserList).has_value());
    EXPECT_TRUE(third.account_data.empty());
}

// An initial sync has no token to take a delta against, so it carries
// everything — which is also the answer for a client that has been away long
// enough to have lost its token.
TEST(AccountDataSync, AnInitialSyncCarriesEveryStoredDocument) {
    Fixture f("initial");
    auto alice = f.add_user("alice");
    f.add_user("spammer");

    f.store->set_account_data(alice, std::string(account_data_type::kIgnoredUserList),
                              ignore_document({"@spammer:test"}),
                              std::vector<std::string>{"@spammer:test"}, 5);
    f.store->set_account_data(alice, "com.example.theme", json{{"mode", "dark"}}.dump(),
                              std::nullopt, 6);

    auto initial = f.sync->handle_sync(alice, "", 0);
    ASSERT_TRUE(document(initial, account_data_type::kIgnoredUserList).has_value());
    auto theme = document(initial, "com.example.theme");
    ASSERT_TRUE(theme.has_value())
        << "a type this server does not interpret must still round-trip; an account-data "
           "store that only carries types the server understands is not a store";
    EXPECT_EQ(theme->value("mode", ""), "dark");
}

// Nobody else's, ever. Account data has no sharing model at all.
TEST(AccountDataSync, OneAccountsDocumentsNeverAppearInAnothersSync) {
    Fixture f("isolation");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    f.store->set_account_data(alice, std::string(account_data_type::kIgnoredUserList),
                              ignore_document({"@bob:test"}),
                              std::vector<std::string>{"@bob:test"}, 5);

    auto bobs = f.sync->handle_sync(bob, "", 0);
    EXPECT_TRUE(bobs.account_data.empty())
        << "the one piece of state on this server whose value is that its subject cannot "
           "see it was delivered to its subject";
}

// ── 2. A read marker set on device A clears unread on device B ───────────

TEST(ReadMarkerSync, AMarkerSetOnOneDeviceClearsTheUnreadOnAnother) {
    Fixture f("cross-device");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(bob, "general");
    f.join(room, alice);

    f.say(room, bob, "one");
    f.say(room, bob, "two");
    const std::string newest = f.say(room, bob, "three");
    const int64_t newest_ts = f.ts;

    // Device B: three unread, and no marker to correct its dot with.
    auto before = f.sync->handle_sync(alice, "", 0);
    ASSERT_EQ(before.rooms.join.count(room), 1u);
    EXPECT_EQ(before.rooms.join[room].unread_count.value_or(0), 3);
    EXPECT_FALSE(read_marker(before, room).has_value());
    const std::string device_b_token = before.next_batch;

    // Device A (the phone) reads the room.
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_read_marker, read_marker_path(room),
                          "token-alice", "{}")));

    // Device B's next poll carries both halves: the count the badge uses, and
    // the marker the dot uses. The count alone was already working before this
    // change, which is exactly why the bug reads as "the number clears but the
    // dot does not".
    auto after = f.sync->handle_sync(alice, device_b_token, 0);
    ASSERT_EQ(after.rooms.join.count(room), 1u)
        << "the room is not in the response at all, so the marker reached nobody";
    EXPECT_EQ(after.rooms.join[room].unread_count.value_or(-1), 0);

    auto marker = read_marker(after, room);
    ASSERT_TRUE(marker.has_value()) << "no m.fully_read for a room that was just read";
    EXPECT_EQ(marker->value(std::string(fully_read::kEventId), ""), newest);
    // The timestamp is the whole point of the bsfchat.* key: the dot compares
    // origin_server_ts, and the event the marker names is one this device has
    // very often never loaded.
    EXPECT_EQ(marker->value(std::string(fully_read::kOriginServerTs), int64_t{0}), newest_ts);
}

// A room with no marker sends no marker. An upgraded server must look exactly
// like the old one for every room nobody has read, or a client seeding from
// `m.fully_read` would seed from a value that means nothing.
TEST(ReadMarkerSync, ARoomNobodyHasReadCarriesNoMarker) {
    Fixture f("unread-room");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(bob, "general");
    f.join(room, alice);
    f.say(room, bob, "hello");

    auto initial = f.sync->handle_sync(alice, "", 0);
    EXPECT_FALSE(read_marker(initial, room).has_value());
}

// ── 3. An offline device cannot rewind the marker ────────────────────────

// The phone read to the end, then the desktop — asleep since before those
// messages arrived — wakes up and posts the newest position IT knows about.
// That position is older. The marker must not move, nothing must be delivered,
// and no parked poll must be woken for a change that did not happen.
TEST(ReadMarkerSync, AStaleDeviceCannotRewindTheMarker) {
    Fixture f("no-rewind");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(bob, "general");
    f.join(room, alice);

    f.say(room, bob, "old");
    const int64_t stale_pos = f.store->get_room_max_stream_position(room);
    f.say(room, bob, "new");
    const std::string newest = f.say(room, bob, "newest");
    const int64_t newest_pos = f.store->get_room_max_stream_position(room);

    // The phone reads everything.
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_read_marker, read_marker_path(room),
                          "token-alice", "{}")));
    ASSERT_EQ(f.store->get_read_marker(alice, room), newest_pos);

    const std::string token = f.sync->handle_sync(alice, "", 0).next_batch;

    // The stale desktop posts the position it had when it went to sleep. It is
    // answered 200 — a read marker is idempotent and the client has no use for
    // the distinction — and it changes nothing.
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_read_marker, read_marker_path(room),
                          "token-alice", json{{"last_read_pos", stale_pos}}.dump())));
    EXPECT_EQ(f.store->get_read_marker(alice, room), newest_pos)
        << "a device that had been offline dragged the read marker backwards";

    // Nothing was delivered either: a write that changed nothing is not news,
    // and a marker going out at the stale value would rewind the OTHER
    // device's dot, which is the same bug one layer further out.
    auto after = f.sync->handle_sync(alice, token, 0);
    EXPECT_FALSE(read_marker(after, room).has_value());
    EXPECT_EQ(after.rooms.join.count(room), 0u);

    // And the marker a fresh device seeds from is still the newest event.
    auto fresh = f.sync->handle_sync(alice, "", 0);
    auto marker = read_marker(fresh, room);
    ASSERT_TRUE(marker.has_value());
    EXPECT_EQ(marker->value(std::string(fully_read::kEventId), ""), newest);
}

// The store's own rule, directly: set_read_marker answers whether it moved,
// and the handler's wake and the whole delta hang off that answer.
TEST(ReadMarkerSync, TheStoreReportsWhetherTheMarkerMoved) {
    Fixture f("moved");
    auto alice = f.add_user("alice");
    auto room = f.add_channel(alice, "general");

    EXPECT_TRUE(f.store->set_read_marker(alice, room, 10));
    EXPECT_FALSE(f.store->set_read_marker(alice, room, 10)) << "same position is not a change";
    EXPECT_FALSE(f.store->set_read_marker(alice, room, 4)) << "backwards is not a change";
    EXPECT_TRUE(f.store->set_read_marker(alice, room, 11));
    EXPECT_EQ(f.store->get_read_marker(alice, room), 11);
}

// ── 4. The wake actually fires ───────────────────────────────────────────

// A read marker writes no event row, so the wake cannot be notify_new_event's
// "has the head passed what I examined" — that was PR #4's finding, measured
// at 29856ms. This is the cross-device half of the same guard: the poll being
// woken belongs to ANOTHER DEVICE of the same account, and what it must come
// back holding is the marker.
TEST(ReadMarkerSync, AParkedPollIsWokenByAMarkerFromAnotherDevice) {
    Fixture f("wake-marker");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(bob, "general");
    f.join(room, alice);
    f.say(room, bob, "hello");

    const std::string since = f.sync->handle_sync(alice, "", 0).next_batch;

    std::atomic<int64_t> waited{-1};
    SyncResponse got;
    clk::time_point marked_at;

    std::thread desktop([&] {
        got = f.sync->handle_sync(alice, since, 30000);
        waited = ms_since(marked_at);
    });

    // Let the poll get all the way into the condition-variable wait, so this
    // passes by waking rather than by racing.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    marked_at = clk::now();
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    auto res = call(events, &EventHandler::handle_read_marker, read_marker_path(room),
                    "token-alice", "{}");
    ASSERT_TRUE(IsOk(res));

    desktop.join();

    EXPECT_LT(waited.load(), kMaxWakeMs)
        << "a parked /sync took " << waited.load()
        << "ms to see a read marker set on another device; it should be woken, not time out";
    auto marker = read_marker(got, room);
    ASSERT_TRUE(marker.has_value())
        << "the poll was woken but came back without the marker, which is the same 30 "
           "seconds of a lit dot one poll later";
    EXPECT_EQ(got.rooms.join[room].unread_count.value_or(-1), 0);
}

// Same for a block list: the PUT wakes the account's other polls. This is the
// call AccountDataHandler deliberately did not make when there was no section
// for it to feed.
TEST(AccountDataSync, AParkedPollIsWokenByAnAccountDataWrite) {
    Fixture f("wake-account-data");
    auto alice = f.add_user("alice");
    f.add_user("spammer");

    const std::string since = f.sync->handle_sync(alice, "", 0).next_batch;

    std::atomic<int64_t> waited{-1};
    SyncResponse got;
    clk::time_point written_at;

    std::thread desktop([&] {
        got = f.sync->handle_sync(alice, since, 30000);
        waited = ms_since(written_at);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    written_at = clk::now();
    AccountDataHandler account_data(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(account_data, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, std::string(account_data_type::kIgnoredUserList)),
                          "token-alice", ignore_document({"@spammer:test"}))));

    desktop.join();

    EXPECT_LT(waited.load(), kMaxWakeMs)
        << "a parked /sync took " << waited.load() << "ms to see an account-data write";
    EXPECT_TRUE(document(got, account_data_type::kIgnoredUserList).has_value())
        << "woken, but the response carried no account data — a response that has to be "
           "judged empty is discarded by the wait, and the change waits out the timeout";
}

// ── 5. Membership is not visibility ──────────────────────────────────────

// A read marker is the reader's own row, and it still must not name a room
// they may not see. Rooms are force-joined on this server, so "they were in it
// once" describes every channel including the private ones.
TEST(ReadMarkerSync, AMarkerForARoomTheReaderCannotViewIsNotDelivered) {
    Fixture f("no-leak");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto secret = f.add_channel(bob, "management");
    f.join(secret, alice);
    f.say(secret, bob, "hush");

    // Read while she could, then denied — a role edit, which happens.
    ASSERT_TRUE(f.store->set_read_marker(alice, secret,
                                         f.store->get_room_max_stream_position(secret)));
    f.deny_view(secret, alice);

    auto initial = f.sync->handle_sync(alice, "", 0);
    EXPECT_EQ(initial.rooms.join.count(secret), 0u)
        << "an initial sync named a channel the reader may not view, via their own read "
           "marker";

    // And through the delta path, which builds the room map from scratch: the
    // marker write is above the token, so this is the case where the room
    // would be ADDED to the response by the marker alone.
    ASSERT_TRUE(f.store->set_read_marker(alice, secret,
                                         f.store->get_room_max_stream_position(secret) + 1));
    auto incremental = f.sync->handle_sync(alice, "s1", 0);
    EXPECT_EQ(incremental.rooms.join.count(secret), 0u)
        << "an incremental sync named a channel the reader may not view, via their own read "
           "marker";
}

// The sidebar stub a category gets is a name and a sort order. A read position
// is contents, so it does not ride along with the exemption.
TEST(ReadMarkerSync, ACategoryStubCarriesNoMarker) {
    Fixture f("category");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto category = f.add_channel(bob, "Voice");
    f.state(category, bob, event_type::kRoomType, "", json{{"type", room_type::kCategory}});
    f.join(category, alice);
    f.say(category, bob, "in a category, which the event API permits");
    ASSERT_TRUE(f.store->set_read_marker(alice, category,
                                         f.store->get_room_max_stream_position(category)));
    f.deny_view(category, alice);

    auto initial = f.sync->handle_sync(alice, "", 0);
    ASSERT_EQ(initial.rooms.join.count(category), 1u) << "the stub itself should still be there";
    EXPECT_FALSE(read_marker(initial, category).has_value());
    EXPECT_FALSE(initial.rooms.join[category].unread_count.has_value());
}
