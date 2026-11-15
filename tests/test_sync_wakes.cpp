// Long-poll wake-ups and scan paging (audit 2026-11-15, R-2 and R-3).
//
// R-3: a scan that fills its 1000-row page with rows the reader may not see
// used to park and re-scan the same page from the same since_pos for a whole
// timeout, once per thousand hidden rows, holding back everything behind them.
//
// R-2: every typing, presence, read-marker and account-data write by ANYONE
// woke EVERY parked /sync on the server, and each then ran a full pass. The
// scoped notifier wakes only the accounts a change concerns; these tests pin
// both halves — the concerned poll still wakes promptly, and an unconcerned
// one stays parked.

#include <gtest/gtest.h>

#include "api/AccountDataHandler.h"
#include "api/EventHandler.h"
#include "api/PresenceHandler.h"
#include "api/RoomHandler.h"
#include "api/TypingHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <regex>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-wakes-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
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
    std::unique_ptr<RoomHandler> rooms;
    int64_t ts = 1000;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        // In memory: the paging test writes a thousand rows, and on a file
        // each insert is its own committed transaction.
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        rooms = std::make_unique<RoomHandler>(*store, *sync, config);

        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    ~Fixture() {
        rooms.reset();
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev");
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomCreate, "", json{{"creator", creator}});
        state(room_id, creator, event_type::kRoomMember, creator, json{{"membership", "join"}});
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        state(room_id, creator, event_type::kRoomType, "", json{{"type", "text"}});
        state(room_id, creator, event_type::kRoomJoinRules, "",
              json{{"join_rule", join_rule::kPublic}});
        return room_id;
    }

    void state(const std::string& room_id, const std::string& sender,
               std::string_view type, const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ts++);
        sync->notify_new_event();
    }

    void join_member(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        state(room_id, user_id, event_type::kRoomMember, user_id, json{{"membership", "join"}});
    }

    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny = 0) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        state(room_id, "@server:test", event_type::kChannelPermissions, target, j);
    }

    httplib::Response call(void (RoomHandler::*method)(const httplib::Request&,
                                                       httplib::Response&),
                           const std::string& path, const std::string& token,
                           const std::string& body = "") {
        httplib::Request req;
        req.path = path;
        req.body = body;
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        ((*rooms).*method)(req, res);
        return res;
    }

    httplib::Response leave(const std::string& room_id, const std::string& token) {
        return call(&RoomHandler::handle_leave,
                    "/_matrix/client/v3/rooms/" + room_id + "/leave", token, "{}");
    }

    httplib::Response kick(const std::string& room_id, const std::string& token,
                           const std::string& target) {
        return call(&RoomHandler::handle_kick, "/_matrix/client/v3/rooms/" + room_id + "/kick",
                    token, json{{"user_id", target}}.dump());
    }

    httplib::Response delete_room(const std::string& room_id, const std::string& token) {
        return call(&RoomHandler::handle_delete_room, "/_matrix/client/v3/rooms/" + room_id,
                    token);
    }

    // A token at the current head, minted the way the client gets one.
    std::string token_now(const std::string& user_id) {
        return sync->handle_sync(user_id, "", 0).next_batch;
    }
};

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

} // namespace

namespace {

using clk = std::chrono::steady_clock;

int64_t ms_between(clk::time_point a, clk::time_point b) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
}

void say(Fixture& f, const std::string& room_id, const std::string& sender,
         const std::string& body) {
    f.store->insert_event(generate_event_id("test"), room_id, sender,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", body}}.dump(), f.ts++);
}

} // namespace

// ── R-3 ─────────────────────────────────────────────────────────────────────

TEST(SyncScanPaging, APageOfHiddenRowsReturnsTheAdvancedTokenAtOnce) {
    Fixture f("hidden-page");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto secret = f.add_channel(alice, "staff");
    f.join_member(secret, bob);
    f.set_override(secret, "user:" + bob, 0, permission::kViewChannel);
    auto since = f.token_now(bob);

    // One more than the scan limit, all in a channel bob cannot view.
    for (int i = 0; i < 1001; ++i) say(f, secret, alice, "hidden " + std::to_string(i));
    f.sync->notify_new_event();

    const auto start = clk::now();
    auto first = f.sync->handle_sync(bob, since, 5000);
    EXPECT_LT(ms_between(start, clk::now()), 2500)
        << "a page of hidden rows sat out the poll timeout";
    EXPECT_TRUE(first.rooms.join.empty());
    EXPECT_NE(first.next_batch, since) << "the token has to move past the hidden page";

    // The remainder fits on one page, so this one is complete and the token
    // reaches the head.
    auto second = f.sync->handle_sync(bob, first.next_batch, 0);
    EXPECT_TRUE(second.rooms.join.empty());
    auto third = f.sync->handle_sync(bob, second.next_batch, 0);
    EXPECT_EQ(third.next_batch, second.next_batch) << "paging converges on the head";
}

// ── R-2: scoped ephemeral wakes ─────────────────────────────────────────────

namespace {

// Parks `user_id`'s poll for up to `timeout_ms` on its own thread and reports
// how long it actually blocked.
struct ParkedPoll {
    std::thread thread;
    std::atomic<int64_t> blocked_ms{-1};

    ParkedPoll(Fixture& f, const std::string& user_id, const std::string& since,
               int timeout_ms) {
        thread = std::thread([&f, user_id, since, timeout_ms, this] {
            const auto start = clk::now();
            f.sync->handle_sync(user_id, since, timeout_ms);
            blocked_ms = ms_between(start, clk::now());
        });
    }
    int64_t join() {
        thread.join();
        return blocked_ms.load();
    }
};

void type_in(Fixture& f, TypingHandler& typing, const std::string& room_id,
             const std::string& user_id, const std::string& token) {
    static const std::regex re(R"(/_matrix/client/v3/rooms/([^/]+)/typing/(.+))");
    httplib::Request req;
    req.path = "/_matrix/client/v3/rooms/" + room_id + "/typing/" + user_id;
    req.body = json{{"typing", true}, {"timeout", 30000}}.dump();
    req.set_header("Authorization", "Bearer " + token);
    ASSERT_TRUE(std::regex_match(req.path, req.matches, re));
    httplib::Response res;
    typing.handle_typing(req, res);
    ASSERT_TRUE(res.status == -1 || res.status == 200) << res.status << " " << res.body;
    (void)f;
}

} // namespace

TEST(SyncScopedWakes, AScopedWakeReachesTheNamedAccount) {
    Fixture f("scoped-hit");
    auto bob = f.add_user("bob");
    auto since = f.token_now(bob);

    ParkedPoll poll(f, bob, since, 10000);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    f.sync->notify_ephemeral_for(bob);
    EXPECT_LT(poll.join(), 3000);
}

TEST(SyncScopedWakes, AScopedWakeLeavesEveryoneElseParked) {
    Fixture f("scoped-miss");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto since = f.token_now(bob);

    // The whole point of R-2: alice's read marker used to return bob's poll.
    ParkedPoll poll(f, bob, since, 1200);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    f.sync->notify_ephemeral_for(alice);
    EXPECT_GE(poll.join(), 1000) << "a change scoped to alice woke bob's poll";
}

TEST(SyncScopedWakes, AScopedWakeDuringTheScanIsNotLost) {
    // The entry snapshot is taken before the first scan, so a change that
    // lands while the scan is running must still return the poll — the same
    // race the broadcast counter's snapshot exists for.
    Fixture f("scoped-race");
    auto bob = f.add_user("bob");
    auto since = f.token_now(bob);

    std::atomic<int> scans{0};
    f.sync->set_post_scan_hook_for_test([&] {
        if (++scans == 1) f.sync->notify_ephemeral_for(bob);
    });
    const auto start = clk::now();
    f.sync->handle_sync(bob, since, 5000);
    const auto blocked = ms_between(start, clk::now());
    f.sync->set_post_scan_hook_for_test(nullptr);
    EXPECT_LT(blocked, 2500) << "a scoped change during the scan waited out the poll";
}

TEST(SyncScopedWakes, TypingWakesTheRoomsMembersAndNobodyElse) {
    Fixture f("typing");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    // carol is in no room alice types in.
    TypingHandler typing(*f.store, *f.sync, f.config);

    ParkedPoll bob_poll(f, bob, f.token_now(bob), 10000);
    ParkedPoll carol_poll(f, carol, f.token_now(carol), 1200);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    type_in(f, typing, room, alice, "token-alice");

    EXPECT_LT(bob_poll.join(), 3000) << "a member of the room was not woken by typing in it";
    EXPECT_GE(carol_poll.join(), 1000) << "typing woke an account that is not in the room";
}
