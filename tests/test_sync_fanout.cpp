// Sync fan-out (audit 2-2026-11-18, S2-4).
//
// One message to N parked polls used to cost O(N²): every woken poll re-ran a
// permission evaluation per room, restated every online peer's presence with a
// ban query each, and did all of its reads behind the store's single mutex.
// The fixes — pooled WAL readers, a cross-poll visibility cache, a presence
// delta, an initial-sync gate — are each a place where an event, a visibility
// change or a presence change could now be missed. These tests pin that none
// is: every parked poll still wakes for every message, a scan racing a writer
// never loses a row, a cached view follows an override, and a presence delta
// still carries every change.
//
// File databases throughout: the reader pool exists only for an on-disk WAL
// database, and an in-memory one would test the fallback instead.

#include <gtest/gtest.h>

#include "api/PresenceHandler.h"
#include "api/SyncHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/InitialSyncGate.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <regex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

using clk = std::chrono::steady_clock;

int64_t ms_since(clk::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - start).count();
}

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-fanout-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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
    int64_t ts = 1000;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);

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
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 4));
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

    // A message, committed and announced the way EventHandler does it.
    void say(const std::string& room_id, const std::string& sender, const std::string& body) {
        store->insert_event(generate_event_id("test"), room_id, sender,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", body}}.dump(), ts++);
        sync->notify_new_event();
    }

    std::string token_now(const std::string& user_id) {
        return sync->handle_sync(user_id, "", 0).next_batch;
    }
};

bool timeline_has(const SyncResponse& r, const std::string& room_id, const std::string& body) {
    auto it = r.rooms.join.find(room_id);
    if (it == r.rooms.join.end()) return false;
    for (const auto& ev : it->second.timeline.events) {
        if (ev.content.data.value("body", "") == body) return true;
    }
    return false;
}

} // namespace

// ── The reader pool ─────────────────────────────────────────────────────────

TEST(StoreReaderPool, AFileDatabaseGetsAPoolAndAnInMemoryOneDoesNot) {
    Fixture f("pool-open");
    EXPECT_GT(f.store->reader_connections_for_test(), 0u)
        << "a WAL file database should serve reads from the pool";

    SqliteStore memory(":memory:");
    memory.initialize();
    EXPECT_EQ(memory.reader_connections_for_test(), 0u)
        << "an in-memory database is private to its connection; a pool would read nothing";
    // ...and its reads still work, through the main connection.
    memory.create_user("@m:test", hash_password("password", 4));
    memory.store_access_token("token-m", "@m:test", "dev");
    EXPECT_EQ(memory.get_user_by_token("token-m"), std::optional<std::string>("@m:test"));
}

TEST(StoreReaderPool, AReadAfterAWriteReturnedSeesIt) {
    // Read-your-writes across connections: a write commits before it returns,
    // so a pooled read issued afterwards must see it — every time, not most.
    Fixture f("pool-ryw");
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    for (int i = 0; i < 200; ++i) {
        const std::string want(i % 2 ? membership::kLeave : membership::kJoin);
        f.store->set_membership(room, bob, want);
        ASSERT_EQ(f.store->get_membership(room, bob), want) << "iteration " << i;
    }

    // Revocation is the case that matters most: a logged-out token must stop
    // working the moment logout returns.
    EXPECT_EQ(f.store->get_user_by_token("token-bob"), std::optional<std::string>(bob));
    f.store->delete_access_token("token-bob");
    EXPECT_EQ(f.store->get_user_by_token("token-bob"), std::nullopt)
        << "a pooled read authenticated a token whose deletion had already returned";

    f.store->set_server_ban(bob, alice, "spam", 0);
    EXPECT_TRUE(f.store->is_server_banned(bob));
    auto banned = f.store->get_server_banned_user_ids();
    EXPECT_NE(std::find(banned.begin(), banned.end(), bob), banned.end());
    f.store->clear_server_ban(bob);
    EXPECT_FALSE(f.store->is_server_banned(bob));
}

TEST(StoreReaderPool, ScansRacingAWriterNeverLoseOrRepeatARow) {
    // The sync token argument, under real concurrency: get_events_since
    // samples the head under the store mutex and scans on a pooled reader.
    // A reader that follows the engine's rule — a full page advances to the
    // last row, a short one to the reported head — must see every message
    // exactly once, in order, while a writer commits underneath it.
    Fixture f("pool-race");
    auto alice = f.add_user("alice");
    auto room = f.add_channel(alice, "general");
    const int64_t start = f.store->get_current_stream_position();

    constexpr int kMessages = 400;
    constexpr int kReaders = 6;
    constexpr int kPage = 7;  // small, so both the full- and short-page paths run
    std::atomic<bool> writing{true};

    std::vector<std::vector<std::string>> seen(kReaders);
    std::vector<std::string> failures(kReaders);
    std::vector<std::thread> readers;
    for (int r = 0; r < kReaders; ++r) {
        readers.emplace_back([&, r] {
            int64_t since = start;
            const auto deadline = clk::now() + std::chrono::seconds(60);
            for (;;) {
                const bool was_writing = writing.load();
                int64_t max_pos = since;
                int64_t head = since;
                auto events = f.store->get_events_since(alice, since, max_pos, head, kPage);
                int64_t last = since;
                for (const auto& ev : events) {
                    seen[r].push_back(ev.content.data.value("body", ""));
                }
                if (max_pos > head) {
                    failures[r] = "scan returned a row above the head it reported";
                    return;
                }
                last = static_cast<int>(events.size()) >= kPage ? max_pos : head;
                if (last < since) {
                    failures[r] = "token moved backwards";
                    return;
                }
                since = last;
                if (!was_writing && static_cast<int>(events.size()) < kPage) return;
                if (clk::now() > deadline) {
                    failures[r] = "reader did not converge";
                    return;
                }
            }
        });
    }
    for (int i = 0; i < kMessages; ++i) f.say(room, alice, "m" + std::to_string(i));
    writing = false;
    for (auto& t : readers) t.join();

    for (int r = 0; r < kReaders; ++r) {
        ASSERT_TRUE(failures[r].empty()) << "reader " << r << ": " << failures[r];
        ASSERT_EQ(seen[r].size(), static_cast<size_t>(kMessages))
            << "reader " << r << " lost or repeated rows";
        for (int i = 0; i < kMessages; ++i) {
            ASSERT_EQ(seen[r][i], "m" + std::to_string(i)) << "reader " << r << " at " << i;
        }
    }
}

// ── Every parked poll wakes for every message ───────────────────────────────

TEST(SyncFanout, EveryParkedPollWakesPromptlyForEveryMessage) {
    Fixture f("fanout-wake");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(alice, "general");
    constexpr int kUsers = 24;
    constexpr int kRounds = 6;
    std::vector<std::string> users;
    for (int i = 0; i < kUsers; ++i) {
        users.push_back(f.add_user("u" + std::to_string(i)));
        f.join_member(room, users.back());
    }
    std::vector<std::string> tokens;
    for (const auto& u : users) tokens.push_back(f.token_now(u));

    for (int round = 0; round < kRounds; ++round) {
        const std::string body = "round " + std::to_string(round);
        std::vector<int64_t> took(kUsers, -1);
        std::vector<char> got(kUsers, 0);  // not vector<bool>: written from many threads
        std::vector<std::thread> polls;
        const auto start = clk::now();
        for (int i = 0; i < kUsers; ++i) {
            polls.emplace_back([&, i] {
                auto r = f.sync->handle_sync(users[i], tokens[i], 15000);
                took[i] = ms_since(start);
                got[i] = timeline_has(r, room, body);
                tokens[i] = r.next_batch;
            });
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        f.say(room, alice, body);
        for (auto& t : polls) t.join();
        for (int i = 0; i < kUsers; ++i) {
            EXPECT_TRUE(got[i]) << users[i] << " missed \"" << body << "\"";
            EXPECT_LT(took[i], 5000) << users[i] << " sat out its poll in round " << round;
        }
    }
}

TEST(SyncFanout, AWriteDuringTheWokenScanIsDeliveredOnTheNextPoll) {
    // The post-scan window, with the scan on a pooled reader: the event that
    // lands there is above the head the scan reported, so the token handed
    // back does not cover it and the next poll returns it at once.
    Fixture f("fanout-postscan");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    auto since = f.token_now(bob);

    f.say(room, alice, "first");
    std::atomic<bool> fired{false};
    f.sync->set_post_scan_hook_for_test([&] {
        if (!fired.exchange(true)) f.say(room, alice, "raced");
    });
    auto first = f.sync->handle_sync(bob, since, 0);
    f.sync->set_post_scan_hook_for_test(nullptr);
    ASSERT_TRUE(timeline_has(first, room, "first"));

    const auto start = clk::now();
    auto second = first;
    bool raced_seen = timeline_has(first, room, "raced");
    if (!raced_seen) {
        second = f.sync->handle_sync(bob, first.next_batch, 10000);
        raced_seen = timeline_has(second, room, "raced");
    }
    EXPECT_TRUE(raced_seen) << "an event committed during the scan was lost";
    EXPECT_LT(ms_since(start), 3000) << "the next poll parked on an event it had not seen";
}

TEST(SyncFanout, TheCrossPollViewCacheFollowsAnOverride) {
    // SyncEngine now remembers VIEW_CHANNEL answers between polls. A deny
    // must stop delivery on the very next poll, and lifting it must restore
    // it — a stale cache in either direction is a bug.
    Fixture f("fanout-viewcache");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    auto since = f.token_now(bob);

    f.say(room, alice, "visible");
    auto r1 = f.sync->handle_sync(bob, since, 0);
    ASSERT_TRUE(timeline_has(r1, room, "visible"));

    f.set_override(room, "user:" + bob, 0, permission::kViewChannel);
    f.say(room, alice, "hidden");
    auto r2 = f.sync->handle_sync(bob, r1.next_batch, 0);
    EXPECT_FALSE(timeline_has(r2, room, "hidden"))
        << "a cached view delivered a message from a channel bob was just denied";

    f.set_override(room, "user:" + bob, 0, 0);
    f.say(room, alice, "visible again");
    auto r3 = f.sync->handle_sync(bob, r2.next_batch, 0);
    EXPECT_TRUE(timeline_has(r3, room, "visible again"))
        << "a cached denial outlived the override that caused it";
}

// ── Presence: a delta on woken polls, never a missed change ────────────────

namespace {

struct PresenceRig {
    Fixture& f;
    PresenceHandler presence;
    SyncHandler handler;

    explicit PresenceRig(Fixture& fx)
        : f(fx), presence(*fx.store, *fx.sync, fx.config), handler(*fx.store, *fx.sync, fx.config) {
        handler.set_presence_handler(&presence);
    }

    // One /sync through the handler; `since` empty for an initial sync.
    json poll(const std::string& localpart, const std::string& since, int timeout_ms = 0) {
        httplib::Request req;
        req.path = "/_matrix/client/v3/sync";
        if (!since.empty()) req.params.emplace("since", since);
        req.params.emplace("timeout", std::to_string(timeout_ms));
        req.set_header("Authorization", "Bearer token-" + localpart);
        httplib::Response res;
        handler.handle_sync(req, res);
        EXPECT_TRUE(res.status == -1 || res.status == 200) << res.status << " " << res.body;
        return json::parse(res.body);
    }

    void put(const std::string& localpart, const std::string& state) {
        static const std::regex re(R"(/_matrix/client/v3/presence/([^/]+)/status)");
        const std::string uid = "@" + localpart + ":test";
        httplib::Request req;
        req.path = "/_matrix/client/v3/presence/" + uid + "/status";
        req.body = json{{"presence", state}}.dump();
        req.set_header("Authorization", "Bearer token-" + localpart);
        ASSERT_TRUE(std::regex_match(req.path, req.matches, re));
        httplib::Response res;
        presence.handle_put_presence(req, res);
        ASSERT_TRUE(res.status == -1 || res.status == 200) << res.status << " " << res.body;
    }
};

std::set<std::string> presence_senders(const json& body) {
    std::set<std::string> out;
    for (const auto& ev : body.value("presence", json::object()).value("events", json::array())) {
        out.insert(ev.value("sender", ""));
    }
    return out;
}

std::string presence_of(const json& body, const std::string& uid) {
    for (const auto& ev : body.value("presence", json::object()).value("events", json::array())) {
        if (ev.value("sender", "") == uid) return ev["content"].value("presence", "");
    }
    return "";
}

} // namespace

TEST(SyncPresenceDelta, AWokenPollCarriesOnlyWhatChangedAndEveryChange) {
    Fixture f("presence-delta");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    f.join_member(room, carol);
    PresenceRig rig(f);

    rig.presence.touch(bob);
    rig.presence.touch(carol);
    f.say(room, bob, "move the head past the stamps");

    auto initial = rig.poll("alice", "");
    auto senders = presence_senders(initial);
    EXPECT_TRUE(senders.count(bob) && senders.count(carol) && senders.count(alice))
        << "an initial sync restates everyone";
    auto since = initial["next_batch"].get<std::string>();

    // A woken delivery (data waiting, so it returns at once). Nobody's
    // presence changed since the token: only the caller's own entry rides.
    f.say(room, bob, "hello");
    auto woken = rig.poll("alice", since);
    ASSERT_TRUE(woken["rooms"]["join"].contains(room));
    EXPECT_EQ(presence_senders(woken), std::set<std::string>{alice})
        << "a woken poll restated peers whose presence had not changed";
    since = woken["next_batch"].get<std::string>();

    // Bob changes; the next woken delivery must carry it, and carol must
    // still not ride along.
    rig.put("bob", "unavailable");
    f.say(room, carol, "again");
    auto after_put = rig.poll("alice", since);
    EXPECT_EQ(presence_of(after_put, bob), "unavailable") << "a presence change was lost";
    EXPECT_FALSE(presence_senders(after_put).count(carol));
}

TEST(SyncPresenceDelta, AChangeWhileTheHeadStandsStillIsNotLost) {
    // A PUT stamps the CURRENT head, which may be exactly the position the
    // parked poll's token names. `>=` is what keeps it; `>` would drop it.
    Fixture f("presence-samehead");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    PresenceRig rig(f);

    rig.presence.touch(bob);
    f.say(room, bob, "x");
    auto since = rig.poll("alice", "")["next_batch"].get<std::string>();

    json woken;
    std::thread parked([&] { woken = rig.poll("alice", since, 10000); });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    const auto start = clk::now();
    rig.put("bob", "unavailable");  // wakes alice's poll; no event is written
    parked.join();
    EXPECT_LT(ms_since(start), 3000);
    EXPECT_EQ(presence_of(woken, bob), "unavailable");
}

TEST(SyncPresenceDelta, AVisibilityChangeForcesAFullRestatement) {
    // Somebody can become a peer without their presence changing; the delta
    // cannot see that, so a new visibility generation restates everyone.
    Fixture f("presence-generation");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    PresenceRig rig(f);

    rig.presence.touch(bob);
    rig.presence.touch(carol);  // online, but shares no room with alice yet
    f.say(room, bob, "x");
    auto initial = rig.poll("alice", "");
    EXPECT_FALSE(presence_senders(initial).count(carol));
    auto since = initial["next_batch"].get<std::string>();

    f.join_member(room, carol);  // a state event: new visibility generation
    f.say(room, bob, "y");
    auto woken = rig.poll("alice", since);
    EXPECT_TRUE(presence_senders(woken).count(carol))
        << "a new peer whose presence predates the token was never reported";
}

TEST(SyncPresenceDelta, AnIdleReplyRestatesEveryone) {
    Fixture f("presence-idle");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    PresenceRig rig(f);

    rig.presence.touch(bob);
    f.say(room, bob, "x");
    auto since = rig.poll("alice", "")["next_batch"].get<std::string>();
    // Nothing new: the poll falls through to the idle reply.
    auto idle = rig.poll("alice", since, 0);
    EXPECT_TRUE(presence_senders(idle).count(bob));
}

// ── Initial-sync gate ───────────────────────────────────────────────────────

TEST(InitialSyncGate, NeverAdmitsMoreThanItsCap) {
    InitialSyncGate gate(3);
    std::atomic<int> inside{0};
    std::atomic<int> peak{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 16; ++i) {
        threads.emplace_back([&] {
            auto slot = gate.enter(std::chrono::milliseconds(10000));
            EXPECT_TRUE(slot);
            const int now = ++inside;
            int seen = peak.load();
            while (now > seen && !peak.compare_exchange_weak(seen, now)) {
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            --inside;
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_LE(peak.load(), 3);
    EXPECT_EQ(gate.in_flight(), 0u);
}

TEST(InitialSyncGate, ProceedsWithoutASlotOnceItsPatienceRunsOut) {
    InitialSyncGate gate(1);
    auto held = gate.enter(std::chrono::milliseconds(100));
    ASSERT_TRUE(held);
    const auto start = clk::now();
    auto late = gate.enter(std::chrono::milliseconds(100));
    EXPECT_FALSE(late) << "the gate must give up waiting, not refuse forever";
    EXPECT_GE(ms_since(start), 90);
    EXPECT_EQ(gate.in_flight(), 1u) << "a slotless request must not be counted";
}
