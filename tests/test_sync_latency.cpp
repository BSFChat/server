// Delivery-latency regression tests.
//
// "Messages take ages to arrive" was traced to two independent things, and
// each half needs its own guard because either one alone reproduces the
// symptom:
//
//   1. SyncEngine must wake a parked long poll the moment an event lands,
//      rather than letting it ride out its timeout. This half was already
//      correct and these tests keep it that way.
//
//   2. The HTTP worker pool must still have a thread to run the send on.
//      This half was broken: HttpServer built httplib's ThreadPool with a
//      base size and no ceiling argument, which httplib reads as "ceiling
//      == base" — a hard cap that never grows. Because httplib runs an
//      entire keep-alive connection on one pool task, every parked /sync
//      held a worker for its whole timeout, so with workers = 4 and two
//      desktop clients the pool was full and a PUT /send sat in the job
//      queue until a long poll expired. Measured 28.4s against 81ms on an
//      idle pool.
//
// The second test is the one that actually fails on the old code. It
// deliberately uses the real bsfchat::HttpServer rather than a bare
// httplib::Server, because the defect lived in how we construct the pool.

#include <gtest/gtest.h>

#include "core/Config.h"
#include "http/HttpServer.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "auth/LocalAuth.h"

#include <bsfchat/Identifiers.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

using namespace bsfchat;
using json = nlohmann::json;
using clk = std::chrono::steady_clock;

static int64_t ms_since(clk::time_point t0) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - t0).count();
}

// Delivery has to beat this on loopback. It is ~3x the measured 60-90ms so a
// loaded CI box does not flake, and still two orders of magnitude below the
// 28s the pool bug produced — there is no overlap to argue about.
static constexpr int64_t kMaxDeliveryMs = 200;

namespace {

class SyncLatencyTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        sync = std::make_unique<SyncEngine>(*store, config);

        store->create_user("@alice:test", hash_password("pass", 10));
        store->create_user("@bob:test", hash_password("pass", 10));

        room_id = generate_room_id("test");
        store->create_room(room_id, "@alice:test");
        store->set_membership(room_id, "@alice:test", "join");
        store->set_membership(room_id, "@bob:test", "join");
    }

    void insert_message(const std::string& body) {
        store->insert_event(generate_event_id("test"), room_id, "@alice:test",
                            "m.room.message", std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", body}}.dump(),
                            2000);
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync;
    std::string room_id;
};

// A sync parked on a 30s long poll must come back as soon as the event is
// there, not when the poll expires.
TEST_F(SyncLatencyTest, PendingSyncWakesWithinBudgetOfASend) {
    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    std::atomic<int64_t> waited{-1};
    SyncResponse got;
    clk::time_point sent_at;

    std::thread bob([&] {
        auto t0 = clk::now();
        got = sync->handle_sync("@bob:test", since, 30000);
        // Measured from the send, not from the start of the poll: the
        // interesting quantity is the lag the *other* user sees.
        waited = ms_since(sent_at);
        (void)t0;
    });

    // Let Bob get all the way into the condition-variable wait. Without this
    // the test could pass by racing rather than by waking.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    sent_at = clk::now();
    insert_message("hello");
    sync->notify_new_event();

    bob.join();

    ASSERT_EQ(got.rooms.join.count(room_id), 1u);
    ASSERT_EQ(got.rooms.join[room_id].timeline.events.size(), 1u);
    EXPECT_EQ(got.rooms.join[room_id].timeline.events[0].content.data["body"], "hello");
    EXPECT_LT(waited.load(), kMaxDeliveryMs)
        << "a parked /sync took " << waited.load()
        << "ms to see a send; it should be woken by notify_new_event(), not by its timeout";
}

// An event in a room the user is not in must not cut their poll short. This
// is the flip side of the test above and it guards a real client-side cost:
// a woken sync that carries nothing leaves next_batch unmoved, which the
// desktop client reads as a no-progress reply and answers with an escalating
// backoff (SyncBackoff::delayForFailure).
TEST_F(SyncLatencyTest, UnrelatedRoomDoesNotWakeAPoll) {
    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    auto other = generate_room_id("test");
    store->create_room(other, "@alice:test");
    store->set_membership(other, "@alice:test", "join");

    auto t0 = clk::now();
    std::thread bob([&] { sync->handle_sync("@bob:test", since, 400); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    store->insert_event(generate_event_id("test"), other, "@alice:test",
                        "m.room.message", std::nullopt,
                        json{{"msgtype", "m.text"}, {"body", "not for bob"}}.dump(), 2000);
    sync->notify_new_event();
    bob.join();

    // It should have ridden out the full 400ms timeout rather than returning
    // empty the instant someone else's room moved.
    EXPECT_GE(ms_since(t0), 350)
        << "Bob's poll returned early for an event in a room he is not in";
}

// The regression test for the pool itself.
//
// Parks more simultaneous connections than two desktop clients would hold and
// then times an ordinary short request — the send. The config is left at its
// SHIPPED DEFAULTS on purpose: the defect was that the default could not carry
// a handful of clients, so pinning a generous size here would test the test.
//
// On the old default (workers = 4, and a pool that could not grow past it)
// this waits for a parked connection to finish. It is the difference between
// 28.4s and 64ms measured end to end.
TEST(HttpWorkerPoolTest, ShortRequestIsNotQueuedBehindParkedLongPolls) {
    // Twelve parked sockets is roughly a ten-client deployment: each signed-in
    // client holds a /sync plus at least one more connection.
    constexpr int kParked = 12;
    constexpr int kBlockMs = 3000;

    Config cfg;
    cfg.bind_address = "127.0.0.1";
    ASSERT_GT(cfg.workers, kParked)
        << "the shipped default worker count (" << cfg.workers << ") cannot carry "
        << kParked << " simultaneous connections, which is a ~10-client deployment. "
           "httplib holds a worker for a whole connection, not a request.";

    HttpServer http(cfg);
    std::atomic<int> blocked{0};

    http.server().Get("/park", [&](const httplib::Request&, httplib::Response& res) {
        ++blocked;
        std::this_thread::sleep_for(std::chrono::milliseconds(kBlockMs));
        res.set_content("{}", "application/json");
    });
    http.server().Get("/send", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{}", "application/json");
    });

    // Bind first so the port is known before anything connects; listening in a
    // second step removes the "did the server come up yet" race entirely.
    const int port = http.server().bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread serve([&] { http.server().listen_after_bind(); });

    std::vector<std::thread> parkers;
    for (int i = 0; i < kParked; ++i) {
        parkers.emplace_back([port] {
            httplib::Client c("127.0.0.1", port);
            c.set_read_timeout(10, 0);
            c.Get("/park");
        });
    }

    // Wait until every parked request is demonstrably inside its handler,
    // rather than sleeping a guessed interval and hoping.
    for (int i = 0; i < 300 && blocked.load() < kParked; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_EQ(blocked.load(), kParked)
        << "only " << blocked.load() << " of " << kParked
        << " connections got a worker; the rest are queued behind them";

    httplib::Client c("127.0.0.1", port);
    c.set_read_timeout(10, 0);
    auto t0 = clk::now();
    auto res = c.Get("/send");
    const int64_t elapsed = ms_since(t0);

    ASSERT_TRUE(res) << "the send never completed";
    EXPECT_EQ(res->status, 200);
    EXPECT_LT(elapsed, kMaxDeliveryMs)
        << "a short request waited " << elapsed << "ms behind " << kParked
        << " parked connections with workers=" << cfg.workers;

    http.server().stop();
    serve.join();
    for (auto& t : parkers) t.join();
}

// A ceiling below the base would make httplib's ThreadPool constructor throw
// std::invalid_argument and abort startup, so validate() must raise it rather
// than pass it through.
TEST(HttpWorkerPoolTest, ValidateRaisesACeilingBelowTheBase) {
    Config cfg;
    cfg.workers = 32;
    cfg.max_workers = 4;
    Config::validate(cfg);
    EXPECT_GE(cfg.max_workers, cfg.workers);

    Config zero;
    zero.workers = 0;
    zero.max_workers = 0;
    Config::validate(zero);
    EXPECT_GE(zero.workers, 1);
    EXPECT_GE(zero.max_workers, zero.workers);
}

// ---------------------------------------------------------------------------
// The two races the scoped-wake change (89c958a) opened, each of which turns
// on the same mistake: reading the global stream head as a SEPARATE step after
// the scan, and treating it as though it described what the scan saw.
//
// Both use SyncEngine's post-scan hook rather than threads and sleeps. The hook
// runs on the syncing thread itself, in the exact instant between the scan and
// everything built from it, so the window is hit every run on every machine
// instead of being aimed at.
// ---------------------------------------------------------------------------

// Race 1: an event that lands while the first scan is running was marked as
// already examined by the wait, because `checked_pos` was bumped to the head as
// read AFTER that scan. The predicate was then false for an event that was
// committed, visible, and not in the response — so the client waited for some
// later event, or for the full timeout, to be told about it.
TEST_F(SyncLatencyTest, EventDuringTheInitialScanWakesThePollAtOnce) {
    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    // Fires once, inside the initial scan, before the wait is entered.
    bool fired = false;
    sync->set_post_scan_hook_for_test([&] {
        if (fired) return;
        fired = true;
        insert_message("landed mid-scan");
        sync->notify_new_event();
    });

    const auto t0 = clk::now();
    auto got = sync->handle_sync("@bob:test", since, 4000);
    const int64_t elapsed = ms_since(t0);

    ASSERT_TRUE(fired);
    ASSERT_EQ(got.rooms.join.count(room_id), 1u);
    ASSERT_EQ(got.rooms.join[room_id].timeline.events.size(), 1u);
    EXPECT_EQ(got.rooms.join[room_id].timeline.events[0].content.data["body"],
              "landed mid-scan");
    // The event was already on disk before the wait began, so this must return
    // immediately. Before the fix it rode out all 4000ms and only picked the
    // message up in the post-deadline scan.
    EXPECT_LT(elapsed, 1000)
        << "a sync took " << elapsed
        << "ms to return an event that was committed before it ever waited";
}

// Race 2: next_batch was built from the head read after the scan, so an event
// committing in between sat at or below the new token without having been in
// the scan. The client polls with that token, asks only for positions above it,
// and never learns the event exists.
TEST_F(SyncLatencyTest, NextBatchNeverJumpsPastAnUnscannedEvent) {
    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    bool fired = false;
    sync->set_post_scan_hook_for_test([&] {
        if (fired) return;
        fired = true;
        insert_message("committed between the scan and the head read");
    });

    // timeout 0: no waiting, just the scan and the token it hands back.
    auto first = sync->handle_sync("@bob:test", since, 0);
    ASSERT_TRUE(fired);
    EXPECT_TRUE(first.rooms.join.empty())
        << "the event landed after the scan, so it cannot be in this response";

    // Whatever the token says, the next poll with it must still produce the
    // event. This is the assertion that fails without the fix: next_batch had
    // already advanced past a row nobody had read.
    sync->set_post_scan_hook_for_test(nullptr);
    auto second = sync->handle_sync("@bob:test", first.next_batch, 0);

    ASSERT_EQ(second.rooms.join.count(room_id), 1u)
        << "next_batch (" << first.next_batch << ") skipped an event that was "
           "never scanned; no later sync will ever ask for it";
    ASSERT_EQ(second.rooms.join[room_id].timeline.events.size(), 1u);
    EXPECT_EQ(second.rooms.join[room_id].timeline.events[0].content.data["body"],
              "committed between the scan and the head read");
}

// The same hazard on the initial-sync path: next_batch there was built from a
// head read after every room had been walked, so an event landing mid-walk was
// in no timeline in the response and still below the token the client then
// polled with. The hook fires inside the walk.
TEST_F(SyncLatencyTest, InitialSyncTokenDoesNotSkipAnEventLandingDuringIt) {
    // An earlier event puts the head somewhere non-zero, so a token that has
    // over-advanced cannot pass by looking like the empty-server case.
    insert_message("older");

    bool fired = false;
    sync->set_post_scan_hook_for_test([&] {
        if (fired) return;
        fired = true;
        insert_message("during the walk");
    });

    auto initial = sync->handle_sync("@bob:test", "", 0);
    ASSERT_TRUE(fired);
    sync->set_post_scan_hook_for_test(nullptr);

    auto next = sync->handle_sync("@bob:test", initial.next_batch, 0);
    ASSERT_EQ(next.rooms.join.count(room_id), 1u)
        << "the initial-sync token (" << initial.next_batch
        << ") ran past an event that was not in the initial response";
    ASSERT_EQ(next.rooms.join[room_id].timeline.events.size(), 1u);
    EXPECT_EQ(next.rooms.join[room_id].timeline.events[0].content.data["body"],
              "during the walk");
}

// Race 3 — the shape production actually hit, and the one that costs the
// SENDER their own message.
//
// The desktop client stops its typing indicator in the same breath as it PUTs
// the message (ServerConnection::sendMessage), so a typing EDU and the send
// reach the server microseconds apart. The EDU wakes that client's own parked
// long poll; the re-scan finds nothing, and because ephemeral_seq_ moved the
// poll returns AT ONCE rather than going back to sleep. If the message commits
// between that re-scan and the token the reply is built from, the sender is
// handed a next_batch past their own message. No later poll asks for it — only
// leaving the room and coming back, which refetches /messages, shows it.
//
// Observed on chat.bsfchat.com (server 0.0.46), nginx access log
// 18/Sep/2026:03:44:16 +0200: a typing PUT and a send PUT, and in the same
// second a 418-byte /sync reply to since=s6071 with no timeline in it; that
// client then polled since=s6072 for the full 30s and got nothing, and the
// message only appeared when it refetched /messages at 03:44:48.
//
// This is a distinct path from NextBatchNeverJumpsPastAnUnscannedEvent above:
// that one covers the scan a poll does before it parks, this one covers the
// re-scan inside the wait and the early return on an ephemeral change.
TEST_F(SyncLatencyTest, AnEphemeralWakeDoesNotHandBackATokenPastAnUnscannedEvent) {
    const std::string since = sync->handle_sync("@alice:test", "", 0).next_batch;

    // Fires on the re-scan the ephemeral wake triggers — scan 1 is the one
    // that runs before the poll parks, and must be left alone.
    std::atomic<int> scans{0};
    sync->set_post_scan_hook_for_test([&] {
        if (++scans != 2) return;
        insert_message("alice's own message");
        sync->notify_new_event();
    });

    SyncResponse woken;
    std::thread alice([&] { woken = sync->handle_sync("@alice:test", since, 4000); });

    // Let the poll reach the wait before the typing indicator stops. It does
    // not have to: edu_at_entry is sampled at entry, so an EDU that lands
    // earlier is still seen. The sleep only keeps the test honest about which
    // path it is exercising.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    sync->notify_ephemeral();
    alice.join();
    sync->set_post_scan_hook_for_test(nullptr);

    ASSERT_EQ(scans.load(), 2) << "the ephemeral wake did not re-scan";
    ASSERT_TRUE(woken.rooms.join.empty())
        << "the message committed after the re-scan, so it cannot be in this reply";

    auto next = sync->handle_sync("@alice:test", woken.next_batch, 0);
    ASSERT_EQ(next.rooms.join.count(room_id), 1u)
        << "next_batch (" << woken.next_batch << ") ran past the sender's own "
           "message; nothing will ever ask for it again, and the sender only "
           "sees their message by leaving the channel and coming back";
    ASSERT_EQ(next.rooms.join[room_id].timeline.events.size(), 1u);
    EXPECT_EQ(next.rooms.join[room_id].timeline.events[0].content.data["body"],
              "alice's own message");
}

// ---------------------------------------------------------------------------
// The shape production is actually in, rather than one poller and one send.
//
// A real account has several parked polls at once — a desktop, a phone, and
// (until the client was fixed) a duplicate connection per desktop, because
// three of ServerManager's four add paths appended a second ServerConnection
// for a homeserver already in the roster. A client log from chat.bsfchat.com
// on 2026-09-23 shows two /sync chains on one token for hours, and across
// that log 25.5% of the polls that CARRIED timeline events returned at the
// 30-second deadline rather than being woken:
//
//     responses that carried timeline events: 2038
//       returned in under 1s                  53.2%
//       returned mid-poll (1-29s)             21.2%
//       returned AT the deadline (~30s)       25.5%   <-- not woken
//
// A poll answered at its deadline WITH events in it did not get its wake; it
// found them in the post-deadline scan. These tests hold the line on the two
// things that can produce that shape and are testable here — every parked
// poll being woken, not just one, and repeated rounds not degrading — so a
// regression in SyncEngine is ruled in or out before anyone goes looking at
// deployment config again.
// ---------------------------------------------------------------------------

// Every parked poll wakes, not merely the first one the condvar happens to
// reach. notify_all() is what makes this true; a notify_one() "optimisation"
// for the thundering herd would leave all but one client waiting out the
// full timeout, which is precisely the observed symptom.
TEST_F(SyncLatencyTest, EveryParkedPollForAnAccountIsWokenByOneSend) {
    // Four of Bob's devices, which is what a desktop with a duplicated
    // connection plus a phone plus a spare looks like to the server.
    constexpr int kPollers = 4;
    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    std::atomic<clk::time_point> sent_at{clk::time_point{}};
    std::vector<int64_t> waited(kPollers, -1);
    std::vector<SyncResponse> got(kPollers);
    std::vector<std::thread> pollers;

    for (int i = 0; i < kPollers; ++i) {
        pollers.emplace_back([&, i] {
            got[i] = sync->handle_sync("@bob:test", since, 30000);
            waited[i] = ms_since(sent_at.load());
        });
    }

    // All of them into the wait before anything is sent.
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    sent_at = clk::now();
    insert_message("one send, four listeners");
    sync->notify_new_event();

    for (auto& t : pollers) t.join();

    for (int i = 0; i < kPollers; ++i) {
        ASSERT_EQ(got[i].rooms.join.count(room_id), 1u)
            << "poller " << i << " came back without the message";
        ASSERT_EQ(got[i].rooms.join[room_id].timeline.events.size(), 1u);
        EXPECT_LT(waited[i], kMaxDeliveryMs)
            << "poller " << i << " took " << waited[i]
            << "ms; it rode out its timeout instead of being woken";
    }
}

// Ten sends in a row, each to a freshly parked poll, all under budget. A
// single wake proves the mechanism exists; this proves it keeps working —
// current_position_ is monotonic and never rewound, checked_pos advances
// every round, and nothing accumulates that makes round N slower than
// round 1.
TEST_F(SyncLatencyTest, RepeatedSendsKeepWakingTheirPolls) {
    constexpr int kRounds = 10;
    std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    for (int round = 0; round < kRounds; ++round) {
        std::atomic<clk::time_point> sent_at{clk::time_point{}};
        int64_t waited = -1;
        SyncResponse got;

        std::thread bob([&] {
            got = sync->handle_sync("@bob:test", since, 30000);
            waited = ms_since(sent_at.load());
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(80));

        sent_at = clk::now();
        insert_message("round " + std::to_string(round));
        sync->notify_new_event();
        bob.join();

        ASSERT_EQ(got.rooms.join.count(room_id), 1u) << "round " << round;
        EXPECT_LT(waited, kMaxDeliveryMs)
            << "round " << round << " took " << waited << "ms";
        since = got.next_batch;
    }
}

// A send into a room the poller cannot see must NOT end their poll, and must
// also not cost them the next event that IS theirs. The re-park path
// (checked_pos advancing to what the re-scan covered) is what makes both
// true; getting it wrong in either direction shows up as latency.
TEST_F(SyncLatencyTest, AnInvisibleEventReparksWithoutLosingTheNextRealOne) {
    // A room Bob is not in at all.
    const std::string other = generate_room_id("test");
    store->create_room(other, "@alice:test");
    store->set_membership(other, "@alice:test", "join");

    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    std::atomic<clk::time_point> sent_at{clk::time_point{}};
    int64_t waited = -1;
    SyncResponse got;

    std::thread bob([&] {
        got = sync->handle_sync("@bob:test", since, 30000);
        waited = ms_since(sent_at.load());
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Three events Bob cannot see. Each wakes him; each must send him back
    // to sleep rather than returning an empty reply (which the desktop
    // client answers with an escalating no-progress backoff, walking its
    // poll interval out to a minute).
    for (int i = 0; i < 3; ++i) {
        store->insert_event(generate_event_id("test"), other, "@alice:test",
                            "m.room.message", std::nullopt,
                            json{{"msgtype", "m.text"},
                                 {"body", "not for bob"}}.dump(), 2000);
        sync->notify_new_event();
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
    }

    sent_at = clk::now();
    insert_message("for bob");
    sync->notify_new_event();
    bob.join();

    ASSERT_EQ(got.rooms.join.count(room_id), 1u)
        << "the poll never came back with Bob's message";
    ASSERT_EQ(got.rooms.join[room_id].timeline.events.size(), 1u);
    EXPECT_EQ(got.rooms.join[room_id].timeline.events[0].content.data["body"],
              "for bob");
    EXPECT_LT(waited, kMaxDeliveryMs)
        << "after re-parking three times the poll took " << waited
        << "ms to see an event it could read";
}

// Marking a room read changes unread and highlight counts but writes no
// event row, so the stream head does not move. It was announced with
// notify_new_event(), whose predicate is "has the head passed what I have
// examined" — which is false, so the wake did nothing at all and the other
// device kept its badge lit until its poll timed out.
//
// The assertion is on the mechanism rather than on the counts: a read marker
// must move the EPHEMERAL epoch, which is what "something changed that is
// not a timeline event" means here and what typing and presence already use.
TEST_F(SyncLatencyTest, AReadMarkerWakesAParkedPoll) {
    insert_message("something to be unread about");
    sync->notify_new_event();
    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    std::atomic<clk::time_point> marked_at{clk::time_point{}};
    int64_t waited = -1;

    std::thread bob([&] {
        sync->handle_sync("@bob:test", since, 30000);
        waited = ms_since(marked_at.load());
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    marked_at = clk::now();
    store->set_read_marker("@bob:test", room_id,
                           store->get_room_max_stream_position(room_id));
    // What EventHandler::handle_read_marker now calls. With
    // notify_new_event() here instead, this test hangs for the full 30s.
    sync->notify_ephemeral();
    bob.join();

    EXPECT_LT(waited, kMaxDeliveryMs)
        << "a read marker took " << waited
        << "ms to reach a parked poll; notify_new_event() cannot wake one "
           "because a read marker does not move the stream head";
}

} // namespace
