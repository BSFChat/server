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

} // namespace
