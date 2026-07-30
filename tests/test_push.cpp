// Push notifications, server half (F2).
//
// The properties that matter here are structural, not cosmetic:
//   * evaluation on the send path must only ENQUEUE — a dead or slow gateway
//     must never be able to hold up a message send or a /sync;
//   * the delivery worker must not hold the store's global mutex across its
//     outbound HTTP request, because every other request in the process
//     serialises behind that mutex;
//   * a pusher a gateway reports as rejected must be removed, not retried
//     forever.

#include <gtest/gtest.h>

#include "api/EventHandler.h"
#include "api/PushHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "push/PushService.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

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

// Records every gateway call and can be told how to answer.
struct FakeGateway {
    struct Call {
        std::string url;
        std::string body;
    };
    std::mutex mutex;
    std::vector<Call> calls;
    // What to return. Default: a healthy 200 with nothing rejected.
    PushService::GatewayResponse response{/*transport_ok=*/true, /*status=*/200, {}};
    // Blocks inside the transport until released, to prove the send path is not
    // waiting on it.
    std::atomic<bool> block{false};
    std::atomic<bool> released{false};
    std::atomic<int> entered{0};

    PushService::Transport transport() {
        return [this](const std::string& url, const std::string& body) {
            ++entered;
            while (block.load() && !released.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            std::lock_guard lock(mutex);
            calls.push_back({url, body});
            return response;
        };
    }

    size_t call_count() {
        std::lock_guard lock(mutex);
        return calls.size();
    }
    json last_payload() {
        std::lock_guard lock(mutex);
        if (calls.empty()) return json::object();
        return json::parse(calls.back().body, nullptr, false);
    }
};

struct PushFixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<PushService> push;
    std::unique_ptr<EventHandler> events;
    std::unique_ptr<PushHandler> pushers;
    FakeGateway gateway;

    static constexpr const char* kRoom = "!general:test";
    static constexpr const char* kGatewayUrl = "https://gateway.example/_matrix/push/v1/notify";

    PushFixture() {
        config = Config::defaults();
        config.server_name = "test";
        // Deterministic: tests drive drain_once() themselves rather than racing
        // a background thread.
        config.push.worker_poll_ms = 50;
        config.push.base_backoff_ms = 100;
        config.push.max_backoff_ms = 100;
        config.push.max_attempts = 2;

        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        push = std::make_unique<PushService>(*store, config);
        push->set_transport(gateway.transport());
        events = std::make_unique<EventHandler>(*store, *sync, config, push.get());
        pushers = std::make_unique<PushHandler>(*store, *push, config);

        store->create_room(kRoom, "@alice:test");
        set_roles(permission::kEveryoneDefault);
    }

    void set_roles(permission::Flags everyone_flags) {
        ServerRolesContent roles;
        ServerRole everyone;
        everyone.id = permission::role_id::kEveryone;
        everyone.name = "@everyone";
        everyone.position = 0;
        everyone.permissions = everyone_flags;
        roles.roles.push_back(everyone);
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart, bool join = true,
                         const std::string& room_id = kRoom) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);
        if (join) store->set_membership(room_id, uid, "join");
        return uid;
    }

    void register_pusher(const std::string& localpart, const std::string& pushkey,
                         const std::string& format = "") {
        json data = {{"url", kGatewayUrl}};
        if (!format.empty()) data["format"] = format;
        auto req = make_request("/_matrix/client/v3/pushers/set", "token-" + localpart,
                                json{{"pushkey", pushkey},
                                     {"kind", "http"},
                                     {"app_id", "com.bsfchat.app"},
                                     {"app_display_name", "BSFChat"},
                                     {"device_display_name", "Phone"},
                                     {"lang", "en"},
                                     {"data", data}}
                                    .dump());
        httplib::Response res;
        pushers->handle_set_pusher(req, res);
        ASSERT_TRUE(IsOk(res)) << res.body;
    }

    httplib::Response send(const std::string& localpart, const json& content,
                           const std::string& txn, const std::string& room_id = kRoom) {
        auto req = make_request(
            "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn,
            "token-" + localpart, content.dump());
        httplib::Response res;
        events->handle_send_event(req, res);
        return res;
    }

    void set_level(const std::string& localpart, const std::string& level,
                   const std::string& room_id = kRoom) {
        auto req = make_request(
            "/_matrix/client/v3/bsfchat/rooms/" + room_id + "/notify_level",
            "token-" + localpart, json{{"level", level}}.dump());
        httplib::Response res;
        pushers->handle_put_notify_level(req, res);
        ASSERT_TRUE(IsOk(res)) << res.body;
    }
};

} // namespace

// ── Pusher registration ───────────────────────────────────────────────────

TEST(Pushers, SetAndListRoundTrip) {
    PushFixture f;
    f.add_user("alice");
    f.register_pusher("alice", "device-token-1");

    auto req = make_request("/_matrix/client/v3/pushers", "token-alice");
    httplib::Response res;
    f.pushers->handle_get_pushers(req, res);
    ASSERT_TRUE(IsOk(res));

    auto body = json::parse(res.body);
    ASSERT_TRUE(body.contains("pushers"));
    ASSERT_EQ(body["pushers"].size(), 1u);
    const auto& p = body["pushers"][0];
    EXPECT_EQ(p["pushkey"], "device-token-1");
    EXPECT_EQ(p["kind"], "http");
    EXPECT_EQ(p["app_id"], "com.bsfchat.app");
    // url lives under `data`, where the spec puts it.
    EXPECT_EQ(p["data"]["url"], PushFixture::kGatewayUrl);
}

TEST(Pushers, NullKindDeletesThePusher) {
    PushFixture f;
    f.add_user("alice");
    f.register_pusher("alice", "device-token-1");
    ASSERT_EQ(f.store->get_pushers("@alice:test").size(), 1u);

    auto req = make_request("/_matrix/client/v3/pushers/set", "token-alice",
                            json{{"pushkey", "device-token-1"},
                                 {"app_id", "com.bsfchat.app"},
                                 {"kind", nullptr}}
                                .dump());
    httplib::Response res;
    f.pushers->handle_set_pusher(req, res);
    ASSERT_TRUE(IsOk(res));
    EXPECT_TRUE(f.store->get_pushers("@alice:test").empty());
}

TEST(Pushers, RegisteringAPushkeyTakesItFromWhoeverHadItBefore) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("alice", "shared-device-token");
    ASSERT_EQ(f.store->get_pushers("@alice:test").size(), 1u);

    // Bob's phone was previously signed in as Alice. `append` defaults to false,
    // so registering the token moves it — otherwise Alice's messages would keep
    // being delivered to a device that is now Bob's.
    f.register_pusher("bob", "shared-device-token");
    EXPECT_TRUE(f.store->get_pushers("@alice:test").empty());
    EXPECT_EQ(f.store->get_pushers("@bob:test").size(), 1u);
}

TEST(Pushers, MalformedRegistrationsAreRejected) {
    PushFixture f;
    f.add_user("alice");

    auto attempt = [&](const json& body) {
        auto req = make_request("/_matrix/client/v3/pushers/set", "token-alice", body.dump());
        httplib::Response res;
        f.pushers->handle_set_pusher(req, res);
        return res.status;
    };

    // Missing identifiers.
    EXPECT_EQ(attempt({{"kind", "http"}, {"app_id", "a"}}), 400);
    EXPECT_EQ(attempt({{"kind", "http"}, {"pushkey", "k"}}), 400);
    // Unsupported kind — better to say so than to store an "email" pusher that
    // will never deliver anything.
    EXPECT_EQ(attempt({{"kind", "email"}, {"pushkey", "k"}, {"app_id", "a"}}), 400);
    // http kind with nowhere to deliver to.
    EXPECT_EQ(attempt({{"kind", "http"}, {"pushkey", "k"}, {"app_id", "a"}}), 400);
    // Unknown format.
    EXPECT_EQ(attempt({{"kind", "http"},
                       {"pushkey", "k"},
                       {"app_id", "a"},
                       {"data", {{"url", PushFixture::kGatewayUrl}, {"format", "weird"}}}}),
              400);
}

TEST(Pushers, GatewayUrlMustBeAbsoluteHttpAndCarryNoCredentials) {
    PushFixture f;
    f.add_user("alice");

    auto attempt = [&](const std::string& url) {
        auto req = make_request("/_matrix/client/v3/pushers/set", "token-alice",
                                json{{"kind", "http"},
                                     {"pushkey", "k"},
                                     {"app_id", "a"},
                                     {"data", {{"url", url}}}}
                                    .dump());
        httplib::Response res;
        f.pushers->handle_set_pusher(req, res);
        return res.status;
    };

    // /pushers/set is the one endpoint where a user names a URL the SERVER will
    // request, so it is an SSRF surface and has to be constrained.
    EXPECT_EQ(attempt("file:///etc/passwd"), 400);
    EXPECT_EQ(attempt("/relative/path"), 400);
    EXPECT_EQ(attempt("gopher://internal/"), 400);
    EXPECT_EQ(attempt("https://user:pass@internal/notify"), 400);
    EXPECT_EQ(attempt("https://gateway.example/notify\r\nX-Injected: 1"), 400);
}

TEST(Pushers, GatewayAllowlistIsEnforcedWhenConfigured) {
    PushFixture f;
    f.config.push.allowed_gateway_prefixes = {"https://gateway.example/"};
    f.add_user("alice");

    auto attempt = [&](const std::string& url) {
        auto req = make_request("/_matrix/client/v3/pushers/set", "token-alice",
                                json{{"kind", "http"},
                                     {"pushkey", "k"},
                                     {"app_id", "a"},
                                     {"data", {{"url", url}}}}
                                    .dump());
        httplib::Response res;
        f.pushers->handle_set_pusher(req, res);
        return res.status;
    };

    // Cloud metadata and loopback are the classic SSRF targets; the allowlist is
    // what makes them unreachable through a pusher.
    EXPECT_EQ(attempt("http://169.254.169.254/latest/meta-data/"), 400);
    EXPECT_EQ(attempt("http://localhost:8448/_matrix/client/v3/sync"), 400);
    // A URL inside the allowlist still works.
    EXPECT_TRUE(IsOk([&] {
        auto req = make_request("/_matrix/client/v3/pushers/set", "token-alice",
                                json{{"kind", "http"},
                                     {"pushkey", "k"},
                                     {"app_id", "a"},
                                     {"data", {{"url", "https://gateway.example/notify"}}}}
                                    .dump());
        httplib::Response res;
        f.pushers->handle_set_pusher(req, res);
        return res;
    }()));
}

TEST(Pushers, RequiresAuthentication) {
    PushFixture f;
    httplib::Request req;
    req.path = "/_matrix/client/v3/pushers";
    httplib::Response res;
    f.pushers->handle_get_pushers(req, res);
    EXPECT_EQ(res.status, 401);

    httplib::Response set_res;
    httplib::Request set_req;
    set_req.path = "/_matrix/client/v3/pushers/set";
    set_req.body = "{}";
    f.pushers->handle_set_pusher(set_req, set_res);
    EXPECT_EQ(set_res.status, 401);
}

// ── Evaluation ────────────────────────────────────────────────────────────

TEST(PushEvaluation, MentionInAChannelEnqueuesAPush) {
    PushFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");
    f.register_pusher("bob", "bob-device");

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "@Bob look"},
                                      {"m.mentions", {{"user_ids", json::array({bob})}}}},
                            "t1")));
    EXPECT_EQ(f.store->count_queued_pushes(), 1);
}

TEST(PushEvaluation, PlainChannelMessageDoesNotPushByDefault) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");

    // Channels default to mentions-only: joining a busy server must not mean a
    // phone buzzing all day.
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "morning all"}}, "t1")));
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
}

TEST(PushEvaluation, EveryMessageInADmPushesByDefault) {
    PushFixture f;
    auto alice = f.add_user("alice", /*join=*/false);
    auto bob = f.add_user("bob", /*join=*/false);
    f.store->create_room("!dm:test", alice, /*is_direct=*/true);
    f.store->set_membership("!dm:test", alice, "join");
    f.store->set_membership("!dm:test", bob, "join");
    f.register_pusher("bob", "bob-device");

    // There is no such thing as an uninteresting message in a two-person
    // conversation, so a DM defaults to "all" without needing a mention.
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hey"}}, "t1", "!dm:test")));
    EXPECT_EQ(f.store->count_queued_pushes(), 1);
}

TEST(PushEvaluation, PerRoomLevelOverridesTheDefault) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");

    // "all" turns a normally-quiet channel loud.
    f.set_level("bob", PushService::kLevelAll);
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "one"}}, "t1")));
    EXPECT_EQ(f.store->count_queued_pushes(), 1);

    // "none" silences it entirely — even a direct mention.
    f.set_level("bob", PushService::kLevelNone);
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "@Bob"},
                                      {"m.mentions", {{"user_ids", json::array({"@bob:test"})}}}},
                            "t2")));
    EXPECT_EQ(f.store->count_queued_pushes(), 1); // unchanged
}

TEST(PushEvaluation, NotifyLevelRejectsUnknownValuesAndNonMembers) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("outsider", /*join=*/false);

    auto put = [&](const std::string& localpart, const json& body) {
        auto req = make_request(
            std::string("/_matrix/client/v3/bsfchat/rooms/") + PushFixture::kRoom +
                "/notify_level",
            "token-" + localpart, body.dump());
        httplib::Response res;
        f.pushers->handle_put_notify_level(req, res);
        return res.status;
    };

    EXPECT_EQ(put("alice", {{"level", "sometimes"}}), 400);
    EXPECT_EQ(put("outsider", {{"level", "all"}}), 403);
}

TEST(PushEvaluation, NotifyLevelGetReportsTheDefaultUntilItIsSet) {
    PushFixture f;
    f.add_user("alice");

    auto req = make_request(
        std::string("/_matrix/client/v3/bsfchat/rooms/") + PushFixture::kRoom + "/notify_level",
        "token-alice");
    httplib::Response res;
    f.pushers->handle_get_notify_level(req, res);
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    EXPECT_EQ(body["level"], PushService::kLevelMentions);
    EXPECT_TRUE(body["is_default"].get<bool>());
}

TEST(PushEvaluation, SenderIsNeverPushedForTheirOwnMessage) {
    PushFixture f;
    f.add_user("alice");
    f.register_pusher("alice", "alice-device");
    f.set_level("alice", PushService::kLevelAll);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "talking to myself"}}, "t1")));
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
}

TEST(PushEvaluation, UsersWithoutViewChannelAreNeverPushed) {
    PushFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);

    // Deny Bob VIEW_CHANNEL. Push must not become a side channel that leaks the
    // existence or content of a channel he cannot see.
    ChannelPermissionOverride ov;
    ov.deny = permission::kViewChannel;
    json j;
    to_json(j, ov);
    f.store->insert_event("$deny", PushFixture::kRoom, "@server:test",
                          std::string(event_type::kChannelPermissions), "user:" + bob, j.dump(), 1);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "secret"}}, "t1")));
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
}

TEST(PushEvaluation, EditsDoNotFireASecondNotification) {
    PushFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);

    auto first = f.send("alice", {{"msgtype", "m.text"}, {"body", "hello"}}, "t1");
    ASSERT_TRUE(IsOk(first));
    ASSERT_EQ(f.store->count_queued_pushes(), 1);
    auto target = json::parse(first.body)["event_id"].get<std::string>();

    // Correcting a typo must not buzz the recipient's phone again.
    ASSERT_TRUE(IsOk(f.send("alice",
                            {{"msgtype", "m.text"},
                             {"body", "* hello there"},
                             {"m.new_content", {{"msgtype", "m.text"}, {"body", "hello there"}}},
                             {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}}},
                            "t2")));
    EXPECT_EQ(f.store->count_queued_pushes(), 1) << "an edit generated a duplicate push";
}

TEST(PushEvaluation, UsersWithNoPusherCostNothing) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.set_level("bob", PushService::kLevelAll);
    // Bob wants everything but has no pusher: nothing to enqueue.
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
}

TEST(PushEvaluation, EventIdOnlyPushersDoNotLeakMessageContent) {
    PushFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");
    f.register_pusher("bob", "bob-device", "event_id_only");
    f.set_level("bob", PushService::kLevelAll);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "sensitive text"}}, "t1")));
    ASSERT_EQ(f.store->count_queued_pushes(), 1);

    f.push->drain_once();
    auto payload = f.gateway.last_payload();
    ASSERT_TRUE(payload.contains("notification"));
    const auto& n = payload["notification"];
    // Enough to identify and fetch the event...
    EXPECT_TRUE(n["event_id"].is_string());
    EXPECT_EQ(n["room_id"], PushFixture::kRoom);
    // ...and nothing more. The whole point of event_id_only: the gateway (and
    // whatever third party sits behind it) learns that something happened, never
    // what was said.
    EXPECT_FALSE(n.contains("content")) << payload.dump();
    EXPECT_FALSE(n.contains("sender_display_name"));
    // Still addressed to the right device.
    EXPECT_EQ(n["devices"][0]["pushkey"], "bob-device");
    (void)bob;
}

TEST(PushEvaluation, DefaultFormatCarriesContentAndDeviceIdentity) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "visible"}}, "t1")));
    f.push->drain_once();

    auto payload = f.gateway.last_payload();
    const auto& n = payload["notification"];
    EXPECT_EQ(n["room_id"], PushFixture::kRoom);
    EXPECT_EQ(n["sender"], "@alice:test");
    EXPECT_EQ(n["type"], "m.room.message");
    EXPECT_EQ(n["content"]["body"], "visible");
    ASSERT_EQ(n["devices"].size(), 1u);
    EXPECT_EQ(n["devices"][0]["pushkey"], "bob-device");
    EXPECT_EQ(n["devices"][0]["app_id"], "com.bsfchat.app");
    EXPECT_EQ(n["counts"]["unread"], 1);
}

// ── Delivery ──────────────────────────────────────────────────────────────

TEST(PushDelivery, SendPathDoesNotWaitOnTheGateway) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);

    // Wedge the gateway open. If evaluation delivered inline, this send would
    // block until released — which is exactly the failure the queue exists to
    // prevent.
    f.gateway.block = true;

    auto started = std::chrono::steady_clock::now();
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));
    auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 500)
        << "the send path blocked on the push gateway";
    // The gateway was never even contacted from the request thread.
    EXPECT_EQ(f.gateway.entered.load(), 0);
    EXPECT_EQ(f.store->count_queued_pushes(), 1);

    f.gateway.released = true;
}

TEST(PushDelivery, WorkerDoesNotHoldTheStoreLockAcrossTheHttpRequest) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));

    // Hold the fake gateway open, then prove from another thread that ordinary
    // store access still works. This server serialises ALL database access
    // behind one global mutex, so a worker that held it across an outbound
    // request would stall every request in the process for the duration of the
    // gateway's timeout.
    f.gateway.block = true;
    std::thread worker([&] { f.push->drain_once(); });

    // Wait until the transport is actually in flight.
    for (int i = 0; i < 2000 && f.gateway.entered.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_GT(f.gateway.entered.load(), 0) << "transport never ran";

    std::atomic<bool> store_reachable{false};
    std::thread reader([&] {
        // Any store call will do; this one takes the same global mutex.
        (void)f.store->count_unread("@bob:test", PushFixture::kRoom);
        store_reachable = true;
    });
    for (int i = 0; i < 2000 && !store_reachable.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(store_reachable.load())
        << "the store mutex was held across the outbound push request";

    f.gateway.released = true;
    reader.join();
    worker.join();
}

TEST(PushDelivery, SuccessfulDeliveryDrainsTheQueue) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));
    ASSERT_EQ(f.store->count_queued_pushes(), 1);

    auto result = f.push->drain_once();
    EXPECT_EQ(result.delivered, 1);
    EXPECT_EQ(f.gateway.call_count(), 1u);
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
    EXPECT_EQ(f.push->drain_once().delivered, 0); // nothing left
}

TEST(PushDelivery, RejectedPushkeyRemovesThePusher) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));

    // A rejection means the device is gone for good — app uninstalled, token
    // revoked. Retrying it forever would just grow the queue.
    f.gateway.response = {true, 200, {"bob-device"}};
    f.push->drain_once();

    EXPECT_TRUE(f.store->get_pushers("@bob:test").empty());
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
}

TEST(PushDelivery, TransportFailureIsRetriedThenGivenUpOn) {
    PushFixture f; // max_attempts = 2, backoff = 100ms
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));

    f.gateway.response = {false, 0, {}}; // gateway unreachable

    auto first = f.push->drain_once();
    EXPECT_EQ(first.failed, 1);
    EXPECT_EQ(f.store->count_queued_pushes(), 1) << "should still be queued for retry";

    // The lease/backoff means it is not immediately due again.
    EXPECT_EQ(f.push->drain_once().failed, 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    auto second = f.push->drain_once();
    EXPECT_EQ(second.failed, 1);
    // Attempts exhausted: the row is dropped rather than retried forever.
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
}

TEST(PushDelivery, LeasePreventsTheSameRowBeingDeliveredTwice) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));

    // claim_due_pushes leases the row by pushing next_attempt_at into the
    // future, so a second pass while the first is still notionally in flight
    // finds nothing.
    auto claimed = f.store->claim_due_pushes(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count(),
        10, 60000);
    ASSERT_EQ(claimed.size(), 1u);
    EXPECT_EQ(f.push->drain_once().delivered, 0);
    EXPECT_EQ(f.gateway.call_count(), 0u);
}

TEST(PushDelivery, MalformedPusherUrlIsNotRetriedForever) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    // Write the pusher straight to the store, bypassing the handler's URL
    // validation, to stand in for a row left by an older build. Then use the
    // REAL transport so post_to_gateway's own guard is what has to catch it —
    // an unparseable URL must be treated as a permanent failure rather than
    // retried until the attempt limit runs out on every restart.
    SqliteStore::Pusher p;
    p.user_id = "@bob:test";
    p.app_id = "a";
    p.pushkey = "k";
    p.kind = "http";
    p.url = "not-a-url";
    p.data_json = "{}";
    f.store->upsert_pusher(p);
    f.set_level("bob", PushService::kLevelAll);

    PushService real(*f.store, f.config); // default transport = post_to_gateway
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));
    ASSERT_EQ(f.store->count_queued_pushes(), 1);

    // The URL guard reports a 4xx, so with max_attempts = 2 the row retires
    // after two passes instead of living forever.
    real.drain_once();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    real.drain_once();
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
    // Never reached the fake gateway — the real transport handled it.
    EXPECT_EQ(f.gateway.call_count(), 0u);
}

TEST(PushDelivery, DisabledPushEnqueuesNothing) {
    PushFixture f;
    f.config.push.enabled = false;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));
    EXPECT_EQ(f.store->count_queued_pushes(), 0);
}

TEST(PushDelivery, WorkerThreadStartsAndStopsCleanly) {
    PushFixture f;
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);

    f.push->start();
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));

    // The worker is woken by the enqueue rather than waiting out its poll.
    for (int i = 0; i < 500 && f.gateway.call_count() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    EXPECT_EQ(f.gateway.call_count(), 1u);
    f.push->stop();
    f.push->stop(); // idempotent
}
