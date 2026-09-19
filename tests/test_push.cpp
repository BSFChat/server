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

#include <spdlog/sinks/ringbuffer_sink.h>

#include "api/EventHandler.h"
#include "api/PushHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
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
        // An empty allowlist now means "no gateway is permitted at all", so a
        // fixture that wants to register a pusher has to configure one — the
        // same thing a real deployment has to do.
        config.push.allowed_gateway_prefixes = {"https://gateway.example/"};

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

// The internal-address gate is applied ON TOP of the allowlist, not only when
// the allowlist is empty: /pushers/set is the one endpoint where an ordinary
// user names a URL that the SERVER then POSTs to, and the delivery worker runs
// inside the compose network. Every host below is allowlisted here on purpose —
// an entry typo'd onto an internal address must fail closed rather than become
// an SSRF aperture.
TEST(Pushers, InternalTargetsAreRefusedEvenWhenAllowlisted) {
    PushFixture f;
    f.config.push.allowed_gateway_prefixes = {
        "http://169.254.169.254/", "http://localhost:8448/",  "http://127.0.0.1:8448/",
        "http://[::1]:8448/",      "http://[::ffff:127.0.0.1]/",
        "http://10.0.0.5/",        "http://172.16.0.9/",      "http://172.31.255.254/",
        "http://192.168.1.1/",     "http://100.64.0.1/",      "http://[fd00::1]/",
        "http://[fe80::1]/",       "http://identity:9000/",   "http://db/",
        "http://gateway.internal/", "http://printer.local/",
        "https://push.example.com/",
    };
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

    // Cloud metadata — the classic one.
    EXPECT_EQ(attempt("http://169.254.169.254/latest/meta-data/"), 400);
    // The server talking to itself, by name and by address, v4 and v6.
    EXPECT_EQ(attempt("http://localhost:8448/_matrix/client/v3/sync"), 400);
    EXPECT_EQ(attempt("http://127.0.0.1:8448/"), 400);
    EXPECT_EQ(attempt("http://[::1]:8448/"), 400);
    EXPECT_EQ(attempt("http://[::ffff:127.0.0.1]/"), 400);
    // Private ranges and CGNAT.
    EXPECT_EQ(attempt("http://10.0.0.5/notify"), 400);
    EXPECT_EQ(attempt("http://172.16.0.9/notify"), 400);
    EXPECT_EQ(attempt("http://172.31.255.254/notify"), 400);
    EXPECT_EQ(attempt("http://192.168.1.1/notify"), 400);
    EXPECT_EQ(attempt("http://100.64.0.1/notify"), 400);
    EXPECT_EQ(attempt("http://[fd00::1]/notify"), 400);
    EXPECT_EQ(attempt("http://[fe80::1]/notify"), 400);
    // Compose service names and internal search domains.
    EXPECT_EQ(attempt("http://identity:9000/notify"), 400);
    EXPECT_EQ(attempt("http://db/notify"), 400);
    EXPECT_EQ(attempt("http://gateway.internal/notify"), 400);
    EXPECT_EQ(attempt("http://printer.local/notify"), 400);

    // A genuinely public gateway is still accepted — this must not become a
    // de-facto allowlist of one.
    EXPECT_TRUE(IsOk([&] {
        auto req = make_request("/_matrix/client/v3/pushers/set", "token-alice",
                                json{{"kind", "http"},
                                     {"pushkey", "k"},
                                     {"app_id", "a"},
                                     {"data", {{"url", "https://push.example.com/_matrix/push/v1/notify"}}}}
                                    .dump());
        httplib::Response res;
        f.pushers->handle_set_pusher(req, res);
        return res;
    }()));
}

// 172.15 and 172.32 are *outside* RFC1918; an off-by-one here would silently
// block a legitimate gateway.
TEST(Pushers, AddressesAdjacentToPrivateRangesAreStillAllowed) {
    PushFixture f;
    f.config.push.allowed_gateway_prefixes = {"http://172.15.0.1/", "http://172.32.0.1/",
                                              "http://11.0.0.1/", "http://8.8.8.8/"};
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
        return res;
    };

    EXPECT_TRUE(IsOk(attempt("http://172.15.0.1/notify")));
    EXPECT_TRUE(IsOk(attempt("http://172.32.0.1/notify")));
    EXPECT_TRUE(IsOk(attempt("http://11.0.0.1/notify")));
    EXPECT_TRUE(IsOk(attempt("http://8.8.8.8/notify")));
}

// A deployment whose gateway really is on localhost (sygnal in the same compose
// file) allowlists it AND opts in to internal addresses, and keeps working.
// Both are needed: the allowlist says which gateway, the opt-in says the server
// may be pointed at its own network at all. tests/e2e/e2e.sh depends on this.
TEST(Pushers, AllowlistPlusOptInReachesAnInternalGateway) {
    PushFixture f;
    f.config.push.allowed_gateway_prefixes = {"http://127.0.0.1:9999/"};
    f.config.push.allow_internal_gateway = true;
    f.add_user("alice");

    auto req = make_request("/_matrix/client/v3/pushers/set", "token-alice",
                            json{{"kind", "http"},
                                 {"pushkey", "k"},
                                 {"app_id", "a"},
                                 {"data", {{"url", "http://127.0.0.1:9999/notify"}}}}
                                .dump());
    httplib::Response res;
    f.pushers->handle_set_pusher(req, res);
    EXPECT_TRUE(IsOk(res));
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

// With push.default_payload = "full" restored, a pusher that names no format
// gets the Matrix default shape. (That the SERVER default is event_id_only is
// PushPayload.DefaultsToEventIdOnly.)
TEST(PushEvaluation, FullPayloadCarriesContentAndDeviceIdentity) {
    PushFixture f;
    f.config.push.default_payload = "full";
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

// ── P4: gateway allowlist, gateway trust, payload default, log injection ───
//
// The shape shared by everything below is "the gateway is a third party and a
// pushkey is not an authorisation". A pusher URL is a request the SERVER will
// issue; a gateway's answer is untrusted input; a pushkey is an opaque device
// token anybody may happen to know.

namespace {

// A config with push configured the way a real deployment must configure it:
// an explicit allowlist. Tests that are about something other than the
// allowlist start from this.
void allow_test_gateway(Config& cfg) {
    cfg.push.allowed_gateway_prefixes = {"https://gateway.example/"};
}

int attempt_register(PushFixture& f, const std::string& url,
                     const std::string& pushkey = "k",
                     const std::string& app_id = "a") {
    auto req = make_request("/_matrix/client/v3/pushers/set", "token-alice",
                            json{{"kind", "http"},
                                 {"pushkey", pushkey},
                                 {"app_id", app_id},
                                 {"data", {{"url", url}}}}
                                .dump());
    httplib::Response res;
    f.pushers->handle_set_pusher(req, res);
    return res.status == -1 ? 200 : res.status;
}

} // namespace

// B6. The headline: with no allowlist the server must not accept ANY gateway.
// Before this, an empty list meant "anything public", which is a self-serve
// exfiltration feed — collect.attacker.tld is a perfectly ordinary public host
// and was therefore allowed.
TEST(PushAllowlist, EmptyAllowlistPermitsNoGatewayAtAll) {
    PushFixture f;
    f.config.push.allowed_gateway_prefixes.clear();
    f.add_user("alice");

    EXPECT_EQ(attempt_register(f, "https://collect.attacker.tld/n"), 400);
    EXPECT_EQ(attempt_register(f, "https://push.example.com/_matrix/push/v1/notify"), 400);
}

// B6. `push.enabled` with no allowlist is a misconfiguration the operator has
// to notice. Forcing the feature OFF is the loud, non-silent failure mode: the
// server still starts (an upgrade must not brick a running deployment) but
// push stops rather than staying open.
TEST(PushAllowlist, EnabledWithNoAllowlistDisablesPushAtStartup) {
    Config cfg = Config::defaults();
    cfg.push.enabled = true;
    cfg.push.allowed_gateway_prefixes.clear();
    Config::validate(cfg);
    EXPECT_FALSE(cfg.push.enabled);

    Config ok = Config::defaults();
    ok.push.enabled = true;
    ok.push.allowed_gateway_prefixes = {"https://gateway.example/"};
    Config::validate(ok);
    EXPECT_TRUE(ok.push.enabled);
}

// B6. A raw string prefix is not an origin. "https://push.example.com" as a
// plain prefix also matches "https://push.example.com.evil.tld/", which hands
// the attacker the allowlisted deployment's own feed.
TEST(PushAllowlist, MatchesOnOriginNotRawStringPrefix) {
    PushFixture f;
    f.config.push.allowed_gateway_prefixes = {"https://push.example.com"};
    f.add_user("alice");

    EXPECT_EQ(attempt_register(f, "https://push.example.com.evil.tld/n"), 400);
    EXPECT_EQ(attempt_register(f, "https://push.example.com@evil.tld/n"), 400);
    // Scheme and port are part of the origin, not decoration.
    EXPECT_EQ(attempt_register(f, "http://push.example.com/n"), 400);
    EXPECT_EQ(attempt_register(f, "https://push.example.com:8443/n"), 400);
    // The gateway itself still works, case-insensitively on the host.
    EXPECT_EQ(attempt_register(f, "https://push.example.com/_matrix/push/v1/notify"), 200);
    EXPECT_EQ(attempt_register(f, "https://PUSH.EXAMPLE.COM/notify"), 200);
}

// B6. An entry with a path scopes to that path, on a segment boundary — so
// ".../push/v1/" does not also authorise ".../push/v1backdoor".
TEST(PushAllowlist, PathScopingHonoursSegmentBoundaries) {
    PushFixture f;
    f.config.push.allowed_gateway_prefixes = {"https://push.example.com/_matrix/push/v1/"};
    f.add_user("alice");

    EXPECT_EQ(attempt_register(f, "https://push.example.com/_matrix/push/v1/notify"), 200);
    EXPECT_EQ(attempt_register(f, "https://push.example.com/_matrix/push/v1"), 200);
    EXPECT_EQ(attempt_register(f, "https://push.example.com/_matrix/push/v1backdoor"), 400);
    EXPECT_EQ(attempt_register(f, "https://push.example.com/admin"), 400);
}

// SSRF. The internal-address backstop is a check on the RESOLVED shape of the
// host, so it has to understand the shapes a resolver understands. These all
// reach 127.0.0.1 through inet_aton/getaddrinfo but were classified as public,
// because the check parsed only dotted-quad decimal.
TEST(PushSsrf, ObfuscatedLoopbackFormsAreRecognised) {
    PushFixture f;
    // Allowlisted deliberately: this is testing the internal-address gate, not
    // the allowlist. Both must hold.
    f.config.push.allowed_gateway_prefixes = {
        "http://0177.0.0.1/",  "http://0x7f.0.0.1/", "http://127.1/",
        "http://2130706433/",  "http://localhost./", "http://127.0.0.1.:8448/",
        "http://010.0.0.1/",   "http://0177.1/",     "http://[0:0:0:0:0:ffff:7f00:1]/",
        "http://0.0.0.0/",
    };
    f.add_user("alice");

    EXPECT_EQ(attempt_register(f, "http://0177.0.0.1/n"), 400) << "octal dotted quad";
    EXPECT_EQ(attempt_register(f, "http://0x7f.0.0.1/n"), 400) << "hex octet";
    EXPECT_EQ(attempt_register(f, "http://127.1/n"), 400) << "short form";
    EXPECT_EQ(attempt_register(f, "http://2130706433/n"), 400) << "integer form";
    EXPECT_EQ(attempt_register(f, "http://localhost./n"), 400) << "trailing dot";
    EXPECT_EQ(attempt_register(f, "http://127.0.0.1.:8448/n"), 400) << "trailing dot, v4";
    // ...and accurate in the other direction: inet_aton reads "010" as octal 8,
    // so this is 8.0.0.1, a public address. The old sscanf("%u") parser read it
    // as 10.0.0.1 and blocked a legitimate gateway.
    EXPECT_EQ(attempt_register(f, "http://010.0.0.1/n"), 200) << "octal 8.0.0.1 is public";
    EXPECT_EQ(attempt_register(f, "http://0177.1/n"), 400) << "octal short form";
    EXPECT_EQ(attempt_register(f, "http://[0:0:0:0:0:ffff:7f00:1]/n"), 400)
        << "uncompressed IPv4-mapped IPv6";
    EXPECT_EQ(attempt_register(f, "http://0.0.0.0/n"), 400) << "this host";
}

// SSRF. The internal-address gate applies to allowlisted hosts too. An
// operator whose gateway really is on loopback (sygnal in the same compose
// file) opts in explicitly rather than getting it as a side effect of the
// allowlist.
TEST(PushSsrf, InternalGatewayNeedsAnExplicitOptIn) {
    PushFixture f;
    f.config.push.allowed_gateway_prefixes = {"http://127.0.0.1:9999/"};
    f.add_user("alice");
    EXPECT_EQ(attempt_register(f, "http://127.0.0.1:9999/notify"), 400);

    f.config.push.allow_internal_gateway = true;
    EXPECT_EQ(attempt_register(f, "http://127.0.0.1:9999/notify"), 200);
}

// A17. `data.url` had no length bound at all — only pushkey and app_id did.
TEST(PushLogging, GatewayUrlIsLengthBounded) {
    PushFixture f;
    allow_test_gateway(f.config);
    f.add_user("alice");
    EXPECT_EQ(attempt_register(f, "https://gateway.example/" + std::string(8192, 'a')), 400);
}

// A17. The rejected URL was logged verbatim by the very check that rejected it
// for containing control characters, so any account could write arbitrary
// lines into the server log — which is where auth events (lockouts, logins,
// password changes) are recorded and nowhere else.
TEST(PushLogging, RejectedGatewayUrlCannotForgeLogLines) {
    auto ring = std::make_shared<spdlog::sinks::ringbuffer_sink_mt>(64);
    get_logger()->sinks().push_back(ring);
    struct Pop {
        ~Pop() { get_logger()->sinks().pop_back(); }
    } pop;

    PushFixture f;
    allow_test_gateway(f.config);
    f.add_user("alice");

    const std::string forged =
        "https://gateway.example/n\n[2026-09-19 03:11:00.000] [warning] "
        "Auth lockout engaged for ip:203.0.113.9\n";
    EXPECT_EQ(attempt_register(f, forged), 400);

    bool saw_rejection = false;
    for (const auto& line : ring->last_formatted()) {
        if (line.find("rejected pusher registration") == std::string::npos) continue;
        saw_rejection = true;
        // One log record is one line. Anything past the record's own trailing
        // newline is a line the user wrote.
        auto body = line;
        if (!body.empty() && body.back() == '\n') body.pop_back();
        // The property that matters: one record is one line, so whatever the
        // user wrote can only ever be a suffix INSIDE a genuine record, never a
        // record of its own. The forged text survives as escaped bytes.
        EXPECT_EQ(body.find('\n'), std::string::npos) << body;
        EXPECT_NE(body.find("Push: rejected pusher registration"), std::string::npos) << body;
        EXPECT_NE(body.find("\\x0a"), std::string::npos)
            << "the newline should be escaped, not dropped: " << body;
    }
    EXPECT_TRUE(saw_rejection) << "the rejection should still be diagnosable";
}

// B7. The headline integrity bug: a gateway's `rejected` list was applied with
// DELETE FROM pushers WHERE pushkey = ?, unscoped by user and unchecked
// against the pushkeys this request actually carried. One gateway — hostile or
// merely compromised — could wipe push for the whole server.
TEST(PushGatewayTrust, RejectionCannotTouchAnotherUsersPusher) {
    PushFixture f;
    allow_test_gateway(f.config);
    f.add_user("alice");
    f.add_user("bob");
    f.add_user("carol");
    f.register_pusher("bob", "bob-device");
    f.register_pusher("carol", "carol-device");
    f.set_level("bob", PushService::kLevelAll);
    f.set_level("carol", PushService::kLevelNone);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));
    ASSERT_EQ(f.store->count_queued_pushes(), 1);

    // Bob's gateway answers the push for bob-device by rejecting carol's key.
    f.gateway.response = {true, 200, {"carol-device"}};
    f.push->drain_once();

    EXPECT_EQ(f.store->get_pushers("@carol:test").size(), 1u)
        << "a gateway must not be able to mutate an account it was never given";
    EXPECT_EQ(f.store->get_pushers("@bob:test").size(), 1u)
        << "nor a pusher this request did not carry";
}

// B7. A rejection is only meaningful for the device this request was actually
// addressed to. One notify carries exactly one device.
TEST(PushGatewayTrust, RejectionOnlyAppliesToThePushkeyThatWasSent) {
    PushFixture f;
    allow_test_gateway(f.config);
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-phone");
    f.register_pusher("bob", "bob-tablet");
    f.set_level("bob", PushService::kLevelAll);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "hi"}}, "t1")));
    ASSERT_EQ(f.store->count_queued_pushes(), 2);

    // Whatever the gateway says, each row may only retire its own pushkey.
    f.gateway.response = {true, 200, {"bob-phone", "bob-tablet"}};
    // Drain only the first claimed row by shrinking the batch.
    f.config.push.batch_size = 1;
    f.push->drain_once();

    EXPECT_EQ(f.store->get_pushers("@bob:test").size(), 1u)
        << "exactly one pusher — the one this notify addressed — should be gone";
}

// A14. `append: false` is spec'd as "this App ID + pushkey pair is mine now".
// It was implemented as "this pushkey is mine now", across app_ids as well as
// accounts — so a pushkey is an authorisation to delete unrelated rows.
TEST(PushGatewayTrust, PushkeyTakeoverIsScopedToTheSameAppId) {
    PushFixture f;
    allow_test_gateway(f.config);
    f.add_user("alice");
    f.add_user("mallory");

    // Alice's phone: the same device token registered by two different apps.
    ASSERT_EQ(attempt_register(f, "https://gateway.example/n", "device-token", "com.bsfchat.app"), 200);
    ASSERT_EQ(attempt_register(f, "https://gateway.example/n", "device-token", "com.bsfchat.beta"), 200);
    ASSERT_EQ(f.store->get_pushers("@alice:test").size(), 2u);

    // Mallory knows the token and claims it for ONE app id.
    auto req = make_request("/_matrix/client/v3/pushers/set", "token-mallory",
                            json{{"kind", "http"},
                                 {"pushkey", "device-token"},
                                 {"app_id", "com.bsfchat.app"},
                                 {"data", {{"url", "https://gateway.example/n"}}}}
                                .dump());
    httplib::Response res;
    f.pushers->handle_set_pusher(req, res);
    ASSERT_TRUE(IsOk(res)) << res.body;

    auto remaining = f.store->get_pushers("@alice:test");
    ASSERT_EQ(remaining.size(), 1u)
        << "only the contested (app_id, pushkey) pair may be displaced";
    EXPECT_EQ(remaining[0].app_id, "com.bsfchat.beta");
}

// B17. What leaves this server, to a third party, when a pusher says nothing
// about what it wants. It used to be the whole message.
TEST(PushPayload, DefaultsToEventIdOnly) {
    PushFixture f;
    allow_test_gateway(f.config);
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device"); // no `format`
    f.set_level("bob", PushService::kLevelAll);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "sensitive text"}}, "t1")));
    f.push->drain_once();

    auto payload = f.gateway.last_payload();
    const auto& n = payload["notification"];
    EXPECT_FALSE(n.contains("content")) << n.dump();
    EXPECT_FALSE(n.contains("sender")) << n.dump();
    EXPECT_FALSE(n.contains("sender_display_name")) << n.dump();
    EXPECT_FALSE(n.contains("type")) << n.dump();
    // Still enough for the device to fetch the event and show a badge.
    EXPECT_TRUE(n["event_id"].is_string());
    EXPECT_EQ(n["room_id"], PushFixture::kRoom);
    EXPECT_EQ(n["devices"][0]["pushkey"], "bob-device");
    EXPECT_EQ(n["counts"]["unread"], 1);
}

// B17. The operator can still choose the Matrix default deployment-wide; the
// point is that it is a choice someone made, not what happens by omission.
TEST(PushPayload, OperatorCanRestoreFullPayloads) {
    PushFixture f;
    allow_test_gateway(f.config);
    f.config.push.default_payload = "full";
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device");
    f.set_level("bob", PushService::kLevelAll);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "visible"}}, "t1")));
    f.push->drain_once();

    auto payload = f.gateway.last_payload();
    const auto& n = payload["notification"];
    EXPECT_EQ(n["content"]["body"], "visible");
    EXPECT_EQ(n["sender"], "@alice:test");
}

// B17. An explicit `format: event_id_only` is still honoured under a "full"
// default — a client asking for privacy outranks the deployment default.
TEST(PushPayload, ExplicitEventIdOnlyBeatsAFullDefault) {
    PushFixture f;
    allow_test_gateway(f.config);
    f.config.push.default_payload = "full";
    f.add_user("alice");
    f.add_user("bob");
    f.register_pusher("bob", "bob-device", "event_id_only");
    f.set_level("bob", PushService::kLevelAll);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "sensitive"}}, "t1")));
    f.push->drain_once();

    auto payload = f.gateway.last_payload();
    const auto& n = payload["notification"];
    EXPECT_FALSE(n.contains("content")) << n.dump();
}
