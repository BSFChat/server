// Tests added with the fixes for docs/security-audit-2026-09.md.
//
// The audit's own proof tests (test_security_audit_2026_09.cpp) reproduce each
// finding at the one site it was found. These cover what the fixes added
// around them: the helpers each fix is built on, the sibling sites the sweep
// found (other event-producing writes for S2, the rest of the resolver contract
// for S4), and the findings that had no proof test (S6, S7, S8).
//
// Handler- and store-level, like the proof tests: no sockets.

#include <gtest/gtest.h>

#include "api/EventHandler.h"
#include "api/PresenceHandler.h"
#include "api/ProfileHandler.h"
#include "api/RoomHandler.h"
#include "api/SyncHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "core/RateLimiter.h"
#include "core/Utf8.h"
#include "http/JsonIo.h"
#include "http/RequestGuard.h"
#include "store/SqliteStore.h"
#include "sync/ParkedSyncGate.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <regex>
#include <string>
#include <thread>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
    return req;
}

int status_of(const httplib::Response& res) { return res.status == -1 ? 200 : res.status; }

struct Fixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;

    Fixture() {
        config = Config::defaults();
        config.server_name = "test";
        config.password_hash_cost = 4;
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        ServerRolesContent c;
        ServerRole r;
        r.id = std::string(permission::role_id::kEveryone);
        r.name = "everyone";
        r.position = 0;
        r.permissions = permission::kEveryoneDefault;
        c.roles.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 4));
        store->store_access_token("token-" + localpart, uid, "dev");
        return uid;
    }

    std::string add_room(const std::string& creator) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        return room_id;
    }

    std::string post_message(const std::string& room, const std::string& sender,
                             const std::string& text) {
        auto id = generate_event_id("test");
        store->insert_event(id, room, sender, std::string(event_type::kRoomMessage),
                            std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", text}}.dump(), now_ms());
        return id;
    }
};

}  // namespace

// ══ S1 — UTF-8-safe truncation and lenient response serialisation ═══════════

TEST(SecurityFixes2026_09, S1_TruncationNeverSplitsACharacter) {
    // The audit's exact shape: 79 ASCII + a two-byte char is 80 characters and
    // must survive intact (the old byte cut left a lone 0xC3).
    const std::string at_limit = std::string(79, 'a') + "\xC3\xA9";
    EXPECT_EQ(truncate_utf8(at_limit, 80), at_limit);

    // One over: the whole trailing character goes, never half of it.
    const std::string over = std::string(80, 'a') + "\xC3\xA9";
    EXPECT_EQ(truncate_utf8(over, 80), std::string(80, 'a'));

    // Three- and four-byte characters count as one each.
    const std::string cjk = "\xE4\xBD\xA0\xE5\xA5\xBD\xE4\xB8\x96";  // 3 chars, 9 bytes
    EXPECT_EQ(truncate_utf8(cjk, 2), "\xE4\xBD\xA0\xE5\xA5\xBD");
    const std::string emoji = "\xF0\x9F\x98\x80\xF0\x9F\x98\x80";    // 2 chars, 8 bytes
    EXPECT_EQ(truncate_utf8(emoji, 1), "\xF0\x9F\x98\x80");

    // Whatever it is given, what comes out can be serialised strictly.
    const std::string broken = std::string("ok") + "\xC3" + "x" + "\xE4\xBD";
    const auto cut = truncate_utf8(broken, 80);
    EXPECT_TRUE(is_valid_utf8(cut)) << "a malformed byte was copied through";
    EXPECT_NO_THROW((void)json(cut).dump());
}

TEST(SecurityFixes2026_09, S1_Utf8ValidatorAgreesWithTheStrictSerialiser) {
    for (const std::string s : {std::string("plain"), std::string("\xC3\xA9"),
                                std::string("\xF0\x9F\x98\x80")}) {
        EXPECT_TRUE(is_valid_utf8(s));
        EXPECT_NO_THROW((void)json(s).dump());
    }
    for (const std::string s : {std::string("\xC3"), std::string("\x80"),
                                std::string("\xC0\xAF"),           // overlong '/'
                                std::string("\xED\xA0\x80"),       // surrogate
                                std::string("\xF4\x90\x80\x80")}) {  // > U+10FFFF
        EXPECT_FALSE(is_valid_utf8(s));
        EXPECT_THROW((void)json(s).dump(), json::type_error);
    }
}

TEST(SecurityFixes2026_09, S1_ResponseSerialisationReplacesRatherThanThrows) {
    json bad = {{"presence", "online"}, {"status_msg", std::string("x\xC3")}};
    std::string out;
    ASSERT_NO_THROW(out = dump_response_json(bad));
    EXPECT_NE(out.find("\xEF\xBF\xBD"), std::string::npos) << out;  // U+FFFD

    // Byte-identical to dump() for valid input, so nothing about a normal
    // response changes.
    json good = {{"a", "\xC3\xA9"}, {"b", {1, 2, 3}}, {"c", nullptr}};
    EXPECT_EQ(dump_response_json(good), good.dump());
}

TEST(SecurityFixes2026_09, S1_StoredStatusIsValidAndCappedByCharacters) {
    Fixture f;
    auto alice = f.add_user("alice");
    PresenceHandler presence(*f.store, *f.sync, f.config);

    const std::string status = std::string(100, 'z') + "\xC3\xA9";
    auto req = make_request("/_matrix/client/v3/presence/" + alice + "/status", "token-alice",
                            json{{"presence", "online"}, {"status_msg", status}}.dump());
    static const std::regex kPresence(R"(/_matrix/client/v3/presence/([^/]+)/status)");
    ASSERT_TRUE(std::regex_match(req.path, req.matches, kPresence));
    httplib::Response res;
    presence.handle_put_presence(req, res);
    ASSERT_EQ(status_of(res), 200) << res.body;

    auto entry = presence.get_for(alice);
    ASSERT_TRUE(entry);
    EXPECT_EQ(entry->status_msg, std::string(80, 'z'));
    EXPECT_TRUE(is_valid_utf8(entry->status_msg));
}

TEST(SecurityFixes2026_09, S1_NonStringPresenceFieldsAre400NotAThrow) {
    Fixture f;
    auto alice = f.add_user("alice");
    PresenceHandler presence(*f.store, *f.sync, f.config);
    static const std::regex kPresence(R"(/_matrix/client/v3/presence/([^/]+)/status)");
    for (const json& body : {json{{"presence", "online"}, {"status_msg", 42}},
                             json{{"presence", 1}}, json::array({1, 2})}) {
        auto req = make_request("/_matrix/client/v3/presence/" + alice + "/status",
                                "token-alice", body.dump());
        ASSERT_TRUE(std::regex_match(req.path, req.matches, kPresence));
        httplib::Response res;
        EXPECT_NO_THROW(presence.handle_put_presence(req, res)) << body.dump();
        EXPECT_EQ(status_of(res), 400) << body.dump();
    }
}

// ══ S2 — every event-producing write has a ceiling ═════════════════════════

TEST(SecurityFixes2026_09, S2_OversizeRedactionReasonLeavesTheMessageAlone) {
    // The size check has to run BEFORE redact_event(): a refused redaction
    // that had already stripped the target would be a half-applied request.
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);
    auto target = f.post_message(room, alice, "still here");

    EventHandler handler(*f.store, *f.sync, f.config);
    auto req = make_request("/_matrix/client/v3/rooms/" + room + "/redact/" + target + "/t1",
                            "token-alice", json{{"reason", std::string(4096, 'r')}}.dump());
    httplib::Response res;
    handler.handle_redact(req, res);
    EXPECT_EQ(status_of(res), 400) << res.body;

    auto ev = f.store->get_event_by_id(target);
    ASSERT_TRUE(ev);
    EXPECT_EQ(ev->content.data.value("body", ""), "still here")
        << "the target was redacted even though the request was refused";

    // A reasonable reason still works.
    auto ok = make_request("/_matrix/client/v3/rooms/" + room + "/redact/" + target + "/t2",
                           "token-alice", json{{"reason", "typo"}}.dump());
    httplib::Response ok_res;
    handler.handle_redact(ok, ok_res);
    EXPECT_EQ(status_of(ok_res), 200) << ok_res.body;
}

TEST(SecurityFixes2026_09, S2_DisplaynameAtTheLimitIsAccepted) {
    Fixture f;
    auto alice = f.add_user("alice");
    ProfileHandler handler(*f.store, *f.sync, f.config);
    auto put = [&](const std::string& name) {
        auto req = make_request("/_matrix/client/v3/profile/" + alice + "/displayname",
                                "token-alice", json{{"displayname", name}}.dump());
        httplib::Response res;
        handler.handle_put_displayname(req, res);
        return status_of(res);
    };
    EXPECT_EQ(put(std::string(256, 'n')), 200);
    EXPECT_EQ(put(std::string(257, 'n')), 400);
}

TEST(SecurityFixes2026_09, S2_AvatarUrlHasItsOwnCeiling) {
    Fixture f;
    auto alice = f.add_user("alice");
    ProfileHandler handler(*f.store, *f.sync, f.config);
    auto req = make_request("/_matrix/client/v3/profile/" + alice + "/avatar_url", "token-alice",
                            json{{"avatar_url", "mxc://test/" + std::string(4096, 'a')}}.dump());
    httplib::Response res;
    handler.handle_put_avatar_url(req, res);
    EXPECT_EQ(status_of(res), 400) << res.body;
    EXPECT_NE(res.body.find("avatar_url"), std::string::npos) << res.body;
}

TEST(SecurityFixes2026_09, S2_ModerationReasonsAreBoundedAndTyped) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice);
    f.store->set_membership(room, bob, std::string(membership::kJoin));
    RoomHandler handler(*f.store, *f.sync, f.config);

    for (const char* action : {"kick", "ban", "unban"}) {
        for (const json& reason : {json(std::string(2048, 'r')), json(12345)}) {
            auto req = make_request("/_matrix/client/v3/rooms/" + room + "/" + action,
                                    "token-alice",
                                    json{{"user_id", bob}, {"reason", reason}}.dump());
            httplib::Response res;
            if (std::string(action) == "kick") {
                EXPECT_NO_THROW(handler.handle_kick(req, res));
            } else if (std::string(action) == "ban") {
                EXPECT_NO_THROW(handler.handle_ban(req, res));
            } else {
                EXPECT_NO_THROW(handler.handle_unban(req, res));
            }
            EXPECT_EQ(status_of(res), 400) << action << " " << reason.dump().substr(0, 20);
        }
    }
    EXPECT_FALSE(f.store->is_server_banned(bob));
}

TEST(SecurityFixes2026_09, S2_RoomNameAndTopicAreBoundedOnBothRoutes) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);
    RoomHandler handler(*f.store, *f.sync, f.config);

    // createRoom: refused before anything is created, whatever the caller's
    // permissions (the size check runs ahead of the MANAGE_CHANNELS gate).
    for (const json& body : {json{{"name", std::string(256, 'n')}},
                             json{{"topic", std::string(4097, 't')}}}) {
        auto req = make_request("/_matrix/client/v3/createRoom", "token-alice", body.dump());
        httplib::Response res;
        handler.handle_create_room(req, res);
        EXPECT_EQ(status_of(res), 400) << res.body;
    }

    // PUT /state: the same ceilings for the same events.
    auto put_state = [&](const std::string& type, const json& content) {
        auto req = make_request("/_matrix/client/v3/rooms/" + room + "/state/" + type,
                                "token-alice", content.dump());
        httplib::Response res;
        handler.handle_set_state(req, res);
        return status_of(res);
    };
    EXPECT_EQ(put_state("m.room.name", json{{"name", std::string(256, 'n')}}), 400);
    EXPECT_EQ(put_state("m.room.topic", json{{"topic", std::string(4097, 't')}}), 400);
    // And any state event over the event ceiling, whatever its type.
    EXPECT_EQ(put_state("com.example.blob",
                        json{{"x", std::string(f.config.send_limits.max_event_bytes, 'x')}}),
              413);
}

// ══ S3 — refresh tokens expire, and the expiry is not a revocation ══════════

TEST(SecurityFixes2026_09, S3_RefreshStillWorksAfterTheAccessTokenLapses) {
    // Refreshing a lapsed access token is what a refresh token is FOR, and the
    // client's first move is to present the lapsed token and get its 401. That
    // presentation used to delete the row, refresh secret included.
    Fixture f;
    auto alice = f.add_user("alice");
    f.store->store_access_token("access-a", alice, "dev2", /*lifetime_ms=*/300,
                                std::optional<std::string>("refresh-a"));
    std::this_thread::sleep_for(std::chrono::milliseconds(350));  // access lapsed,
                                                                  // refresh (600ms) not
    EXPECT_FALSE(f.store->get_user_by_token("access-a").has_value());
    auto session = f.store->consume_refresh_token("refresh-a");
    ASSERT_TRUE(session.has_value()) << "a refresh inside its window was refused";
    EXPECT_EQ(session->user_id, alice);
}

TEST(SecurityFixes2026_09, S3_AnExpiredRefreshIsNotTreatedAsAReplay) {
    // Past its deadline a refresh token is refused and reaped — but it was never
    // redeemed, so presenting it must not look like a copied chain and revoke
    // the family's live sessions.
    Fixture f;
    auto alice = f.add_user("alice");
    f.store->store_access_token("live-access", alice, "dev1", kDefaultAccessTokenLifetimeMs,
                                std::optional<std::string>("live-refresh"), "family-1");
    f.store->store_access_token("old-access", alice, "dev1", /*lifetime_ms=*/1,
                                std::optional<std::string>("old-refresh"), "family-1");
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    EXPECT_FALSE(f.store->consume_refresh_token("old-refresh").has_value());
    EXPECT_EQ(f.store->revoke_family_for_replayed_refresh_token("old-refresh"), 0);
    EXPECT_TRUE(f.store->get_user_by_token("live-access").has_value())
        << "an expired refresh token revoked a live session in its family";
    EXPECT_FALSE(f.store->get_token_expiry("old-access").has_value())
        << "the expired row was not reaped at redemption";
}

TEST(SecurityFixes2026_09, S3_AbandonedSessionsAreReapedWithoutBeingPresented) {
    const auto path = std::filesystem::temp_directory_path() /
                      ("bsfchat-s3-reap-" + std::to_string(now_ms()) + ".db");
    struct Cleanup {
        std::filesystem::path p;
        ~Cleanup() {
            for (const char* sfx : {"", "-wal", "-shm"}) {
                std::error_code ec;
                std::filesystem::remove(p.string() + sfx, ec);
            }
        }
    } cleanup{path};

    {
        SqliteStore store(path.string());
        store.initialize();
        store.create_user("@a:test", hash_password("password", 4));
        store.store_access_token("dead-plain", "@a:test", "d1", /*lifetime_ms=*/1);
        store.store_access_token("dead-refresh", "@a:test", "d2", /*lifetime_ms=*/1,
                                 std::optional<std::string>("r2"));
        store.store_access_token("alive", "@a:test", "d3");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    {
        // A restart sweeps. Nobody presented either dead token.
        SqliteStore store(path.string());
        store.initialize();
        EXPECT_FALSE(store.get_token_expiry("dead-plain").has_value());
        EXPECT_FALSE(store.get_token_expiry("dead-refresh").has_value());
        EXPECT_TRUE(store.get_token_expiry("alive").has_value());
    }
}

// ══ S5 — the tables evict, they do not flush ═══════════════════════════════

TEST(SecurityFixes2026_09, S5_TheFailureTableStaysBounded) {
    FailureTracker tracker(3, std::chrono::seconds(300));
    for (int i = 0; i < 100'050; ++i) tracker.record_failure("k" + std::to_string(i));
    EXPECT_EQ(tracker.size(), 100'000u);
    // The newest entries are the ones kept.
    tracker.record_failure("k100049");
    tracker.record_failure("k100049");
    EXPECT_GT(tracker.locked_for("k100049"), 0);
}

TEST(SecurityFixes2026_09, S5_AnActivelyLimitedAddressKeepsItsWindow) {
    RateLimiter limiter(3, std::chrono::seconds(60));
    for (int i = 0; i < 3; ++i) ASSERT_EQ(limiter.acquire("hot"), 0);
    ASSERT_GT(limiter.acquire("hot"), 0);
    // A flood of new keys, while the limited client keeps trying (which is what
    // a client under a limit does).
    for (int i = 0; i < 100'050; ++i) {
        limiter.acquire("cold" + std::to_string(i));
        if (i % 1000 == 0) limiter.acquire("hot");
    }
    EXPECT_EQ(limiter.size(), 100'000u);
    EXPECT_GT(limiter.acquire("hot"), 0) << "the flood reset a client that was being limited";
}

// ══ S6 — pre-body guard and depth-capped parsing ═══════════════════════════

TEST(SecurityFixes2026_09, S6_NestingDepthIsCappedAndStringAware) {
    EXPECT_FALSE(json_nesting_exceeds(std::string(32, '[') + std::string(32, ']')));
    EXPECT_TRUE(json_nesting_exceeds(std::string(33, '[')));
    // Brackets inside strings (including after an escaped quote) do not count.
    EXPECT_FALSE(json_nesting_exceeds(R"({"a":")" + std::string(1000, '[') + R"(\"["})"));
    EXPECT_THROW((void)parse_request_json(std::string(100'000, '[')), JsonTooDeep);
    EXPECT_TRUE(parse_request_json_or_discarded(std::string(100'000, '[')).is_discarded());
    EXPECT_EQ(parse_request_json(R"({"a":[1,{"b":2}]})")["a"][1]["b"], 2);
}

TEST(SecurityFixes2026_09, S6_ADeepBodyIsABadJson400AtTheHandler) {
    Fixture f;
    auto alice = f.add_user("alice");
    PresenceHandler presence(*f.store, *f.sync, f.config);
    auto req = make_request("/_matrix/client/v3/presence/" + alice + "/status", "token-alice",
                            std::string(50'000, '['));
    static const std::regex kPresence(R"(/_matrix/client/v3/presence/([^/]+)/status)");
    ASSERT_TRUE(std::regex_match(req.path, req.matches, kPresence));
    httplib::Response res;
    presence.handle_put_presence(req, res);
    EXPECT_EQ(status_of(res), 400);
    EXPECT_NE(res.body.find("M_BAD_JSON"), std::string::npos) << res.body;
}

TEST(SecurityFixes2026_09, S6_PreBodyGuard) {
    auto config = Config::defaults();
    const auto cap = max_json_body_bytes(config);
    auto req = [](const std::string& path,
                  std::initializer_list<std::pair<const char*, std::string>> headers) {
        httplib::Request r;
        r.method = "PUT";
        r.path = path;
        for (const auto& [k, v] : headers) r.set_header(k, v);
        return r;
    };
    const std::string json_route = "/_matrix/client/v3/profile/@a:test/displayname";

    EXPECT_FALSE(refuse_before_body(req(json_route, {{"Content-Length", "20"}}), config));
    EXPECT_FALSE(refuse_before_body(req(json_route, {}), config));  // no body at all
    EXPECT_FALSE(refuse_before_body(
        req(json_route, {{"Content-Length", "20"}, {"Content-Encoding", "identity"}}), config));

    auto r = refuse_before_body(req(json_route, {{"Content-Encoding", "gzip"}}), config);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, 415);
    r = refuse_before_body(req(json_route, {{"Content-Encoding", "gzip, identity"}}), config);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, 415);

    r = refuse_before_body(req(json_route, {{"Content-Length", std::to_string(cap + 1)}}), config);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, 413);
    EXPECT_FALSE(
        refuse_before_body(req(json_route, {{"Content-Length", std::to_string(cap)}}), config));
    r = refuse_before_body(
        req(json_route, {{"Content-Length", "99999999999999999999999999"}}), config);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, 413);

    // Chunked is refused even alongside a small Content-Length, because httplib
    // reads the chunked framing and would ignore the length.
    r = refuse_before_body(req(json_route, {{"Transfer-Encoding", "chunked"}}), config);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, 411);
    r = refuse_before_body(
        req(json_route, {{"Transfer-Encoding", "chunked"}, {"Content-Length", "5"}}), config);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, 411);

    // The media upload is the one route that takes a large, non-JSON body.
    const std::string upload(api_path::kMediaUpload);
    EXPECT_FALSE(refuse_before_body(
        req(upload, {{"Content-Length", std::to_string(40 * 1024 * 1024)}}), config));
    EXPECT_FALSE(refuse_before_body(req(upload, {{"Transfer-Encoding", "chunked"}}), config));
}

// ══ S7 — parked /sync per account ══════════════════════════════════════════

TEST(SecurityFixes2026_09, S7_GateCountsPerAccountAndReleases) {
    ParkedSyncGate gate(2);
    auto a1 = gate.try_park("@a:test");
    auto a2 = gate.try_park("@a:test");
    EXPECT_TRUE(a1);
    EXPECT_TRUE(a2);
    EXPECT_FALSE(gate.try_park("@a:test"));
    EXPECT_TRUE(gate.try_park("@b:test")) << "one account's cap must not touch another's";
    { auto moved = std::move(a1); }  // released at scope end
    EXPECT_EQ(gate.parked_for("@a:test"), 1u);
    EXPECT_TRUE(gate.try_park("@a:test"));
}

TEST(SecurityFixes2026_09, S7_OverTheCapASyncAnswersInsteadOfParking) {
    Fixture f;
    auto alice = f.add_user("alice");
    f.add_room(alice);
    SyncHandler handler(*f.store, *f.sync, f.config);

    httplib::Response first;
    handler.handle_sync(make_request("/_matrix/client/v3/sync", "token-alice"), first);
    ASSERT_EQ(status_of(first), 200) << first.body;
    const std::string since = json::parse(first.body).at("next_batch");

    // Every slot taken, as if by that many connections already long-polling.
    std::vector<ParkedSyncGate::Slot> held;
    for (std::size_t i = 0; i < SyncHandler::kMaxParkedSyncsPerAccount; ++i) {
        held.push_back(handler.parked_sync_gate_for_test().try_park(alice));
        ASSERT_TRUE(held.back());
    }

    auto req = make_request("/_matrix/client/v3/sync", "token-alice");
    req.params.emplace("since", since);
    req.params.emplace("timeout", "20000");
    httplib::Response res;
    const auto t0 = std::chrono::steady_clock::now();
    handler.handle_sync(req, res);
    const auto waited = std::chrono::steady_clock::now() - t0;
    EXPECT_EQ(status_of(res), 200);
    EXPECT_LT(waited, std::chrono::seconds(5)) << "the poll parked past the per-account cap";
    EXPECT_EQ(handler.parked_sync_gate_for_test().parked_for(alice),
              SyncHandler::kMaxParkedSyncsPerAccount)
        << "a poll served without parking must not hold a slot";
}

// ══ S8 — CORS is an allowlist, never a wildcard ════════════════════════════

TEST(SecurityFixes2026_09, S8_NoCorsHeadersByDefault) {
    httplib::Request req;
    req.set_header("Origin", "https://evil.example");
    httplib::Response res;
    apply_cors_headers(req, res, {});
    EXPECT_FALSE(res.has_header("Access-Control-Allow-Origin"));
    EXPECT_FALSE(res.has_header("Vary"));
}

TEST(SecurityFixes2026_09, S8_AllowlistedOriginIsReflectedAndOthersAreNot) {
    const std::vector<std::string> allowed = {"https://App.Example.com"};
    {
        httplib::Request req;
        req.set_header("Origin", "https://app.example.com");
        httplib::Response res;
        apply_cors_headers(req, res, allowed);
        EXPECT_EQ(res.get_header_value("Access-Control-Allow-Origin"), "https://app.example.com");
        EXPECT_EQ(res.get_header_value("Vary"), "Origin");
    }
    {
        httplib::Request req;
        req.set_header("Origin", "https://app.example.com.evil.example");
        httplib::Response res;
        apply_cors_headers(req, res, allowed);
        EXPECT_FALSE(res.has_header("Access-Control-Allow-Origin"));
        EXPECT_EQ(res.get_header_value("Vary"), "Origin");
    }
}

TEST(SecurityFixes2026_09, S8_WildcardOriginIsDroppedByValidate) {
    auto cfg = Config::defaults();
    cfg.cors_allowed_origins = {"*", "https://ok.example", "null", ""};
    Config::validate(cfg);
    EXPECT_EQ(cfg.cors_allowed_origins, std::vector<std::string>{"https://ok.example"});
}
