// Proof tests for docs/security-audit-2026-09.md.
//
// Every test here asserts the SECURE behaviour and therefore FAILED on the code
// it was written against (main at ed7bd1d): S1, S2a, S2b, S3, S4 and S5 failed
// there, S2c passed. Each failure was the reproduction for the finding named in
// its comment. The assertions are exactly as the audit wrote them; the fixes on
// fix/security-audit-2026-09 make them pass, and from here on they are the
// regression guards. Further tests added with the fixes live in
// test_security_fixes_2026_09.cpp.
//
// All are handler- or store-level: no sockets, bodies of at most 1 MiB.

#include <gtest/gtest.h>

#include "api/AuthHandler.h"
#include "api/EventHandler.h"
#include "api/PresenceHandler.h"
#include "api/ProfileHandler.h"
#include "api/RoomHandler.h"
#include "api/SyncHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "core/RateLimiter.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <regex>
#include <string>
#include <thread>
#include <vector>

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
        config.password_hash_cost = 4;  // keep PBKDF2 out of the test's runtime
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        set_everyone(permission::kEveryoneDefault);
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

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
    }

    void set_everyone(permission::Flags flags) {
        ServerRolesContent c;
        ServerRole r;
        r.id = std::string(permission::role_id::kEveryone);
        r.name = "everyone";
        r.position = 0;
        r.permissions = flags;
        c.roles.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
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

// ══ S1. Presence status_msg is truncated mid-UTF-8, and that 500s everyone's /sync ══
//
// PresenceHandler cuts status_msg with std::string::resize(80), a BYTE count.
// Put a two-byte character across byte 80 and the stored string ends in a lone
// lead byte. SyncHandler then serialises every co-member's presence with
// nlohmann's strict dump(), which throws type_error.316 on invalid UTF-8 — out of
// the handler, so httplib answers 500. Every /sync of every account that shares
// a room with the attacker fails for as long as the presence entry lives, and
// the attacker keeps it alive by re-PUTting (or just syncing) every <150 s.

TEST(SecurityAudit2026_09, S1_PresenceTruncationMustNotBreakOtherUsersSync) {
    Fixture f;
    auto mallory = f.add_user("mallory");
    auto victim = f.add_user("victim");
    auto room = f.add_room(victim);
    f.join(room, mallory);

    PresenceHandler presence(*f.store, *f.sync, f.config);
    SyncHandler sync_handler(*f.store, *f.sync, f.config);
    sync_handler.set_presence_handler(&presence);

    // 79 ASCII bytes, then U+00E9 (0xC3 0xA9): valid UTF-8 on the wire, and the
    // 80-byte cut lands between the two bytes of the last character.
    const std::string status = std::string(79, 'a') + "\xC3\xA9";
    auto req = make_request("/_matrix/client/v3/presence/" + mallory + "/status", "token-mallory",
                            json{{"presence", "online"}, {"status_msg", status}}.dump());
    static const std::regex kPresence(R"(/_matrix/client/v3/presence/([^/]+)/status)");
    ASSERT_TRUE(std::regex_match(req.path, req.matches, kPresence));
    httplib::Response put_res;
    presence.handle_put_presence(req, put_res);
    ASSERT_EQ(status_of(put_res), 200) << put_res.body;

    // The victim's own sync. On the vulnerable code this throws out of the
    // handler (httplib turns that into a bare 500).
    auto sync_req = make_request("/_matrix/client/v3/sync", "token-victim");
    httplib::Response sync_res;
    EXPECT_NO_THROW(sync_handler.handle_sync(sync_req, sync_res))
        << "one presence PUT by another account made this account's /sync fail";
}


// ══ S2. Size ceilings exist on /send only ════════════════════════════════════
//
// PUT /send refuses a body over limits.max_event_bytes (128 KiB). Other writes
// that become events every member downloads have no ceiling of their own. Each
// test uses 1 MiB, eight times the /send ceiling.

namespace {
const std::string kOneMiB(1024 * 1024, 'x');
}

TEST(SecurityAudit2026_09, S2a_DisplaynameHasASizeCeiling) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto r1 = f.add_room(alice);
    auto r2 = f.add_room(alice);
    (void)r1; (void)r2;

    ProfileHandler handler(*f.store, *f.sync, f.config);
    auto req = make_request("/_matrix/client/v3/profile/" + alice + "/displayname",
                            "token-alice", json{{"displayname", kOneMiB}}.dump());
    httplib::Response res;
    handler.handle_put_displayname(req, res);
    EXPECT_EQ(status_of(res), 400)
        << "a 1 MiB display name was accepted and re-emitted into every joined room";
}

TEST(SecurityAudit2026_09, S2b_RedactionReasonIsBoundedLikeSend) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);
    auto target = f.post_message(room, alice, "hi");

    EventHandler handler(*f.store, *f.sync, f.config);
    auto req = make_request("/_matrix/client/v3/rooms/" + room + "/redact/" + target + "/t1",
                            "token-alice", json{{"reason", kOneMiB}}.dump());
    httplib::Response res;
    handler.handle_redact(req, res);
    EXPECT_NE(status_of(res), 200)
        << "redaction accepted a reason 8x larger than /send's whole-body ceiling";
}

TEST(SecurityAudit2026_09, S2c_DirectRoomTopicIsBounded) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto req = make_request("/_matrix/client/v3/createRoom", "token-alice",
                            json{{"is_direct", true}, {"invite", {bob}},
                                 {"topic", kOneMiB}}.dump());
    httplib::Response res;
    handler.handle_create_room(req, res);
    EXPECT_NE(status_of(res), 200)
        << "an account holding no permissions created a DM carrying a 1 MiB topic";
}

// ══ S3. A refresh token outlives the session it belongs to ═══════════════════
//
// consume_refresh_token() never reads expires_at, and nothing sweeps expired
// rows (they are reaped only when the ACCESS token is presented). A session
// abandoned without logout keeps a redeemable refresh token indefinitely.

TEST(SecurityAudit2026_09, S3_ExpiredSessionsRefreshTokenIsNotRedeemable) {
    Fixture f;
    auto alice = f.add_user("alice");
    f.store->store_access_token("access-short", alice, "dev2", /*lifetime_ms=*/1,
                                std::optional<std::string>("refresh-short"));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(f.store->consume_refresh_token("refresh-short").has_value())
        << "a refresh token from an expired session minted a fresh session";
}

// ══ S4. Client-address resolution fails OPEN ═════════════════════════════════
//
// When the peer is a trusted proxy and X-Forwarded-For contains a hop that does
// not parse, resolve() returns nullopt, client_key() returns "", and
// over_attempt_limit() / locked_out() treat "" as "do not limit". Any trusted
// hop that forwards attacker-supplied XFF unmodified therefore switches the
// per-address login limits off.

TEST(SecurityAudit2026_09, S4_UnparseableForwardedForStillRateLimited) {
    Fixture f;
    f.config.auth_limits.enabled = true;
    f.config.auth_limits.rate_limit = 3;
    f.config.auth_limits.max_failures = 1000;  // isolate the attempt limiter
    AuthHandler handler(*f.store, *f.sync, f.config);

    int limited = 0;
    for (int i = 0; i < 10; ++i) {
        httplib::Request req;
        req.path = "/_matrix/client/v3/login";
        req.remote_addr = "127.0.0.1";  // trusted by default
        req.set_header("X-Forwarded-For", "not-an-address");
        req.body = json{{"type", "m.login.password"},
                        {"identifier", {{"type", "m.id.user"}, {"user", "u" + std::to_string(i)}}},
                        {"password", "wrong-password"}}.dump();
        httplib::Response res;
        handler.handle_login(req, res);
        if (res.status == 429) ++limited;
    }
    EXPECT_GT(limited, 0) << "10 attempts against a limit of 3 were never rate-limited";
}

// ══ S5. The lockout table forgets every lockout when it fills ═══════════════
//
// FailureTracker::prune_locked() clears the WHOLE map at 100,000 keys, so
// filling it with throwaway identifiers lifts the per-account lockout on the
// account actually under attack.

TEST(SecurityAudit2026_09, S5_FillingTheFailureTableDoesNotLiftExistingLockouts) {
    FailureTracker tracker(2, std::chrono::seconds(300));
    tracker.record_failure("user:@victim:test");
    tracker.record_failure("user:@victim:test");
    ASSERT_GT(tracker.locked_for("user:@victim:test"), 0);

    for (int i = 0; i < 100'001; ++i) tracker.record_failure("user:filler" + std::to_string(i));
    EXPECT_GT(tracker.locked_for("user:@victim:test"), 0)
        << "the victim's lockout was discarded when unrelated keys filled the table";
}
