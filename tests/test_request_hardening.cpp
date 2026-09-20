// Request-path hardening — docs/audit-requests-2026-09.md findings 5, 7, 8, 9,
// 10 and 11.
//
// Each block below names the finding it pins down and the shape of the defect,
// because the interesting part of every one of them is what the server used to
// be willing to TELL you, not what it was willing to do.
//
//   5.  The edit path answered "404 / 400 / 403" for "no such event / exists
//       elsewhere / not yours", which turns PUT .../send into a global
//       event-existence oracle usable from a room you own against an event in a
//       channel you were removed from.
//   7.  A profile write emits one m.room.member per joined channel and wakes
//       every parked /sync, with no rate limit at all.
//   8.  EMBED_LINKS and MENTION_EVERYONE were tested against `body` only, so
//       `formatted_body` — the HTML clients actually render — walked past both.
//   9.  /versions published the exact build and git revision to anyone, which
//       tells a scanner which self-hosted instances have not upgraded yet.
//  10.  Config::validate said nothing about the static-TURN branch, where one
//       shared long-lived credential goes to every authenticated account.
//  11.  PUT /state/{type} accepted UNKNOWN types on MANAGE_CHANNELS — the same
//       allow-by-default shape the send path already closed with an allowlist.
//  12.  Nothing anywhere bounded the SIZE of a message. Any member could post a
//       multi-megabyte body, which is then stored, FTS-indexed, delivered to
//       every member through /sync and paginated forever: one request from one
//       account, paid for by everybody else.

#include <gtest/gtest.h>

#include "api/AuthHandler.h"
#include "api/EventHandler.h"
#include "api/ProfileHandler.h"
#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>
#include <spdlog/sinks/ringbuffer_sink.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
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

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

::testing::AssertionResult HasStatus(const httplib::Response& res, int want) {
    const int got = res.status == -1 ? 200 : res.status;
    if (got == want) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure()
           << "expected " << want << ", got " << got << ", body: " << res.body;
}

struct Fixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;

    Fixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
    }

    std::string add_user(const std::string& localpart) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
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

    // Replaces the server role set with one @everyone carrying exactly `flags`.
    // Used to build "a member who lacks EMBED_LINKS" without inventing a role.
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

    // A per-channel permission override — the natural way to give somebody
    // their own channel, and the lever every scope bug in this codebase has
    // turned out to be. `target` is "user:<mxid>" or "role:<id>".
    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny = 0) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target, j.dump(),
                            now_ms());
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

std::string send_path(const std::string& room, const std::string& txn) {
    return "/_matrix/client/v3/rooms/" + room + "/send/m.room.message/" + txn;
}

std::string state_path(const std::string& room, const std::string& type) {
    return "/_matrix/client/v3/rooms/" + room + "/state/" + type;
}

std::string edit_body(const std::string& target, const std::string& text = "edited") {
    return json{{"msgtype", "m.text"},
                {"body", "* " + text},
                {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}},
                {"m.new_content", {{"msgtype", "m.text"}, {"body", text}}}}
        .dump();
}

} // namespace

// ══ 5. The edit path must not answer questions about other rooms ══════════
//
// The assertion that bites is the EQUALITY of the two answers, not either one
// on its own: a test that only checked "cross-room edit is refused" stayed
// green while the refusal said 400 "Edit target is in a different room", which
// is precisely the disclosure. Compare against a target id that exists nowhere.

TEST(EditOracle, CrossRoomTargetIsIndistinguishableFromNoSuchEvent) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    // A channel Alice cannot see, with a message in it.
    auto hidden = f.add_room(bob);
    auto secret = f.post_message(hidden, bob, "moderation happens here");

    // Alice's own room, from which she replays ids she remembers.
    auto mine = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);

    httplib::Response real;
    auto req_real = make_request(send_path(mine, "t1"), "token-alice", edit_body(secret));
    handler.handle_send_event(req_real, real);

    httplib::Response fake;
    auto req_fake =
        make_request(send_path(mine, "t2"), "token-alice", edit_body(generate_event_id("test")));
    handler.handle_send_event(req_fake, fake);

    EXPECT_TRUE(HasStatus(real, 404));
    EXPECT_TRUE(HasStatus(fake, 404));
    EXPECT_EQ(real.body, fake.body)
        << "an event that exists in another room answers differently from one that does not "
           "exist at all — that difference IS the oracle";
}

// A redacted event in another room must not be distinguishable from a live one
// there either: "which messages get deleted, and when" is the feed the audit
// describes, and it survives a fix that only merges the not-found cases.
TEST(EditOracle, RedactedCrossRoomTargetLooksTheSame) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto hidden = f.add_room(bob);
    auto live = f.post_message(hidden, bob, "still here");
    auto gone = f.post_message(hidden, bob, "deleted by a mod");
    ASSERT_TRUE(f.store->redact_event(gone, bob));

    auto mine = f.add_room(alice);
    EventHandler handler(*f.store, *f.sync, f.config);

    httplib::Response res_live;
    auto req_live = make_request(send_path(mine, "t1"), "token-alice", edit_body(live));
    handler.handle_send_event(req_live, res_live);

    httplib::Response res_gone;
    auto req_gone = make_request(send_path(mine, "t2"), "token-alice", edit_body(gone));
    handler.handle_send_event(req_gone, res_gone);

    EXPECT_TRUE(HasStatus(res_live, 404));
    EXPECT_TRUE(HasStatus(res_gone, 404));
    EXPECT_EQ(res_live.body, res_gone.body)
        << "redaction state in a room the caller cannot see is still being reported";
}

// The chain-resolution loop followed m.relates_to pointers through
// get_event_by_id BEFORE the room check, so it walked out of this room to find a
// parent. Scoping the hops is what stops an edit in room A resolving onto an
// original in room B and then being accepted because the RESOLVED target is
// local.
TEST(EditOracle, ChainResolutionDoesNotLeaveTheRoom) {
    Fixture f;
    auto alice = f.add_user("alice");

    auto other = f.add_room(alice);
    auto original = f.post_message(other, alice, "original, elsewhere");

    // A replacement that lives in Alice's room but points at a parent that does
    // not. Following the pointer would rewrite the target to `original`.
    auto mine = f.add_room(alice);
    auto chained = generate_event_id("test");
    f.store->insert_event(chained, mine, alice, std::string(event_type::kRoomMessage),
                          std::nullopt,
                          json{{"msgtype", "m.text"},
                               {"body", "* first edit"},
                               {"m.relates_to",
                                {{"rel_type", "m.replace"}, {"event_id", original}}}}
                              .dump(),
                          now_ms());

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(mine, "t1"), "token-alice", edit_body(chained));
    handler.handle_send_event(req, res);

    ASSERT_TRUE(IsOk(res)) << "an in-room edit was refused";

    // The stored replacement must point at the in-room event, not at the one the
    // loop would have walked to in the other room.
    auto stored = f.store->get_event_by_id(json::parse(res.body).at("event_id"));
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->content.data["m.relates_to"].value("event_id", ""), chained)
        << "chain resolution followed a relation into another room";
}

// The in-room cases must keep their own answers: inside a channel the caller can
// read, "that is not yours" leaks nothing they cannot already see, and collapsing
// it to 404 would make a perfectly ordinary client error unexplainable.
TEST(EditOracle, SameRoomRefusalsAreStillSpecific) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice);
    f.join(room, bob);

    auto bobs = f.post_message(room, bob, "bob's message");

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(room, "t1"), "token-alice", edit_body(bobs));
    handler.handle_send_event(req, res);

    EXPECT_TRUE(HasStatus(res, 403));
    EXPECT_NE(res.body.find("your own"), std::string::npos) << res.body;
}

TEST(EditOracle, EditingYourOwnMessageStillWorks) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);
    auto mine = f.post_message(room, alice, "typo");

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(room, "t1"), "token-alice", edit_body(mine, "fixed"));
    handler.handle_send_event(req, res);

    EXPECT_TRUE(IsOk(res)) << res.body;
}

// ══ 7. Profile writes are rate limited ════════════════════════════════════
//
// The amplification is (1 request -> N channels), so the test asserts the
// LIMIT, not the fan-out: capping the requests is what bounds the fan-out.

TEST(ProfileFlood, DisplaynameIsRateLimited) {
    Fixture f;
    auto alice = f.add_user("alice");
    for (int i = 0; i < 5; ++i) f.join(f.add_room(alice), alice);

    ProfileHandler handler(*f.store, *f.sync, f.config);
    const std::string path = "/_matrix/client/v3/profile/" + alice + "/displayname";

    int limited = 0;
    for (int i = 0; i < f.config.send_limits.profile_limit + 5; ++i) {
        httplib::Response res;
        auto req = make_request(path, "token-alice",
                                json{{"displayname", "name" + std::to_string(i)}}.dump());
        handler.handle_put_displayname(req, res);
        if (res.status == 429) ++limited;
    }
    EXPECT_GT(limited, 0) << "a profile-write loop was never refused";
}

// All three writes share one budget. They share one amplifier, so separate
// buckets would just triple the ceiling.
TEST(ProfileFlood, AvatarAndNicknameShareTheDisplaynameBudget) {
    Fixture f;
    auto alice = f.add_user("alice");
    f.join(f.add_room(alice), alice);

    ProfileHandler handler(*f.store, *f.sync, f.config);
    for (int i = 0; i < f.config.send_limits.profile_limit; ++i) {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/profile/" + alice + "/displayname",
                                "token-alice", json{{"displayname", "n"}}.dump());
        handler.handle_put_displayname(req, res);
    }

    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/profile/" + alice + "/avatar_url", "token-alice",
                            json{{"avatar_url", "mxc://test/x"}}.dump());
    handler.handle_put_avatar_url(req, res);
    EXPECT_TRUE(HasStatus(res, 429)) << res.body;
}

TEST(ProfileFlood, OrdinaryUseIsUnaffected) {
    Fixture f;
    auto alice = f.add_user("alice");
    f.join(f.add_room(alice), alice);

    ProfileHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request("/_matrix/client/v3/profile/" + alice + "/displayname", "token-alice",
                            json{{"displayname", "Alice"}}.dump());
    handler.handle_put_displayname(req, res);
    EXPECT_TRUE(IsOk(res)) << res.body;
    EXPECT_EQ(f.store->get_display_name(alice).value_or(""), "Alice");
}

// ══ 8. EMBED_LINKS covers every text-bearing field ════════════════════════

TEST(EmbedLinks, FormattedBodyIsGated) {
    Fixture f;
    f.set_everyone(permission::kEveryoneDefault & ~permission::kEmbedLinks);
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        send_path(room, "t1"), "token-alice",
        json{{"msgtype", "m.text"},
             {"body", "see attached"},
             {"format", "org.matrix.custom.html"},
             {"formatted_body", "<a href=\"https://phish.example/login\">chat.host login</a>"}}
            .dump());
    handler.handle_send_event(req, res);

    EXPECT_TRUE(HasStatus(res, 403)) << res.body;
}

TEST(EmbedLinks, EditContentIsGated) {
    Fixture f;
    f.set_everyone(permission::kEveryoneDefault & ~permission::kEmbedLinks);
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);
    auto target = f.post_message(room, alice, "harmless");

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        send_path(room, "t1"), "token-alice",
        json{{"msgtype", "m.text"},
             {"body", "* harmless"},
             {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}},
             {"m.new_content",
              {{"msgtype", "m.text"}, {"body", "now with https://phish.example/login"}}}}
            .dump());
    handler.handle_send_event(req, res);

    EXPECT_TRUE(HasStatus(res, 403)) << res.body;
}

TEST(EmbedLinks, MentionEveryoneInFormattedBodyIsGated) {
    Fixture f;
    f.set_everyone(permission::kEveryoneDefault & ~permission::kMentionEveryone);
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(room, "t1"), "token-alice",
                            json{{"msgtype", "m.text"},
                                 {"body", "hello"},
                                 {"format", "org.matrix.custom.html"},
                                 {"formatted_body", "<b>@everyone</b> look here"}}
                                .dump());
    handler.handle_send_event(req, res);

    EXPECT_TRUE(HasStatus(res, 403)) << res.body;
}

TEST(EmbedLinks, PermittedUserStillPostsFormattedLinks) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        send_path(room, "t1"), "token-alice",
        json{{"msgtype", "m.text"},
             {"body", "look"},
             {"format", "org.matrix.custom.html"},
             {"formatted_body", "<a href=\"https://example.com/\">example</a>"}}
            .dump());
    handler.handle_send_event(req, res);

    EXPECT_TRUE(IsOk(res)) << res.body;
}

// ══ 9. /versions does not fingerprint the build to strangers ══════════════

TEST(VersionsEndpoint, BuildIdentityIsNotServedUnauthenticated) {
    Fixture f;
    AuthHandler handler(*f.store, *f.sync, f.config);

    httplib::Response res;
    httplib::Request req;
    req.path = "/_matrix/client/versions";
    handler.handle_versions(req, res);

    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);

    // The spec fields stay exactly as they were: the client's server-discovery
    // probe decides "this is a homeserver" from `versions` being an array,
    // BEFORE anyone has a token, so hiding these would break adding a server.
    ASSERT_TRUE(body.contains("versions"));
    EXPECT_TRUE(body["versions"].is_array());
    EXPECT_TRUE(body["unstable_features"].value("bsfchat.server", false));

    EXPECT_FALSE(body.contains("bsfchat.version"));
    EXPECT_FALSE(body.contains("bsfchat.revision"));
    EXPECT_FALSE(body.contains("bsfchat.channel"));
}

TEST(VersionsEndpoint, BuildIdentityIsServedToATokenHolder) {
    Fixture f;
    f.add_user("alice");
    AuthHandler handler(*f.store, *f.sync, f.config);

    httplib::Response res;
    auto req = make_request("/_matrix/client/versions", "token-alice");
    handler.handle_versions(req, res);

    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    EXPECT_TRUE(body.contains("bsfchat.version"));
    EXPECT_TRUE(body.contains("bsfchat.revision"));
    EXPECT_TRUE(body.contains("bsfchat.channel"));
}

TEST(VersionsEndpoint, AnInvalidTokenIsTreatedAsNoToken) {
    Fixture f;
    AuthHandler handler(*f.store, *f.sync, f.config);

    httplib::Response res;
    auto req = make_request("/_matrix/client/versions", "not-a-real-token");
    handler.handle_versions(req, res);

    // Still 200 — this endpoint must never require auth, or discovery breaks.
    ASSERT_TRUE(IsOk(res));
    auto body = json::parse(res.body);
    EXPECT_TRUE(body.contains("versions"));
    EXPECT_FALSE(body.contains("bsfchat.revision"));
}

// ══ 10. The shared static TURN credential is a named misconfiguration ═════
//
// The handler cannot fix this — a shared secret handed to an authenticated
// caller is shared however carefully it is handed over — so what is under test
// is that the server can RECOGNISE the state, which is what the startup warning
// is built on.

TEST(TurnCredentials, StaticPasswordModeIsRecognisedAsShared) {
    Config cfg = Config::defaults();
    cfg.voice.enabled = true;
    cfg.voice.turn_uris = {"turn:turn.example.com:3478"};
    cfg.voice.turn_secret.clear();
    cfg.voice.turn_username = "bsfchat";
    cfg.voice.turn_password = "one-password-for-everybody";
    EXPECT_TRUE(turn_credentials_are_shared(cfg.voice));
}

TEST(TurnCredentials, EphemeralModeIsNotShared) {
    Config cfg = Config::defaults();
    cfg.voice.enabled = true;
    cfg.voice.turn_uris = {"turn:turn.example.com:3478"};
    cfg.voice.turn_secret = "a-real-coturn-static-auth-secret";
    cfg.voice.turn_username = "bsfchat";
    cfg.voice.turn_password = "ignored-in-this-mode";
    EXPECT_FALSE(turn_credentials_are_shared(cfg.voice))
        << "the REST-API branch mints a per-user credential; it is the safe mode";
}

TEST(TurnCredentials, NoTurnAtAllIsNotShared) {
    Config cfg = Config::defaults();
    cfg.voice.enabled = true;
    EXPECT_FALSE(turn_credentials_are_shared(cfg.voice));
}

TEST(TurnCredentials, VoiceDisabledIsNotShared) {
    Config cfg = Config::defaults();
    cfg.voice.enabled = false;
    cfg.voice.turn_uris = {"turn:turn.example.com:3478"};
    cfg.voice.turn_password = "one-password-for-everybody";
    EXPECT_FALSE(turn_credentials_are_shared(cfg.voice))
        << "nothing serves /voip/turnServer credentials when voice is off";
}

// ══ 11. Unknown state event types are refused ═════════════════════════════

TEST(StateGate, UnknownTypeIsRefused) {
    Fixture f;
    // MANAGE_CHANNELS exactly — the flag that USED to be the fallback gate. An
    // @everyone without it refuses for lack of permission whether or not the
    // allowlist exists, which is a test that cannot fail.
    f.set_everyone(permission::kEveryoneDefault | permission::kManageChannels);
    auto admin = f.add_user("admin");
    auto room = f.add_room(admin);

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(state_path(room, "com.evil.arbitrary"), "token-admin",
                            json{{"payload", "anything at all"}}.dump());
    handler.handle_set_state(req, res);

    EXPECT_TRUE(HasStatus(res, 403)) << res.body;
    EXPECT_FALSE(f.store->get_state_event(room, "com.evil.arbitrary", "").has_value())
        << "an unknown state type was stored despite the refusal";
}

// ADMINISTRATOR short-circuits every permission flag, so the allowlist has to be
// checked BEFORE the permission test or an owner still gets the hole.
TEST(StateGate, UnknownTypeIsRefusedEvenForAnAdministrator) {
    Fixture f;
    auto admin = f.add_user("admin");
    f.set_everyone(permission::kAllFlags);
    auto room = f.add_room(admin);

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(state_path(room, "bsfchat.not.a.real.type"), "token-admin",
                            json{{"x", 1}}.dump());
    handler.handle_set_state(req, res);

    EXPECT_TRUE(HasStatus(res, 403)) << res.body;
}

// m.room.create describes the room's origin and is written once, by the server.
// It was reachable here on MANAGE_CHANNELS like any other unlisted type.
TEST(StateGate, RoomCreateCannotBeRewritten) {
    Fixture f;
    auto admin = f.add_user("admin");
    f.set_everyone(permission::kAllFlags);
    auto room = f.add_room(admin);

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(state_path(room, std::string(event_type::kRoomCreate)), "token-admin",
                            json{{"creator", "@someone-else:test"}}.dump());
    handler.handle_set_state(req, res);

    EXPECT_TRUE(HasStatus(res, 403)) << res.body;
}

// The allowlist must not have shrunk the surface clients actually use. Every
// type below is one the shipped client PUTs through this route.
TEST(StateGate, EveryTypeTheClientWritesIsStillAccepted) {
    Fixture f;
    auto admin = f.add_user("admin");
    f.set_everyone(permission::kAllFlags);
    auto room = f.add_room(admin);

    RoomHandler handler(*f.store, *f.sync, f.config);
    const std::vector<std::pair<std::string, json>> cases = {
        {std::string(event_type::kRoomName), json{{"name", "general"}}},
        {std::string(event_type::kRoomTopic), json{{"topic", "chatter"}}},
        {std::string(event_type::kRoomAvatar), json{{"url", "mxc://test/a"}}},
        {std::string(event_type::kRoomPowerLevels), json{{"users_default", 0}}},
        {std::string(event_type::kRoomPinnedEvents), json{{"pinned", json::array()}}},
        {std::string(event_type::kRoomJoinRules), json{{"join_rule", "public"}}},
        {std::string(event_type::kRoomCanonicalAlias), json{{"alias", "#general:test"}}},
        {std::string(event_type::kRoomHistoryVisibility), json{{"history_visibility", "shared"}}},
        {std::string(event_type::kRoomVoice), json{{"enabled", true}}},
        {std::string(event_type::kRoomCategory), json{{"order", 3}}},
        {std::string(event_type::kChannelSettings), json{{"slowmode", 0}}},
        {std::string(event_type::kServerInfo), json{{"name", "Test Server"}}},
        {std::string(event_type::kServerScreenShare), json{{"max_quality", 2}}},
    };

    for (const auto& [type, content] : cases) {
        httplib::Response res;
        auto req = make_request(state_path(room, type), "token-admin", content.dump());
        handler.handle_set_state(req, res);
        EXPECT_TRUE(IsOk(res)) << type << " was refused: " << res.body;
    }
}

// ══ 21. bsfchat.server.screenshare is server-wide, so its gate is too ═════
//
// The setting is the maximum screen-share quality FOR THE DEPLOYMENT: the
// client writes it into whichever room happens to be active
// (ServerConnection::setScreenSharePolicy picks m_activeRoomId, falling back to
// the first room in the list) and every client applies whichever copy reaches
// it through /sync, whatever room it arrived in. Nothing scopes it to a
// channel. It was nevertheless gated on MANAGE_CHANNELS evaluated at ROOM
// scope, so an allow override in one unimportant channel — the natural way to
// give somebody their own channel — was a lever on a server-wide media
// setting.
//
// Same shape as bsfchat.room.type, and it gets the same treatment: the
// PERMISSION moves to server scope, the event stays ordinary room state. It is
// deliberately NOT folded into is_server_scoped, which additionally moves the
// authoritative copy into server_state — nothing reads a screen-share cap from
// there, so that would write a row no read path consults while leaving the copy
// clients actually obey exactly where it is now. See the comment on the flag in
// RoomHandler::handle_set_state.

TEST(ServerScopedSettings, PerChannelManageChannelsDoesNotSetTheScreenShareCap) {
    Fixture f;
    auto admin = f.add_user("admin");
    auto mallory = f.add_user("mallory");
    // Nobody holds MANAGE_CHANNELS server-wide.
    f.set_everyone(permission::kEveryoneDefault);
    auto room = f.add_room(admin);
    f.join(room, mallory);
    f.set_override(room, "user:" + mallory, permission::kManageChannels);

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(mallory, room, permission::kManageChannels))
        << "the override did not apply at channel scope; the test proves nothing";
    ASSERT_FALSE(perms.can(mallory, std::string(), permission::kManageChannels));

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(state_path(room, std::string(event_type::kServerScreenShare)),
                            "token-mallory", json{{"max_quality", 0}}.dump());
    handler.handle_set_state(req, res);

    EXPECT_TRUE(HasStatus(res, 403)) << res.body;
    EXPECT_FALSE(f.store->get_state_event(room, std::string(event_type::kServerScreenShare), "")
                     .has_value())
        << "the cap was written anyway";
}

// The ordinary case must still work, or the fix is a denial of service on an
// admin feature. A channel-scoped DENY must not block it either: the setting is
// not about that channel, so a per-channel rule has no say over it in either
// direction. That is what "server scope" means, and checking only the allow
// direction would leave half the bug in place.
TEST(ServerScopedSettings, ServerWideManageChannelsStillSetsTheScreenShareCap) {
    Fixture f;
    auto admin = f.add_user("admin");
    f.set_everyone(permission::kEveryoneDefault | permission::kManageChannels);
    auto room = f.add_room(admin);
    f.set_override(room, "user:" + admin, 0, permission::kManageChannels);

    RoomHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(state_path(room, std::string(event_type::kServerScreenShare)),
                            "token-admin", json{{"max_quality", 1}}.dump());
    handler.handle_set_state(req, res);
    EXPECT_TRUE(IsOk(res)) << res.body;

    // Written as ORDINARY ROOM STATE, which is how every client learns it —
    // this is the half of is_server_scoped that deliberately did NOT move.
    auto stored = f.store->get_state_event(room, std::string(event_type::kServerScreenShare), "");
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->content.data.value("max_quality", -1), 1);
    EXPECT_FALSE(
        f.store->get_server_state(std::string(event_type::kServerScreenShare), "").has_value())
        << "the write moved into server_state, where nothing reads it";
}

// ══ 17 (extension). The auth lockout line is the one an attacker forges ═══
//
// Finding 17 is already fixed where it was reported: PushHandler wraps the
// rejected gateway URL in log_safe, and gateway_url_allowed bounds its length.
// Its closing note asked for a sweep of the other user-controlled strings
// reaching the logger, and named "the AuthHandler lockout lines" as a
// candidate. They are not a candidate — they are the same defect, unauthenticated
// and on the exact line the audit used as its worked example:
//
//   user_failure_key() builds "user:" + the identifier as SUBMITTED, deliberately
//   keyed on what was typed rather than on an account that exists, and
//   record_failure() then logged that key verbatim. A login identifier
//   containing a newline plus a plausible record, failed enough times to trip
//   the lockout, writes whatever the caller likes into the server log — which
//   auth-hardening-2026-09.md finding 19 makes the security-event record by
//   declining to duplicate auth events into AuditLog.
//
// One log call must produce exactly one record. That is what is asserted, rather
// than the presence of any particular escape, because it is the property that
// matters and it cannot be satisfied by escaping only the characters somebody
// thought of.
TEST(LogForgery, ALoginIdentifierCannotWriteExtraLogRecords) {
    auto ring = std::make_shared<spdlog::sinks::ringbuffer_sink_mt>(64);
    auto logger = get_logger();
    logger->sinks().push_back(ring);
    logger->set_level(spdlog::level::trace);

    Fixture f;
    f.config.password_hash_cost = 10;
    f.config.auth_limits.enabled = true;
    f.config.auth_limits.rate_limit = 1000;
    f.config.auth_limits.max_failures = 2;
    f.config.auth_limits.lockout_seconds = 300;
    AuthHandler handler(*f.store, *f.sync, f.config);

    // Two forged records, in the exact shape src/core/Logger.cpp emits.
    const std::string forged =
        "victim\n[2026-09-19 03:11:00.000] [warning] Auth lockout engaged for ip:203.0.113.9\n"
        "[2026-09-19 03:11:01.000] [warning] Auth lockout engaged for ip:198.51.100.4";

    for (int attempt = 0; attempt < 4; ++attempt) {
        httplib::Request req;
        req.path = "/_matrix/client/v3/login";
        req.remote_addr = "198.51.100.7";
        req.body = json{{"type", "m.login.password"},
                        {"identifier", {{"type", "m.id.user"}, {"user", forged}}},
                        {"password", "wrong"}}
                       .dump();
        httplib::Response res;
        handler.handle_login(req, res);
    }

    const auto lines = ring->last_formatted(64);
    logger->sinks().pop_back();

    ASSERT_FALSE(lines.empty()) << "nothing was logged, so the test proves nothing";
    bool saw_lockout = false;
    for (const auto& line : lines) {
        if (line.find("Auth lockout engaged") != std::string::npos) saw_lockout = true;
        // spdlog terminates each record with exactly one newline. Any other
        // newline in the string is a record the caller wrote.
        EXPECT_EQ(std::count(line.begin(), line.end(), '\n'), 1)
            << "a single log call emitted more than one record: " << line;
    }
    EXPECT_TRUE(saw_lockout) << "the lockout never engaged, so the forging path was not reached";
}

// ══ 12. A message body has a size ═════════════════════════════════════════
//
// There was no bound on the text of an m.room.message anywhere — not in the
// client composer, not in Constants.h, not in handle_send_event.
// kMaxMessagesLimit = 1000 is a PAGE SIZE and was repeatedly read as though it
// were a size limit.
//
// The asymmetry is the whole finding: one authenticated member spends one
// request, and every other member of the room pays for the result on every
// sync, every backfill and forever in storage, with the FTS index roughly
// doubling the on-disk cost. Cheaper to send than to receive is the definition
// of an amplifier.
//
// What the tests below pin, in order: the boundary is inclusive and one byte
// past it is refused; formatted_body gets its own larger ceiling because it is
// the same message with markup; an edit cannot smuggle a large body in through
// m.new_content; the request as a whole is bounded whatever the event type, so
// the hole cannot reopen under a key nobody parses; and the two shapes that
// MUST keep working — a fifty-name formatted roster, and non-Latin text, which
// a byte limit taxes hardest.

namespace {

std::string repeat(char c, size_t n) { return std::string(n, c); }

// Body of exactly `bytes` bytes, carrying no URL and no @everyone so neither
// content gate can be what refuses it.
std::string body_of(size_t bytes) { return repeat('a', bytes); }

std::string message_body(const std::string& body) {
    return json{{"msgtype", "m.text"}, {"body", body}}.dump();
}

std::string errcode_of(const httplib::Response& res) {
    try {
        return json::parse(res.body).value("errcode", "");
    } catch (...) {
        return "<unparseable: " + res.body + ">";
    }
}

} // namespace

TEST(MessageSize, ABodyExactlyAtTheLimitIsAccepted) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(room, "t1"), "token-alice",
                            message_body(body_of(limits::kMaxMessageBodyBytes)));
    handler.handle_send_event(req, res);

    EXPECT_TRUE(IsOk(res)) << "the boundary is inclusive: " << res.body;
}

TEST(MessageSize, ABodyOneByteOverTheLimitIsRefused) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(room, "t1"), "token-alice",
                            message_body(body_of(limits::kMaxMessageBodyBytes + 1)));
    handler.handle_send_event(req, res);

    EXPECT_TRUE(HasStatus(res, 413)) << res.body;
    EXPECT_EQ(errcode_of(res), "M_TOO_LARGE");
    // Nothing may be stored. A refusal that still writes the event would leave
    // the amplifier in place and only change what the sender is told.
    EXPECT_TRUE(f.store->get_room_events(room, 100).empty())
        << "an oversize message was stored despite the refusal";
}

// The composer can count what the user typed, so the plain-text ceiling is the
// one it can warn about in advance. A megabyte is the shape the finding was
// actually about.
TEST(MessageSize, AMultiMegabyteBodyIsRefused) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(room, "t1"), "token-alice",
                            message_body(body_of(4 * 1024 * 1024)));
    handler.handle_send_event(req, res);

    EXPECT_TRUE(HasStatus(res, 413)) << res.body;
    EXPECT_EQ(errcode_of(res), "M_TOO_LARGE");
}

// formatted_body is the same message after markup and is legitimately larger,
// so it has its own ceiling — and that ceiling is real, not absent.
TEST(MessageSize, FormattedBodyGetsALargerCeilingOfItsOwn) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);

    {
        httplib::Response res;
        auto req = make_request(
            send_path(room, "at-limit"), "token-alice",
            json{{"msgtype", "m.text"},
                 {"body", "short"},
                 {"format", "org.matrix.custom.html"},
                 {"formatted_body", body_of(limits::kMaxFormattedBodyBytes)}}
                .dump());
        handler.handle_send_event(req, res);
        EXPECT_TRUE(IsOk(res)) << "formatted_body at its own boundary: " << res.body;
    }
    {
        httplib::Response res;
        auto req = make_request(
            send_path(room, "over"), "token-alice",
            json{{"msgtype", "m.text"},
                 {"body", "short"},
                 {"format", "org.matrix.custom.html"},
                 {"formatted_body", body_of(limits::kMaxFormattedBodyBytes + 1)}}
                .dump());
        handler.handle_send_event(req, res);
        EXPECT_TRUE(HasStatus(res, 413)) << res.body;
        EXPECT_EQ(errcode_of(res), "M_TOO_LARGE");
    }
}

// An edit replaces the message everyone already has, so an unbounded
// m.new_content is the same amplifier reached one level down — and it was the
// exact level the EMBED_LINKS gate had already been caught missing.
TEST(MessageSize, AnOversizeEditIsRefusedAndLeavesTheOriginal) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);
    auto target = f.post_message(room, alice, "hello");

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        send_path(room, "t1"), "token-alice",
        json{{"msgtype", "m.text"},
             {"body", "* edited"},
             {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}},
             {"m.new_content",
              {{"msgtype", "m.text"}, {"body", body_of(limits::kMaxMessageBodyBytes + 1)}}}}
            .dump());
    handler.handle_send_event(req, res);

    EXPECT_TRUE(HasStatus(res, 413)) << res.body;
    EXPECT_EQ(errcode_of(res), "M_TOO_LARGE");

    auto original = f.store->get_event_by_id(target);
    ASSERT_TRUE(original.has_value());
    EXPECT_EQ(original->content.data.value("body", ""), "hello")
        << "the refused edit was applied anyway";
}

// The send allowlist admits m.reaction and the call-signalling types, and
// `content` on any of them is stored and delivered exactly like a message.
// Bounding only the fields we read would leave the hole open under a key
// nobody parses.
TEST(MessageSize, AReactionCarryingABulkFieldIsRefused) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);
    auto target = f.post_message(room, alice, "hello");

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        "/_matrix/client/v3/rooms/" + room + "/send/m.reaction/t1", "token-alice",
        json{{"m.relates_to",
              {{"rel_type", "m.annotation"}, {"event_id", target}, {"key", "\xF0\x9F\x91\x8D"}}},
             // A perfectly valid reaction with 4 MB bolted onto a key the
             // server never looks at.
             {"com.evil.payload", body_of(4 * 1024 * 1024)}}
            .dump());
    handler.handle_send_event(req, res);

    EXPECT_TRUE(HasStatus(res, 413)) << res.body;
    EXPECT_EQ(errcode_of(res), "M_TOO_LARGE");
}

TEST(MessageSize, AnOrdinaryReactionStillWorks) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);
    auto target = f.post_message(room, alice, "hello");

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(
        "/_matrix/client/v3/rooms/" + room + "/send/m.reaction/t1", "token-alice",
        json{{"m.relates_to",
              {{"rel_type", "m.annotation"}, {"event_id", target}, {"key", "\xF0\x9F\x91\x8D"}}}}
            .dump());
    handler.handle_send_event(req, res);

    EXPECT_TRUE(IsOk(res)) << res.body;
}

// The use case that must not break. A bot posting a formatted roster of fifty
// names is a real thing this deployment does (TibiaGuru), and it is the worst
// realistic body/formatted_body ratio there is: every name is a plain word in
// `body` and a full matrix.to anchor in the HTML.
TEST(MessageSize, AFiftyNameFormattedRosterFitsComfortably) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    std::string body;
    std::string html = "<p><b>Raid roster</b></p><ul>";
    for (int i = 0; i < 50; ++i) {
        const std::string name = "Knight Of The Long Name " + std::to_string(i);
        const std::string uid = "@knight_of_the_long_name_" + std::to_string(i) + ":test";
        body += name + " — level 3" + std::to_string(i) + " Elite Knight\n";
        html += "<li><a href=\"https://matrix.to/#/" + uid + "\">" + name +
                "</a> — level 3" + std::to_string(i) + " Elite Knight</li>";
    }
    html += "</ul>";

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(room, "t1"), "token-alice",
                            json{{"msgtype", "m.text"},
                                 {"body", body},
                                 {"format", "org.matrix.custom.html"},
                                 {"formatted_body", html}}
                                .dump());
    handler.handle_send_event(req, res);

    ASSERT_TRUE(IsOk(res)) << res.body;
    // Not just "it fits" — it fits with room to spare, so the limit is not one
    // longer name away from breaking the bot.
    EXPECT_LT(body.size() * 4, limits::kMaxMessageBodyBytes)
        << "a roster body is within a quarter of the plain-text ceiling";
    EXPECT_LT(html.size() * 4, limits::kMaxFormattedBodyBytes)
        << "a roster's HTML is within a quarter of the formatted ceiling";
}

// A byte limit taxes non-Latin text hardest, which is why the number is set
// where it is rather than at Discord's 2,000 characters. Four-byte characters
// are the worst case and still get thousands of them.
TEST(MessageSize, NonLatinTextGetsTheWholeByteBudget) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    // U+1F600, four bytes each. Fill the budget exactly.
    const std::string emoji = "\xF0\x9F\x98\x80";
    const size_t count = limits::kMaxMessageBodyBytes / emoji.size();
    std::string body;
    body.reserve(count * emoji.size());
    for (size_t i = 0; i < count; ++i) body += emoji;

    EventHandler handler(*f.store, *f.sync, f.config);
    httplib::Response res;
    auto req = make_request(send_path(room, "t1"), "token-alice", message_body(body));
    handler.handle_send_event(req, res);

    EXPECT_TRUE(IsOk(res)) << res.body;
    EXPECT_GT(count, 2000u)
        << "worst-case four-byte text must still get more characters than Discord allows";
}

// The number is an operator's to set — a deployment of five friends and one of
// five thousand strangers do not want the same ceiling — so the default must
// not be baked into the handler.
TEST(MessageSize, TheCeilingIsConfigurable) {
    Fixture f;
    f.config.send_limits.max_message_bytes = 2000; // Discord's, roughly
    auto alice = f.add_user("alice");
    auto room = f.add_room(alice);

    EventHandler handler(*f.store, *f.sync, f.config);
    {
        httplib::Response res;
        auto req = make_request(send_path(room, "under"), "token-alice",
                                message_body(body_of(2000)));
        handler.handle_send_event(req, res);
        EXPECT_TRUE(IsOk(res)) << res.body;
    }
    {
        // Comfortably inside the DEFAULT, and refused anyway: the handler is
        // reading config and not the constant.
        httplib::Response res;
        auto req = make_request(send_path(room, "over"), "token-alice",
                                message_body(body_of(2001)));
        handler.handle_send_event(req, res);
        EXPECT_TRUE(HasStatus(res, 413)) << res.body;
        EXPECT_LT(2001u, limits::kMaxMessageBodyBytes)
            << "this case only proves anything while it is under the default";
    }
}

// Zero is "no limit" for every COUNT in [limits] and would be "refuse
// everything" for a size, which is the one reading an operator cannot have
// meant. Same for a value small enough to be a unit mix-up.
TEST(MessageSize, AnUnusableCeilingIsFlooredRatherThanHonoured) {
    Config cfg = Config::defaults();
    cfg.send_limits.max_message_bytes = 0;
    Config::validate(cfg);
    EXPECT_GE(cfg.send_limits.max_message_bytes, 512u)
        << "a zero ceiling would refuse every message ever sent";
}

// The request ceiling has to admit a message that passes the field ceilings,
// or the field ceiling is unreachable and its error message is a lie.
TEST(MessageSize, TheRequestCeilingIsRaisedToFitTheFieldCeilings) {
    Config cfg = Config::defaults();
    cfg.send_limits.max_message_bytes = 64 * 1024; // operator raised one…
    cfg.send_limits.max_event_bytes = 70 * 1024;   // …and not the other
    Config::validate(cfg);
    EXPECT_GT(cfg.send_limits.max_event_bytes,
              cfg.send_limits.max_message_bytes * (1 + limits::kFormattedBodyMultiplier))
        << "a maximal body plus its formatted_body must fit inside the request ceiling";
}

// Defaults must not trip their own validation — if they did, every server
// would log a warning on every boot and operators would learn to ignore it.
TEST(MessageSize, TheDefaultsAreSelfConsistent) {
    Config cfg = Config::defaults();
    const auto before = cfg.send_limits;
    Config::validate(cfg);
    EXPECT_EQ(cfg.send_limits.max_message_bytes, before.max_message_bytes);
    EXPECT_EQ(cfg.send_limits.max_event_bytes, before.max_event_bytes);
}

// The keys have to actually be read out of [limits]. An option documented in
// the example config and silently ignored by the parser is worse than no
// option: the operator believes they have set a ceiling.
TEST(MessageSize, TheKeysLoadFromTheLimitsTable) {
    auto path = std::filesystem::temp_directory_path() / "bsfchat_test_msg_size.toml";
    std::ofstream(path) << "[limits]\n"
                           "max_message_bytes = 4096\n"
                           "max_event_bytes = 262144\n";
    auto cfg = Config::load(path.string());
    std::filesystem::remove(path);
    EXPECT_EQ(cfg.send_limits.max_message_bytes, 4096u);
    EXPECT_EQ(cfg.send_limits.max_event_bytes, 262144u);
}

// toml++ hands back whatever is in the file, and a negative folded into a
// size_t is the largest ceiling there is — a typo that reads as "no limit".
TEST(MessageSize, ANegativeCeilingDoesNotWrapIntoNoLimit) {
    auto path = std::filesystem::temp_directory_path() / "bsfchat_test_msg_size_neg.toml";
    std::ofstream(path) << "[limits]\nmax_message_bytes = -1\n";
    auto cfg = Config::load(path.string());
    std::filesystem::remove(path);
    EXPECT_EQ(cfg.send_limits.max_message_bytes, limits::kMaxMessageBodyBytes)
        << "a nonsense value must fall back to the default, not to SIZE_MAX";
}
