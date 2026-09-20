// POST /rooms/{id}/invite classifies each of its seven refusals.
//
// ── what was wrong ───────────────────────────────────────────────────────
//
// handle_invite answers seven genuinely different situations with 403 and
// M_FORBIDDEN: the caller is not in the room, the room is a DM, the caller
// lacks MANAGE_CHANNELS, the target is banned here, the target is banned
// server-wide, no account holds the id, the target is a deactivated bot. Each
// one calls for different advice, and until now the only thing that told them
// apart was the `error` sentence — so the client's add-member dialog matched
// SUBSTRINGS of it (client/src/model/ChannelInviteModel.cpp, explainFailure,
// whose own comment says a distinct code per refusal is the real fix).
//
// That is brittle in both directions. Reword a sentence here and the client
// silently mis-attributes the refusal or falls through to showing raw server
// text; add an eighth refusal and an earlier fragment may swallow it. Neither
// shows up as a failure on either side.
//
// ── what this file pins ──────────────────────────────────────────────────
//
// THE CODES ARE A WIRE CONTRACT. The client is a separate program in a
// separate repository that compares these against string literals of its own;
// nothing links the two, so a typo is not a build error anywhere — it is a
// branch that silently never fires while the fallback keeps the dialog
// looking like it works. So every expectation below is a hand-written
// literal, never `refusal::kX == refusal::kX`, which would pass against any
// typo. protocol's test_error_codes.cpp pins the same strings from the other
// side; this file pins that the right one reaches the right refusal.
//
// THE SENTENCES ARE UNCHANGED. An older client is still matching them, so
// each case asserts the exact sentence as well as the code. Together those
// two assertions are the compatibility statement: the body gained a field and
// changed nothing else.
//
// THE CODES DISCLOSE NOTHING NEW. handle_invite is safe to be specific
// because of its ORDERING — existence is tested after MANAGE_CHANNELS, so an
// ordinary member's refusal is identical for a real id and a fictional one
// (see kNoSuchAccount in RoomHandler.cpp, and the tests in
// test_phantom_membership.cpp). The last two tests here re-pin that with the
// field present, because a code attached one branch too early would hand an
// attacker a cheaper oracle than the prose ever did.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <set>
#include <memory>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-refusal-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

// Through RoomHandler, not through the store — the subject is what a real
// request puts on the wire, and a store-level shortcut would prove nothing
// about the body a client parses. Same shape as test_phantom_membership.cpp.
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
        store = std::make_unique<SqliteStore>(db_path);
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

    std::string add_bot(const std::string& localpart, const std::string& owner) {
        std::string uid = "@" + localpart + ":test";
        SqliteStore::BotRecord bot;
        bot.user_id = uid;
        bot.display_name = localpart;
        bot.owner_id = owner;
        bot.created_at = ts++;
        bot.created_by = owner;
        store->create_bot(bot);
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    std::string add_room(const std::string& creator, const std::string& name,
                         bool is_direct = false) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator, is_direct);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomCreate, "", json{{"creator", creator}});
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        state(room_id, creator, event_type::kRoomType, "", json{{"type", "text"}});
        state(room_id, creator, event_type::kRoomJoinRules, "",
              json{{"join_rule", join_rule::kInvite}});
        return room_id;
    }

    void state(const std::string& room_id, const std::string& sender,
               std::string_view type, const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ts++);
    }

    httplib::Response invite(const std::string& room_id, const std::string& token,
                             const std::string& target) {
        httplib::Request req;
        req.path = "/_matrix/client/v3/rooms/" + room_id + "/invite";
        req.body = json{{"user_id", target}}.dump();
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        rooms->handle_invite(req, res);
        return res;
    }
};

// One assertion per refusal: the status, the SENTENCE (unchanged, for the
// older client still matching it) and the CODE (hand-written, for the new
// one). Reading the body as JSON rather than searching it, because the point
// of the change is that the client stops searching.
void expect_refusal(const httplib::Response& res, const char* sentence, const char* code) {
    ASSERT_EQ(res.status, 403) << res.body;
    const auto body = json::parse(res.body);
    EXPECT_EQ(body.value("errcode", ""), "M_FORBIDDEN") << res.body;
    EXPECT_EQ(body.value("error", ""), sentence) << res.body;
    EXPECT_EQ(body.value("bsfchat.errcode", ""), code) << res.body;
}

} // namespace

// ── the seven, in the order handle_invite evaluates them ─────────────────

TEST(InviteRefusalCodes, CallerIsNotInTheRoom) {
    Fixture f("not-in-room");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice, "general");
    // mallory holds the permission everywhere but is not in this room, so this
    // is the membership refusal and not the permission one.
    expect_refusal(f.invite(room, "token-mallory", bob),
                   "Not a member of this room", "BSFCHAT.INVITE_NOT_IN_ROOM");
}

TEST(InviteRefusalCodes, TheRoomIsADirectMessage) {
    Fixture f("dm");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto dm = f.add_room(alice, "dm", /*is_direct=*/true);
    f.store->set_membership(dm, bob, std::string(membership::kJoin));
    // alice is a participant AND an admin. Neither helps: a DM cannot be
    // widened by anyone, which is why this is checked before the permission.
    expect_refusal(f.invite(dm, "token-alice", carol),
                   "Cannot invite someone into a direct message",
                   "BSFCHAT.INVITE_DIRECT_ROOM");
}

TEST(InviteRefusalCodes, CallerLacksManageChannels) {
    Fixture f("no-permission");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");   // @everyone only
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice, "general");
    f.store->set_membership(room, mallory, std::string(membership::kJoin));
    expect_refusal(f.invite(room, "token-mallory", bob),
                   "Insufficient permissions to invite",
                   "BSFCHAT.INVITE_NO_PERMISSION");
}

TEST(InviteRefusalCodes, TargetIsBannedFromThisRoom) {
    Fixture f("banned-room");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice, "general");
    f.store->set_membership(room, bob, std::string(membership::kBan));
    expect_refusal(f.invite(room, "token-alice", bob),
                   "User is banned from this room",
                   "BSFCHAT.INVITE_TARGET_BANNED_ROOM");
}

TEST(InviteRefusalCodes, TargetIsBannedFromTheServer) {
    Fixture f("banned-server");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice, "general");
    // No membership row in THIS room — the case the per-room check misses, and
    // the reason the two refusals are separate codes: the remedy differs.
    f.store->set_server_ban(bob, alice, "spam");
    expect_refusal(f.invite(room, "token-alice", bob),
                   "User is banned from this server",
                   "BSFCHAT.INVITE_TARGET_BANNED_SERVER");
}

TEST(InviteRefusalCodes, NoAccountHoldsTheId) {
    Fixture f("no-account");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_room(alice, "general");
    expect_refusal(f.invite(room, "token-alice", "@tpyo:test"),
                   "There is no account on this server with that id",
                   "BSFCHAT.INVITE_NO_SUCH_ACCOUNT");
}

TEST(InviteRefusalCodes, TargetIsADeactivatedBot) {
    Fixture f("deactivated-bot");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_room(alice, "general");
    auto bot = f.add_bot("bot_helper", alice);
    ASSERT_TRUE(f.store->deactivate_bot(bot, 2000));
    expect_refusal(f.invite(room, "token-alice", bot),
                   "That bot is deactivated and cannot be added to a channel",
                   "BSFCHAT.INVITE_TARGET_DEACTIVATED");
}

// ── the properties the seven have to hold as a SET ───────────────────────

TEST(InviteRefusalCodes, NoTwoRefusalsShareACode) {
    // The whole point. Two refusals with one code is the substring collision
    // this replaces, moved into a field where it would be harder to spot.
    // Held as a set rather than asserted case by case so an eighth refusal
    // that reuses a code is caught by a test nobody had to remember to update.
    Fixture f("distinct");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");
    auto outsider = f.add_user("outsider", {std::string(permission::role_id::kAdmin)});
    auto banned_here = f.add_user("banned_here");
    auto banned_server = f.add_user("banned_server");
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice, "general");
    auto dm = f.add_room(alice, "dm", /*is_direct=*/true);
    f.store->set_membership(room, mallory, std::string(membership::kJoin));
    f.store->set_membership(room, banned_here, std::string(membership::kBan));
    f.store->set_server_ban(banned_server, alice, "spam");
    auto bot = f.add_bot("bot_helper", alice);
    ASSERT_TRUE(f.store->deactivate_bot(bot, 2000));

    const std::vector<httplib::Response> refusals = {
        f.invite(room, "token-outsider", bob),      // not in the room
        f.invite(dm, "token-alice", bob),           // DM
        f.invite(room, "token-mallory", bob),       // no MANAGE_CHANNELS
        f.invite(room, "token-alice", banned_here), // banned here
        f.invite(room, "token-alice", banned_server),
        f.invite(room, "token-alice", "@tpyo:test"),
        f.invite(room, "token-alice", bot),
    };

    std::set<std::string> codes;
    for (const auto& res : refusals) {
        ASSERT_EQ(res.status, 403) << res.body;
        const auto code = json::parse(res.body).value("bsfchat.errcode", "");
        EXPECT_FALSE(code.empty()) << "unclassified refusal: " << res.body;
        codes.insert(code);
    }
    EXPECT_EQ(codes.size(), refusals.size());
}

TEST(InviteRefusalCodes, ASuccessCarriesNoCode) {
    // The field belongs to refusals. A `{}` that grew one would be a new thing
    // for a client to have an opinion about for no reason.
    Fixture f("success");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice, "general");
    auto res = f.invite(room, "token-alice", bob);
    EXPECT_TRUE(res.status == -1 || res.status == 200) << res.status << " " << res.body;
    EXPECT_EQ(res.body, "{}");
}

// ── the disclosure boundary, re-pinned with the field present ────────────

TEST(InviteRefusalCodes, AnUnprivilegedCallerStillLearnsNothingAboutExistence) {
    // The same property test_phantom_membership.cpp pins on the prose, asserted
    // again now that there is a second field in the body — because a code
    // attached one branch too early is exactly how this endpoint would become
    // the account-existence oracle the ordering exists to prevent. Byte
    // equality of the WHOLE body, so the new field is inside the guarantee
    // rather than beside it.
    Fixture f("no-oracle");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");   // @everyone only
    auto bob = f.add_user("bob");           // a real account
    auto room = f.add_room(alice, "general");
    f.store->set_membership(room, mallory, std::string(membership::kJoin));

    auto real = f.invite(room, "token-mallory", bob);
    auto fake = f.invite(room, "token-mallory", "@tpyo:test");

    EXPECT_EQ(real.status, 403);
    EXPECT_EQ(fake.status, 403);
    EXPECT_EQ(real.body, fake.body);
    EXPECT_EQ(json::parse(real.body).value("bsfchat.errcode", ""),
              "BSFCHAT.INVITE_NO_PERMISSION");
}

TEST(InviteRefusalCodes, OneCodeForEveryShapeOfWrongId) {
    // A mistyped localpart, an id on another homeserver and a string that is
    // not an mxid share one sentence on purpose. They must share one CODE for
    // the same reason: three codes would classify the namespace for whoever
    // wanted that, and would be a machine-readable version of the distinction
    // the single wording refuses to draw.
    Fixture f("one-code");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_room(alice, "general");

    auto typo = f.invite(room, "token-alice", "@tpyo:test");
    auto remote = f.invite(room, "token-alice", "@alice:example.org");
    auto junk = f.invite(room, "token-alice", "not-an-id");

    ASSERT_EQ(typo.status, 403) << typo.body;
    EXPECT_EQ(typo.body, remote.body);
    EXPECT_EQ(typo.body, junk.body);
    EXPECT_EQ(json::parse(typo.body).value("bsfchat.errcode", ""),
              "BSFCHAT.INVITE_NO_SUCH_ACCOUNT");
}

// ── the rest of the API is deliberately untouched ────────────────────────

TEST(InviteRefusalCodes, AnUnclassifiedRefusalIsTheExactBodyItAlwaysWas) {
    // 113 refusal sites exist; seven are classified, because POST /invite is
    // the only one with a client matching its prose today (explainFailure is
    // the sole such consumer in client/src). Every other refusal must be
    // byte-identical to what it was, so this change cannot have moved anything
    // a client is already parsing. /leave's "Not a member of this room" is the
    // check: it shares its SENTENCE with one of the seven, which is precisely
    // the case where a careless shared-constant refactor would have leaked a
    // code onto an endpoint nobody classified.
    Fixture f("untouched");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(alice, "general");

    httplib::Request req;
    req.path = "/_matrix/client/v3/rooms/" + room + "/leave";
    req.body = "{}";
    req.set_header("Authorization", "Bearer token-bob");
    httplib::Response res;
    f.rooms->handle_leave(req, res);

    ASSERT_EQ(res.status, 403) << res.body;
    EXPECT_EQ(res.body, R"({"errcode":"M_FORBIDDEN","error":"Not a member of this room"})");
}
