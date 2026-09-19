// The server-wide ban list, and the entry points it has to hold.
//
// Before this, "ban from server" was implemented in the CLIENT: a loop over the
// rooms its own sync had surfaced, calling POST /rooms/{id}/ban once per room,
// with a comment in ServerConnection::banFromServer conceding that rooms the
// client had not synced "fall through the cracks — acceptable". They were not
// acceptable. A banned user stayed a fully joined member of every channel the
// moderator's client had not seen, and because creating any public channel
// force-joins every user on the server, the next channel anybody made silently
// re-admitted them.
//
// The properties under test, in the order they appear:
//   1. A ban prevents joining, and reaches channels the moderator never touched.
//   2. Both auto-join paths refuse a banned user — on registration, and on
//      channel creation.
//   3. A ban survives the deletion of the channel it was placed from. This is why
//      it is a table and not room state: delete_room hard-deletes room events.
//   4. Unban clears it and restores access, and the per-room unban endpoint is
//      the server-wide unban.
//   5. The rank check still holds, and is refused for the RIGHT reason.
//   6. Sync, invite and registration are all closed to a banned identity.
//   7. Migration v15 recovers the bans a pre-existing deployment already had.

#include <gtest/gtest.h>

#include "api/AuthHandler.h"
#include "api/RoomHandler.h"
#include "audit/AuditLog.h"
#include "auth/AutoJoin.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "store/Migrations.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <sqlite3.h>
#include <unistd.h>

#include <filesystem>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-ban-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

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

// A 403 refused for the REASON given, not merely a 403.
//
// Load-bearing here for the same reason it is in test_permission_scope: every
// moderation path can refuse for several separate reasons, and a test that only
// checks the status code passes when the refusal came from somewhere else
// entirely. A prior sweep found five tests green with the fix reverted because a
// rank check was refusing regardless of the property under test.
::testing::AssertionResult IsForbiddenBecause(const httplib::Response& res,
                                              const std::string& needle) {
    if (res.status != 403) {
        return ::testing::AssertionFailure() << "expected 403, got status " << res.status
                                             << ", body: " << res.body;
    }
    if (res.body.find(needle) == std::string::npos) {
        return ::testing::AssertionFailure()
               << "403 for the wrong reason: expected a message containing \"" << needle
               << "\", got: " << res.body;
    }
    return ::testing::AssertionSuccess();
}

template <typename Handler, typename Method>
httplib::Response call(Handler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
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

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kModerator, 10,
                                     permission::kEveryoneDefault | permission::kKickMembers |
                                         permission::kBanMembers));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
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

    // A public text channel, in the shape auto-join recognises: list_public_rooms
    // requires a public join_rule and a non-category bsfchat.room.type.
    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "text"}}.dump(), 1001);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomJoinRules), std::string(""),
                            json{{"join_rule", "public"}}.dump(), 1002);
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, user_id,
                            std::string(event_type::kRoomMember), user_id,
                            json{{"membership", membership::kJoin}}.dump(), 1003);
    }

    std::vector<SqliteStore::AuditRecord> records() {
        return store->list_audit_records(limits::kMaxAuditLimit, std::nullopt).records;
    }

    // A session minted straight into the store, bypassing /login.
    //
    // Needed because a ban now revokes every session AND /login refuses a banned
    // identity, so after a ban there is no legitimate way to obtain a token for
    // that user — which would leave the /join and /sync ban guards unreachable
    // from a test, and therefore untested. This stands in for the state those
    // guards exist to catch: a token that outlived the revocation it should have
    // died in.
    std::string mint_token(const std::string& user_id, const std::string& name) {
        store->store_access_token(name, user_id, "dev");
        return name;
    }
};

const std::string kRoomsPrefix = "/_matrix/client/v3/rooms/";

std::string ban_path(const std::string& room) { return kRoomsPrefix + room + "/ban"; }
std::string unban_path(const std::string& room) { return kRoomsPrefix + room + "/unban"; }
std::string kick_path(const std::string& room) { return kRoomsPrefix + room + "/kick"; }
std::string invite_path(const std::string& room) { return kRoomsPrefix + room + "/invite"; }
std::string join_path(const std::string& room) {
    return "/_matrix/client/v3/rooms/" + room + "/join";
}

std::string target_body(const std::string& user, const std::string& reason = "") {
    json j = {{"user_id", user}};
    if (!reason.empty()) j["reason"] = reason;
    return j.dump();
}

} // namespace

// ══ 1. A ban actually prevents joining, everywhere ════════════════════════

TEST(ServerBan, BanPreventsJoining) {
    Fixture f("prevents-join");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim, "spam"))));
    ASSERT_TRUE(f.store->is_server_banned(victim));

    // The ban revoked the victim's session, so their old token is simply gone.
    EXPECT_EQ(call(handler, &RoomHandler::handle_join, join_path(room), "token-victim").status,
              401);

    // ...and the join guard refuses independently of that, for a token that
    // somehow survived. Both halves matter: without the second, deleting the
    // /join guard would leave this test green, because the 401 above would still
    // fire. (Mutation testing on the sync guard caught exactly that shape.)
    auto survivor = f.mint_token(victim, "token-victim-survivor");
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_join, join_path(room),
                                        survivor),
                                   "You are banned from this server"));
    EXPECT_FALSE(f.store->is_room_member(room, victim));
}

TEST(ServerBan, BanReachesChannelsTheModeratorNeverTouched) {
    Fixture f("reaches-all");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");

    // Three channels. The ban is placed through `general` only — which is exactly
    // what the client's loop did for the rooms it had synced, and it did nothing
    // at all for the ones it had not.
    auto general = f.add_channel(mod, "general");
    auto unsynced = f.add_channel(mod, "off-topic");
    auto also_unsynced = f.add_channel(mod, "secret-plans");
    f.join(general, victim);
    f.join(unsynced, victim);
    f.join(also_unsynced, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(general), "token-mod",
                          target_body(victim))));

    // The membership row, not just the event: every server-side check reads the row.
    for (const auto& room : {general, unsynced, also_unsynced}) {
        EXPECT_EQ(f.store->get_membership(room, victim), membership::kBan) << "room " << room;
        EXPECT_FALSE(f.store->is_room_member(room, victim)) << "room " << room;
    }
    // ...and clients, which rebuild member lists from events, agree.
    auto ev = f.store->get_state_event(unsynced, std::string(event_type::kRoomMember), victim);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->content.data.value("membership", ""), membership::kBan);
}

TEST(ServerBan, BanAppliesToARoomTheTargetWasNeverAMemberOf) {
    Fixture f("nonmember-room");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    // Deliberately NOT joined: POST /rooms/{id}/ban on a non-member must still
    // produce a ban in the room the request named.
    ASSERT_FALSE(f.store->is_room_member(room, victim));

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));

    EXPECT_EQ(f.store->get_membership(room, victim), membership::kBan);
    EXPECT_TRUE(f.store->is_server_banned(victim));
}

// ══ 2. Both auto-join paths refuse a banned user ══════════════════════════

TEST(ServerBan, AutoJoinOnRegistrationRefusesABannedUser) {
    Fixture f("autojoin-registration");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto general = f.add_channel(mod, "general");
    auto other = f.add_channel(mod, "off-topic");

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(general), "token-mod",
                          target_body(victim))));

    // The sweep a registration runs. It force-joins every public channel, which is
    // how a banned account used to walk straight back in.
    auto_join_public_rooms(*f.store, *f.sync, f.config, victim);

    EXPECT_FALSE(f.store->is_room_member(general, victim));
    EXPECT_FALSE(f.store->is_room_member(other, victim));
    EXPECT_TRUE(f.store->get_joined_rooms(victim).empty());
}

TEST(ServerBan, AutoJoinOnChannelCreationRefusesABannedUser) {
    Fixture f("autojoin-creation");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto innocent = f.add_user("innocent");
    auto general = f.add_channel(mod, "general");
    f.join(general, victim);
    f.join(general, innocent);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(general), "token-mod",
                          target_body(victim))));

    // A channel created AFTER the ban. There is no membership row for the ban
    // projection to have touched, so this is the case the projection alone cannot
    // cover and the ban list must.
    auto fresh = f.add_channel(mod, "new-channel");
    auto_join_all_users(*f.store, *f.sync, f.config, fresh, mod);

    EXPECT_FALSE(f.store->is_room_member(fresh, victim));
    // The sweep still works for everybody else — this is not a test that passes
    // because auto_join_all_users stopped doing anything.
    EXPECT_TRUE(f.store->is_room_member(fresh, innocent));
}

TEST(ServerBan, BootBackfillRefusesABannedUser) {
    Fixture f("autojoin-backfill");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto innocent = f.add_user("innocent");
    auto general = f.add_channel(mod, "general");
    f.join(general, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(general), "token-mod",
                          target_body(victim))));

    // The third auto-join path: the one that runs on every server start. If a ban
    // did not hold here, a restart would undo it.
    backfill_auto_join(*f.store, *f.sync, f.config);

    EXPECT_FALSE(f.store->is_room_member(general, victim));
    EXPECT_TRUE(f.store->is_room_member(general, innocent));
}

// ══ 3. A ban survives channel deletion ════════════════════════════════════

TEST(ServerBan, BanSurvivesDeletionOfTheChannelItWasPlacedFrom) {
    Fixture f("survives-delete");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto victim = f.add_user("victim");
    auto general = f.add_channel(admin, "general");
    auto other = f.add_channel(admin, "off-topic");
    f.join(general, victim);
    f.join(other, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(general), "token-admin",
                          target_body(victim, "the reason"))));

    // delete_room hard-deletes every event in the room. A ban recorded as room
    // state — or inferred from the timeline — would be destroyed here, which is
    // exactly why server-wide roles were moved out of room state earlier, and why
    // the ban list is a table of its own.
    f.store->delete_room(general);
    ASSERT_FALSE(f.store->room_exists(general));

    EXPECT_TRUE(f.store->is_server_banned(victim));
    auto ban = f.store->get_server_ban(victim);
    ASSERT_TRUE(ban.has_value());
    EXPECT_EQ(ban->actor, admin);
    EXPECT_EQ(ban->reason, "the reason");

    // And it still bites: the surviving channel is still closed to them.
    auto survivor = f.mint_token(victim, "token-victim-survivor");
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_join, join_path(other),
                                        survivor),
                                   "You are banned from this server"));
}

// ══ 4. Unban ══════════════════════════════════════════════════════════════

TEST(ServerBan, UnbanRestoresAccessEverywhere) {
    Fixture f("unban-restores");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto general = f.add_channel(mod, "general");
    auto other = f.add_channel(mod, "off-topic");
    f.join(general, victim);
    f.join(other, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(general), "token-mod",
                          target_body(victim))));
    ASSERT_EQ(f.store->get_membership(other, victim), membership::kBan);

    // Unbanned through `general`, and it must lift in `other` too — the same
    // "rooms the client never synced" problem in the opposite direction.
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_unban, unban_path(general), "token-mod",
                          target_body(victim))));

    EXPECT_FALSE(f.store->is_server_banned(victim));
    // "leave", not "join": lifting a ban restores the ability to come back, it
    // does not decide for them that they have.
    EXPECT_EQ(f.store->get_membership(general, victim), membership::kLeave);
    EXPECT_EQ(f.store->get_membership(other, victim), membership::kLeave);

    // Unban does NOT resurrect the sessions the ban revoked — those rows are
    // gone, and nothing recreates them. The user comes back by logging in again.
    EXPECT_EQ(call(handler, &RoomHandler::handle_join, join_path(other), "token-victim").status,
              401);

    // And once they have re-authenticated, they can actually come back.
    auto fresh = f.mint_token(victim, "token-victim-relogin");
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_join, join_path(other), fresh)));
    EXPECT_TRUE(f.store->is_room_member(other, victim));
}

TEST(ServerBan, UnbanningSomebodyWhoIsNotBannedIsRefusedForThatReason) {
    Fixture f("unban-notbanned");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    // The actor HAS ban permission and outranks the target, so neither of those
    // can be what refuses this — the precondition is the only thing left.
    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_unban, unban_path(room),
                                        "token-mod", target_body(victim)),
                                   "User is not banned"));
    // Critically, it did not silently kick them instead: "set leave on a user who
    // is not banned" is the wire shape of a kick, and an endpoint named unban must
    // not perform one.
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);
}

TEST(ServerBan, KickingABannedUserDoesNotLiftTheBan) {
    Fixture f("kick-not-unban");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));

    // A kick sets membership to "leave". Inferring intent from that transition
    // would read it as an unban, because the target IS banned — so the dedicated
    // endpoints declare what they are instead of inferring.
    call(handler, &RoomHandler::handle_kick, kick_path(room), "token-mod", target_body(victim));
    EXPECT_TRUE(f.store->is_server_banned(victim))
        << "POST /kick lifted a ban";
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kBan);
}

// ══ 5. The rank check still holds ═════════════════════════════════════════

TEST(ServerBan, ModeratorCannotBanAnAdminAndNoBanIsRecorded) {
    Fixture f("rank");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(mod, "general");
    f.join(room, admin);

    // The actor holds BAN_MEMBERS at server scope, so the permission check passes
    // and rank is the only thing that can refuse. Asserted, so this test cannot
    // quietly become a permission test.
    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(mod, std::string(), permission::kBanMembers));
    ASSERT_FALSE(perms.outranks(mod, admin));

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_ban, ban_path(room),
                                        "token-mod", target_body(admin)),
                                   "Cannot ban a user with equal or higher role"));

    // A refusal must leave NOTHING behind — not a ban row, not a membership
    // change, not an audit record.
    EXPECT_FALSE(f.store->is_server_banned(admin));
    EXPECT_EQ(f.store->get_membership(room, admin), membership::kJoin);
    EXPECT_TRUE(f.records().empty());
}

// ══ 6. Sync, invite and registration ══════════════════════════════════════

TEST(ServerBan, SyncReturnsNothingForABannedUser) {
    Fixture f("sync");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    // Sync works first, so the emptiness below is caused by the ban and not by a
    // fixture that never had anything to return.
    ASSERT_FALSE(f.sync->handle_sync(victim, "", 0).rooms.join.empty());

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));

    EXPECT_TRUE(f.sync->handle_sync(victim, "", 0).rooms.join.empty());
    // And an incremental sync, which takes a different code path.
    EXPECT_TRUE(f.sync->handle_sync(victim, "s0", 0).rooms.join.empty());
}

// The sync guard specifically, isolated from the ban projection.
//
// The test above cannot fail if the guard is deleted: a full ban sets every
// room_members row to "ban", so get_joined_rooms returns nothing and sync is empty
// for that reason alone. Mutation testing caught it passing with the guard removed
// — the exact "green for the wrong reason" shape a prior sweep found five of.
//
// Here the ban row is written with NO projection, which is the state the server is
// in if it dies between the ban-list write and the membership rewrite, or if some
// future code path adds a membership row for a banned user. The guard is what
// makes that state fail closed, so this is the only test that can see it.
TEST(ServerBan, SyncIsClosedByTheBanListEvenWhenMembershipStillSaysJoin) {
    Fixture f("sync-failclosed");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    f.store->set_server_ban(victim, mod, "no projection", 0);

    // The membership row deliberately still says "join" — if the projection had
    // run, this test would be the one above and would prove nothing.
    ASSERT_TRUE(f.store->is_room_member(room, victim));
    ASSERT_FALSE(f.store->get_joined_rooms(victim).empty());

    EXPECT_TRUE(f.sync->handle_sync(victim, "", 0).rooms.join.empty());
    EXPECT_TRUE(f.sync->handle_sync(victim, "s0", 0).rooms.join.empty());
}

TEST(ServerBan, ABannedUserCannotBeInvitedBackIntoAFreshChannel) {
    Fixture f("invite");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto victim = f.add_user("victim");
    auto general = f.add_channel(admin, "general");
    f.join(general, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(general), "token-admin",
                          target_body(victim))));

    // A channel created after the ban: the target has no membership row in it, so
    // the pre-existing "is their membership 'ban' in this room" check reads
    // "leave" and would let the invite through.
    auto fresh = f.add_channel(admin, "fresh");
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_invite, invite_path(fresh),
                                        "token-admin", target_body(victim)),
                                   "User is banned from this server"));
    EXPECT_EQ(f.store->get_membership(fresh, victim), membership::kLeave);
}

TEST(ServerBan, ABannedIdentityCannotReRegister) {
    Fixture f("register");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(rooms, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));

    // The account still exists, so this would ordinarily be refused as
    // "user in use" (400). The ban is checked FIRST and refuses with 403, which is
    // what keeps holding if the account row is ever removed — the ban list has no
    // foreign key to users(user_id) precisely so deleting the account cannot
    // launder the ban.
    //
    // NOT tested, because it is not true: that the same human cannot register a
    // DIFFERENT username. Nothing binds an account to a person on an
    // open-registration deployment. See the comment in AuthHandler::handle_register.
    AuthHandler auth(*f.store, *f.sync, f.config);
    auto res = call(auth, &AuthHandler::handle_register, "/_matrix/client/v3/register", "",
                    json{{"username", "victim"}, {"password", "hunter2hunter2"}}.dump());
    EXPECT_TRUE(IsForbiddenBecause(res, "banned"));
}

// ══ 6b. A ban revokes every session ═══════════════════════════════════════
//
// Without this a ban was "you may stay signed in, but everything you ask for is
// refused" — enforcement resting on every present and future read path
// remembering to consult the ban list. Revocation makes the ban act at the
// identity, not at each endpoint.

TEST(ServerBanSessions, BanRevokesThePreviouslyValidAccessToken) {
    Fixture f("revoke-access");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    // The token works first, so its death below is caused by the ban and not by a
    // fixture that never issued a usable session.
    ASSERT_TRUE(f.store->get_user_by_token("token-victim").has_value());

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));

    EXPECT_FALSE(f.store->get_user_by_token("token-victim").has_value());
    // The moderator's own session is untouched — a ban revokes the target's
    // sessions, not everybody's.
    EXPECT_TRUE(f.store->get_user_by_token("token-mod").has_value());
}

TEST(ServerBanSessions, BanRevokesTheRefreshTokenToo) {
    Fixture f("revoke-refresh");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    // A session WITH a refresh token, which is the interesting case: revoking the
    // access token alone would be pointless, because the refresh token mints a
    // replacement without needing the password.
    f.store->store_access_token("victim-access", victim, "dev",
                                kDefaultAccessTokenLifetimeMs, std::string("victim-refresh"));
    ASSERT_TRUE(f.store->get_user_by_token("victim-access").has_value());

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));

    // The REFRESH token is asserted first, and the order is load-bearing.
    //
    // get_user_by_token reaps a row it finds expired. So if this test checked the
    // access token first, a hypothetical revocation that merely EXPIRED the row
    // instead of deleting it would have the reaping delete the row as a side
    // effect — and the refresh check below would then pass against a row that the
    // assertion above had just removed, rather than against revocation doing its
    // job. Mutation testing found exactly that: replacing the DELETE with an
    // expiry UPDATE left this test green until these two lines were swapped.
    EXPECT_FALSE(f.store->consume_refresh_token("victim-refresh").has_value());
    // ...and it is gone, not merely spent: a ban deletes the row, so there is
    // no consumed-token record either and nothing for reuse detection to
    // revoke. Checked so that the family bookkeeping added in v19 cannot
    // quietly turn a ban into "revoked on the next replay".
    EXPECT_EQ(f.store->revoke_family_for_replayed_refresh_token("victim-refresh"), 0);
    EXPECT_FALSE(f.store->get_user_by_token("victim-access").has_value());
}

TEST(ServerBanSessions, KickDoesNotRevokeSessions) {
    Fixture f("kick-keeps-session");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_kick, kick_path(room), "token-mod",
                          target_body(victim))));

    // A kick is per-channel: the user is removed from one room and remains a
    // member of the server, so signing them out everywhere would be wrong.
    EXPECT_TRUE(f.store->get_user_by_token("token-victim").has_value());
    EXPECT_FALSE(f.store->is_server_banned(victim));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kLeave);
}

TEST(ServerBanSessions, BanningAUserWithNoSessionDoesNotFault) {
    Fixture f("no-session");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    // Revoking zero sessions is an ordinary outcome, not an error: an account that
    // never logged in, or is already logged out, must ban exactly like any other.
    f.store->delete_all_tokens_for_user(victim);
    ASSERT_FALSE(f.store->get_user_by_token("token-victim").has_value());
    EXPECT_EQ(f.store->delete_all_tokens_for_user(victim), 0);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));
    EXPECT_TRUE(f.store->is_server_banned(victim));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kBan);
    // Still exactly one audit record: revocation is a side effect of the decision,
    // not a second decision.
    EXPECT_EQ(f.records().size(), 1u);
}

TEST(ServerBanSessions, ABannedUserCannotLogInAgain) {
    Fixture f("login-refused");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    // add_user stores a bcrypt hash of "password", so this is a real credential.
    const std::string creds =
        json{{"type", "m.login.password"},
             {"identifier", {{"type", "m.id.user"}, {"user", "victim"}}},
             {"password", "password"}}.dump();

    AuthHandler auth(*f.store, *f.sync, f.config);
    // Logging in works BEFORE the ban, so the refusal below is the ban and not a
    // malformed request or a wrong password.
    ASSERT_TRUE(IsOk(call(auth, &AuthHandler::handle_login, "/_matrix/client/v3/login", "",
                          creds)));

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));

    // Revocation without this would be theatre: the client would be logged out and
    // would immediately log back in with the password it still has.
    EXPECT_TRUE(IsForbiddenBecause(call(auth, &AuthHandler::handle_login,
                                        "/_matrix/client/v3/login", "", creds),
                                   "You are banned from this server"));
}

TEST(ServerBanSessions, UnbanLetsTheUserLogInFresh) {
    Fixture f("login-after-unban");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(mod, "general");
    f.join(room, victim);

    const std::string creds =
        json{{"type", "m.login.password"},
             {"identifier", {{"type", "m.id.user"}, {"user", "victim"}}},
             {"password", "password"}}.dump();

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-mod",
                          target_body(victim))));
    // Unban must not error just because the target has no sessions left to restore.
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_unban, unban_path(room), "token-mod",
                          target_body(victim))));

    // The account and its password survived the ban untouched, so the ordinary
    // login path is the way back in — no session was resurrected for them.
    AuthHandler auth(*f.store, *f.sync, f.config);
    auto res = call(auth, &AuthHandler::handle_login, "/_matrix/client/v3/login", "", creds);
    EXPECT_TRUE(IsOk(res));
    auto token = json::parse(res.body).value("access_token", "");
    EXPECT_FALSE(token.empty());
    EXPECT_EQ(f.store->get_user_by_token(token).value_or(""), victim);
}

// ══ 7. Audit records are preserved ════════════════════════════════════════

TEST(ServerBanAudit, BanAndUnbanEachRecordExactlyOneRecord) {
    Fixture f("audit");
    f.seed_roles();
    auto mod = f.add_user("mod", {std::string(permission::role_id::kModerator)});
    auto victim = f.add_user("victim");
    auto general = f.add_channel(mod, "general");
    auto other = f.add_channel(mod, "off-topic");
    f.join(general, victim);
    f.join(other, victim);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(general), "token-mod",
                          target_body(victim, "spam"))));

    // ONE record, not one per projected room. The ban touched two channels but it
    // was one act of authority, and a 40-channel server must not bury its audit
    // log under 40 rows describing the mechanical consequence of one click.
    auto after_ban = f.records();
    ASSERT_EQ(after_ban.size(), 1u);
    EXPECT_EQ(after_ban[0].action, audit_action::kMemberBan);
    EXPECT_EQ(after_ban[0].actor, mod);
    EXPECT_EQ(after_ban[0].target_user, victim);
    EXPECT_EQ(after_ban[0].target_room, general);
    EXPECT_EQ(after_ban[0].reason, "spam");

    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_unban, unban_path(general), "token-mod",
                          target_body(victim))));
    auto after_unban = f.records();
    ASSERT_EQ(after_unban.size(), 2u);
    EXPECT_EQ(after_unban[0].action, audit_action::kMemberUnban);
}

// ══ 8. Migration v15 against a populated pre-existing database ════════════

namespace {

int scalar(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return -1;
    sqlite3_stmt* stmt = nullptr;
    int out = -1;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) out = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

void exec_raw(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
    char* err = nullptr;
    ASSERT_EQ(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err), SQLITE_OK)
        << (err ? err : "?");
    sqlite3_close(db);
}

} // namespace

// The v15 step has a BACKFILL, and a backfill is exactly the kind of step that
// passes on an empty database and does the wrong thing on a populated one. So it
// is exercised against a database that already has rooms, users and — the point —
// pre-existing membership='ban' rows placed by the old client-side loop.
TEST(ServerBanMigration, ExistingPerRoomBansAreRecoveredIntoTheBanList) {
    auto path = temp_db_path("v14-upgrade");
    remove_db(path);

    std::string banned_a = "@banned-a:test";
    std::string banned_b = "@banned-b:test";
    std::string innocent = "@innocent:test";
    std::string room_one = generate_room_id("test");
    std::string room_two = generate_room_id("test");

    // Build a populated database, then wind it back to the v14 shape: drop the
    // table v15 adds and reset user_version. What remains is what a real
    // deployment running yesterday's build looks like.
    {
        SqliteStore store(path);
        store.initialize();
        store.create_user(banned_a, "");
        store.create_user(banned_b, "");
        store.create_user(innocent, "");
        store.create_room(room_one, banned_a);
        store.create_room(room_two, banned_a);

        // banned_a: banned in both rooms, as the client's loop would have left
        // them. banned_b: banned in one room only, because the loop reached one.
        store.set_membership(room_one, banned_a, std::string(membership::kBan));
        store.set_membership(room_two, banned_a, std::string(membership::kBan));
        store.set_membership(room_one, banned_b, std::string(membership::kBan));
        store.set_membership(room_two, banned_b, std::string(membership::kJoin));
        store.set_membership(room_one, innocent, std::string(membership::kJoin));
    }

    ASSERT_EQ(scalar(path, "PRAGMA user_version"), kTargetSchemaVersion);
    exec_raw(path, "DROP TABLE server_bans; PRAGMA user_version = 14;");
    ASSERT_EQ(scalar(path, "PRAGMA user_version"), 14);

    // Reopening runs the migration.
    {
        SqliteStore store(path);
        store.initialize();

        EXPECT_EQ(scalar(path, "PRAGMA user_version"), kTargetSchemaVersion);

        // Both users had at least one ban row, so both are banned. Dropping them
        // would have silently un-banned everybody the instant this migration ran.
        EXPECT_TRUE(store.is_server_banned(banned_a));
        EXPECT_TRUE(store.is_server_banned(banned_b));
        EXPECT_FALSE(store.is_server_banned(innocent));

        // One row per user, not one per (user, room): banned_a had two ban rows.
        EXPECT_EQ(scalar(path, "SELECT COUNT(*) FROM server_bans"), 2);

        // The actor is honestly blank rather than invented — room_members never
        // recorded who placed the ban.
        auto ban = store.get_server_ban(banned_a);
        ASSERT_TRUE(ban.has_value());
        EXPECT_EQ(ban->actor, "");
        EXPECT_GT(ban->created_at, 0);

        // Everything else survived the upgrade.
        EXPECT_TRUE(store.user_exists(innocent));
        EXPECT_TRUE(store.is_room_member(room_one, innocent));
        EXPECT_EQ(store.get_membership(room_two, banned_b), membership::kJoin);
    }

    remove_db(path);
}

TEST(ServerBanMigration, AFreshDatabaseGetsAnEmptyBanList) {
    Fixture f("fresh");
    EXPECT_EQ(scalar(f.db_path, "PRAGMA user_version"), kTargetSchemaVersion);
    EXPECT_EQ(scalar(f.db_path, "SELECT COUNT(*) FROM server_bans"), 0);
    EXPECT_TRUE(f.store->list_server_bans().empty());
}

// ══ 8. The ban-list read endpoint ═════════════════════════════════════════
//
// SqliteStore::list_server_bans existed from v15 but had NO HTTP route and NO
// caller anywhere in server/. The consequence was on the client: its bans tab was
// rebuilt from the m.room.member rows its own sync had surfaced, so a user banned
// while holding no membership row in any synced room never appeared in it — and
// therefore could not be unbanned from it. That is the same blind spot the
// server-wide ban list exists to close, reappearing on the read side.
//
// The properties, in order:
//   a. It is gated on BAN_MEMBERS at SERVER scope — the same permission that
//      places and lifts a ban — and a per-channel override does not grant it.
//   b. It returns bans that NO membership row anywhere could have revealed.
//   c. Pagination is keyset on user_id and stays correct while bans are placed
//      and lifted underneath a reader.

namespace {

// A request with query parameters (the ban list's limit/after).
httplib::Response call_bans(RoomHandler& handler, const std::string& token,
                            const httplib::Params& params = {}) {
    auto req = make_request(std::string(api_path::kServerBans), token);
    req.params = params;
    httplib::Response res;
    handler.handle_list_server_bans(req, res);
    return res;
}

std::vector<std::string> banned_ids(const json& body) {
    std::vector<std::string> out;
    for (const auto& b : body.at("bans")) out.push_back(b.at("user_id").get<std::string>());
    return out;
}

// Writes a per-channel allow/deny override the way handle_set_state does.
void set_override(Fixture& f, const std::string& room_id, const std::string& target,
                  permission::Flags allow, permission::Flags deny) {
    ChannelPermissionOverride ov;
    ov.allow = allow;
    ov.deny = deny;
    json j;
    to_json(j, ov);
    f.store->insert_event(generate_event_id("test"), room_id, "@server:test",
                          std::string(event_type::kChannelPermissions), target, j.dump(), 1002);
}

} // namespace

TEST(ServerBanList, RequiresAuthentication) {
    Fixture f("banlist-401");
    f.seed_roles();
    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_EQ(call_bans(handler, "bogus-token").status, 401);
}

TEST(ServerBanList, PlainMemberIsRefusedForTheRightReason) {
    Fixture f("banlist-403");
    f.seed_roles();
    f.add_user("bob");
    f.store->set_server_ban("@mallory:test", "@admin:test", "spam", 1000);

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call_bans(handler, "token-bob");
    ASSERT_TRUE(IsForbiddenBecause(res, "server ban list")) << res.body;
    EXPECT_EQ(res.body.find("bans"), std::string::npos) << "no ban list may leak in a 403";
    EXPECT_EQ(res.body.find("@mallory"), std::string::npos) << "no ban content may leak";
}

TEST(ServerBanList, BanMembersCanReadAndKickOnlyModeratorCannot) {
    Fixture f("banlist-permission");
    // A role with KICK_MEMBERS but deliberately NOT BAN_MEMBERS, so the gate is
    // exercised on its own flag rather than on a moderator role that happens to
    // carry both.
    ServerRolesContent content;
    content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                 permission::kEveryoneDefault));
    content.roles.push_back(role("kicker", 10,
                                 permission::kEveryoneDefault | permission::kKickMembers));
    content.roles.push_back(role("banner", 20,
                                 permission::kEveryoneDefault | permission::kBanMembers));
    content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
    json j;
    to_json(j, content);
    f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                              j.dump());

    f.add_user("kicker", {"kicker"});
    f.add_user("banner", {"banner"});
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    f.store->set_server_ban("@mallory:test", "@banner:test", "spam", 1000);

    RoomHandler handler(*f.store, *f.sync, f.config);

    // The permission that places a ban is the permission that sees the list.
    // Anything stricter (MANAGE_SERVER) would mean a moderator who may ban cannot
    // see or undo their own bans, which is the bug this endpoint fixes.
    auto banner = call_bans(handler, "token-banner");
    ASSERT_TRUE(IsOk(banner)) << banner.body;
    EXPECT_EQ(json::parse(banner.body).at("bans").size(), 1u);

    // KICK_MEMBERS is not enough: kicking is not banning.
    EXPECT_TRUE(IsForbiddenBecause(call_bans(handler, "token-kicker"), "server ban list"));

    // ADMINISTRATOR short-circuits to every flag, so an admin reads it too.
    EXPECT_TRUE(IsOk(call_bans(handler, "token-admin")));
}

// The escalation shape that has been a real bug here twice.
TEST(ServerBanList, PerChannelOverrideDoesNotGrantAccess) {
    Fixture f("banlist-override-escalation");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin, "bobs-corner");
    f.join(room, bob);
    f.store->set_server_ban("@mallory:test", admin, "spam", 1000);

    // Bob is handed BAN_MEMBERS — and ADMINISTRATOR for good measure — inside this
    // one channel.
    set_override(f, room, "user:" + bob,
                 permission::kBanMembers | permission::kAdministrator, 0);

    // Positive control: the override really is in effect at CHANNEL scope.
    // Without this the assertion below would pass just as well if the override had
    // silently failed to apply, and would prove nothing.
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.can(bob, room, permission::kBanMembers))
            << "override did not apply; the rest of this test would prove nothing";
        EXPECT_FALSE(perms.can(bob, "", permission::kBanMembers));
    }
    // And a control that the list is not simply empty.
    ASSERT_EQ(f.store->list_server_bans(50, std::nullopt).bans.size(), 1u);

    RoomHandler handler(*f.store, *f.sync, f.config);
    // `room_id` and `channel` are parameters this endpoint does NOT define, and
    // they are here on purpose. The permission scope must never be taken from the
    // request: the plausible way to reintroduce this bug is for somebody to add a
    // room filter later and pass it to perms.can() as the scope, at which point
    // Bob's channel override would unlock the server-wide list. Without a request
    // that actually names a room, a test cannot tell a server-scoped check from a
    // room-scoped one that happened to receive an empty string — mutation testing
    // caught exactly that hole here.
    for (const auto& params : std::vector<httplib::Params>{
             {},
             {{"limit", "1"}},
             {{"after", "@a:test"}},
             {{"room_id", room}},
             {{"channel", room}},
             {{"room_id", room}, {"limit", "1"}}}) {
        auto res = call_bans(handler, "token-bob", params);
        ASSERT_TRUE(IsForbiddenBecause(res, "server ban list")) << res.body;
        EXPECT_EQ(res.body.find("@mallory"), std::string::npos)
            << "no ban content may leak in a 403";
    }

    // And the same requests DO work for someone holding BAN_MEMBERS at server
    // scope, so the refusals above are about Bob and not about the parameters.
    auto ok = call_bans(handler, "token-admin", {{"room_id", room}});
    ASSERT_TRUE(IsOk(ok)) << ok.body;
    EXPECT_EQ(json::parse(ok.body).at("bans").size(), 1u)
        << "an unknown parameter must not filter the list either";
}

TEST(ServerBanList, SurfacesABanNoMembershipRowCouldReveal) {
    Fixture f("banlist-invisible");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto ghost = f.add_user("ghost");
    f.store->set_display_name(ghost, "Ghost");

    // The exact case the client could not see: banned while a member of NOTHING,
    // so there is no m.room.member row anywhere for a sync to deliver.
    ASSERT_TRUE(f.store->get_user_memberships(ghost).empty())
        << "the ghost must have no membership rows or this test proves nothing";
    f.store->set_server_ban(ghost, admin, "ban placed out of band", 4242);

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call_bans(handler, "token-admin");
    ASSERT_TRUE(IsOk(res)) << res.body;
    auto body = json::parse(res.body);
    ASSERT_EQ(body.at("bans").size(), 1u);
    const auto& ban = body.at("bans")[0];
    EXPECT_EQ(ban.at("user_id"), ghost);
    EXPECT_EQ(ban.at("actor"), admin);
    EXPECT_EQ(ban.at("reason"), "ban placed out of band");
    EXPECT_EQ(ban.at("created_at"), 4242);
    // The name a moderator recognises. The client cannot derive this for a user
    // with no member events, so a bans tab would otherwise show a bare MXID.
    EXPECT_EQ(ban.at("display_name"), "Ghost");
    EXPECT_EQ(body.at("total"), 1);
}

TEST(ServerBanList, OmitsFieldsTheDatabaseHasNoValueFor) {
    Fixture f("banlist-omissions");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    // The shape migrate_v15 recovers from pre-existing per-room bans: no actor,
    // no reason, and (here) no account row at all, because a ban deliberately
    // outlives the account it names.
    f.store->set_server_ban("@recovered:test", "", "", 7);

    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call_bans(handler, "token-admin");
    ASSERT_TRUE(IsOk(res)) << res.body;
    // Held in a named local: binding a reference into json::parse(...)'s temporary
    // dangles the moment the statement ends.
    const auto body = json::parse(res.body);
    ASSERT_EQ(body.at("bans").size(), 1u);
    const auto& ban = body.at("bans")[0];

    EXPECT_EQ(ban.at("user_id"), "@recovered:test");
    // Absent, not "". An empty string renders as a moderator with no name rather
    // than as "unknown", and the two mean different things here.
    EXPECT_FALSE(ban.contains("actor"));
    EXPECT_FALSE(ban.contains("reason"));
    EXPECT_FALSE(ban.contains("display_name"));
}

TEST(ServerBanList, PaginatesOverTheWholeListWithoutRepeatingOrSkipping) {
    Fixture f("banlist-pages");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});

    std::set<std::string> expected;
    for (int i = 0; i < 17; ++i) {
        // Zero-padded so lexicographic order is also numeric order, making an
        // out-of-order page obvious rather than plausible.
        auto uid = "@u" + std::string(2 - std::to_string(i).size(), '0') +
                   std::to_string(i) + ":test";
        // created_at runs DELIBERATELY BACKWARDS relative to user_id. With the two
        // orderings agreeing, this test could not tell which column the query
        // ordered by, and a mutation swapping ORDER BY user_id for ORDER BY
        // created_at survived it. Anti-correlated, the two disagree on every pair,
        // so ordering by the wrong column fails the strictly-increasing assertion
        // below immediately.
        f.store->set_server_ban(uid, "@admin:test", "r", 9000 - i);
        expected.insert(uid);
    }

    RoomHandler handler(*f.store, *f.sync, f.config);
    std::vector<std::string> seen;
    httplib::Params params{{"limit", "5"}};
    std::string last;
    for (int page = 0; page < 10; ++page) {
        auto res = call_bans(handler, "token-admin", params);
        ASSERT_TRUE(IsOk(res)) << res.body;
        auto body = json::parse(res.body);
        EXPECT_EQ(body.at("total"), 17) << "total is the whole table on every page";
        for (const auto& id : banned_ids(body)) {
            EXPECT_GT(id, last) << "pagination repeated or went backwards";
            last = id;
            seen.push_back(id);
        }
        if (!body.contains("next_from")) break;
        params = {{"limit", "5"}, {"after", body.at("next_from").get<std::string>()}};
    }

    EXPECT_EQ(seen.size(), 17u) << "the walk did not reach every ban";
    EXPECT_EQ(std::set<std::string>(seen.begin(), seen.end()), expected);
}

TEST(ServerBanList, ACursorSurvivesBansPlacedAndLiftedMidWalk) {
    Fixture f("banlist-cursor-stability");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});

    // Bans that exist before the walk starts and are never touched during it.
    std::set<std::string> stable;
    for (int i = 0; i < 8; ++i) {
        auto uid = "@m" + std::to_string(i) + ":test";
        // Anti-correlated with user_id, for the same reason as above: the churn
        // below re-bans @m0 and rewrites its created_at, and that can only be
        // shown to be harmless if created_at is not already the ordering.
        f.store->set_server_ban(uid, "@admin:test", "r", 9000 - i);
        stable.insert(uid);
    }

    RoomHandler handler(*f.store, *f.sync, f.config);
    std::vector<std::string> seen;
    httplib::Params params{{"limit", "2"}};
    for (int page = 0; page < 20; ++page) {
        auto res = call_bans(handler, "token-admin", params);
        ASSERT_TRUE(IsOk(res)) << res.body;
        auto body = json::parse(res.body);
        for (const auto& id : banned_ids(body)) seen.push_back(id);
        if (!body.contains("next_from")) break;
        auto cursor = body.at("next_from").get<std::string>();
        params = {{"limit", "2"}, {"after", cursor}};

        // Churn between pages, of every kind the table permits:
        //  * a brand-new ban far after the cursor (@z...) — may or may not be
        //    seen, but must not disturb anything;
        //  * a RE-ban of an already-listed user, which is a REPLACE that rewrites
        //    created_at. This is precisely why the cursor is user_id and not
        //    created_at: the row moves in a created_at ordering and a reader would
        //    be handed it twice or lose it.
        f.store->set_server_ban("@z" + std::to_string(page) + ":test", "@admin:test", "late",
                                9000 + page);
        f.store->set_server_ban("@m0:test", "@admin:test", "re-banned", 9999);
    }

    // No stable row was returned twice...
    std::set<std::string> unique_seen(seen.begin(), seen.end());
    EXPECT_EQ(unique_seen.size(), seen.size()) << "a ban was returned twice";
    // ...and every stable row was returned at least once, despite the churn.
    for (const auto& id : stable) {
        EXPECT_TRUE(unique_seen.count(id)) << "ban " << id << " was skipped";
    }
}

TEST(ServerBanList, RejectsAMalformedLimitOrAnEmptyCursor) {
    Fixture f("banlist-params");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    RoomHandler handler(*f.store, *f.sync, f.config);

    auto bad_limit = call_bans(handler, "token-admin", {{"limit", "lots"}});
    ASSERT_EQ(bad_limit.status, 400) << bad_limit.body;
    EXPECT_EQ(json::parse(bad_limit.body).value("errcode", ""), "M_INVALID_PARAM");
    EXPECT_NE(json::parse(bad_limit.body).value("error", "").find("limit"), std::string::npos)
        << "refused for the wrong reason: " << bad_limit.body;

    // An empty cursor is refused rather than treated as "start from the
    // beginning": silently restarting would hand a paginating moderator page one
    // forever while looking like progress.
    auto empty_cursor = call_bans(handler, "token-admin", {{"after", ""}});
    ASSERT_EQ(empty_cursor.status, 400) << empty_cursor.body;
    EXPECT_NE(json::parse(empty_cursor.body).value("error", "").find("after"),
              std::string::npos)
        << "refused for the wrong reason: " << empty_cursor.body;
}

TEST(ServerBanList, ClampsAnOversizedLimit) {
    Fixture f("banlist-limit-clamp");
    f.seed_roles();
    f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    for (int i = 0; i < limits::kMaxServerBanLimit + 5; ++i) {
        f.store->set_server_ban("@u" + std::string(4 - std::to_string(i).size(), '0') +
                                    std::to_string(i) + ":test",
                                "@admin:test", "r", 1000 + i);
    }
    RoomHandler handler(*f.store, *f.sync, f.config);
    auto res = call_bans(handler, "token-admin", {{"limit", "100000"}});
    ASSERT_TRUE(IsOk(res)) << res.body;
    auto body = json::parse(res.body);
    EXPECT_EQ(body.at("bans").size(), static_cast<size_t>(limits::kMaxServerBanLimit));
    EXPECT_TRUE(body.contains("next_from"));
}

TEST(ServerBanList, AnUnbanRemovesTheEntry) {
    Fixture f("banlist-unban");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(admin, "general");
    f.join(room, bob);

    RoomHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_ban, ban_path(room), "token-admin",
                          json{{"user_id", bob}, {"reason", "spam"}}.dump())));

    auto after_ban = json::parse(call_bans(handler, "token-admin").body);
    ASSERT_EQ(after_ban.at("bans").size(), 1u);
    EXPECT_EQ(after_ban.at("bans")[0].at("user_id"), bob);
    EXPECT_EQ(after_ban.at("bans")[0].at("reason"), "spam");

    // The round trip the client's bans tab needs: read the list, unban from it,
    // read again. This is what could not be done at all before the endpoint
    // existed for a user with no synced membership row.
    ASSERT_TRUE(IsOk(call(handler, &RoomHandler::handle_unban, unban_path(room), "token-admin",
                          json{{"user_id", bob}}.dump())));
    auto after_unban = json::parse(call_bans(handler, "token-admin").body);
    EXPECT_TRUE(after_unban.at("bans").empty());
    EXPECT_EQ(after_unban.at("total"), 0);
}
