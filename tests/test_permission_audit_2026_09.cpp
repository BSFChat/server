// Proof tests for docs/audit-permissions-2026-09.md.
//
// Each test in this file DEMONSTRATES A DEFECT that exists on main at the time
// of writing. They are written to FAIL against the current server and to pass
// once the recommended fix in the audit lands — the opposite polarity from the
// rest of the suite, which pins behaviour that is already correct.
//
// They are disabled by default (DISABLED_ prefix) so that adding an audit to
// the tree does not redden CI before anyone has decided what to do about the
// findings. Run them with:
//
//     ./build/tests/server_tests --gtest_also_run_disabled_tests \
//         --gtest_filter='PermissionAudit2026_09.*'
//
// When a finding is fixed, drop the DISABLED_ prefix and move the test into the
// file that owns the area (test_permission_scope.cpp for F1/F2, and
// test_dm_membership.cpp for F3).
//
// The fixture is deliberately a near-copy of the one in test_permission_scope
// .cpp rather than a shared header: an audit's proofs should not be able to go
// green because somebody changed a helper somewhere else.

#include <gtest/gtest.h>

#include "api/EventHandler.h"
#include "api/MediaHandler.h"
#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "identity/Nickname.h"
#include "storage/LocalStorage.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <regex>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-permaudit-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

::testing::AssertionResult IsForbidden(const httplib::Response& res) {
    if (res.status == 403) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected 403, got status " << res.status
                                         << ", body: " << res.body;
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

    // The role set every test here shares.
    //
    // `builder` is THE ACTOR THESE PROOFS ARE ABOUT: a delegated, non-admin
    // holder of MANAGE_ROLES. It is the role an owner hands to somebody who is
    // trusted to arrange who may see which channel and is deliberately NOT
    // trusted to run the server — exactly the separation
    // PermissionsEngine::may_edit_role_definitions already names in its own
    // comment ("MANAGE_ROLES ... must not be a one-request path to owning the
    // server"). It holds MANAGE_ROLES and nothing else beyond @everyone: no
    // MANAGE_SERVER, no MANAGE_CHANNELS, no ADMINISTRATOR.
    //
    // `member` is an ordinary account holding only @everyone. Every "this is
    // really refused" control asserts against `member`, never against an
    // administrator, because ADMINISTRATOR short-circuits every flag and proves
    // nothing.
    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        content.roles.push_back(role("builder", 10,
                                     permission::kEveryoneDefault | permission::kManageRoles));
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
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, user_id,
                            std::string(event_type::kRoomMember), user_id,
                            member_event_content(*store, user_id,
                                                 std::string(membership::kJoin)).dump(),
                            1002);
    }
};

const std::string kRoomsPrefix = "/_matrix/client/v3/rooms/";

std::string state_path(const std::string& room, const std::string& type,
                       const std::string& key = "") {
    auto p = kRoomsPrefix + room + "/state/" + type;
    if (!key.empty()) p += "/" + key;
    return p;
}

// The latest bsfchat.server.info content anywhere on the server, which is what
// the client renders: ServerConnection applies whichever copy reaches it through
// /sync, whatever room it arrived in (ServerConnection.cpp, the two
// kServerInfo branches).
std::string server_display_name(SqliteStore& store, const std::string& room_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kServerInfo), "");
    return ev ? ev->content.data.value("name", "") : std::string();
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// F1 — bsfchat.server.info is gated at ROOM scope.
//
// RoomHandler.cpp's state_gate_for maps bsfchat.server.info to MANAGE_SERVER,
// but the event is in neither `is_server_scoped` nor `is_scope_only_server_act`,
// so `perm_scope` is the ROOM. A per-channel ALLOW override granting
// MANAGE_SERVER in one channel is therefore enough to rewrite the whole
// deployment's name and icon.
//
// This is the same defect the same function already fixed twice, for
// bsfchat.room.type and bsfchat.server.screenshare, each with a comment saying
// why: the setting is not scoped to the room it is written in, so a per-channel
// grant must not be a lever on it. server.info was left behind.
// ─────────────────────────────────────────────────────────────────────────────

TEST(PermissionAudit2026_09, DISABLED_F1_ChannelOverrideGrantsServerWideRename) {
    Fixture f("f1-rename");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    // An ordinary member. Not a builder, not an admin — the weakest account the
    // server has.
    auto mallory = f.add_user("mallory");

    auto room = f.add_channel(admin, "general");
    f.join(room, mallory);

    RoomHandler rooms(*f.store, *f.sync, f.config);

    // Control: without the override, an ordinary member is refused. If this
    // fails the test proves nothing.
    ASSERT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_set_state,
                                 state_path(room, std::string(event_type::kServerInfo)),
                                 "token-mallory", json{{"name", "control"}}.dump())));

    // An admin gives Mallory MANAGE_SERVER IN THIS ONE CHANNEL. Nothing about
    // this gesture says "you may rename the server": a channel override is, by
    // the model's own description, a statement about one channel.
    ChannelPermissionOverride ov;
    ov.allow = permission::kManageServer;
    json ovj;
    to_json(ovj, ov);
    ASSERT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          state_path(room, std::string(event_type::kChannelPermissions),
                                     "user:" + mallory),
                          "token-admin", ovj.dump())));

    // Mallory now renames the SERVER.
    auto res = call(rooms, &RoomHandler::handle_set_state,
                    state_path(room, std::string(event_type::kServerInfo)), "token-mallory",
                    json{{"name", "Owned"}, {"avatar", "mxc://test/evil"}}.dump());

    // THE ASSERTION THAT FAILS TODAY. A per-channel grant must not reach a
    // server-wide setting, so this must be a 403.
    EXPECT_TRUE(IsForbidden(res))
        << "a per-channel MANAGE_SERVER override rewrote bsfchat.server.info";
    EXPECT_NE(server_display_name(*f.store, room), "Owned")
        << "the server's name was changed by a user holding only a channel override";
}

// ─────────────────────────────────────────────────────────────────────────────
// F2 — channel overrides have no containment rule.
//
// Writing bsfchat.channel.permissions is gated on MANAGE_ROLES at ROOM scope
// and on nothing else. There is no "you cannot grant a bit you do not hold"
// rule (which may_edit_role_definitions enforces for the role document), and no
// rank check on a `user:<target>` override (which may_assign_roles enforces for
// a role assignment). The channel-override route is the third way to hand out
// permissions and it enforces neither.
// ─────────────────────────────────────────────────────────────────────────────

// F2a — a delegated MANAGE_ROLES holder grants itself every flag in the channel.
TEST(PermissionAudit2026_09, DISABLED_F2a_ManageRolesGrantsItselfEveryChannelFlag) {
    Fixture f("f2a-selfgrant");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    PermissionsEngine before(*f.store, f.config);
    // The builder starts with @everyone plus MANAGE_ROLES and nothing else.
    ASSERT_FALSE(before.can(builder, room, permission::kManageChannels));
    ASSERT_FALSE(before.can(builder, room, permission::kManageMessages));
    ASSERT_FALSE(before.can(builder, room, permission::kMentionEveryone));

    RoomHandler rooms(*f.store, *f.sync, f.config);

    ChannelPermissionOverride ov;
    ov.allow = permission::kAllFlags;  // including bits the actor does not hold
    json ovj;
    to_json(ovj, ov);
    auto res = call(rooms, &RoomHandler::handle_set_state,
                    state_path(room, std::string(event_type::kChannelPermissions),
                               "user:" + builder),
                    "token-builder", ovj.dump());

    // THE ASSERTION THAT FAILS TODAY.
    EXPECT_TRUE(IsForbidden(res))
        << "MANAGE_ROLES let the holder grant itself permissions it does not hold";

    PermissionsEngine after(*f.store, f.config);
    EXPECT_FALSE(after.can(builder, room, permission::kManageChannels))
        << "self-granted MANAGE_CHANNELS — this is DELETE /rooms/{id} on this channel";
    EXPECT_FALSE(after.can(builder, room, permission::kManageMessages))
        << "self-granted MANAGE_MESSAGES — redact anyone's message in this channel";
    EXPECT_FALSE(after.can(builder, room, permission::kMentionEveryone));
}

// F2b — the chain. F2a plus F1: MANAGE_ROLES in ONE channel becomes a
// server-wide act, which is the sentence may_edit_role_definitions already says
// must not be true.
TEST(PermissionAudit2026_09, DISABLED_F2b_ManageRolesInOneChannelRenamesTheServer) {
    Fixture f("f2b-chain");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    RoomHandler rooms(*f.store, *f.sync, f.config);

    // Step 1: the builder writes itself a MANAGE_SERVER override in the one
    // channel it was given. MANAGE_ROLES at room scope is the whole gate.
    ChannelPermissionOverride ov;
    ov.allow = permission::kManageServer;
    json ovj;
    to_json(ovj, ov);
    call(rooms, &RoomHandler::handle_set_state,
         state_path(room, std::string(event_type::kChannelPermissions), "user:" + builder),
         "token-builder", ovj.dump());

    // Step 2: it renames the server.
    call(rooms, &RoomHandler::handle_set_state,
         state_path(room, std::string(event_type::kServerInfo)), "token-builder",
         json{{"name", "Owned"}}.dump());

    // THE ASSERTION THAT FAILS TODAY. Either fix alone closes this chain, which
    // is why the audit recommends both.
    EXPECT_NE(server_display_name(*f.store, room), "Owned")
        << "MANAGE_ROLES in one channel was a two-request path to a server-wide setting";
}

// F2c — no rank check on a `user:<target>` override. A delegated MANAGE_ROLES
// holder silences an ADMINISTRATOR in a channel it administers.
//
// may_assign_roles refuses to touch "a user ranked at or above you" and
// ProfileHandler refuses to rename one. The override route, which decides the
// same question about the same people, asks nothing.
TEST(PermissionAudit2026_09, DISABLED_F2c_NoRankCheckOnAUserOverride) {
    Fixture f("f2c-rank");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto builder = f.add_user("builder", {"builder"});

    auto room = f.add_channel(admin, "general");
    f.join(room, builder);

    RoomHandler rooms(*f.store, *f.sync, f.config);

    ChannelPermissionOverride ov;
    ov.deny = permission::kSendMessages | permission::kAddReactions;
    json ovj;
    to_json(ovj, ov);
    auto res = call(rooms, &RoomHandler::handle_set_state,
                    state_path(room, std::string(event_type::kChannelPermissions),
                               "user:" + admin),
                    "token-builder", ovj.dump());

    // THE ASSERTION THAT FAILS TODAY.
    //
    // Note it is only a DENY that bites: ADMINISTRATOR short-circuits inside
    // compute() BEFORE overrides are applied, so an administrator keeps every
    // flag whatever this writes. The defect is the missing rank check, not the
    // effect on this particular target — swap `admin` for any senior
    // non-administrator and the silencing is real.
    EXPECT_TRUE(IsForbidden(res))
        << "a channel override was written against a user ranked above the actor, "
           "with no rank check anywhere on the path";
}

// ─────────────────────────────────────────────────────────────────────────────
// F3 — `is_direct` is a caller-controlled bypass of handle_create_room's
// only permission check, and the room it makes force-joins arbitrary accounts.
//
// handle_create_room reads `is_direct` straight from the request body and skips
// the MANAGE_CHANNELS check when it is true. The invite loop then joins every
// invitee OUTRIGHT (`is_direct` => membership::kJoin) with no cap on the list.
//
// The resulting room is a "DM" by every predicate on the server, which is what
// makes it more than spam: PermissionsEngine::compute() CLEARS channel
// overrides on a direct room, list_room_directory_rows() excludes direct rooms
// in SQL, and handle_delete_room admits only participants. So it is a room
// nobody consented to join, nobody can be denied VIEW_CHANNEL in, no
// administrator can see in the channel directory, and no administrator can
// delete.
// ─────────────────────────────────────────────────────────────────────────────

TEST(PermissionAudit2026_09, DISABLED_F3_IsDirectBypassesCreateRoomPermission) {
    Fixture f("f3-isdirect");
    f.seed_roles();
    auto mallory = f.add_user("mallory");       // @everyone only
    auto victim1 = f.add_user("victim1");
    auto victim2 = f.add_user("victim2");
    auto victim3 = f.add_user("victim3");

    RoomHandler rooms(*f.store, *f.sync, f.config);

    // Control: an ordinary member cannot create a channel. This is the check
    // `is_direct` walks around, and the handler's own comment explains why it
    // exists ("an amplification primitive").
    ASSERT_TRUE(IsForbidden(call(rooms, &RoomHandler::handle_create_room,
                                 "/_matrix/client/v3/createRoom", "token-mallory",
                                 json{{"name", "control"}}.dump())));

    // The same request with one extra body field.
    json body{
        {"is_direct", true},
        {"name", "not a dm"},
        {"invite", json::array({victim1, victim2, victim3})},
    };
    auto res = call(rooms, &RoomHandler::handle_create_room,
                    "/_matrix/client/v3/createRoom", "token-mallory", body.dump());
    ASSERT_TRUE(IsOk(res)) << "expected the bypass to succeed so the rest can be asserted";

    const auto room_id = json::parse(res.body).value("room_id", "");
    ASSERT_FALSE(room_id.empty());

    // THE ASSERTIONS THAT FAIL TODAY.
    //
    // A "direct message" is defined everywhere in this codebase as a
    // conversation between exactly the two people in it, into which nobody is
    // ever force-joined. Both halves are false here.
    EXPECT_NE(f.store->get_membership(room_id, victim1), std::string(membership::kJoin))
        << "an account was force-joined into a room it never asked for, by a user "
           "holding no permission at all";
    EXPECT_NE(f.store->get_membership(room_id, victim2), std::string(membership::kJoin));
    EXPECT_NE(f.store->get_membership(room_id, victim3), std::string(membership::kJoin));

    // And the room is a DM to every predicate that matters, which is what makes
    // the invariant break load-bearing rather than cosmetic.
    if (f.store->is_direct_room(room_id)) {
        PermissionsEngine perms(*f.store, f.config);
        // Nothing can hide it from the people dragged into it: compute() clears
        // channel overrides on a direct room, so a VIEW_CHANNEL deny is inert.
        ChannelPermissionOverride ov;
        ov.deny = permission::kViewChannel;
        json ovj;
        to_json(ovj, ov);
        f.store->insert_event(generate_event_id("test"), room_id, "@server:test",
                              std::string(event_type::kChannelPermissions),
                              std::string("role:") + permission::role_id::kEveryone,
                              ovj.dump(), 2000);
        EXPECT_FALSE(perms.can(victim1, room_id, permission::kViewChannel))
            << "a VIEW_CHANNEL deny is silently discarded because the room claims to "
               "be a DM";
    }
}

// F3b — the multi-party fake DM is invisible to the channel directory AND
// undeletable by an administrator, so there is no moderation remedy.
TEST(PermissionAudit2026_09, DISABLED_F3b_FakeDmHasNoModerationRemedy) {
    Fixture f("f3b-remedy");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");
    auto victim = f.add_user("victim");

    RoomHandler rooms(*f.store, *f.sync, f.config);

    auto res = call(rooms, &RoomHandler::handle_create_room,
                    "/_matrix/client/v3/createRoom", "token-mallory",
                    json{{"is_direct", true}, {"invite", json::array({victim})}}.dump());
    ASSERT_TRUE(IsOk(res));
    const auto room_id = json::parse(res.body).value("room_id", "");
    ASSERT_FALSE(room_id.empty());

    // The administrator is not a participant, so DELETE is refused — the guard
    // that protects a genuine two-person DM from a server admin also protects
    // this.
    auto del = call(rooms, &RoomHandler::handle_delete_room, kRoomsPrefix + room_id,
                    "token-admin");

    // THE ASSERTION THAT FAILS TODAY: an administrator has no way to remove a
    // room an unprivileged account manufactured.
    EXPECT_TRUE(IsOk(del))
        << "an ADMINISTRATOR cannot delete a room created by an unprivileged user, "
           "and the channel directory excludes direct rooms so they cannot find it "
           "either";
}

// ─────────────────────────────────────────────────────────────────────────────
// F4 — NOT A FINDING. Recorded as a control, and ENABLED.
//
// The hypothesis was that POST /createRoom has no server-ban check on the
// CREATOR, so a banned account could manufacture a room with its victim already
// joined (F3 makes the room free) and go on messaging them — the gap handle_join
// closes for every EXISTING channel and cannot close for a channel that does
// not exist yet.
//
// The hypothesis is wrong, and this test says why so the next auditor does not
// re-derive it: apply_membership_moderation calls delete_all_tokens_for_user()
// when it places a server ban (RoomHandler.cpp), and handle_login,
// handle_register and handle_refresh each consult the ban list, so a banned
// account cannot obtain a credential to reach ANY route with. The ban is
// enforced at the credential layer, which is why the absence of a ban check on
// this one handler costs nothing.
//
// Left enabled and asserting the correct behaviour: it is the property that
// makes every unchecked route safe, so it is worth pinning.
// ─────────────────────────────────────────────────────────────────────────────

TEST(PermissionAudit2026_09, BanRevokesEveryCredentialSoCreateRoomIsUnreachable) {
    Fixture f("f4-banevade");
    f.seed_roles();
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");
    auto victim = f.add_user("victim");

    RoomHandler rooms(*f.store, *f.sync, f.config);

    auto channel = f.add_channel(admin, "general");
    f.join(channel, mallory);
    f.join(channel, victim);
    ASSERT_TRUE(IsOk(call(rooms, &RoomHandler::handle_ban, kRoomsPrefix + channel + "/ban",
                          "token-admin",
                          json{{"user_id", mallory}, {"reason", "spam"}}.dump())));
    ASSERT_TRUE(f.store->is_server_banned(mallory));

    auto res = call(rooms, &RoomHandler::handle_create_room,
                    "/_matrix/client/v3/createRoom", "token-mallory",
                    json{{"is_direct", true}, {"invite", json::array({victim})}}.dump());

    // 401, not 403: the token is gone, so the request never reaches the handler.
    EXPECT_EQ(res.status, 401)
        << "a server ban must revoke every session the account holds";
    EXPECT_FALSE(f.store->get_user_by_token("token-mallory").has_value());
}

// ─────────────────────────────────────────────────────────────────────────────
// F5 — the media object -> room binding is written by the caller.
//
// SqliteStore::insert_event indexes EVERY mxc:// string anywhere in an event's
// content into `media_refs` (SqliteStore.cpp, media_uris_in_content), with no
// check that the sender may currently read that object. MediaHandler::
// may_download then answers "VIEW_CHANNEL in any room where a surviving event
// names this object" from that table.
//
// So a user who merely KNOWS a media id — because they saw it while permitted,
// or before it was redacted — re-attaches it to a channel they can still see
// and restores their own access, and grants it to everyone else in that channel.
// This is the revocation the B3 fix and the redaction hook both claim to
// perform. The id is 128 random bits, so this is not blind enumeration: it is a
// revocation bypass by whoever already held the id.
// ─────────────────────────────────────────────────────────────────────────────

TEST(PermissionAudit2026_09, DISABLED_F5_ASenderCanRebindMediaItMayNotRead) {
    Fixture f("f5-rebind");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("mallory");

    auto secret = f.add_channel(alice, "leadership");
    auto open = f.add_channel(alice, "general");
    f.join(secret, mallory);
    f.join(open, mallory);

    // Alice posts an attachment in #leadership.
    const std::string media_id = "00000000000000000000000000000abc";
    const std::string mxc = "mxc://test/" + media_id;
    f.store->insert_media(media_id, alice, "image/png", "p.png", 8, "/x/" + media_id);
    f.store->insert_event(generate_event_id("test"), secret, alice,
                          std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.image"}, {"body", "p.png"}, {"url", mxc}}.dump(),
                          2000);

    // Mallory is then denied the channel. The attachment is supposed to go with
    // it — that is MediaAcl.LosingViewChannelRevokesTheAttachmentsToo.
    ChannelPermissionOverride deny;
    deny.deny = permission::kViewChannel;
    json dj;
    to_json(dj, deny);
    f.store->insert_event(generate_event_id("test"), secret, "@server:test",
                          std::string(event_type::kChannelPermissions), "user:" + mallory,
                          dj.dump(), 2001);

    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_FALSE(perms.can(mallory, secret, permission::kViewChannel))
            << "precondition: Mallory is out of #leadership";
    }

    // Mallory sends a message into #general through the REAL send handler.
    //
    // msgtype is m.text, so EventHandler's `has_attachment` is false and the
    // ATTACH_FILES gate never runs: this needs nothing beyond the @everyone
    // default. The uri rides in an unrecognised key, which the send path stores
    // verbatim and no client renders — media_uris_in_content walks every string
    // at every depth, so the key it sits under is irrelevant.
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    auto sent = call(events, &EventHandler::handle_send_event,
                     kRoomsPrefix + open + "/send/m.room.message/txn-f5", "token-mallory",
                     json{{"msgtype", "m.text"}, {"body", "hi"},
                          {"com.example.note", mxc}}.dump());
    ASSERT_TRUE(IsOk(sent)) << "the send itself is legitimate and must succeed";

    // THE ASSERTION THAT FAILS TODAY. #general must not become a room in which
    // this object is readable, because the person who put the reference there
    // was not allowed to read it.
    auto bound = f.store->get_media_rooms(mxc);
    EXPECT_EQ(std::find(bound.begin(), bound.end(), open), bound.end())
        << "a sender who may not read an object bound it to a channel of their "
           "choosing, restoring their own access and publishing it to everyone "
           "who can see that channel";

    // Not asserted through handle_download here on purpose: that path also
    // touches the storage backend, so a 404 from a missing blob would look
    // like a refusal. The binding above IS the defect — may_download's rule 2
    // is "VIEW_CHANNEL in any room where a surviving event names this object",
    // and Mallory has just named it in a room where she has VIEW_CHANNEL.
}

// ─────────────────────────────────────────────────────────────────────────────
// F6 — the bot rank check measures roles, and a scoped bot holds none.
//
// authorize_bot_admin gates token rotation on `outranks(actor, bot)`, and
// BotHandler.h explains why: a bot token is a bearer credential for the bot's
// access. But `highest_role_position` reads ONLY the role assignment
// (Permissions.cpp) — per-channel overrides contribute nothing to rank — and
// BotHandler.h itself prescribes the channel override as THE way to scope a
// bot ("Granting a bot a channel is writing bsfchat.channel.permissions with
// state_key user:<bot id>"), while handle_create_bot writes the new bot an
// explicitly EMPTY role assignment.
//
// So a correctly-scoped bot sits at position 0 forever, and every MANAGE_BOTS
// holder at position >= 1 outranks it. The rank check is inert for exactly the
// configuration the feature documents.
// ─────────────────────────────────────────────────────────────────────────────

TEST(PermissionAudit2026_09, DISABLED_F6_BotRankIsBlindToChannelOverrides) {
    Fixture f("f6-botrank");

    // A `botmod` role holding MANAGE_BOTS and nothing else beyond @everyone, at
    // a position above @everyone — the delegated bot administrator the flag
    // exists to make possible.
    ServerRolesContent content;
    content.roles.push_back(
        role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
    content.roles.push_back(role("botmod", 10,
                                 permission::kEveryoneDefault | permission::kManageBots));
    content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
    json rj;
    to_json(rj, content);
    f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                              rj.dump());

    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto botmod = f.add_user("botmod", {"botmod"});

    // A channel the bot administrator is explicitly shut out of.
    auto secret = f.add_channel(admin, "leadership");
    f.join(secret, botmod);
    ChannelPermissionOverride deny;
    deny.deny = permission::kViewChannel;
    json dj;
    to_json(dj, deny);
    f.store->insert_event(generate_event_id("test"), secret, "@server:test",
                          std::string(event_type::kChannelPermissions), "user:" + botmod,
                          dj.dump(), 3000);

    // A bot, scoped the way BotHandler.h says to scope one: no roles at all,
    // plus a `user:<bot>` ALLOW override on the channel it is for.
    const std::string bot_id = "@bot_minutes:test";
    f.store->create_user(bot_id, std::string());
    {
        MemberRolesContent none;  // exactly what handle_create_bot writes
        json j;
        to_json(j, none);
        f.store->set_server_state(std::string(event_type::kMemberRoles), bot_id,
                                  "@server:test", j.dump());
    }
    ChannelPermissionOverride allow;
    allow.allow = permission::kViewChannel | permission::kSendMessages;
    json aj;
    to_json(aj, allow);
    f.store->insert_event(generate_event_id("test"), secret, "@server:test",
                          std::string(event_type::kChannelPermissions), "user:" + bot_id,
                          aj.dump(), 3001);
    f.store->set_membership(secret, bot_id, std::string(membership::kJoin));

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_FALSE(perms.can(botmod, secret, permission::kViewChannel))
        << "precondition: the bot administrator cannot see #leadership";
    ASSERT_TRUE(perms.can(bot_id, secret, permission::kViewChannel))
        << "precondition: the bot can";

    // THE ASSERTION THAT FAILS TODAY. `outranks` is the ONLY thing standing
    // between this actor and a permanent credential for an account that can
    // read a channel they cannot, and it says yes.
    EXPECT_FALSE(perms.outranks(botmod, bot_id))
        << "a MANAGE_BOTS holder outranks a channel-scoped bot, so POST "
           "/bsfchat/bots/{id}/token hands them a non-expiring credential for an "
           "account with access they do not have";
}
