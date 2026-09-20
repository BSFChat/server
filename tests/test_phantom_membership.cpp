// A membership row is never written for an account that does not exist.
//
// ── The bug ──────────────────────────────────────────────────────────────
//
// POST /rooms/{id}/invite took the `user_id` out of the request body, checked
// the caller's permission and the TARGET'S BAN STATE, and wrote the membership
// row. It never asked whether the id named an account, and `room_members` has
// no foreign key to `users` to ask on its behalf (SqliteStore.cpp: room_id
// REFERENCES rooms, user_id references nothing, while access_tokens, bots and
// linked_identities all constrain theirs). So inviting `@tpyo:chat.bsfchat.com`
// — a mistyped localpart, a pasted id from another homeserver, anything at all
// — returned 200 with `{}` and left a membership row behind for an account that
// does not exist. Nothing anywhere surfaced it, and the operator who sent it had
// every reason to believe it had worked.
//
// ── What the row then does ───────────────────────────────────────────────
//
// It is not inert. GET /rooms/{id}/members reports every row in room_members
// with no membership predicate, so the phantom appears in the roster with no
// displayname and no avatar (member_event_content reads a profile that is not
// there) — and, if the mistyped id happens to start with the bot prefix, with a
// bot badge, because that endpoint classifies from the id alone. The
// m.room.member event goes into the room, so every joined client renders the
// arrival. joined_member_count (AuditLog.cpp) counts a phantom `join`. The
// presence sweep in SyncHandler walks joined members. project_membership_
// everywhere finds the row and writes more events onto it. And the account the
// operator MEANT to add is not in the channel at all.
//
// ── The three ways in, all closed here ───────────────────────────────────
//
// A sweep for "membership written from a caller-supplied id" found three:
//
//   1. POST /rooms/{id}/invite          — the reported one.
//   2. PUT  /rooms/{id}/state/m.room.member/{userId} with membership join or
//      invite — the same decision through the generic state route, which
//      classify_transition sends to invite_intent(). This one FORCE-JOINS,
//      so it is strictly worse than the reported bug.
//   3. POST /rooms/{id}/ban — which must keep working on an id with no
//      account (a pre-ban is a reservation: handle_register consults the ban
//      list before it creates anything), but must not invent a membership row
//      in the origin room while it does.
//
// POST /rooms/{id}/kick and /unban were checked and cannot produce one:
// require_target_in_room and require_target_banned both refuse first.
// handle_create_room's `invite` list has checked user_exists since the DM work.
//
// ── The disclosure question, which is the reason for the last two tests ──
//
// "Does this account exist" is the question a directory attack asks, and a
// refusal that answers it is an oracle. The argument for answering it here is
// written out in full at kNoSuchAccount in RoomHandler.cpp; what the tests pin
// is the boundary it depends on — that the answer is never reachable by a
// caller who has not already passed the MANAGE_CHANNELS check, and that a
// caller who has cannot tell a mistyped localpart from a remote id from a
// malformed string.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-phantom-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

// Everything goes through RoomHandler rather than through the store, for the
// same reason test_sync_invites.cpp does: the subject is what a real request
// writes, and a store-level shortcut would prove nothing about the path a
// client actually takes.
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

    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
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

    httplib::Response post(void (RoomHandler::*method)(const httplib::Request&,
                                                       httplib::Response&),
                           const std::string& path, const std::string& token,
                           const std::string& body) {
        httplib::Request req;
        req.path = path;
        req.body = body;
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        ((*rooms).*method)(req, res);
        return res;
    }

    httplib::Response invite(const std::string& room_id, const std::string& token,
                             const std::string& target) {
        return post(&RoomHandler::handle_invite,
                    "/_matrix/client/v3/rooms/" + room_id + "/invite", token,
                    json{{"user_id", target}}.dump());
    }

    httplib::Response ban(const std::string& room_id, const std::string& token,
                          const std::string& target) {
        return post(&RoomHandler::handle_ban,
                    "/_matrix/client/v3/rooms/" + room_id + "/ban", token,
                    json{{"user_id", target}}.dump());
    }

    // The generic state route, which is the SECOND way to write somebody
    // else's membership and the one that force-joins.
    httplib::Response set_member_state(const std::string& room_id, const std::string& token,
                                       const std::string& target,
                                       const std::string& membership_value) {
        return post(&RoomHandler::handle_set_state,
                    "/_matrix/client/v3/rooms/" + room_id + "/state/" +
                        std::string(event_type::kRoomMember) + "/" + target,
                    token, json{{"membership", membership_value}}.dump());
    }

    // Every m.room.member event in the room whose state key is `target`. The
    // membership row is only half the damage; the event is what other clients
    // render, and a fix that wrote one without the other would be the exact
    // defect apply_membership_moderation was built to stop.
    int member_events_for(const std::string& room_id, const std::string& target) {
        int n = 0;
        for (const auto& ev : store->get_room_events(room_id, 1000)) {
            if (ev.type == event_type::kRoomMember &&
                ev.state_key && *ev.state_key == target) {
                ++n;
            }
        }
        return n;
    }

    bool has_membership_row(const std::string& room_id, const std::string& target) {
        for (const auto& [uid, state_value] : store->get_room_members(room_id)) {
            if (uid == target) return true;
        }
        return false;
    }
};

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

bool mentions_no_account(const httplib::Response& res) {
    return res.body.find("no account") != std::string::npos;
}

} // namespace

// ── 1. the reported bug ──────────────────────────────────────────────────

TEST(PhantomMembership, InvitingAnIdWithNoAccountIsRefusedAndWritesNothing) {
    Fixture f("invite-typo");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(alice, "general");

    const std::string ghost = "@tpyo:test";
    auto res = f.invite(room, "token-alice", ghost);

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_no_account(res)) << res.body;

    // Both halves, separately. The 200 was the visible symptom; the row and the
    // event are the thing that outlives the request.
    EXPECT_FALSE(f.has_membership_row(room, ghost));
    EXPECT_EQ(f.member_events_for(room, ghost), 0);
    EXPECT_EQ(f.store->get_membership(room, ghost), std::string(membership::kLeave));
}

TEST(PhantomMembership, InvitingAnIdFromAnotherHomeserverIsRefusedTheSameWay) {
    // There is no federation on this server, so an id whose domain is not ours
    // can never name an account here. The client has been GUESSING at this with
    // a warning (ChannelInviteModel::homeserverWarning) precisely because the
    // server would not say.
    Fixture f("invite-remote");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(alice, "general");

    auto res = f.invite(room, "token-alice", "@nobody:example.org");
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_no_account(res)) << res.body;
    EXPECT_FALSE(f.has_membership_row(room, "@nobody:example.org"));
}

TEST(PhantomMembership, AFictionalBotIdIsRefusedRatherThanJoinedOutright) {
    // The bot branch of handle_invite JOINS outright and emits a join event sent
    // BY the bot. It is gated on store_.is_bot(), which reads the users table,
    // so a fictional @bot_* id has always fallen THROUGH to the human path — the
    // damage was an invite row rather than a join. That is the only reason this
    // was not much worse, and it is a property worth holding still: nothing
    // should ever emit a join event whose sender is an account that does not
    // exist.
    Fixture f("invite-fake-bot");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(alice, "general");

    const std::string fake_bot = "@bot_ghost:test";
    auto res = f.invite(room, "token-alice", fake_bot);

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_no_account(res)) << res.body;
    EXPECT_FALSE(f.has_membership_row(room, fake_bot));
    EXPECT_EQ(f.member_events_for(room, fake_bot), 0);
}

TEST(PhantomMembership, InvitingARealAccountStillWorks) {
    // The control. A refusal that also refuses the ordinary case is not a fix.
    Fixture f("invite-control");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");

    EXPECT_TRUE(IsOk(f.invite(room, "token-alice", bob)));
    EXPECT_EQ(f.store->get_membership(room, bob), std::string(membership::kInvite));
    EXPECT_EQ(f.member_events_for(room, bob), 1);
}

// ── 2. the second way in: the generic state route ────────────────────────

TEST(PhantomMembership, TheStateRouteCannotForceJoinAnIdWithNoAccount) {
    // PUT /state/m.room.member/@ghost:test {"membership":"join"} went through
    // classify_transition -> invite_intent(), which has no rank check and no
    // require_target_in_room, and landed on the same unguarded set_membership.
    // Unlike the invite endpoint it writes a JOIN, so the phantom shows up in
    // the roster as a present member and in every joined-member count.
    Fixture f("state-force-join");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(alice, "general");

    const std::string ghost = "@nobody:test";
    auto res = f.set_member_state(room, "token-alice", ghost, std::string(membership::kJoin));

    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_TRUE(mentions_no_account(res)) << res.body;
    EXPECT_FALSE(f.has_membership_row(room, ghost));
    EXPECT_EQ(f.member_events_for(room, ghost), 0);
}

TEST(PhantomMembership, TheStateRouteStillMovesARealAccount) {
    Fixture f("state-control");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");

    EXPECT_TRUE(IsOk(f.set_member_state(room, "token-alice", bob,
                                        std::string(membership::kInvite))));
    EXPECT_EQ(f.store->get_membership(room, bob), std::string(membership::kInvite));
}

// ── 3. the ban path, which must keep its capability ──────────────────────

TEST(PhantomMembership, BanningAnIdWithNoAccountReservesItWithoutAMembershipRow) {
    // A ban on an id nobody holds is NOT a mistake to refuse. handle_register
    // consults the ban list before it creates anything, so banning an id that
    // does not exist yet is the only way to stop it being registered — and
    // `server_bans` deliberately has no foreign key to `users` for that reason.
    // What must not happen is the membership row: project_membership_everywhere
    // force-writes the ORIGIN room even when the target has no row there, which
    // is right for a real non-member and is how a phantom got in here.
    Fixture f("ban-reservation");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(alice, "general");

    const std::string future = "@spammer:test";
    EXPECT_TRUE(IsOk(f.ban(room, "token-alice", future)));

    // The capability is intact...
    EXPECT_TRUE(f.store->is_server_banned(future));
    // ...and nothing was invented in the channel.
    EXPECT_FALSE(f.has_membership_row(room, future));
    EXPECT_EQ(f.member_events_for(room, future), 0);
}

TEST(PhantomMembership, BanningARealNonMemberStillWritesTheRowInTheOriginRoom) {
    // The control for the branch above, and the behaviour the override in
    // project_membership_everywhere exists for: POST /rooms/{id}/ban against a
    // real account that is not in that room must still produce a ban there.
    Fixture f("ban-control");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");

    EXPECT_TRUE(IsOk(f.ban(room, "token-alice", bob)));
    EXPECT_TRUE(f.store->is_server_banned(bob));
    EXPECT_EQ(f.store->get_membership(room, bob), std::string(membership::kBan));
    EXPECT_EQ(f.member_events_for(room, bob), 1);
}

// ── 4. the disclosure boundary ───────────────────────────────────────────

TEST(PhantomMembership, AnUnprivilegedCallerLearnsNothingAboutWhetherAnAccountExists) {
    // THE constraint on this refusal. A caller without MANAGE_CHANNELS must get
    // byte-identical answers for a real account and a fictional one, so the
    // endpoint is not a namespace walk for an ordinary member. The existence
    // check is therefore ordered AFTER the permission check, the same way the
    // ban checks already are.
    Fixture f("no-oracle");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");   // @everyone only
    auto bob = f.add_user("bob");           // a real account
    auto room = f.add_channel(alice, "general");
    f.store->set_membership(room, mallory, std::string(membership::kJoin));

    auto real = f.invite(room, "token-mallory", bob);
    auto fake = f.invite(room, "token-mallory", "@tpyo:test");

    EXPECT_EQ(real.status, 403);
    EXPECT_EQ(fake.status, 403);
    EXPECT_EQ(real.body, fake.body);
    EXPECT_FALSE(mentions_no_account(real)) << real.body;
}

TEST(PhantomMembership, TheRefusalDoesNotSayWhichKindOfWrongIdItWas) {
    // One wording for a mistyped localpart, an id on another homeserver and a
    // string that is not an mxid at all. A privileged caller has no use for the
    // distinction — the remedy is "check what you typed" in all three — and
    // three wordings would classify the namespace for whoever did want it.
    Fixture f("one-wording");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(alice, "general");

    auto typo = f.invite(room, "token-alice", "@tpyo:test");
    auto remote = f.invite(room, "token-alice", "@alice:example.org");
    auto junk = f.invite(room, "token-alice", "not-an-id");

    EXPECT_EQ(typo.status, 403) << typo.body;
    EXPECT_EQ(typo.body, remote.body);
    EXPECT_EQ(typo.body, junk.body);
}
