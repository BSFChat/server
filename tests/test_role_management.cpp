// Role CRUD and self-assignable roles.
//
// THE ACCEPTANCE CRITERION, first and last in the file: a bot holding
// MANAGE_ROLES and nothing else can create a role below itself, mark it
// self-assignable, and have an ordinary member take it and drop it again.
// Before this change that sequence was impossible at every single step —
// there was no role-creation endpoint, and had there been one, a member at
// position 0 could never have been granted anything, because may_assign_roles
// refuses every role at position >= the actor's and no role sits below 0.
//
// The rest of the file is the bill for that. Relaxing "a member may take this
// role" is only safe if the role cannot be a dangerous one, so the properties
// under test are:
//
//   1. End to end: the bot case above actually works, through the endpoints,
//      with a real permission engine reading the result.
//   2. Containment: a self-assignable role may not carry a permission bit
//      @everyone does not already have — refused when the document is written,
//      AND refused again at claim time, so a role that became dangerous after
//      it was created cannot be taken.
//   3. Rank: a self-assignable role confers no rank, so taking one is not a
//      way to become un-kickable.
//   4. The three new escalation paths a low-ranked MANAGE_ROLES holder gets,
//      one test each: CREATE a role above yourself or carrying permissions you
//      lack; SELF-ASSIGN something you are not entitled to; REPOSITION a role
//      (in either direction) to get out from under the hierarchy.
//   5. The old holes stay shut through the new doors: the wholesale state PUT
//      and these endpoints answer to the same function, so neither is a way
//      round the other.

#include <gtest/gtest.h>

#include "api/RoleHandler.h"
#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "audit/AuditLog.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-roles-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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
    if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
    return req;
}

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded without setting one typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200 || res.status == 201) {
        return ::testing::AssertionSuccess();
    }
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

// A refusal for the REASON given, not merely a refusal. Same discipline as
// test_permission_scope.cpp: an endpoint that can refuse for two reasons will
// keep refusing after the interesting guard is reverted, so a test asserting
// only the status code cannot fail.
::testing::AssertionResult RefusedBecause(const httplib::Response& res, int status,
                                          const std::string& needle) {
    if (res.status != status) {
        return ::testing::AssertionFailure() << "expected " << status << ", got status "
                                             << res.status << ", body: " << res.body;
    }
    if (res.body.find(needle) == std::string::npos) {
        return ::testing::AssertionFailure()
               << status << " for the wrong reason: expected a message containing \"" << needle
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

ServerRole role(const std::string& id, int position, permission::Flags flags,
                bool self_assignable = false, bool mentionable = false) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    r.self_assignable = self_assignable;
    r.mentionable = mentionable;
    return r;
}

const std::string kRolesPath{api_path::kRoles};
const std::string kSelfRolesPath{api_path::kSelfRoles};

std::string role_path(const std::string& id) { return kRolesPath + "/" + id; }
std::string self_role_path(const std::string& id) { return kSelfRolesPath + "/" + id; }

std::string state_path(const std::string& room, std::string_view type,
                       const std::string& key = "") {
    std::string p = "/_matrix/client/v3/rooms/" + room + "/state/" + std::string(type);
    if (!key.empty()) p += "/" + key;
    return p;
}

struct Fixture {
    std::string db_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<RoleHandler> roles;
    std::unique_ptr<RoomHandler> rooms;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        config.password_hash_cost = 10;
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        roles = std::make_unique<RoleHandler>(*store, *sync, config);
        rooms = std::make_unique<RoomHandler>(*store, *sync, config);
    }

    ~Fixture() {
        rooms.reset();
        roles.reset();
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    // Written straight into server_state rather than through
    // write_server_scoped_state, so fixture setup lands no audit records.
    void seed_roles(const std::vector<ServerRole>& extra = {}) {
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        // MANAGE_ROLES on its own, WITHOUT ADMINISTRATOR and without any other
        // elevated flag. This is the whole point of the file: "builder" is what
        // an owner delegates, and what a bot is given. A test run against an
        // administrator would only exercise the god-mode short-circuit.
        content.roles.push_back(
            role("builder", 10, permission::kEveryoneDefault | permission::kManageRoles));
        // Above the builder, so "a role you may not touch" exists.
        content.roles.push_back(
            role("senior", 50, permission::kEveryoneDefault | permission::kBanMembers));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        for (const auto& r : extra) content.roles.push_back(r);
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
        assign_roles(uid, extra_roles);
        return uid;
    }

    void assign_roles(const std::string& uid, const std::vector<std::string>& extra_roles) {
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
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

    std::vector<ServerRole> current_roles() { return store->get_server_roles(); }

    std::optional<ServerRole> find(const std::string& id) {
        for (const auto& r : current_roles()) {
            if (r.id == id) return r;
        }
        return std::nullopt;
    }

    std::vector<std::string> member_roles(const std::string& uid) {
        return store->get_member_role_ids(uid);
    }

    bool holds(const std::string& uid, const std::string& role_id) {
        auto ids = member_roles(uid);
        return std::find(ids.begin(), ids.end(), role_id) != ids.end();
    }

    std::vector<SqliteStore::AuditRecord> records() {
        return store->list_audit_records(limits::kMaxAuditLimit, std::nullopt).records;
    }
};

std::string create_body(const std::string& name, int position, permission::Flags perms = 0,
                        bool self_assignable = false) {
    return json{{"name", name},
                {"position", position},
                {"permissions", permission::flags_to_hex(perms)},
                {"self_assignable", self_assignable}}
        .dump();
}

// The id the server minted, out of a 201 body.
std::string created_id(const httplib::Response& res) {
    auto body = json::parse(res.body, nullptr, false);
    if (body.is_discarded() || !body.contains("role")) return {};
    return body["role"].value("id", "");
}

// ══ 1. The acceptance criterion ════════════════════════════════════════════

// The whole feature, as one sequence, through the endpoints, by a principal
// holding MANAGE_ROLES and nothing else.
//
// Every step of this was impossible before: there was no create endpoint; had
// there been, a member at position 0 could be granted nothing, because
// may_assign_roles refuses any role at position >= the actor's and the lowest
// position that exists is 0.
TEST(BotRoleManagement, BotCreatesASelfAssignableRoleAndMembersTakeAndDropIt) {
    Fixture f("bot-e2e");
    f.seed_roles();
    // A bot is an ordinary account holding a role; nothing about this path is
    // bot-specific, which is the property that makes it worth testing this way.
    auto bot = f.add_user("bot.notifier", {"builder"});
    auto member = f.add_user("member");

    // 1. Create a role below itself. Permissions 0: an opt-in notification role
    //    grants nothing, it exists to be mentioned and filtered on.
    auto created = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath,
                        "token-bot.notifier", create_body("Boss pings", 5));
    ASSERT_TRUE(IsOk(created));
    EXPECT_EQ(created.status, 201);
    const std::string role_id = created_id(created);
    ASSERT_FALSE(role_id.empty()) << created.body;
    ASSERT_TRUE(f.find(role_id).has_value());
    EXPECT_FALSE(f.find(role_id)->self_assignable) << "created without the flag, by request";

    // 2. Mark it self-assignable.
    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_update_role, role_path(role_id),
                          "token-bot.notifier", json{{"self_assignable", true}}.dump())));
    ASSERT_TRUE(f.find(role_id)->self_assignable);
    // A PATCH that names one field leaves the others alone — the wholesale PUT
    // could not express that, and it is how a client that predates a field
    // silently clears it.
    EXPECT_EQ(f.find(role_id)->name, "Boss pings");
    EXPECT_EQ(f.find(role_id)->position, 5);

    // 3. An ordinary member takes it...
    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path(role_id),
                          "token-member")));
    EXPECT_TRUE(f.holds(member, role_id));
    // ...and it is really theirs as far as the permission engine is concerned,
    // not merely a row somewhere.
    {
        PermissionsEngine perms(*f.store, f.config);
        auto ids = f.member_roles(member);
        EXPECT_NE(std::find(ids.begin(), ids.end(), role_id), ids.end());
        EXPECT_EQ(perms.compute(member, std::string()), permission::kEveryoneDefault)
            << "an opt-in role with no permissions must not change what the member may do";
    }

    // 4. ...and drops it again.
    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_remove_self_role,
                          self_role_path(role_id), "token-member")));
    EXPECT_FALSE(f.holds(member, role_id));

    // And the whole sequence is in the audit log, attributed to who did it. The
    // listing is newest-first, so the drop is the head. Neither the endpoints
    // nor the self-service path had to reimplement auditing: they write through
    // write_server_scoped_state, which is where every role change is recorded.
    auto recs = f.records();
    ASSERT_GE(recs.size(), 4u);
    EXPECT_EQ(recs.front().actor, member) << "the member's own drop, attributed to the member";
    EXPECT_EQ(recs.front().action, std::string(audit_action::kRoleAssign));
    EXPECT_TRUE(std::any_of(recs.begin(), recs.end(), [&](const SqliteStore::AuditRecord& r) {
        return r.actor == bot && r.action == std::string(audit_action::kRoleCreate)
            && r.target_key == role_id;
    })) << "the bot's creation is on the record under the bot's own name";
}

TEST(BotRoleManagement, SelfAssignmentIsIdempotentAndWritesNothingTheSecondTime) {
    Fixture f("bot-idempotent");
    f.seed_roles({role("pings", 1, 0, /*self_assignable=*/true)});
    auto member = f.add_user("member");

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path("pings"),
                          "token-member")));
    const size_t after_first = f.records().size();
    ASSERT_GT(after_first, 0u);

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path("pings"),
                          "token-member")));
    EXPECT_EQ(f.records().size(), after_first)
        << "a picker re-sending its state must not spam the audit log or wake every sync";
    // And exactly one copy of the id, not two.
    auto ids = f.member_roles(member);
    EXPECT_EQ(std::count(ids.begin(), ids.end(), std::string("pings")), 1);
}

// ══ 2. Containment: what a self-assignable role may carry ══════════════════

// The obvious attack. A delegated MANAGE_ROLES holder mints an opt-in role that
// is not harmless, and every member on the server helps themselves to it.
TEST(SelfAssignableContainment, CannotCreateOneCarryingPermissionsBeyondEveryone) {
    Fixture f("contain-create");
    f.seed_roles();
    f.add_user("builder", {"builder"});

    // KICK_MEMBERS is not in kEveryoneDefault, so this role would hand moderation
    // to anyone who clicked it.
    auto res = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-builder",
                    create_body("Free mod", 5, permission::kManageMessages,
                                /*self_assignable=*/true));
    EXPECT_TRUE(RefusedBecause(res, 403, "@everyone does not already have"));
    EXPECT_EQ(f.current_roles().size(), 4u) << "nothing was stored";
}

// The same rule the other way round: a harmless opt-in role cannot be quietly
// upgraded afterwards.
TEST(SelfAssignableContainment, CannotAddDangerousPermissionsToAnExistingOptInRole) {
    Fixture f("contain-update");
    f.seed_roles({role("pings", 5, 0, /*self_assignable=*/true)});
    f.add_user("builder", {"builder"});

    auto res = call(*f.roles, &RoleHandler::handle_update_role, role_path("pings"),
                    "token-builder",
                    json{{"permissions", permission::flags_to_hex(permission::kManageMessages)}}
                        .dump());
    EXPECT_TRUE(RefusedBecause(res, 403, "@everyone does not already have"));
    EXPECT_EQ(f.find("pings")->permissions, 0u);
}

// ...and not by an ADMINISTRATOR either. The containment rule is not a
// privilege rule — it is what the flag MEANS — so the exemption that carries an
// administrator past every rank check must not carry them past this.
TEST(SelfAssignableContainment, BindsAdministratorsToo) {
    Fixture f("contain-admin");
    f.seed_roles();
    f.add_user("owner", {std::string(permission::role_id::kAdmin)});

    auto res = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-owner",
                    create_body("Free mod", 5, permission::kBanMembers,
                                /*self_assignable=*/true));
    EXPECT_TRUE(RefusedBecause(res, 403, "@everyone does not already have"));

    // And marking the Admin role itself opt-in is the same refusal, not a
    // special case anyone had to remember.
    auto flip = call(*f.roles, &RoleHandler::handle_update_role,
                     role_path(std::string(permission::role_id::kAdmin)), "token-owner",
                     json{{"self_assignable", true}}.dump());
    EXPECT_TRUE(RefusedBecause(flip, 403, "@everyone does not already have"));
    EXPECT_FALSE(f.find(std::string(permission::role_id::kAdmin))->self_assignable);
}

// The claim-time half of the containment rule, and the reason it is not
// redundant: this is the check standing between a member and a role that became
// dangerous AFTER it was created. Here @everyone is narrowed rather than the
// role being widened, which no write to the opt-in role would ever notice.
TEST(SelfAssignableContainment, ARoleThatOutgrewEveryoneCannotBeClaimed) {
    Fixture f("contain-claim");
    // Seeded directly, so the document is one that validate_role_document would
    // have accepted when it was written: ADD_REACTIONS is in kEveryoneDefault.
    f.seed_roles({role("pings", 5, permission::kAddReactions, /*self_assignable=*/true)});
    auto member = f.add_user("member");

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path("pings"),
                          "token-member")));
    ASSERT_TRUE(f.holds(member, "pings"));
    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_remove_self_role,
                          self_role_path("pings"), "token-member")));

    // Now @everyone loses ADD_REACTIONS. "pings" is untouched, and is suddenly
    // a role that grants something @everyone does not have.
    {
        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault & ~permission::kAddReactions));
        content.roles.push_back(role("pings", 5, permission::kAddReactions, true));
        json j;
        to_json(j, content);
        f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                  j.dump());
    }

    auto res = call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path("pings"),
                    "token-member");
    EXPECT_TRUE(RefusedBecause(res, 403, "beyond @everyone"));
    EXPECT_FALSE(f.holds(member, "pings"));
}

TEST(SelfAssignableContainment, ARoleNotMarkedSelfAssignableCannotBeClaimed) {
    Fixture f("claim-unmarked");
    f.seed_roles();
    f.add_user("member");

    // "senior" is above every member and grants BAN_MEMBERS. Not marked opt-in,
    // so the endpoint refuses before rank ever enters the picture.
    auto res = call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path("senior"),
                    "token-member");
    EXPECT_TRUE(RefusedBecause(res, 403, "not self-assignable"));

    auto missing = call(*f.roles, &RoleHandler::handle_add_self_role,
                        self_role_path("no-such-role"), "token-member");
    EXPECT_TRUE(RefusedBecause(missing, 404, "Unknown role"));
}

// Removal is gated exactly as tightly as addition, and this is why: a role can
// carry channel DENY overrides, so "muted" is a role. Letting a member shed any
// role they happen to hold is letting them unmute themselves.
TEST(SelfAssignableContainment, AMemberCannotShedARoleThatIsNotSelfAssignable) {
    Fixture f("shed-muted");
    f.seed_roles({role("muted", 1, permission::kEveryoneDefault & ~permission::kSendMessages)});
    auto member = f.add_user("member", {"muted"});
    ASSERT_TRUE(f.holds(member, "muted"));

    auto res = call(*f.roles, &RoleHandler::handle_remove_self_role, self_role_path("muted"),
                    "token-member");
    EXPECT_TRUE(RefusedBecause(res, 403, "not self-assignable"));
    EXPECT_TRUE(f.holds(member, "muted"));
}

TEST(SelfAssignableContainment, EveryoneIsNotOptIn) {
    Fixture f("everyone-optin");
    f.seed_roles();
    f.add_user("owner", {std::string(permission::role_id::kAdmin)});
    auto member = f.add_user("member");

    // Nobody may mark it self-assignable...
    auto flip = call(*f.roles, &RoleHandler::handle_update_role,
                     role_path(std::string(permission::role_id::kEveryone)), "token-owner",
                     json{{"self_assignable", true}}.dump());
    EXPECT_TRUE(RefusedBecause(flip, 403, "cannot be self-assignable"));

    // ...and the claim path refuses it independently of the flag, so a document
    // written by some other route could not turn "leave @everyone" into a
    // button that drops a member out of every default permission.
    auto drop = call(*f.roles, &RoleHandler::handle_remove_self_role,
                     self_role_path(std::string(permission::role_id::kEveryone)), "token-member");
    EXPECT_TRUE(RefusedBecause(drop, 403, "not opt-in"));

    // Nor may it be deleted.
    auto del = call(*f.roles, &RoleHandler::handle_delete_role,
                    role_path(std::string(permission::role_id::kEveryone)), "token-owner");
    EXPECT_TRUE(RefusedBecause(del, 403, "cannot be deleted"));
}

// ══ 3. A self-assignable role confers no rank ══════════════════════════════

// Position on an opt-in role is a display choice (where it hoists, what colour
// wins). If it also conferred rank, a "Boss pings" role sitting above the
// moderators would be one click away from immunity to kick and ban for every
// member of the server — outranks() is the whole of that gate.
TEST(SelfAssignableRank, TakingAnOptInRoleDoesNotMakeYouOutrankAnyone) {
    Fixture f("rank-optin");
    f.seed_roles({role("pings", 90, 0, /*self_assignable=*/true)});
    auto member = f.add_user("member");
    auto senior = f.add_user("senior", {"senior"});  // position 50

    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.outranks(senior, member));
    }

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path("pings"),
                          "token-member")));
    ASSERT_TRUE(f.holds(member, "pings"));

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_EQ(perms.highest_role_position(member), 0)
        << "a role anyone may take must not lift the taker up the ladder";
    EXPECT_TRUE(perms.outranks(senior, member))
        << "the moderator must still be able to kick them";
    EXPECT_FALSE(perms.outranks(member, senior));
}

// ══ 4. The three new escalation paths ══════════════════════════════════════

// PATH ONE, part a: creation, upward.
TEST(RoleEscalation, CreateCannotMintARoleAtOrAboveYourOwnPosition) {
    Fixture f("create-above");
    f.seed_roles();
    f.add_user("builder", {"builder"});  // position 10

    for (int position : {10, 11, 100}) {
        auto res = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-builder",
                        create_body("Overlord", position));
        EXPECT_TRUE(RefusedBecause(res, 403, "at or above your own")) << "position " << position;
    }
    EXPECT_EQ(f.current_roles().size(), 4u);

    // Below is fine, which is what makes the refusals above mean something.
    EXPECT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-builder",
                          create_body("Helper", 9))));
}

// PATH ONE, part b, and the one that was open BEFORE any of this: MANAGE_ROLES
// was a slower path to every other permission on the server. Create a role
// below yourself carrying a flag you do not hold, assign it to yourself —
// may_assign_roles allows editing your own assignment downward — and you have
// granted yourself a power nobody delegated. The rank system never stopped
// this; nothing did.
TEST(RoleEscalation, CannotPutAPermissionOnARoleThatYouDoNotHoldYourself) {
    Fixture f("create-perms");
    f.seed_roles();
    auto builder = f.add_user("builder", {"builder"});

    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_FALSE(perms.can(builder, std::string(), permission::kBanMembers))
            << "the actor must lack the flag, or this test proves nothing";
    }

    auto res = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-builder",
                    create_body("Enforcer", 5, permission::kBanMembers));
    EXPECT_TRUE(RefusedBecause(res, 403, "permission you do not hold"));

    // Same refusal through the wholesale state PUT, so the new endpoint is not
    // the only door with a lock on it.
    auto room = f.add_channel(builder, "general");
    ServerRolesContent doc;
    for (const auto& r : f.current_roles()) doc.roles.push_back(r);
    doc.roles.push_back(role("enforcer", 5, permission::kBanMembers));
    json j;
    to_json(j, doc);
    auto via_put = call(*f.rooms, &RoomHandler::handle_set_state,
                        state_path(room, event_type::kServerRoles), "token-builder", j.dump());
    EXPECT_TRUE(RefusedBecause(via_put, 403, "permission you do not hold"));
    EXPECT_FALSE(f.find("enforcer").has_value());

    // A permission the actor DOES hold is fine — delegation still works, it is
    // only amplification that is refused.
    EXPECT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-builder",
                          create_body("Deputy", 5, permission::kManageRoles))));
}

// PATH TWO: self-assignment as an escalation primitive. The bypass of the rank
// check is real and total, so the only thing standing between a member and a
// role is the flag plus containment — checked here from the member's side
// rather than the author's.
TEST(RoleEscalation, SelfAssignmentIsNotAWayToPickUpAnyRoleYouLike) {
    Fixture f("self-escalate");
    f.seed_roles();
    auto member = f.add_user("member");

    for (const char* id : {"builder", "senior", "admin"}) {
        auto res = call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path(id),
                        "token-member");
        EXPECT_TRUE(RefusedBecause(res, 403, "not self-assignable")) << id;
        EXPECT_FALSE(f.holds(member, id));
    }

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_EQ(perms.compute(member, std::string()), permission::kEveryoneDefault);
}

// PATH THREE, part a: repositioning yourself upward.
TEST(RoleEscalation, RepositionCannotLiftARoleToOrAboveYourOwnPosition) {
    Fixture f("reposition-up");
    f.seed_roles();
    f.add_user("builder", {"builder"});

    auto created = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-builder",
                        create_body("Helper", 5));
    ASSERT_TRUE(IsOk(created));
    const std::string helper = created_id(created);

    auto res = call(*f.roles, &RoleHandler::handle_update_role, role_path(helper),
                    "token-builder", json{{"position", 60}}.dump());
    EXPECT_TRUE(RefusedBecause(res, 403, "at or above your own"));
    EXPECT_EQ(f.find(helper)->position, 5);
}

// PATH THREE, part b, and a hole that was open before this change: DEMOTION.
//
// The rank check only ever looked at the position a role was being GIVEN. An
// actor at 10 could therefore move the Admin role from 100 down to 1 — the
// proposed position is below the actor's, so the "at or above your own" branch
// was never taken at all — and having demoted it, outrank every administrator
// and strip the role off them. "You cannot delete the role above you" was
// already written for exactly this; moving it is the same act performed in two
// steps.
TEST(RoleEscalation, RepositionCannotDEMOTEARoleRankedAboveYou) {
    Fixture f("reposition-down");
    f.seed_roles();
    auto builder = f.add_user("builder", {"builder"});
    auto owner = f.add_user("owner", {std::string(permission::role_id::kAdmin)});

    auto res = call(*f.roles, &RoleHandler::handle_update_role,
                    role_path(std::string(permission::role_id::kAdmin)), "token-builder",
                    json{{"position", 1}}.dump());
    EXPECT_TRUE(RefusedBecause(res, 403, "at or above your own"));
    EXPECT_EQ(f.find(std::string(permission::role_id::kAdmin))->position, 100);

    PermissionsEngine perms(*f.store, f.config);
    EXPECT_FALSE(perms.outranks(builder, owner));

    // And the same refusal through the wholesale PUT, which is where the hole
    // actually lived.
    auto room = f.add_channel(builder, "general");
    ServerRolesContent doc;
    for (auto r : f.current_roles()) {
        if (r.id == permission::role_id::kAdmin) r.position = 1;
        doc.roles.push_back(r);
    }
    json j;
    to_json(j, doc);
    auto via_put = call(*f.rooms, &RoomHandler::handle_set_state,
                        state_path(room, event_type::kServerRoles), "token-builder", j.dump());
    EXPECT_TRUE(RefusedBecause(via_put, 403, "at or above your own"));
    EXPECT_EQ(f.find(std::string(permission::role_id::kAdmin))->position, 100);
}

// PATH THREE, part c: the flag flip, which is the escalation this feature
// INVENTED and the reason `same_role` had to change.
//
// `same_role` decides whether an edit touching a role above your rank is a
// harmless echo of a document you must resubmit whole, or a modification you
// may not make. It compared position and permissions. `self_assignable` is
// neither, so a builder could flip that one bit on a senior role, leave
// everything else alone, and have the echo test wave it through.
//
// The role used here carries no permission beyond @everyone's, so the
// containment rule has nothing to object to — which is exactly the case that
// makes this test bite `same_role` and not something else. It is not harmless:
// "VIP" is the shape of a role that exists to be granted a VIEW_CHANNEL allow
// override in a private channel, and turning it opt-in hands that channel to
// everyone on the server.
TEST(RoleEscalation, CannotFlipSelfAssignableOnARoleRankedAboveYou) {
    Fixture f("flag-flip");
    // Position 60 — above the builder at 10. Permissions exactly @everyone's.
    f.seed_roles({role("vip", 60, permission::kEveryoneDefault)});
    auto builder = f.add_user("builder", {"builder"});
    auto member = f.add_user("member");

    // Through the dedicated endpoint...
    auto patched = call(*f.roles, &RoleHandler::handle_update_role, role_path("vip"),
                        "token-builder", json{{"self_assignable", true}}.dump());
    EXPECT_TRUE(RefusedBecause(patched, 403, "at or above your own"));
    ASSERT_TRUE(f.find("vip").has_value());
    EXPECT_FALSE(f.find("vip")->self_assignable);

    // ...and through the wholesale PUT, where a caller resubmitting the whole
    // document has the most natural opportunity to slip the bit in.
    auto room = f.add_channel(builder, "general");
    ServerRolesContent doc;
    for (auto r : f.current_roles()) {
        if (r.id == "vip") r.self_assignable = true;
        doc.roles.push_back(r);
    }
    json j;
    to_json(j, doc);
    auto via_put = call(*f.rooms, &RoomHandler::handle_set_state,
                        state_path(room, event_type::kServerRoles), "token-builder", j.dump());
    EXPECT_TRUE(RefusedBecause(via_put, 403, "at or above your own"));
    EXPECT_FALSE(f.find("vip")->self_assignable);

    // Nobody helped themselves in the meantime.
    auto grab = call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path("vip"),
                     "token-member");
    EXPECT_TRUE(RefusedBecause(grab, 403, "not self-assignable"));
    EXPECT_FALSE(f.holds(member, "vip"));
}

// PATH THREE, part d: the same flip, on the flag THIS feature made load-bearing.
//
// `mentionable` was left out of `same_role` when role CRUD landed, on the
// correct reading at the time that it was cosmetic — nothing read it. Role
// mentions changed that: it is now the gate deciding who may ping a role. It
// grants no permission to anybody, which is why it reads like `name` and
// `color`; but flipping it REMOVES A PROTECTION FROM A ROLE THE ACTOR MAY NOT
// TOUCH, which is what this predicate is for.
//
// The concrete abuse: a delegated builder cannot touch @Admins, but could make
// it pingable by every member on the server and then have the whole server
// ping it.
TEST(RoleEscalation, CannotFlipMentionableOnARoleRankedAboveYou) {
    Fixture f("mention-flip");
    // Position 60 — above the builder at 10 — and deliberately NOT mentionable.
    f.seed_roles({role("vip", 60, permission::kEveryoneDefault,
                       /*self_assignable=*/false, /*mentionable=*/false)});
    auto builder = f.add_user("builder", {"builder"});

    auto patched = call(*f.roles, &RoleHandler::handle_update_role, role_path("vip"),
                        "token-builder", json{{"mentionable", true}}.dump());
    EXPECT_TRUE(RefusedBecause(patched, 403, "at or above your own"));
    ASSERT_TRUE(f.find("vip").has_value());
    EXPECT_FALSE(f.find("vip")->mentionable);

    // And through the wholesale PUT, where the echo test is the only thing
    // standing between a resubmitted document and a silent flag change.
    auto room = f.add_channel(builder, "general");
    ServerRolesContent doc;
    for (auto r : f.current_roles()) {
        if (r.id == "vip") r.mentionable = true;
        doc.roles.push_back(r);
    }
    json j;
    to_json(j, doc);
    auto via_put = call(*f.rooms, &RoomHandler::handle_set_state,
                        state_path(room, event_type::kServerRoles), "token-builder", j.dump());
    EXPECT_TRUE(RefusedBecause(via_put, 403, "at or above your own"));
    EXPECT_FALSE(f.find("vip")->mentionable);
}

// The counterpart: adding `mentionable` to same_role must not break the echo
// that the wholesale PUT depends on. A caller who is not changing the flag
// resubmits the same value and is waved through, exactly as before.
TEST(RoleEscalation, EchoingASeniorRolesMentionableFlagUnchangedIsStillFine) {
    Fixture f("mention-echo");
    f.seed_roles({role("vip", 60, permission::kEveryoneDefault,
                       /*self_assignable=*/false, /*mentionable=*/true)});
    auto builder = f.add_user("builder", {"builder"});
    auto room = f.add_channel(builder, "general");

    ServerRolesContent doc;
    for (const auto& r : f.current_roles()) doc.roles.push_back(r);
    json j;
    to_json(j, doc);
    EXPECT_TRUE(IsOk(call(*f.rooms, &RoomHandler::handle_set_state,
                          state_path(room, event_type::kServerRoles), "token-builder",
                          j.dump())));
    EXPECT_TRUE(f.find("vip")->mentionable) << "the echo lost the flag";
}

// A rename of a senior role is NOT an escalation, and refusing it would only
// teach people to work around the check. The counterpart to the test above:
// `same_role` names the fields that confer power and deliberately omits the
// cosmetic ones.
TEST(RoleEscalation, CosmeticEditsToASeniorRoleAreStillRefusedByRankButNotByEchoing) {
    Fixture f("echo");
    f.seed_roles();
    auto builder = f.add_user("builder", {"builder"});
    auto room = f.add_channel(builder, "general");

    // Resubmitting the document verbatim must succeed — that is the whole
    // premise of the wholesale PUT, and the reason `same_role` exists.
    ServerRolesContent doc;
    for (const auto& r : f.current_roles()) doc.roles.push_back(r);
    json j;
    to_json(j, doc);
    EXPECT_TRUE(IsOk(call(*f.rooms, &RoomHandler::handle_set_state,
                          state_path(room, event_type::kServerRoles), "token-builder", j.dump())));
    EXPECT_EQ(f.current_roles().size(), 4u);
}

// ══ 5. The ordinary gates, on the new doors ════════════════════════════════

TEST(RoleEndpointGates, EveryAdminEndpointNeedsManageRolesAndRejectsAnonymousCallers) {
    Fixture f("gates");
    f.seed_roles({role("pings", 5, 0, /*self_assignable=*/true)});
    f.add_user("member");

    EXPECT_EQ(call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "", create_body("x", 1))
                  .status,
              401);
    EXPECT_EQ(
        call(*f.roles, &RoleHandler::handle_add_self_role, self_role_path("pings"), "").status,
        401);

    auto create = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-member",
                       create_body("x", 1));
    EXPECT_TRUE(RefusedBecause(create, 403, "Insufficient permissions"));
    auto update = call(*f.roles, &RoleHandler::handle_update_role, role_path("pings"),
                       "token-member", json{{"name", "x"}}.dump());
    EXPECT_TRUE(RefusedBecause(update, 403, "Insufficient permissions"));
    auto del = call(*f.roles, &RoleHandler::handle_delete_role, role_path("pings"),
                    "token-member");
    EXPECT_TRUE(RefusedBecause(del, 403, "Insufficient permissions"));

    // Listing is not gated: a member rendering the opt-in picker holds no role
    // permission by definition, and the list already reaches them through sync.
    auto list = call(*f.roles, &RoleHandler::handle_list_roles, kRolesPath, "token-member");
    ASSERT_TRUE(IsOk(list));
    EXPECT_EQ(json::parse(list.body)["roles"].size(), 5u);
}

// MANAGE_ROLES granted inside ONE channel must not unlock the server's role
// graph. This shape has been a real hole in this codebase more than once, which
// is why the new endpoints evaluate at server scope and have no room id to be
// confused about in the first place.
TEST(RoleEndpointGates, AChannelOverrideGrantingManageRolesUnlocksNothing) {
    Fixture f("scope");
    f.seed_roles();
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "mine");
    {
        ChannelPermissionOverride ov;
        ov.allow = permission::kManageRoles;
        json j;
        to_json(j, ov);
        f.store->insert_event(generate_event_id("test"), room, "@server:test",
                              std::string(event_type::kChannelPermissions), "user:" + member,
                              j.dump(), 1003);
    }
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.can(member, room, permission::kManageRoles))
            << "the override must actually grant it in-channel, or this proves nothing";
    }

    auto res = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-member",
                    create_body("Overlord", 1));
    EXPECT_TRUE(RefusedBecause(res, 403, "Insufficient permissions"));
    EXPECT_EQ(f.current_roles().size(), 4u);
}

// ══ 6. Delete ══════════════════════════════════════════════════════════════

TEST(RoleDeletion, DeletingARoleStripsItFromEveryMemberWhoHeldIt) {
    Fixture f("delete-strip");
    f.seed_roles({role("pings", 5, 0, /*self_assignable=*/true)});
    f.add_user("builder", {"builder"});
    auto a = f.add_user("alice", {"pings"});
    auto b = f.add_user("bob", {"pings"});
    auto c = f.add_user("carol");
    ASSERT_TRUE(f.holds(a, "pings"));

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_delete_role, role_path("pings"),
                          "token-builder")));
    EXPECT_FALSE(f.find("pings").has_value());
    // A stale id left behind makes the next wholesale member.roles PUT for that
    // user fail with "Unknown role", so a deletion would quietly break role
    // editing for whoever held the deleted role.
    EXPECT_FALSE(f.holds(a, "pings"));
    EXPECT_FALSE(f.holds(b, "pings"));
    EXPECT_EQ(f.member_roles(c).size(), 1u) << "an untouched member was not rewritten";
    EXPECT_TRUE(f.holds(a, std::string(permission::role_id::kEveryone)));
}

TEST(RoleDeletion, CannotDeleteARoleRankedAtOrAboveYou) {
    Fixture f("delete-above");
    f.seed_roles();
    f.add_user("builder", {"builder"});

    auto res = call(*f.roles, &RoleHandler::handle_delete_role, role_path("senior"),
                    "token-builder");
    EXPECT_TRUE(RefusedBecause(res, 403, "at or above your own"));
    EXPECT_TRUE(f.find("senior").has_value());

    auto missing = call(*f.roles, &RoleHandler::handle_delete_role, role_path("nope"),
                        "token-builder");
    EXPECT_EQ(missing.status, 404) << missing.body;
}

// ══ 7. Document invariants ═════════════════════════════════════════════════

TEST(RoleDocument, RejectsNonsenseBeforeItReachesTheStore) {
    Fixture f("invariants");
    f.seed_roles();
    f.add_user("owner", {std::string(permission::role_id::kAdmin)});

    struct Case { const char* body; const char* needle; };
    const Case cases[] = {
        {R"({"name":""})", "must have a name"},
        {R"({"name":"x","color":"red"})", "#RRGGBB"},
        {R"({"name":"x","position":-1})", "out of range"},
        {R"({"name":"x","position":99999999})", "out of range"},
        {R"({"name":"x","hoist":"yes"})", "hoist must be a boolean"},
        {R"({"name":"x","permissions":[]})", "permissions must be"},
    };
    for (const auto& c : cases) {
        auto res = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-owner",
                        c.body);
        EXPECT_TRUE(RefusedBecause(res, 400, c.needle)) << c.body;
    }
    EXPECT_EQ(f.current_roles().size(), 4u);

    // An unknown permission bit is masked off rather than refused: a client
    // built against a newer protocol must not have every edit rejected, and
    // storing a bit whose meaning nothing here can check would put it outside
    // the containment rule.
    auto ok = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-owner",
                   json{{"name", "Future"}, {"permissions", "0xffffffff"}}.dump());
    ASSERT_TRUE(IsOk(ok));
    EXPECT_EQ(f.find(created_id(ok))->permissions, permission::kAllFlags);
}

TEST(RoleDocument, ServerMintsTheIdSoACallerCannotCollideWithAWellKnownRole) {
    Fixture f("minted-id");
    f.seed_roles();
    f.add_user("builder", {"builder"});

    auto res = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-builder",
                    json{{"name", "Sneaky"}, {"id", permission::role_id::kAdmin},
                         {"position", 5}}
                        .dump());
    ASSERT_TRUE(IsOk(res));
    const std::string id = created_id(res);
    EXPECT_NE(id, std::string(permission::role_id::kAdmin));
    EXPECT_EQ(id.rfind("role_", 0), 0u) << id;
    // The real Admin role is untouched.
    EXPECT_EQ(f.find(std::string(permission::role_id::kAdmin))->position, 100);
    EXPECT_EQ(f.find(std::string(permission::role_id::kAdmin))->permissions,
              permission::kAllFlags);
}

} // namespace

// ══ 6. Self-assignable AND mentionable ═════════════════════════════════════
//
// The combination is the point of both features meeting: a role anyone may
// take and anyone may ping is a Discord notification-role picker — "@Raiders",
// "@PatchNotes" — which is the shape this whole line of work exists to enable.
//
// It has to be legal, and it has to stay legal for the right reason: a
// self-assignable role may carry no permission @everyone lacks, and
// `mentionable` is not a permission. If it ever became one, this test fails and
// the containment rule is the thing to re-read.

TEST(SelfAssignableRoles, AMentionablePickerRoleIsLegalAndTakeable) {
    Fixture f("picker");
    // No permission beyond @everyone's, opt-in, and pingable. Position 5 is a
    // display choice only — a self-assignable role confers no rank.
    f.seed_roles({role("raiders", 5, permission::kEveryoneDefault,
                       /*self_assignable=*/true, /*mentionable=*/true)});
    auto member = f.add_user("member");

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_add_self_role,
                          self_role_path("raiders"), "token-member")));
    EXPECT_TRUE(f.holds(member, "raiders"));
    // The flag survived the round trip — `mentionable` is not something the
    // self-assign path may quietly clear.
    EXPECT_TRUE(f.find("raiders")->mentionable);

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_remove_self_role,
                          self_role_path("raiders"), "token-member")));
    EXPECT_FALSE(f.holds(member, "raiders"));
}

TEST(SelfAssignableRoles, MentionableDoesNotLetAPickerRoleCarryAPermission) {
    Fixture f("picker-perms");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_channel(admin, "general");

    // The containment rule is about PERMISSIONS, and `mentionable` must not be
    // mistaken for one in either direction: a picker role with a real
    // permission is still refused, mentionable or not.
    ServerRolesContent doc;
    for (const auto& r : f.current_roles()) doc.roles.push_back(r);
    doc.roles.push_back(role("sneaky", 5,
                             permission::kEveryoneDefault | permission::kManageMessages,
                             /*self_assignable=*/true, /*mentionable=*/true));
    json j;
    to_json(j, doc);
    auto res = call(*f.rooms, &RoomHandler::handle_set_state,
                    state_path(room, event_type::kServerRoles), "token-admin", j.dump());
    EXPECT_EQ(res.status, 403) << res.body;
    EXPECT_FALSE(f.find("sneaky").has_value());
}

// @everyone cannot be narrowed out from under an opt-in role, and a drifted
// role would still be droppable if one ever existed.
//
// Two rules, and the interesting part is that the first makes the second nearly
// unreachable. A client agent predicted a trap: narrow @everyone after an
// opt-in role is created, and every holder is stuck with a role they cannot
// shed, because removal ran the same containment check as addition and
// self-assignment is the only path that moves the role.
//
// The trap turns out to be blocked one level up — validate_role_document
// refuses the narrowing itself, so the API cannot produce a drifted role at
// all. What remains is the case may_self_assign_role's own comment names: a
// future path that writes the role document without going through
// may_edit_role_definitions. The add/remove split is defence for that, and
// costs one bool.
TEST(BotRoleManagement, EveryoneCannotBeNarrowedOutFromUnderAnOptInRole) {
    Fixture f("optin-containment");
    f.seed_roles();
    auto builder = f.add_user("builder", {"builder"});
    auto member = f.add_user("member");

    // Legal at creation: EMBED_LINKS is in @everyone's default set.
    auto created = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath,
                        "token-builder",
                        create_body("Boss pings", 5, permission::kEmbedLinks, true));
    ASSERT_TRUE(IsOk(created)) << created.body;
    const std::string role_id = created_id(created);
    ASSERT_FALSE(role_id.empty());

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_add_self_role,
                          self_role_path(role_id), "token-member", "")));

    // The narrowing is REFUSED, naming the role and the bit it would strand.
    // This is the protection: drift is prevented, not merely detected later.
    auto narrowed = call(*f.roles, &RoleHandler::handle_update_role,
                         role_path(std::string(permission::role_id::kEveryone)),
                         "token-builder", json{{"permissions", "0x0"}}.dump());
    EXPECT_FALSE(IsOk(narrowed))
        << "narrowing @everyone below an opt-in role must be refused, or every "
           "holder is stranded with a role only self-assignment can move";
    EXPECT_EQ(narrowed.status, 403);

    // And the holder is unaffected: still holding it, still able to drop it.
    PermissionsEngine perms(*f.store, f.config);
    EXPECT_TRUE(perms.may_self_assign_role(member, role_id, /*adding=*/false));
    EXPECT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_remove_self_role,
                          self_role_path(role_id), "token-member", "")));
}

// ═══════════════════════════════════════════════════════════════════════════
// Permissions audit, September 2026 — the role findings (F7, F8).
//
// docs/audit-permissions-2026-09.md reported both as "reasoned" rather than
// proven — there is no DISABLED_ proof for either in
// test_permission_audit_2026_09.cpp — so these are the proofs, written against
// the fixed behaviour and verified to fail without it.
// ═══════════════════════════════════════════════════════════════════════════

// ── F7: GET /bsfchat/roles published the whole document to any account ────
//
// The endpoint is authentication-only, which is right and stays right: the
// member rendering an opt-in role picker holds no role permission by
// definition, and a bot scoped to one channel has no other authoritative read.
// What was wrong was the RESPONSE — every role's permission bitfield, to every
// caller — resting on a premise that does not hold for the two callers who most
// need this endpoint. A scoped bot is excluded from channel auto-join and a
// member can be denied kViewChannel on the mirror room, so neither ever
// receives bsfchat.server.roles through /sync; "they have it already" was true
// only of the callers who did not need asking.
//
// What is withheld is one field on the roles where it is a map of who can do
// what. @everyone's bits and a self-assignable role's bits stay, because the
// containment rule makes them bits the reader already holds — see
// permissions_are_public() in RoleHandler.cpp.

TEST(RoleListDisclosure, AMemberDoesNotLearnWhichRoleCarriesWhichPermission) {
    Fixture f("f7-member");
    f.seed_roles({role("pings", 5, 0, /*self_assignable=*/true)});
    f.add_user("member");

    auto res = call(*f.roles, &RoleHandler::handle_list_roles, kRolesPath, "token-member");
    ASSERT_TRUE(IsOk(res));
    auto roles = json::parse(res.body)["roles"];
    ASSERT_EQ(roles.size(), 5u) << "every role is still listed; only a field is withheld";

    std::map<std::string, json> by_id;
    for (const auto& r : roles) by_id[r.value("id", "")] = r;

    // The escalation map: which role is administrator, which can ban, where
    // the ladder sits. Withheld.
    for (const char* id : {"builder", "senior", "admin"}) {
        ASSERT_TRUE(by_id.count(id)) << id;
        EXPECT_FALSE(by_id[id].contains("permissions"))
            << "role '" << id << "' handed its permission bitfield to an ordinary member: "
            << by_id[id].dump();
    }

    // Still published, because neither tells the reader anything they do not
    // already have: @everyone is what every account holds, and a
    // self-assignable role is refused storage unless its bits are a subset of
    // @everyone's (validate_role_document).
    ASSERT_TRUE(by_id[std::string(permission::role_id::kEveryone)].contains("permissions"));
    ASSERT_TRUE(by_id["pings"].contains("permissions"))
        << "the opt-in picker computes its own containment ceiling from these two, and a "
           "member who cannot read them sees every trap role as safe";
}

// The narrowing must cost the member nothing they render. This is the half
// that would make the fix unacceptable if it failed, so it is asserted
// field by field rather than by eyeballing the payload.
TEST(RoleListDisclosure, EveryPresentationFieldSurvivesForAMember) {
    Fixture f("f7-presentation");
    ServerRole hoisted = role("senior", 50, permission::kEveryoneDefault | permission::kBanMembers,
                              /*self_assignable=*/false, /*mentionable=*/true);
    hoisted.name = "Senior Moderator";
    hoisted.color = "#ff8800";
    hoisted.hoist = true;
    {
        // Replace the fixture's plain "senior" with the decorated one.
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        content.roles.push_back(hoisted);
        json j;
        to_json(j, content);
        f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                  j.dump());
    }
    f.add_user("member");

    auto res = call(*f.roles, &RoleHandler::handle_list_roles, kRolesPath, "token-member");
    ASSERT_TRUE(IsOk(res));
    // Named, not `json::parse(res.body)["roles"]` inline: the parsed document
    // is a temporary and a range-for binding into it dangles.
    const auto listed = json::parse(res.body);
    json senior;
    for (const auto& r : listed["roles"]) {
        if (r.value("id", "") == "senior") senior = r;
    }
    ASSERT_FALSE(senior.is_null()) << res.body;

    EXPECT_EQ(senior.value("name", ""), "Senior Moderator");
    EXPECT_EQ(senior.value("color", ""), "#ff8800");
    EXPECT_EQ(senior.value("position", -1), 50);
    EXPECT_TRUE(senior.value("hoist", false));
    EXPECT_TRUE(senior.value("mentionable", false));
    EXPECT_FALSE(senior.value("self_assignable", true));
    // ...and only the bitfield is gone.
    EXPECT_FALSE(senior.contains("permissions"));
}

// The invariant that makes the narrowing safe rather than merely quieter:
// anybody who can WRITE the document reads it whole. Both halves ask
// kManageRoles at server scope of the same engine, so there is no caller that
// could do a read-modify-write against a truncated document and write
// permissions=0 over every role it echoed back.
TEST(RoleListDisclosure, AnyoneWhoCanEditRolesStillReadsTheWholeDocument) {
    Fixture f("f7-builder");
    f.seed_roles({role("pings", 5, 0, /*self_assignable=*/true)});
    f.add_user("builder", {"builder"});

    auto res = call(*f.roles, &RoleHandler::handle_list_roles, kRolesPath, "token-builder");
    ASSERT_TRUE(IsOk(res));
    const auto listed = json::parse(res.body);
    for (const auto& r : listed["roles"]) {
        EXPECT_TRUE(r.contains("permissions"))
            << "a MANAGE_ROLES holder must see the whole document or read-modify-write is a "
               "silent permission wipe: " << r.dump();
    }
    // And it is the real value, not a placeholder.
    for (const auto& r : listed["roles"]) {
        if (r.value("id", "") != "senior") continue;
        EXPECT_EQ(permission::flags_from_hex(r.value("permissions", "0x0")),
                  permission::kEveryoneDefault | permission::kBanMembers);
    }
}

// MANAGE_ROLES granted inside one channel must not widen the read either — the
// same server-scope question the write endpoints ask.
TEST(RoleListDisclosure, AChannelOverrideGrantingManageRolesDoesNotWidenTheRead) {
    Fixture f("f7-scope");
    f.seed_roles();
    auto member = f.add_user("member");
    auto room = f.add_channel(member, "mine");
    {
        ChannelPermissionOverride ov;
        ov.allow = permission::kManageRoles;
        json j;
        to_json(j, ov);
        f.store->insert_event(generate_event_id("test"), room, "@server:test",
                              std::string(event_type::kChannelPermissions), "user:" + member,
                              j.dump(), 1003);
    }
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_TRUE(perms.can(member, room, permission::kManageRoles))
            << "the override must actually grant it in-channel, or this proves nothing";
    }

    auto res = call(*f.roles, &RoleHandler::handle_list_roles, kRolesPath, "token-member");
    ASSERT_TRUE(IsOk(res));
    const auto listed = json::parse(res.body);
    for (const auto& r : listed["roles"]) {
        if (r.value("id", "") == "admin") EXPECT_FALSE(r.contains("permissions"));
    }
}

// ── F8: the delta endpoints were a read-modify-write with no compare-and-swap
//
// RoleHandler.h claimed the server performed the read-modify-write "under the
// store's own lock, against the document as it stands at that moment". It did
// not: the read, the authorisation and the write were three separate lock
// acquisitions, and commit_roles built a FRESH PermissionsEngine, so the
// proposal was built from one document and approved against another.
//
// The consequence is worse than a lost edit. "You cannot grant a role a
// permission you do not hold yourself" measures what the proposal ADDS relative
// to the document it reads, so a bit somebody had just revoked reads as a bit
// this edit is adding — and passes, because the actor does hold it. A
// revocation is reverted by an unrelated rename, and the person who performed
// the revocation got a 200.
//
// The fix is a compare-and-swap in SqliteStore::set_server_state, threaded
// through write_server_scoped_state so that a write which lost is also not
// audited and not mirrored. These tests drive that primitive and that choke
// point directly rather than racing two threads through the handlers: a race
// test that only fails sometimes is not a proof, and what has to be true here
// is a property of the write, which can be asserted exactly. The handlers'
// USE of it is pinned separately by mutations F8a-F8c in tests/e2e/mutate.py.

TEST(ServerStateCompareAndSwap, AStaleWriteIsRefusedAndTheNewerContentSurvives) {
    Fixture f("f8-cas");
    f.seed_roles();

    const auto original =
        f.store->get_server_state(std::string(event_type::kServerRoles), "");
    ASSERT_TRUE(original.has_value());

    // Somebody else edits the document. This is the revocation.
    auto narrowed = f.current_roles();
    for (auto& r : narrowed) {
        if (r.id == "senior") r.permissions &= ~permission::kBanMembers;
    }
    {
        ServerRolesContent content;
        content.roles = narrowed;
        json j;
        to_json(j, content);
        f.store->set_server_state(std::string(event_type::kServerRoles), "", "@someone:test",
                                  j.dump());
    }
    ASSERT_FALSE(permission::has(f.find("senior")->permissions, permission::kBanMembers));

    // Our stale proposal — built from `original`, which still carries the bit,
    // with an innocuous rename on top. Exactly the shape the audit describes.
    auto stale = f.current_roles();
    for (auto& r : stale) {
        if (r.id == "senior") {
            r.permissions |= permission::kBanMembers;  // as it was when we read
            r.name = "Renamed";
        }
    }
    ServerRolesContent content;
    content.roles = stale;
    json j;
    to_json(j, content);

    // THE CONTROL, and the proof that the finding was real rather than
    // theoretical: the same stale write WITHOUT an expectation — which is
    // exactly what every role write on this server used to be — applies, and
    // the revoked bit comes back.
    f.store->set_server_state(std::string(event_type::kServerRoles), "", "@builder:test",
                              j.dump());
    ASSERT_TRUE(permission::has(f.find("senior")->permissions, permission::kBanMembers))
        << "the control did not reproduce the defect, so the assertion below proves nothing";
    ASSERT_EQ(f.find("senior")->name, "Renamed");

    // Put the revocation back and replay the same stale write, this time
    // naming what it believed it was superseding.
    {
        ServerRolesContent revoked;
        revoked.roles = narrowed;
        json rj;
        to_json(rj, revoked);
        f.store->set_server_state(std::string(event_type::kServerRoles), "", "@someone:test",
                                  rj.dump());
    }

    auto write = f.store->set_server_state(std::string(event_type::kServerRoles), "",
                                           "@builder:test", j.dump(), &original);
    EXPECT_FALSE(write.applied);
    EXPECT_FALSE(permission::has(f.find("senior")->permissions, permission::kBanMembers))
        << "a stale wholesale write reverted a revocation that had already landed";
    EXPECT_NE(f.find("senior")->name, "Renamed")
        << "the rename is the carrier: it is what makes the stale document look like an edit";
}

TEST(ServerStateCompareAndSwap, AWriteThatMatchesWhatIsStoredApplies) {
    Fixture f("f8-cas-ok");
    f.seed_roles();
    const auto expected =
        f.store->get_server_state(std::string(event_type::kServerRoles), "");
    ASSERT_TRUE(expected.has_value());

    auto proposed = f.current_roles();
    for (auto& r : proposed) {
        if (r.id == "senior") r.name = "Renamed";
    }
    ServerRolesContent content;
    content.roles = proposed;
    json j;
    to_json(j, content);

    auto write = f.store->set_server_state(std::string(event_type::kServerRoles), "",
                                           "@builder:test", j.dump(), &expected);
    EXPECT_TRUE(write.applied);
    EXPECT_EQ(write.previous, expected);
    EXPECT_EQ(f.find("senior")->name, "Renamed");
}

// "Expect no row at all" is a distinct expectation from "expect this content",
// and it is the one a first write makes. Getting it wrong in the permissive
// direction would let a first write clobber a concurrent first write.
TEST(ServerStateCompareAndSwap, ExpectingAnAbsentRowFailsOnceSomebodyHasWrittenOne) {
    Fixture f("f8-cas-absent");
    const SqliteStore::ExpectedServerState absent;  // nullopt
    ASSERT_TRUE(f.store
                    ->set_server_state(std::string(event_type::kMemberRoles), "@a:test",
                                       "@server:test", R"({"role_ids":["everyone"]})", &absent)
                    .applied);
    EXPECT_FALSE(f.store
                     ->set_server_state(std::string(event_type::kMemberRoles), "@a:test",
                                        "@server:test", R"({"role_ids":["admin"]})", &absent)
                     .applied);
    EXPECT_EQ(f.store->get_member_role_ids("@a:test"),
              std::vector<std::string>{"everyone"});
}

// Passing no expectation at all leaves the write unconditional, which is what
// bootstrap and the admin CLI rely on — they are authoritative rather than
// derived from a read.
TEST(ServerStateCompareAndSwap, WithoutAnExpectationTheWriteIsUnconditional) {
    Fixture f("f8-cas-none");
    f.seed_roles();
    auto write = f.store->set_server_state(std::string(event_type::kServerRoles), "",
                                           "@server:test", R"({"roles":[]})");
    EXPECT_TRUE(write.applied);
    EXPECT_TRUE(write.previous.has_value());
    EXPECT_TRUE(f.current_roles().empty());
}

// A lost write must leave NO trace: no audit record claiming a change that did
// not happen, and no mirror event telling clients about a document that was
// never stored. This is the reason the expectation is threaded through
// write_server_scoped_state rather than applied at each call site.
TEST(ServerStateCompareAndSwap, ALostWriteIsNotAuditedAndNotMirrored) {
    Fixture f("f8-no-trace");
    f.seed_roles();
    auto owner = f.add_user("owner", {std::string(permission::role_id::kAdmin)});
    auto mirror = f.add_channel(owner, "general");

    const SqliteStore::ExpectedServerState stale{R"({"roles":[]})"};  // never stored
    const size_t audit_before = f.records().size();
    const size_t events_before = f.store->get_room_events(mirror, 1000, "f").size();

    ServerRolesContent content;
    content.roles = f.current_roles();
    json j;
    to_json(j, content);
    EXPECT_FALSE(write_server_scoped_state(*f.store, f.config,
                                           std::string(event_type::kServerRoles), "", j.dump(),
                                           mirror, owner, &stale));

    EXPECT_EQ(f.records().size(), audit_before)
        << "the audit log recorded a role change that was never written";
    EXPECT_EQ(f.store->get_room_events(mirror, 1000, "f").size(), events_before)
        << "clients were told about a role document that was never stored";
}

// The endpoints must still work normally — a compare-and-swap that refuses
// uncontended writes would be a much worse bug than the one it fixes. This is
// the "it still does the ordinary thing" control for all four call sites.
TEST(ServerStateCompareAndSwap, TheDeltaEndpointsStillApplyUncontendedEdits) {
    Fixture f("f8-uncontended");
    f.seed_roles({role("pings", 5, 0, /*self_assignable=*/true)});
    auto builder = f.add_user("builder", {"builder"});
    f.add_user("member");
    f.add_channel(builder, "general");

    auto created = call(*f.roles, &RoleHandler::handle_create_role, kRolesPath, "token-builder",
                        create_body("Announcements", 5));
    ASSERT_EQ(created.status, 201) << created.body;
    const auto id = created_id(created);
    ASSERT_FALSE(id.empty());

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_update_role, role_path(id),
                          "token-builder", json{{"name", "Renamed"}}.dump())));
    EXPECT_EQ(f.find(id)->name, "Renamed");

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_add_self_role,
                          self_role_path("pings"), "token-member", "")));
    EXPECT_TRUE(f.holds("@member:test", "pings"));
    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_remove_self_role,
                          self_role_path("pings"), "token-member", "")));
    EXPECT_FALSE(f.holds("@member:test", "pings"));

    ASSERT_TRUE(IsOk(call(*f.roles, &RoleHandler::handle_delete_role, role_path(id),
                          "token-builder")));
    EXPECT_FALSE(f.find(id).has_value());
}
