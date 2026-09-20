// The offline admin CLI: `bsfchat-server grant-admin`.
//
// THE ACCEPTANCE CRITERION, and it is not "the user ends up with admin".
//
// The production recovery this replaces DID give the account the admin role —
// by hand-writing rows into `server_state` and `events` over SSH — and the
// result was still wrong in three specific ways, every one of which is a
// silent failure that only shows up later:
//
//   1. no audit record, so the most powerful role on the server changed hands
//      with nothing to show for it;
//   2. no /sync mirror event, so no connected client learned about the grant
//      until it was restarted;
//   3. a stream position chosen by hand.
//
// So the central test asserts all three properties of the write, not the role
// list. A version of this command that wrote the server_state row directly —
// the obvious, shorter implementation, and the one the SSH session was — passes
// a "does bob have admin" assertion and fails this file.
//
// The rest covers the refusals, because a recovery tool that writes to the
// wrong database or behind a live server is worse than no tool: it exits 0.

#include <gtest/gtest.h>

#include "audit/AuditLog.h"
#include "auth/LocalAuth.h"
#include "auth/RoleBootstrap.h"
#include "cli/AdminCli.h"
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
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_path(const std::string& name, const std::string& ext) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-admincli-" + name + "-" + std::to_string(::getpid()) + ext)).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

// A probe that always says "nothing is listening" — the stopped-server case,
// which is what almost every test here wants. The refusal path gets the other
// one. Injecting this instead of binding a real port keeps the suite from
// depending on which ports happen to be free on the machine running it.
ListenProbe server_stopped() {
    return [](const std::string&, int) { return false; };
}

ListenProbe server_running() {
    return [](const std::string&, int) { return true; };
}

struct Fixture {
    std::string db_path;
    std::string config_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::string mirror_room;

    explicit Fixture(const std::string& name) {
        db_path = temp_path(name, ".db");
        config_path = temp_path(name, ".toml");
        remove_db(db_path);

        // A real TOML file on disk, because --config taking a path IS the
        // interface under test: the command has to be usable by an operator
        // with nothing but a shell and the config the server already uses.
        std::ofstream(config_path) << "[server]\nname = \"test\"\nport = 18448\n"
                                   << "[database]\npath = \"" << db_path << "\"\n";

        config = Config::defaults();
        config.server_name = "test";
        config.database_path = db_path;
        config.password_hash_cost = 10;

        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);

        // A channel has to exist for there to be anywhere to mirror into.
        // pick_server_state_mirror_room returns "" on a server with no
        // channels, and the mirror is skipped — presentation only, by design.
        mirror_room = generate_room_id("test");
        store->create_room(mirror_room, "@root:test");
        store->insert_event(generate_event_id("test"), mirror_room, "@root:test",
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "text"}}.dump(), 1000);

        // Seeds the default role DEFINITIONS the way a real server start does.
        bootstrap_roles(*store, *sync, config);
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
        std::filesystem::remove(config_path);
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& roles = {}) {
        const std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        if (!roles.empty()) {
            MemberRolesContent c;
            c.role_ids = roles;
            json j;
            to_json(j, c);
            // Straight into server_state, so fixture setup leaves no audit
            // records for the assertions below to trip over.
            store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                    j.dump());
        }
        return uid;
    }

    std::vector<std::string> roles_of(const std::string& uid) {
        return store->get_member_role_ids(uid);
    }

    bool holds_admin(const std::string& uid) {
        auto r = roles_of(uid);
        return std::find(r.begin(), r.end(), std::string(permission::role_id::kAdmin)) != r.end();
    }

    std::vector<SqliteStore::AuditRecord> role_assignments_for(const std::string& uid) {
        SqliteStore::AuditFilter filter;
        filter.target_user = uid;
        filter.action = std::string(audit_action::kRoleAssign);
        return store->list_audit_records(50, std::nullopt, filter).records;
    }
};

// Runs the command and hands back both halves of what an operator sees.
struct Run {
    int code;
    std::string output;
};

Run run(const std::vector<std::string>& args, ListenProbe probe) {
    std::ostringstream out;
    const int code = run_admin_cli(args, out, probe);
    return {code, out.str()};
}

} // namespace

// ── The one that matters ──────────────────────────────────────────────────

TEST(AdminCli, GrantAdminWritesAuthoritativeStateAndAuditAndSyncMirror) {
    Fixture f("grant");
    const auto bob = f.add_user("bob", {std::string(permission::role_id::kEveryone)});
    ASSERT_FALSE(f.holds_admin(bob));

    auto r = run({"grant-admin", "--config", f.config_path, "--user", bob}, server_stopped());
    ASSERT_EQ(r.code, 0) << r.output;

    // 1. AUTHORITATIVE. The server_state row, which is the copy no channel
    //    deletion can destroy and the only one the permission engine reads.
    EXPECT_TRUE(f.holds_admin(bob)) << r.output;

    // 2. AUDITED. The SSH recovery left nothing here at all, which is how a
    //    server ends up unable to answer "who made that account an admin?".
    auto records = f.role_assignments_for(bob);
    ASSERT_EQ(records.size(), 1u) << "expected exactly one role.assign record for " << bob;
    // Attributed to the console actor, NOT to @server:test. Telling a
    // bootstrap grant apart from one made by a human with shell access is the
    // entire reason the actor is distinct.
    EXPECT_EQ(records.front().actor, "@console:test");
    EXPECT_NE(records.front().after_json.find(permission::role_id::kAdmin), std::string::npos);

    // 3. MIRRORED INTO A ROOM. Without this a connected client keeps rendering
    //    the old role set — on production, the Server Settings gear stayed
    //    missing after the grant until the app was restarted.
    auto mirrored = f.store->get_state_event(f.mirror_room,
                                             std::string(event_type::kMemberRoles), bob);
    ASSERT_TRUE(mirrored.has_value()) << "no mirror event: clients will not learn about this";
    EXPECT_NE(mirrored->content.data.dump().find(permission::role_id::kAdmin),
              std::string::npos);
    EXPECT_EQ(mirrored->sender, "@console:test");
}

TEST(AdminCli, GrantAdminKeepsTheRolesTheAccountAlreadyHad) {
    Fixture f("keep");
    const auto bob = f.add_user("bob", {std::string(permission::role_id::kEveryone),
                                        std::string(permission::role_id::kModerator)});

    ASSERT_EQ(run({"grant-admin", "--config", f.config_path, "--user", bob},
                  server_stopped()).code, 0);

    auto roles = f.roles_of(bob);
    // A grant is an addition, not a replacement. Writing {everyone, admin}
    // over the top would silently strip every delegated role the account held
    // — invisible on the account being recovered, and destructive on any
    // other.
    EXPECT_NE(std::find(roles.begin(), roles.end(),
                        std::string(permission::role_id::kModerator)), roles.end());
    EXPECT_TRUE(f.holds_admin(bob));
}

TEST(AdminCli, GrantAdminGivesEveryoneToAnAccountThatHadNoAssignmentAtAll) {
    Fixture f("noassign");
    const std::string bob = "@bob:test";
    f.store->create_user(bob, hash_password("password", 10));
    ASSERT_TRUE(f.roles_of(bob).empty());

    ASSERT_EQ(run({"grant-admin", "--config", f.config_path, "--user", bob},
                  server_stopped()).code, 0);

    auto roles = f.roles_of(bob);
    // @everyone as well as admin. An account holding admin alone would be
    // skipped by every future bootstrap pass (it only writes where the list is
    // empty) and would take its base permissions from one role — a difference
    // nobody would notice until a permission was removed from admin.
    EXPECT_NE(std::find(roles.begin(), roles.end(),
                        std::string(permission::role_id::kEveryone)), roles.end());
    EXPECT_TRUE(f.holds_admin(bob));
}

TEST(AdminCli, GrantAdminIsIdempotentAndDoesNotRepeatTheAuditRecord) {
    Fixture f("idem");
    const auto bob = f.add_user("bob", {std::string(permission::role_id::kEveryone)});

    ASSERT_EQ(run({"grant-admin", "--config", f.config_path, "--user", bob},
                  server_stopped()).code, 0);
    auto second = run({"grant-admin", "--config", f.config_path, "--user", bob},
                      server_stopped());
    EXPECT_EQ(second.code, 0);
    EXPECT_NE(second.output.find("already holds"), std::string::npos) << second.output;

    // Still one record. An operator running the command twice because the
    // first run scrolled off the screen must not manufacture a second "admin
    // granted" entry — an audit log that cries wolf is one nobody reads.
    EXPECT_EQ(f.role_assignments_for(bob).size(), 1u);
}

// ── Refusals ──────────────────────────────────────────────────────────────

TEST(AdminCli, RefusesToWriteBehindARunningServer) {
    Fixture f("running");
    const auto bob = f.add_user("bob", {std::string(permission::role_id::kEveryone)});

    auto r = run({"grant-admin", "--config", f.config_path, "--user", bob}, server_running());

    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.output.find("still running"), std::string::npos) << r.output;
    // And nothing was written. The failure mode this prevents is not a lost
    // grant: it is the RUNNING server claiming the same event stream position
    // and throwing on the next message anybody sends, long after this command
    // exited.
    EXPECT_FALSE(f.holds_admin(bob));
    EXPECT_TRUE(f.role_assignments_for(bob).empty());
}

TEST(AdminCli, RefusesWithoutAConfigRatherThanGuessingADatabase) {
    Fixture f("noconfig");
    auto r = run({"grant-admin", "--user", "@bob:test"}, server_stopped());
    EXPECT_EQ(r.code, 2);
    EXPECT_NE(r.output.find("--config is required"), std::string::npos) << r.output;
    // The default database path is RELATIVE (./data/bsfchat.db). A command that
    // fell back to it would create an empty database wherever the operator
    // happened to be standing, grant admin in it, and print success.
    EXPECT_FALSE(std::filesystem::exists("./data/bsfchat.db"));
}

TEST(AdminCli, RefusesAnAccountThatDoesNotExistInsteadOfCreatingIt) {
    Fixture f("nouser");
    auto r = run({"grant-admin", "--config", f.config_path, "--user", "@nobody:test"},
                 server_stopped());
    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.output.find("list-users"), std::string::npos) << r.output;
    EXPECT_FALSE(f.store->user_exists("@nobody:test"));
    // A typo must not mint an account nobody can sign in as while leaving the
    // real lockout exactly where it was.
    EXPECT_TRUE(f.store->get_server_state(std::string(event_type::kMemberRoles),
                                          "@nobody:test") == std::nullopt);
}

TEST(AdminCli, RefusesAMalformedUserId) {
    Fixture f("badid");
    auto r = run({"grant-admin", "--config", f.config_path, "--user", "bob"}, server_stopped());
    EXPECT_EQ(r.code, 2);
    EXPECT_NE(r.output.find("not a valid user id"), std::string::npos) << r.output;
}

TEST(AdminCli, RefusesAnUnrecognisedFlag) {
    Fixture f("badflag");
    // Same discipline as main()'s argument loop: an unrecognised argument is a
    // mistake, and the safe response to a mistake against a database is to stop.
    auto r = run({"grant-admin", "--config", f.config_path, "--user", "@bob:test", "--force"},
                 server_stopped());
    EXPECT_EQ(r.code, 2);
    EXPECT_NE(r.output.find("unrecognised argument"), std::string::npos) << r.output;
}

// ── list-users ────────────────────────────────────────────────────────────

TEST(AdminCli, ListUsersShowsIdsDisplayNamesAndWhoHoldsAdmin) {
    Fixture f("list");
    const auto alice = f.add_user("alice", {std::string(permission::role_id::kEveryone),
                                            std::string(permission::role_id::kAdmin)});
    const auto bob = f.add_user("oidc_a5cdbefe", {std::string(permission::role_id::kEveryone)});
    f.store->set_display_name(bob, "josh");

    auto r = run({"list-users", "--config", f.config_path}, server_stopped());
    ASSERT_EQ(r.code, 0) << r.output;
    EXPECT_NE(r.output.find(alice), std::string::npos);
    EXPECT_NE(r.output.find(bob), std::string::npos);
    // The display name is shown because it is the ONLY thing the locked-out
    // operator recognises: on production the duplicate accounts were
    // @oidc_a5cdbefe-… and @oidc_76ea6af7-…, both displaying as a name he knew.
    EXPECT_NE(r.output.find("josh"), std::string::npos);
    EXPECT_NE(r.output.find("[admin]"), std::string::npos);
}
