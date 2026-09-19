// Lookalike ("homoglyph") usernames: the confusable skeleton, its storage, and
// what the rule would have cost if it had always been in force.
//
// Audit finding 20. The rule is a registration policy — see
// identity/Localpart.h — so these tests are as much about what it does NOT do
// (to logins, to existing accounts, to names that merely contain a digit) as
// about what it refuses.

#include <gtest/gtest.h>

#include "auth/LocalAuth.h"
#include "identity/Localpart.h"
#include "store/Migrations.h"
#include "store/SqliteStore.h"

#include <sqlite3.h>

#include <filesystem>
#include <string>

using namespace bsfchat;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() / ("bsfchat-" + name + ".db")).string();
}

} // namespace

// ── the folding itself ────────────────────────────────────────────────────

TEST(LocalpartSkeleton, FoldsThePairsTheAuditNamed) {
    EXPECT_EQ(localpart_skeleton("josh"), localpart_skeleton("j0sh"));   // 0 / o
    EXPECT_EQ(localpart_skeleton("lily"), localpart_skeleton("1ily"));   // 1 / l
    EXPECT_EQ(localpart_skeleton("bernard"), localpart_skeleton("bemard")); // rn / m
    EXPECT_EQ(localpart_skeleton("sawy"), localpart_skeleton("savvy"));  // w / vv
    EXPECT_EQ(localpart_skeleton("j.osh"), localpart_skeleton("j_osh"));
    EXPECT_EQ(localpart_skeleton("j-osh"), localpart_skeleton("josh"));

    // And the whole point: distinct names stay distinct.
    EXPECT_NE(localpart_skeleton("josh"), localpart_skeleton("joshua"));
    EXPECT_NE(localpart_skeleton("alice"), localpart_skeleton("bob"));
}

TEST(LocalpartSkeleton, SeparatorsGoBeforeTheMultigraphFolding) {
    // The ordering a naive implementation gets wrong. Folding `rn` -> `m` on
    // the raw input leaves `r.n` untouched, and `r.n` is exactly what someone
    // writes once they have worked out the rule.
    EXPECT_EQ(localpart_skeleton("r.n"), localpart_skeleton("m"));
    EXPECT_EQ(localpart_skeleton("be_rn-ard"), localpart_skeleton("bemard"));
    EXPECT_EQ(localpart_skeleton("sa.v.vy"), localpart_skeleton("sawy"));
}

TEST(LocalpartSkeleton, TheMultigraphFoldingHasNoPreferredOrder) {
    // Why the folding EXPANDS `m` -> `rn` rather than contracting `rn` -> `m`:
    // contraction is not confluent, and these are the cases that expose it.
    const auto m = localpart_skeleton("mm");
    EXPECT_EQ(m, localpart_skeleton("rnrn"));
    EXPECT_EQ(m, localpart_skeleton("mrn"));
    EXPECT_EQ(m, localpart_skeleton("rnm"));

    const auto w = localpart_skeleton("vvv");
    EXPECT_EQ(w, localpart_skeleton("vw"));
    EXPECT_EQ(w, localpart_skeleton("wv"));
}

TEST(LocalpartSkeleton, LeavesLeetspeakAndOtherWeakConfusablesAlone) {
    // Deliberate holes, each with a false-positive behind it. A trailing digit
    // is how people ordinarily disambiguate a taken name, `ian` and `lan` are
    // both real, and folding `cl` -> `d` would collide `clark` with `dark`.
    EXPECT_NE(localpart_skeleton("dave5"), localpart_skeleton("daves"));
    EXPECT_NE(localpart_skeleton("ian"), localpart_skeleton("lan"));
    EXPECT_NE(localpart_skeleton("clark"), localpart_skeleton("dark"));
    EXPECT_NE(localpart_skeleton("t3d"), localpart_skeleton("ted"));
}

TEST(LocalpartSkeleton, IsCaseInsensitiveAndTotal) {
    // Registration forces lowercase, but OIDC-derived localparts need not be,
    // and a skeleton that depended on case would silently stop matching.
    EXPECT_EQ(localpart_skeleton("Josh"), localpart_skeleton("josh"));
    EXPECT_EQ(localpart_skeleton(""), "");
    EXPECT_EQ(localpart_skeleton("..--__"), "") << "a name of nothing but separators";
}

// ── storage ───────────────────────────────────────────────────────────────

TEST(LocalpartPolicy, CreateUserRecordsASkeletonThatIsThenFindable) {
    SqliteStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_user("@josh:test", hash_password("p", 10)));

    auto found = store.find_user_by_localpart_skeleton(localpart_skeleton("j0sh"));
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(*found, "@josh:test");

    EXPECT_FALSE(store.find_user_by_localpart_skeleton(localpart_skeleton("alice")).has_value());
    // Never asked, because "" is also the column's default and would match
    // every row a backfill had missed.
    EXPECT_FALSE(store.find_user_by_localpart_skeleton("").has_value());
}

TEST(LocalpartPolicy, AnAccountIsNotItsOwnLookalike) {
    SqliteStore store(":memory:");
    store.initialize();
    store.create_user("@josh:test", hash_password("p", 10));
    auto c = store.count_localpart_skeleton_collisions();
    EXPECT_EQ(c.groups, 0);
    EXPECT_EQ(c.accounts, 0);
}

// ── the upgrade case ──────────────────────────────────────────────────────

TEST(LocalpartPolicy, TheMigrationBackfillsAndCountsWhatWouldHaveCollided) {
    // The question an operator upgrading into this rule actually has: how many
    // accounts do I already have that it would have refused? It is REPORTED,
    // never enforced — these accounts exist and their owners must keep being
    // able to sign in.
    auto path = temp_db_path("v20-skeletons");
    std::filesystem::remove(path);

    auto set_user_version = [&](int v) {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, ("PRAGMA user_version = " + std::to_string(v)).c_str(),
                               nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    };
    auto clear_skeletons = [&]() {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, "UPDATE users SET localpart_skeleton = ''",
                               nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    };

    // Two lookalike groups — {josh, j0sh, j.osh} and {bernard, bemard} — plus
    // three accounts that collide with nobody.
    {
        SqliteStore store(path);
        store.initialize();
        for (const char* local : {"josh", "j0sh", "j.osh", "bernard", "bemard",
                                  "alice", "bob", "carol"}) {
            ASSERT_TRUE(store.create_user(std::string("@") + local + ":test",
                                          hash_password("p", 10)))
                << local;
        }
    }

    // Rewind to a database as it was before v20: the column blank on every row,
    // which is what an upgrading deployment actually presents.
    clear_skeletons();
    set_user_version(19);
    {
        SqliteStore store(path);
        store.initialize();

        // The backfill ran: a name nobody typed into create_user is findable.
        auto found = store.find_user_by_localpart_skeleton(localpart_skeleton("alice"));
        ASSERT_TRUE(found.has_value()) << "pre-v20 rows were left without a skeleton";
        EXPECT_EQ(*found, "@alice:test");

        auto c = store.count_localpart_skeleton_collisions();
        EXPECT_EQ(c.groups, 2);
        EXPECT_EQ(c.accounts, 5) << "josh/j0sh/j.osh and bernard/bemard";

        // And nobody was evicted to make the numbers work.
        for (const char* local : {"josh", "j0sh", "j.osh", "bernard", "bemard",
                                  "alice", "bob", "carol"}) {
            EXPECT_TRUE(store.user_exists(std::string("@") + local + ":test")) << local;
        }
    }

    // Re-running the step is a no-op, not a failure: ALTER TABLE ADD COLUMN
    // has no IF NOT EXISTS, so the step has to check for itself.
    clear_skeletons();
    set_user_version(19);
    {
        SqliteStore store(path);
        store.initialize();
        auto c = store.count_localpart_skeleton_collisions();
        EXPECT_EQ(c.groups, 2);
        EXPECT_EQ(c.accounts, 5);
    }

    std::filesystem::remove(path);
}
