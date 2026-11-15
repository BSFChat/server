// The indexed edit and reaction lookups, and the v32 backfill behind them
// (audit 2026-11-15, R-7/8).
//
// find_reaction_event() used json_extract over every reaction a sender made in
// a room, and reresolve_edit_locked() used `content LIKE '%<id>%'` over every
// message in it. Both now ride columns written at insert (`relates_to`,
// `replaces`); these tests pin that the answers did not change, including for
// rows written before the column existed.

#include <gtest/gtest.h>

#include "store/Migrations.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>

#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <unistd.h>

#include <filesystem>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-indexes-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

void seed(SqliteStore& store) {
    store.create_user("@alice:test", "hash");
    store.create_room("!r:test", "@alice:test");
    store.set_membership("!r:test", "@alice:test", "join");
    store.insert_event("$msg", "!r:test", "@alice:test", "m.room.message", std::nullopt,
                       json{{"msgtype", "m.text"}, {"body", "hi"}}.dump(), 1);
    store.insert_event("$react", "!r:test", "@alice:test", std::string(event_type::kReaction),
                       std::nullopt,
                       json{{"m.relates_to",
                             {{"rel_type", "m.annotation"}, {"event_id", "$msg"}, {"key", "👍"}}}}
                           .dump(),
                       2);
}

} // namespace

TEST(StoreIndexes, ReactionDedupeFindsExactlyTheMatchingReaction) {
    SqliteStore store(":memory:");
    store.initialize();
    seed(store);

    EXPECT_EQ(store.find_reaction_event("!r:test", "@alice:test", "$msg", "👍").value_or(""),
              "$react");
    EXPECT_FALSE(store.find_reaction_event("!r:test", "@alice:test", "$msg", "🎉"));
    EXPECT_FALSE(store.find_reaction_event("!r:test", "@bob:test", "$msg", "👍"));
    EXPECT_FALSE(store.find_reaction_event("!other:test", "@alice:test", "$msg", "👍"));
    ASSERT_TRUE(store.redact_event("$react", "@alice:test"));
    EXPECT_FALSE(store.find_reaction_event("!r:test", "@alice:test", "$msg", "👍"))
        << "a redacted reaction must not block re-reacting";
}

TEST(StoreIndexes, V32BackfillsReactionsWrittenBeforeTheColumn) {
    const auto path = temp_db_path("v32");
    remove_db(path);
    {
        SqliteStore store(path);
        store.initialize();
        seed(store);
    }
    // Rewind to the v31 shape as far as the data goes: the column exists but
    // holds nothing, exactly what ALTER TABLE leaves on an upgraded database.
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, "UPDATE events SET relates_to = NULL; PRAGMA user_version = 31",
                               nullptr, nullptr, nullptr),
                  SQLITE_OK);
        sqlite3_close(db);
    }
    {
        SqliteStore store(path);
        store.initialize();
        EXPECT_EQ(store.find_reaction_event("!r:test", "@alice:test", "$msg", "👍").value_or(""),
                  "$react")
            << "a reaction from before v32 is invisible to the dedupe";
    }
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        EXPECT_EQ(get_schema_version(db), kTargetSchemaVersion);
        sqlite3_close(db);
    }
    remove_db(path);
}

TEST(StoreIndexes, AnEditStillResolvesAndARedactedEditFallsBack) {
    SqliteStore store(":memory:");
    store.initialize();
    seed(store);
    auto edit = [&](const std::string& id, const std::string& body, int64_t ts) {
        store.insert_event(id, "!r:test", "@alice:test", "m.room.message", std::nullopt,
                           json{{"msgtype", "m.text"},
                                {"body", "* " + body},
                                {"m.new_content", {{"msgtype", "m.text"}, {"body", body}}},
                                {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", "$msg"}}}}
                               .dump(),
                           ts);
        ASSERT_TRUE(store.apply_edit("$msg", id));
    };
    edit("$e1", "first", 3);
    edit("$e2", "second", 4);
    EXPECT_EQ(store.get_edit_pointer("$msg").value_or(""), "$e2");
    // Redacting the winning edit re-resolves through reresolve_edit_locked,
    // which now finds candidates by `replaces` instead of a LIKE scan.
    ASSERT_TRUE(store.redact_event("$e2", "@alice:test"));
    EXPECT_EQ(store.get_edit_pointer("$msg").value_or(""), "$e1");
}
