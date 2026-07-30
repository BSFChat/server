// Message search (F3).
//
// The security-critical property is permission filtering: a search must never
// surface a channel the caller lacks VIEW_CHANNEL on, nor a DM they are not part
// of. The correctness-critical properties are that redacted content is not
// searchable and that an edited message matches its CURRENT text rather than the
// pristine original — both of which depend on the index being maintained at the
// same choke points the edit/redaction work established.

#include <gtest/gtest.h>

#include "api/EventHandler.h"
#include "api/SearchHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <sqlite3.h>
#include <unistd.h>

#include <filesystem>
#include <memory>
#include <set>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

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

struct SearchFixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<EventHandler> events;
    std::unique_ptr<SearchHandler> search;

    static constexpr const char* kGeneral = "!general:test";
    static constexpr const char* kSecret = "!secret:test";

    SearchFixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        events = std::make_unique<EventHandler>(*store, *sync, config);
        search = std::make_unique<SearchHandler>(*store, config);

        store->create_room(kGeneral, "@alice:test");
        store->create_room(kSecret, "@alice:test");
        set_roles(permission::kEveryoneDefault);
    }

    void set_roles(permission::Flags everyone_flags) {
        ServerRolesContent roles;
        ServerRole everyone;
        everyone.id = permission::role_id::kEveryone;
        everyone.name = "@everyone";
        everyone.position = 0;
        everyone.permissions = everyone_flags;
        roles.roles.push_back(everyone);
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& rooms = {kGeneral}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);
        for (const auto& r : rooms) store->set_membership(r, uid, "join");
        return uid;
    }

    void deny_view(const std::string& user_id, const std::string& room_id) {
        ChannelPermissionOverride ov;
        ov.deny = permission::kViewChannel;
        json j;
        to_json(j, ov);
        store->insert_event("$deny-" + user_id + room_id, room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), "user:" + user_id,
                            j.dump(), 1);
    }

    httplib::Response send(const std::string& localpart, const std::string& text,
                           const std::string& txn, const std::string& room_id = kGeneral) {
        auto req = make_request(
            "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn,
            "token-" + localpart, json{{"msgtype", "m.text"}, {"body", text}}.dump());
        httplib::Response res;
        events->handle_send_event(req, res);
        return res;
    }

    httplib::Response edit(const std::string& localpart, const std::string& target,
                           const std::string& new_text, const std::string& txn,
                           const std::string& room_id = kGeneral) {
        auto content = json{
            {"msgtype", "m.text"},
            {"body", "* " + new_text},
            {"m.new_content", {{"msgtype", "m.text"}, {"body", new_text}}},
            {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}}};
        auto req = make_request(
            "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn,
            "token-" + localpart, content.dump());
        httplib::Response res;
        events->handle_send_event(req, res);
        return res;
    }

    static std::string event_id_of(const httplib::Response& res) {
        auto j = json::parse(res.body, nullptr, false);
        if (j.is_discarded() || !j.contains("event_id")) return {};
        return j["event_id"].get<std::string>();
    }

    // Runs a search and returns the room_events category.
    json run(const std::string& localpart, const json& room_events,
             const json& extra = json::object()) {
        json body;
        body["search_categories"]["room_events"] = room_events;
        for (auto& [k, v] : extra.items()) body[k] = v;
        auto req = make_request("/_matrix/client/v3/search", "token-" + localpart, body.dump());
        httplib::Response res;
        search->handle_search(req, res);
        if (!IsOk(res)) return json{{"__status", res.status}, {"__body", res.body}};
        auto parsed = json::parse(res.body, nullptr, false);
        if (parsed.is_discarded()) return json::object();
        return parsed["search_categories"]["room_events"];
    }

    static std::set<std::string> bodies_of(const json& category) {
        std::set<std::string> out;
        if (!category.contains("results")) return out;
        for (const auto& r : category["results"]) {
            out.insert(r["result"]["content"].value("body", ""));
        }
        return out;
    }
};

} // namespace

TEST(Search, Fts5IndexIsAvailable) {
    SearchFixture f;
    // If this fails the SQLite build has no FTS5 module; every other test in this
    // file is then meaningless, so assert it up front.
    ASSERT_TRUE(f.store->search_index_available())
        << "SQLite built without FTS5 — message search cannot work";
}

// ── Basic matching ────────────────────────────────────────────────────────

TEST(Search, FindsMessagesByTerm) {
    SearchFixture f;
    f.add_user("alice");
    ASSERT_TRUE(IsOk(f.send("alice", "the quick brown fox", "t1")));
    ASSERT_TRUE(IsOk(f.send("alice", "lazy dog sleeping", "t2")));

    auto cat = f.run("alice", {{"search_term", "fox"}});
    EXPECT_EQ(cat["count"], 1);
    EXPECT_EQ(f.bodies_of(cat), (std::set<std::string>{"the quick brown fox"}));
}

TEST(Search, MultipleTermsRequireAllOfThem) {
    SearchFixture f;
    f.add_user("alice");
    ASSERT_TRUE(IsOk(f.send("alice", "deploy the staging server", "t1")));
    ASSERT_TRUE(IsOk(f.send("alice", "deploy the production database", "t2")));

    auto cat = f.run("alice", {{"search_term", "deploy staging"}});
    EXPECT_EQ(cat["count"], 1);
    EXPECT_EQ(f.bodies_of(cat), (std::set<std::string>{"deploy the staging server"}));
}

TEST(Search, IsCaseInsensitive) {
    SearchFixture f;
    f.add_user("alice");
    ASSERT_TRUE(IsOk(f.send("alice", "Kubernetes Rollout", "t1")));
    EXPECT_EQ(f.run("alice", {{"search_term", "kubernetes"}})["count"], 1);
    EXPECT_EQ(f.run("alice", {{"search_term", "ROLLOUT"}})["count"], 1);
}

TEST(Search, HighlightsAreTheParsedTerms) {
    SearchFixture f;
    f.add_user("alice");
    ASSERT_TRUE(IsOk(f.send("alice", "alpha beta", "t1")));
    auto cat = f.run("alice", {{"search_term", "alpha beta"}});
    auto highlights = cat["highlights"].get<std::vector<std::string>>();
    EXPECT_EQ(highlights, (std::vector<std::string>{"alpha", "beta"}));
}

TEST(Search, NonMessageEventsAreNotIndexed) {
    SearchFixture f;
    f.add_user("alice");
    // State and signalling events carry JSON that would otherwise pollute
    // results — a topic change should not be a search hit for a message.
    f.store->insert_event("$s1", SearchFixture::kGeneral, "@alice:test",
                          std::string(event_type::kRoomTopic), "",
                          R"({"topic":"needle"})", 1);
    f.store->insert_event("$s2", SearchFixture::kGeneral, "@alice:test",
                          std::string(event_type::kCallInvite), std::nullopt,
                          R"({"call_id":"needle"})", 2);
    EXPECT_EQ(f.run("alice", {{"search_term", "needle"}})["count"], 0);
}

// ── Permission filtering (the security-critical part) ─────────────────────

TEST(Search, NeverSurfacesARoomTheUserIsNotIn) {
    SearchFixture f;
    f.add_user("alice", {SearchFixture::kGeneral, SearchFixture::kSecret});
    // Bob is only in #general.
    f.add_user("bob", {SearchFixture::kGeneral});

    ASSERT_TRUE(IsOk(f.send("alice", "pineapple in general", "t1", SearchFixture::kGeneral)));
    ASSERT_TRUE(IsOk(f.send("alice", "pineapple in secret", "t2", SearchFixture::kSecret)));

    auto alice_hits = f.run("alice", {{"search_term", "pineapple"}});
    EXPECT_EQ(alice_hits["count"], 2);

    auto bob_hits = f.run("bob", {{"search_term", "pineapple"}});
    EXPECT_EQ(bob_hits["count"], 1);
    EXPECT_EQ(f.bodies_of(bob_hits), (std::set<std::string>{"pineapple in general"}));
}

TEST(Search, NeverSurfacesARoomTheUserLacksViewChannelOn) {
    SearchFixture f;
    f.add_user("alice", {SearchFixture::kGeneral, SearchFixture::kSecret});
    // Bob is a MEMBER of both but is denied VIEW_CHANNEL on #secret. Membership
    // alone must not be enough.
    f.add_user("bob", {SearchFixture::kGeneral, SearchFixture::kSecret});
    f.deny_view("@bob:test", SearchFixture::kSecret);

    ASSERT_TRUE(IsOk(f.send("alice", "mango general", "t1", SearchFixture::kGeneral)));
    ASSERT_TRUE(IsOk(f.send("alice", "mango secret", "t2", SearchFixture::kSecret)));

    auto cat = f.run("bob", {{"search_term", "mango"}});
    EXPECT_EQ(cat["count"], 1);
    EXPECT_EQ(f.bodies_of(cat), (std::set<std::string>{"mango general"}))
        << "search leaked a channel the user cannot view";
}

TEST(Search, NeverSurfacesSomeoneElsesDm) {
    SearchFixture f;
    auto alice = f.add_user("alice", {});
    auto bob = f.add_user("bob", {});
    auto carol = f.add_user("carol", {});
    f.store->create_room("!dm:test", alice, /*is_direct=*/true);
    f.store->set_membership("!dm:test", alice, "join");
    f.store->set_membership("!dm:test", bob, "join");

    ASSERT_TRUE(IsOk(f.send("alice", "tangerine secret plan", "t1", "!dm:test")));

    // Both participants can find it.
    EXPECT_EQ(f.run("alice", {{"search_term", "tangerine"}})["count"], 1);
    EXPECT_EQ(f.run("bob", {{"search_term", "tangerine"}})["count"], 1);
    // Carol, who is not in the DM, cannot.
    EXPECT_EQ(f.run("carol", {{"search_term", "tangerine"}})["count"], 0)
        << "search leaked a DM the user is not part of";
    (void)carol;
}

TEST(Search, ClientSuppliedRoomFilterCanOnlyNarrowNotWiden) {
    SearchFixture f;
    f.add_user("alice", {SearchFixture::kGeneral, SearchFixture::kSecret});
    f.add_user("bob", {SearchFixture::kGeneral});

    ASSERT_TRUE(IsOk(f.send("alice", "papaya general", "t1", SearchFixture::kGeneral)));
    ASSERT_TRUE(IsOk(f.send("alice", "papaya secret", "t2", SearchFixture::kSecret)));

    // Bob explicitly asks to search #secret, which he cannot see. The filter is
    // intersected with what he is allowed to search, never substituted for it.
    auto cat = f.run("bob", {{"search_term", "papaya"},
                             {"filter", {{"rooms", json::array({SearchFixture::kSecret})}}}});
    EXPECT_EQ(cat["count"], 0);
    EXPECT_TRUE(f.bodies_of(cat).empty());

    // And narrowing to a room he CAN see works normally.
    auto narrowed = f.run("bob", {{"search_term", "papaya"},
                                  {"filter", {{"rooms", json::array({SearchFixture::kGeneral})}}}});
    EXPECT_EQ(narrowed["count"], 1);
}

TEST(Search, UserWithNoVisibleRoomsGetsNothingNotEverything) {
    SearchFixture f;
    f.add_user("alice", {SearchFixture::kGeneral});
    // Loner is a member of nothing.
    f.add_user("loner", {});
    ASSERT_TRUE(IsOk(f.send("alice", "durian", "t1")));

    // Fail-closed: an empty permitted-room set must produce an empty result, not
    // an unrestricted query.
    auto cat = f.run("loner", {{"search_term", "durian"}});
    EXPECT_EQ(cat["count"], 0);
}

TEST(Search, RequiresAuthentication) {
    SearchFixture f;
    httplib::Request req;
    req.path = "/_matrix/client/v3/search";
    req.body = R"({"search_categories":{"room_events":{"search_term":"x"}}})";
    httplib::Response res;
    f.search->handle_search(req, res);
    EXPECT_EQ(res.status, 401);
}

TEST(Search, RoomDeletionRemovesContentFromTheIndex) {
    SearchFixture f;
    f.add_user("alice", {SearchFixture::kGeneral, SearchFixture::kSecret});
    ASSERT_TRUE(IsOk(f.send("alice", "lychee somewhere", "t1", SearchFixture::kSecret)));
    ASSERT_TRUE(IsOk(f.send("alice", "kept in general", "t2", SearchFixture::kGeneral)));
    ASSERT_EQ(f.run("alice", {{"search_term", "lychee"}})["count"], 1);
    ASSERT_EQ(f.store->count_search_index_rows(), 2);

    f.store->delete_room(SearchFixture::kSecret);

    // Asserted on the INDEX, not just on the endpoint. The endpoint would report
    // zero either way, because deleting a room also drops its memberships and the
    // permission pass then excludes it — so an endpoint-only assertion passes
    // even if the index still holds every word of the deleted channel forever.
    EXPECT_EQ(f.store->count_search_index_rows(), 1)
        << "deleted room's messages were left in the search index";
    EXPECT_EQ(f.store->search_messages({SearchFixture::kSecret}, {"lychee"}, {}, 10, 0, false)
                  .hits.size(),
              0u)
        << "deleted room's content is still matchable in the index";
    // The surviving room is untouched.
    EXPECT_EQ(f.run("alice", {{"search_term", "kept"}})["count"], 1);
    EXPECT_EQ(f.run("alice", {{"search_term", "lychee"}})["count"], 0);
}

// ── Redaction and edits ───────────────────────────────────────────────────

TEST(Search, RedactedContentIsNotSearchable) {
    SearchFixture f;
    auto alice = f.add_user("alice");
    auto res = f.send("alice", "embarrassing rutabaga remark", "t1");
    ASSERT_TRUE(IsOk(res));
    ASSERT_EQ(f.run("alice", {{"search_term", "rutabaga"}})["count"], 1);

    ASSERT_TRUE(f.store->redact_event(SearchFixture::event_id_of(res), alice));
    EXPECT_EQ(f.run("alice", {{"search_term", "rutabaga"}})["count"], 0)
        << "redacted content was still searchable";
}

TEST(Search, EditedMessagesMatchCurrentTextNotPristine) {
    SearchFixture f;
    f.add_user("alice");
    auto first = f.send("alice", "meeting about apricots", "t1");
    ASSERT_TRUE(IsOk(first));
    auto target = SearchFixture::event_id_of(first);

    ASSERT_TRUE(IsOk(f.edit("alice", target, "meeting about blueberries", "t2")));

    // The old text is gone from the index...
    EXPECT_EQ(f.run("alice", {{"search_term", "apricots"}})["count"], 0)
        << "search still matched pre-edit text";
    // ...and the new text is findable, exactly once (the replacement must not
    // show up as a second, duplicate hit).
    auto cat = f.run("alice", {{"search_term", "blueberries"}});
    EXPECT_EQ(cat["count"], 1);
    EXPECT_EQ(f.bodies_of(cat), (std::set<std::string>{"meeting about blueberries"}));
}

TEST(Search, ResultsCarryTheOriginalEventIdentityAfterAnEdit) {
    SearchFixture f;
    f.add_user("alice");
    auto first = f.send("alice", "cranberry draft", "t1");
    ASSERT_TRUE(IsOk(first));
    auto target = SearchFixture::event_id_of(first);
    ASSERT_TRUE(IsOk(f.edit("alice", target, "cranberry final", "t2")));

    auto cat = f.run("alice", {{"search_term", "cranberry"}});
    ASSERT_EQ(cat["count"], 1);
    // The hit is the ORIGINAL event, so clicking through jumps to the right place
    // in the timeline, and it carries the same bundled-edit metadata /messages
    // returns.
    EXPECT_EQ(cat["results"][0]["result"]["event_id"], target);
    EXPECT_EQ(cat["results"][0]["result"]["content"]["body"], "cranberry final");
}

TEST(Search, RedactingAnEditRollsSearchBackToTheSurvivingText) {
    SearchFixture f;
    auto alice = f.add_user("alice");
    auto first = f.send("alice", "gooseberry original", "t1");
    ASSERT_TRUE(IsOk(first));
    auto target = SearchFixture::event_id_of(first);
    auto edit = f.edit("alice", target, "gooseberry revised", "t2");
    ASSERT_TRUE(IsOk(edit));
    ASSERT_EQ(f.run("alice", {{"search_term", "revised"}})["count"], 1);

    // Deleting the edit must roll the searchable text back to the original, the
    // same way the timeline rolls back.
    ASSERT_TRUE(f.store->redact_event(SearchFixture::event_id_of(edit), alice));
    EXPECT_EQ(f.run("alice", {{"search_term", "revised"}})["count"], 0);
    EXPECT_EQ(f.run("alice", {{"search_term", "original"}})["count"], 1);
}

// ── Request handling ──────────────────────────────────────────────────────

TEST(Search, MalformedRequestsAreRejected) {
    SearchFixture f;
    f.add_user("alice");

    auto attempt = [&](const std::string& raw) {
        auto req = make_request("/_matrix/client/v3/search", "token-alice", raw);
        httplib::Response res;
        f.search->handle_search(req, res);
        return res.status;
    };

    EXPECT_EQ(attempt("not json"), 400);
    EXPECT_EQ(attempt("{}"), 400);
    EXPECT_EQ(attempt(R"({"search_categories":{}})"), 400);
    EXPECT_EQ(attempt(R"({"search_categories":{"room_events":{}}})"), 400);
    EXPECT_EQ(attempt(R"({"search_categories":{"room_events":{"search_term":""}}})"), 400);
}

TEST(Search, Fts5SyntaxInTheSearchTermIsNeutralisedNotExecuted) {
    SearchFixture f;
    f.add_user("alice");
    ASSERT_TRUE(IsOk(f.send("alice", "harmless message", "t1")));

    // Every one of these is either a MATCH syntax error (which would surface as a
    // 500) or an expression that matches the whole index. They must all come back
    // as ordinary, well-formed responses.
    for (const auto& hostile : {"\"", "harmless\"", "*", "harmless OR *", "NEAR(a b",
                                "((((", "a AND AND b", "^", "harmless*", "\"unclosed",
                                "message NOT harmless", "col:value", "-harmless"}) {
        auto cat = f.run("alice", {{"search_term", hostile}});
        ASSERT_FALSE(cat.contains("__status")) << hostile << " -> " << cat.dump();
        ASSERT_TRUE(cat.contains("count")) << hostile;
        // A bare `*` must not become "return everything".
        if (std::string(hostile) == "*" || std::string(hostile) == "^" ||
            std::string(hostile) == "((((") {
            EXPECT_EQ(cat["count"], 0) << hostile;
        }
    }
}

TEST(Search, TokenizeDropsSyntaxAndBoundsTermCount) {
    // Operators and punctuation become separators, so no input can construct a
    // MATCH expression.
    EXPECT_EQ(SearchHandler::tokenize("hello world"),
              (std::vector<std::string>{"hello", "world"}));
    EXPECT_EQ(SearchHandler::tokenize("\"hello\" OR *"),
              (std::vector<std::string>{"hello", "OR"}));
    EXPECT_TRUE(SearchHandler::tokenize("*^()\"").empty());
    // Duplicates collapse.
    EXPECT_EQ(SearchHandler::tokenize("dup dup dup"), (std::vector<std::string>{"dup"}));
    // And the count is bounded.
    std::string many;
    for (int i = 0; i < 100; ++i) many += "term" + std::to_string(i) + " ";
    EXPECT_LE(SearchHandler::tokenize(many).size(), 16u);
}

TEST(Search, PunctuationOnlyTermReturnsEmptyRatherThanEverything) {
    SearchFixture f;
    f.add_user("alice");
    ASSERT_TRUE(IsOk(f.send("alice", "something", "t1")));
    auto cat = f.run("alice", {{"search_term", "!!! ??? ***"}});
    EXPECT_EQ(cat["count"], 0);
}

TEST(Search, SenderFilterNarrowsResults) {
    SearchFixture f;
    f.add_user("alice");
    f.add_user("bob");
    ASSERT_TRUE(IsOk(f.send("alice", "quince from alice", "t1")));
    ASSERT_TRUE(IsOk(f.send("bob", "quince from bob", "t2")));

    auto cat = f.run("alice", {{"search_term", "quince"},
                               {"filter", {{"senders", json::array({"@bob:test"})}}}});
    EXPECT_EQ(cat["count"], 1);
    EXPECT_EQ(f.bodies_of(cat), (std::set<std::string>{"quince from bob"}));
}

TEST(Search, LimitAndPaginationWork) {
    SearchFixture f;
    f.add_user("alice");
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(IsOk(f.send("alice", "persimmon number " + std::to_string(i),
                                "t" + std::to_string(i))));
    }

    auto page1 = f.run("alice", {{"search_term", "persimmon"},
                                 {"order_by", "recent"},
                                 {"filter", {{"limit", 2}}}});
    EXPECT_EQ(page1["count"], 5);
    EXPECT_EQ(page1["results"].size(), 2u);
    ASSERT_TRUE(page1.contains("next_batch"));

    auto page2 = f.run("alice",
                       {{"search_term", "persimmon"},
                        {"order_by", "recent"},
                        {"filter", {{"limit", 2}}}},
                       {{"next_batch", page1["next_batch"]}});
    EXPECT_EQ(page2["results"].size(), 2u);
    // Different page, no overlap.
    auto b1 = f.bodies_of(page1);
    auto b2 = f.bodies_of(page2);
    for (const auto& b : b2) EXPECT_EQ(b1.count(b), 0u) << "pages overlapped on " << b;

    // Limits are clamped, not trusted.
    auto huge = f.run("alice", {{"search_term", "persimmon"},
                                {"filter", {{"limit", 1000000}}}});
    EXPECT_LE(huge["results"].size(), static_cast<size_t>(limits::kMaxSearchLimit));
}

TEST(Search, RecentOrderingReturnsNewestFirst) {
    SearchFixture f;
    f.add_user("alice");
    ASSERT_TRUE(IsOk(f.send("alice", "elderberry one", "t1")));
    ASSERT_TRUE(IsOk(f.send("alice", "elderberry two", "t2")));
    ASSERT_TRUE(IsOk(f.send("alice", "elderberry three", "t3")));

    auto cat = f.run("alice", {{"search_term", "elderberry"}, {"order_by", "recent"}});
    ASSERT_EQ(cat["results"].size(), 3u);
    EXPECT_EQ(cat["results"][0]["result"]["content"]["body"], "elderberry three");
    EXPECT_EQ(cat["results"][2]["result"]["content"]["body"], "elderberry one");
}

// ── Index maintenance invariants ──────────────────────────────────────────

TEST(Search, IndexDoesNotGrowOnRepeatedEdits) {
    SearchFixture f;
    f.add_user("alice");
    auto first = f.send("alice", "version zero", "t0");
    ASSERT_TRUE(IsOk(first));
    auto target = SearchFixture::event_id_of(first);

    for (int i = 1; i <= 4; ++i) {
        ASSERT_TRUE(IsOk(f.edit("alice", target, "version " + std::to_string(i),
                                "e" + std::to_string(i))));
    }

    // One indexed row for the message, however many times it was rewritten.
    EXPECT_EQ(f.store->count_search_index_rows(), 1);
    EXPECT_EQ(f.run("alice", {{"search_term", "version"}})["count"], 1);
    EXPECT_EQ(f.run("alice", {{"search_term", "zero"}})["count"], 0);
    auto cat = f.run("alice", {{"search_term", "version"}});
    EXPECT_EQ(f.bodies_of(cat), (std::set<std::string>{"version 4"}));
}

TEST(Search, EmptyBodiesAreNotIndexed) {
    SearchFixture f;
    f.add_user("alice");
    // A message with no body (e.g. an attachment-only event some clients send)
    // contributes nothing to search and should not occupy an index row.
    auto req = make_request(
        std::string("/_matrix/client/v3/rooms/") + SearchFixture::kGeneral +
            "/send/m.room.message/tx",
        "token-alice", json{{"msgtype", "m.image"}, {"url", "mxc://x/y"}}.dump());
    httplib::Response res;
    f.events->handle_send_event(req, res);
    ASSERT_TRUE(IsOk(res));
    EXPECT_EQ(f.store->count_search_index_rows(), 0);
}

TEST(Search, BackfillIndexesPreExistingMessages) {
    SearchFixture f;
    f.add_user("alice");
    // Events inserted directly (as a pre-v12 deployment's rows would be) are
    // indexed by insert_event itself, which is the choke point the backfill
    // mirrors.
    f.store->insert_event("$old", SearchFixture::kGeneral, "@alice:test",
                          std::string(event_type::kRoomMessage), std::nullopt,
                          R"({"msgtype":"m.text","body":"historic watermelon"})", 1);
    EXPECT_EQ(f.run("alice", {{"search_term", "watermelon"}})["count"], 1);
}

// ══ Atomicity of insert_event and its search-index write ══════════════════
//
// The defect: insert_event wrote the `events` row and then, as a separate
// statement, the `event_search` row. A throw between the two left an event that
// was permanently in the timeline and permanently invisible to /search. Nothing
// notices — the sender sees their message, the reader sees it, and only a search
// that should have matched quietly does not. There is no reindex pass anywhere in
// the server that would ever repair it.
//
// A happy-path test proves NOTHING about this: both writes succeed whether or not
// they share a transaction. The only honest proof is an injected failure between
// them, so a SECOND connection to the same database file installs a BEFORE INSERT
// trigger on `event_search` that RAISEs ABORT. That makes the index write — and
// only the index write — fail after the events row has already been written,
// which is precisely the window in question.
//
// RAISE(ABORT) is the right injection shape here: ABORT undoes the current
// statement and leaves the enclosing transaction OPEN, so the events row survives
// unless insert_event explicitly rolls back. A fault that auto-rolled-back
// (SQLITE_FULL) would let a broken implementation pass.

namespace {

std::string atomicity_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-atomicity-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_atomicity_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

// Runs SQL on a SEPARATE connection to the same file, so the fault is installed
// in the DATABASE rather than by reaching inside SqliteStore. Returns the sqlite
// result code.
int fault_exec(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return SQLITE_ERROR;
    sqlite3_busy_timeout(db, 5000);
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    sqlite3_close(db);
    return rc;
}

int64_t raw_scalar(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return -1;
    sqlite3_busy_timeout(db, 5000);
    sqlite3_stmt* stmt = nullptr;
    int64_t out = -1;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) out = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

std::string message_json(const std::string& body) {
    return json{{"msgtype", "m.text"}, {"body", body}}.dump();
}

// A file-backed store (not ":memory:") so a second connection can reach the same
// data to install the fault.
struct AtomicityFixture {
    std::string path;
    std::unique_ptr<SqliteStore> store;
    static constexpr const char* kRoom = "!atomic:test";

    explicit AtomicityFixture(const std::string& name) {
        path = atomicity_db_path(name);
        remove_atomicity_db(path);
        store = std::make_unique<SqliteStore>(path);
        store->initialize();
        store->create_room(kRoom, "@alice:test");
    }
    ~AtomicityFixture() {
        store.reset();
        remove_atomicity_db(path);
    }

    int64_t events_rows(const std::string& event_id) {
        return raw_scalar(path, "SELECT COUNT(*) FROM events WHERE event_id = '" + event_id + "'");
    }
    int64_t index_rows(const std::string& event_id) {
        return raw_scalar(path,
                          "SELECT COUNT(*) FROM event_search WHERE event_id = '" + event_id + "'");
    }
    int install_fault() {
        return fault_exec(path,
            "CREATE TRIGGER fault_on_index BEFORE INSERT ON event_search "
            "BEGIN SELECT RAISE(ABORT, 'injected search-index failure'); END");
    }
    int remove_fault() { return fault_exec(path, "DROP TRIGGER fault_on_index"); }
};

} // namespace

TEST(SearchIndexAtomicity, AFailedIndexWriteLeavesNoOrphanedEvent) {
    AtomicityFixture f("orphan");

    // Positive control, BEFORE anything is broken: a normal insert really does
    // populate both tables. Without this the assertions below could pass because
    // insert_event never writes anything at all.
    ASSERT_NO_THROW(f.store->insert_event("$ok", AtomicityFixture::kRoom, "@alice:test",
                                          std::string(event_type::kRoomMessage), std::nullopt,
                                          message_json("indexable pineapple"), 1000));
    ASSERT_EQ(f.events_rows("$ok"), 1);
    ASSERT_EQ(f.index_rows("$ok"), 1);

    // Now the SECOND write, and only the second write, fails.
    ASSERT_EQ(f.install_fault(), SQLITE_OK);

    // Control that the fault is real and is aimed where we think: an insert that
    // would NOT be indexed (a state event) is untouched by it. If this threw, the
    // trigger would be breaking something other than the index write and the
    // assertion below would be proving the wrong thing.
    ASSERT_NO_THROW(f.store->insert_event("$state", AtomicityFixture::kRoom, "@alice:test",
                                          std::string(event_type::kRoomName), std::string(""),
                                          json{{"name", "atomic"}}.dump(), 1001));
    ASSERT_EQ(f.events_rows("$state"), 1);

    // The message insert must fail...
    EXPECT_THROW(f.store->insert_event("$bad", AtomicityFixture::kRoom, "@alice:test",
                                       std::string(event_type::kRoomMessage), std::nullopt,
                                       message_json("orphan watermelon"), 1002),
                 std::exception);

    // ...and must have left NOTHING behind. Checked on the raw tables through a
    // separate connection, so no read-path filtering can hide a surviving row.
    // Note the fault is still installed here: these are pure reads, and removing
    // it first would let a rollback that happened for the wrong reason pass.
    EXPECT_EQ(f.events_rows("$bad"), 0) << "the event row survived a failed index write";
    EXPECT_EQ(f.index_rows("$bad"), 0);

    // Belt and braces on the read path too.
    EXPECT_FALSE(f.store->get_event_by_id("$bad").has_value());
    EXPECT_EQ(f.store->count_search_index_rows(), 1) << "only $ok should be indexed";

    // The store must still be usable: a rolled-back transaction must not have
    // been left open, which would make every later write fail.
    ASSERT_EQ(f.remove_fault(), SQLITE_OK);
    ASSERT_NO_THROW(f.store->insert_event("$after", AtomicityFixture::kRoom, "@alice:test",
                                          std::string(event_type::kRoomMessage), std::nullopt,
                                          message_json("recovered mango"), 1003));
    EXPECT_EQ(f.events_rows("$after"), 1);
    EXPECT_EQ(f.index_rows("$after"), 1);
}

TEST(SearchIndexAtomicity, ARolledBackInsertIsInvisibleToSearchAndToTheTimeline) {
    AtomicityFixture f("invisible");
    f.store->set_membership(AtomicityFixture::kRoom, "@alice:test", "join");

    ASSERT_EQ(f.install_fault(), SQLITE_OK);
    EXPECT_THROW(f.store->insert_event("$ghost", AtomicityFixture::kRoom, "@alice:test",
                                       std::string(event_type::kRoomMessage), std::nullopt,
                                       message_json("ghost blueberry"), 2000),
                 std::exception);
    ASSERT_EQ(f.remove_fault(), SQLITE_OK);

    // The half-written state this test exists to rule out is "in the timeline,
    // absent from search". Assert BOTH halves: an implementation that rolled back
    // only the index would pass the search check alone.
    auto timeline = f.store->get_room_events(AtomicityFixture::kRoom, 50);
    for (const auto& e : timeline) {
        EXPECT_NE(e.event_id, "$ghost") << "a rolled-back event is in the timeline";
    }
    auto hits = f.store->search_messages({AtomicityFixture::kRoom}, {"blueberry"}, {}, 10, 0, true);
    EXPECT_TRUE(hits.hits.empty()) << "a rolled-back event is in the search index";

    // And the SAME body inserted afterwards is fully searchable, which proves the
    // emptiness above is the rollback and not a broken search fixture.
    ASSERT_NO_THROW(f.store->insert_event("$real", AtomicityFixture::kRoom, "@alice:test",
                                          std::string(event_type::kRoomMessage), std::nullopt,
                                          message_json("ghost blueberry"), 2001));
    auto after = f.store->search_messages({AtomicityFixture::kRoom}, {"blueberry"}, {}, 10, 0, true);
    ASSERT_EQ(after.hits.size(), 1u);
    EXPECT_EQ(after.hits[0].event_id, "$real");
}
