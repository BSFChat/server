// Redaction residue: what a redaction has to reach.
//
// The model these tests pin down is stated once, in SqliteStore::redact_event:
// a message is not a row, it is the original event plus every m.replace of it,
// and redaction removes the text of ALL of them from every surface that holds
// it — the events table, the FTS index, the bundled edit history, the mention
// rows and the undispatched push queue.
//
// Each test names the surface it guards. They were all confirmed to fail (or,
// where noted, to already hold) against the pre-fix build.

#include <gtest/gtest.h>

#include "api/EventHandler.h"
#include "api/PushHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "push/PushService.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <sqlite3.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

constexpr const char* kSecret = "AWS_SECRET_ACCESS_KEY=hunter2";

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

// httplib leaves status at -1 until the response is written to a socket, so a
// handler that succeeded typically never touched it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

// Records what the gateway was asked to deliver. A push that leaves the server
// cannot be recalled, so "the gateway never saw it" is the property under test.
struct FakeGateway {
    std::mutex mutex;
    std::vector<std::string> bodies;
    PushService::GatewayResponse response{/*transport_ok=*/true, /*status=*/200, {}};

    PushService::Transport transport() {
        return [this](const std::string&, const std::string& body) {
            std::lock_guard lock(mutex);
            bodies.push_back(body);
            return response;
        };
    }
    size_t call_count() {
        std::lock_guard lock(mutex);
        return bodies.size();
    }
    bool any_body_contains(const std::string& needle) {
        std::lock_guard lock(mutex);
        for (const auto& b : bodies) {
            if (b.find(needle) != std::string::npos) return true;
        }
        return false;
    }
};

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-residue-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

// Raw SQL against a file database, outside the store. Used to put a database
// into a state the fixed code cannot produce — the state an EARLIER build left
// behind — so the repair paths can be tested at all.
void raw_exec(const std::string& path, const std::string& sql) {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
    char* err = nullptr;
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    std::string msg = err ? err : "";
    sqlite3_free(err);
    sqlite3_close(db);
    ASSERT_EQ(rc, SQLITE_OK) << msg << " [" << sql << "]";
}

struct ResidueFixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<PushService> push;
    std::unique_ptr<EventHandler> events;
    std::unique_ptr<PushHandler> pushers;
    FakeGateway gateway;

    std::string alice;
    std::string bob;
    std::string room = "!general:test";

    static constexpr const char* kGatewayUrl = "https://gateway.example/_matrix/push/v1/notify";

    // `db_path` empty means an in-memory database. A file is needed only by the
    // tests that reach around the store with raw SQL. `seed` is false when
    // reopening a database this fixture already populated — the second open is
    // the upgrade under test, and creating the room again would collide.
    explicit ResidueFixture(const std::string& db_path = "", bool seed = true) {
        config = Config::defaults();
        config.server_name = "test";
        config.push.worker_poll_ms = 50;
        config.push.base_backoff_ms = 100;
        config.push.max_backoff_ms = 100;
        config.push.max_attempts = 2;

        store = std::make_unique<SqliteStore>(db_path.empty() ? ":memory:" : db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        push = std::make_unique<PushService>(*store, config);
        push->set_transport(gateway.transport());
        events = std::make_unique<EventHandler>(*store, *sync, config, push.get());
        pushers = std::make_unique<PushHandler>(*store, *push, config);

        alice = "@alice:test";
        bob = "@bob:test";
        if (!seed) return;

        ServerRolesContent roles;
        ServerRole everyone;
        everyone.id = permission::role_id::kEveryone;
        everyone.name = "@everyone";
        everyone.position = 0;
        everyone.permissions = permission::kEveryoneDefault;
        roles.roles.push_back(everyone);
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());

        store->create_room(room, "@alice:test");
        alice = add_user("alice");
        bob = add_user("bob");
    }

    std::string add_user(const std::string& localpart) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);
        store->set_membership(room, uid, "join");
        return uid;
    }

    void register_pusher(const std::string& localpart, const std::string& pushkey) {
        auto req = make_request("/_matrix/client/v3/pushers/set", "token-" + localpart,
                                json{{"pushkey", pushkey},
                                     {"kind", "http"},
                                     {"app_id", "com.bsfchat.app"},
                                     {"app_display_name", "BSFChat"},
                                     {"device_display_name", "Phone"},
                                     {"lang", "en"},
                                     {"data", {{"url", kGatewayUrl}}}}
                                    .dump());
        httplib::Response res;
        pushers->handle_set_pusher(req, res);
        ASSERT_TRUE(IsOk(res)) << res.body;
    }

    std::string send(const std::string& body, const std::string& txn) {
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + room + "/send/m.room.message/" + txn,
                                "token-alice",
                                json{{"msgtype", "m.text"}, {"body", body}}.dump());
        events->handle_send_event(req, res);
        EXPECT_TRUE(IsOk(res)) << res.body;
        return json::parse(res.body).value("event_id", "");
    }

    // The payload the desktop client sends: "* " fallback body plus the
    // authoritative m.new_content. BOTH carry the text, which is why stripping
    // only one of them would not be a fix.
    std::string edit(const std::string& target, const std::string& new_body,
                     const std::string& txn) {
        json content = {
            {"msgtype", "m.text"},
            {"body", "* " + new_body},
            {"m.new_content", {{"msgtype", "m.text"}, {"body", new_body}}},
            {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}},
        };
        httplib::Response res;
        auto req = make_request("/_matrix/client/v3/rooms/" + room + "/send/m.room.message/" + txn,
                                "token-alice", content.dump());
        events->handle_send_event(req, res);
        EXPECT_TRUE(IsOk(res)) << res.body;
        return json::parse(res.body).value("event_id", "");
    }

    httplib::Response redact(const std::string& target, const std::string& txn,
                             const std::string& token = "token-alice") {
        httplib::Response res;
        auto req = make_request(
            "/_matrix/client/v3/rooms/" + room + "/redact/" + target + "/" + txn, token, "{}");
        events->handle_redact(req, res);
        return res;
    }

    std::vector<RoomEvent> timeline() {
        return store->get_room_events_paginated(room, 100, "b").first;
    }

    std::optional<RoomEvent> from_timeline(const std::string& event_id) {
        for (const auto& ev : timeline()) {
            if (ev.event_id == event_id) return ev;
        }
        return std::nullopt;
    }

    // The question every one of these tests really asks: can a plain member
    // still read this text anywhere in the room's history?
    bool timeline_contains(const std::string& needle) {
        for (const auto& ev : timeline()) {
            if (ev.content.data.dump().find(needle) != std::string::npos) return true;
            if (ev.unsigned_data && ev.unsigned_data->data.dump().find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    int search_hits(const std::string& term) {
        return store->search_messages({room}, {term}, {}, 10, 0, false).total;
    }
};

} // namespace

// ── B1: the edit's text survived the redaction ────────────────────────────

// The composition nothing covered: redaction was tested on an unedited message
// and on the edits themselves, never on a message that still HAS surviving
// replacements. Each replacement is an ordinary m.room.message row that
// /messages returns with no type and no relation filter, so the text the user
// asked to delete came straight back.
TEST(RedactionResidue, RedactingAnEditedMessageRemovesTheEditsText) {
    ResidueFixture f;
    auto original = f.send("nothing to see", "t1");
    auto replacement = f.edit(original, kSecret, "t2");
    ASSERT_TRUE(f.timeline_contains(kSecret)) << "the probe cannot see the text it must delete";

    ASSERT_TRUE(IsOk(f.redact(original, "r1")));

    EXPECT_FALSE(f.timeline_contains(kSecret))
        << "the edit's text is still readable through /messages after redaction";

    auto stripped = f.from_timeline(replacement);
    ASSERT_TRUE(stripped.has_value()) << "the replacement row vanished; it should be a tombstone";
    EXPECT_EQ(stripped->content.data.value("body", ""), "");
    EXPECT_FALSE(stripped->content.data.contains("m.new_content"));
    EXPECT_TRUE(f.store->is_event_redacted(replacement))
        << "the replacement must be marked redacted, not merely emptied";
}

// A tombstoned replacement keeps its relation and nothing else. Without it a
// client cannot tell the empty row is an edit of something, and renders it as a
// standalone blank message — the spec preserves m.relates_to through redaction
// for exactly this reason.
TEST(RedactionResidue, ARedactedEditKeepsItsRelationAndNothingElse) {
    ResidueFixture f;
    auto original = f.send("v1", "t1");
    auto replacement = f.edit(original, kSecret, "t2");
    ASSERT_TRUE(IsOk(f.redact(original, "r1")));

    auto stripped = f.from_timeline(replacement);
    ASSERT_TRUE(stripped.has_value());
    const auto& content = stripped->content.data;
    ASSERT_TRUE(content.contains("m.relates_to")) << "the edit lost the link to what it replaced";
    EXPECT_EQ(content["m.relates_to"].value("rel_type", ""), "m.replace");
    EXPECT_EQ(content["m.relates_to"].value("event_id", ""), original);
    // Nothing else: no body, no fallback body, no msgtype-carrying payload.
    EXPECT_EQ(content.size(), 1u) << "redacted edit kept more than its relation: " << content.dump();
}

// A replacement of a replacement is what a third-party client produces (ours
// chain-resolves to the original before sending). The cascade has to follow the
// whole chain or the newest version — the one on screen — is the one left
// behind.
TEST(RedactionResidue, AChainOfEditsIsRemovedTransitively) {
    ResidueFixture f;
    auto original = f.send("v1", "t1");
    auto first = f.edit(original, "v2", "t2");

    // Inserted directly: the handler would rewrite this to target `original`.
    auto second = generate_event_id("test");
    f.store->insert_event(second, f.room, f.alice, std::string(event_type::kRoomMessage),
                          std::nullopt,
                          json{{"msgtype", "m.text"},
                               {"body", std::string("* ") + kSecret},
                               {"m.new_content", {{"msgtype", "m.text"}, {"body", kSecret}}},
                               {"m.relates_to",
                                {{"rel_type", "m.replace"}, {"event_id", first}}}}
                              .dump(),
                          now_ms());
    ASSERT_TRUE(f.timeline_contains(kSecret));

    ASSERT_TRUE(IsOk(f.redact(original, "r1")));

    EXPECT_FALSE(f.timeline_contains(kSecret))
        << "an edit of an edit survived the redaction of the message";
    EXPECT_TRUE(f.store->is_event_redacted(first));
    EXPECT_TRUE(f.store->is_event_redacted(second));
}

// Redacting one edit is NOT the same operation and must keep behaving as it
// does today: the message rolls back to the newest surviving version rather
// than being deleted. The cascade runs downwards only.
TEST(RedactionResidue, RedactingOneEditStillOnlyRollsThatEditBack) {
    ResidueFixture f;
    auto original = f.send("v1", "t1");
    f.edit(original, "v2", "t2");
    auto third = f.edit(original, "v3", "t3");
    ASSERT_EQ(f.from_timeline(original)->content.data.value("body", ""), "v3");

    ASSERT_TRUE(IsOk(f.redact(third, "r1")));
    EXPECT_EQ(f.from_timeline(original)->content.data.value("body", ""), "v2")
        << "redacting an edit deleted more than the edit";
    EXPECT_FALSE(f.store->is_event_redacted(original));
}

// ── B9: the bundled pre-edit text ─────────────────────────────────────────

// Edit history is kept deliberately (see docs/redaction-and-edit-history.md),
// which is only defensible if redaction reaches it. This held before the fix as
// a side effect of clearing `edited_by`; it is pinned here because the model now
// depends on it.
TEST(RedactionResidue, RedactionTakesTheBundledEditHistoryWithIt) {
    ResidueFixture f;
    auto original = f.send(kSecret, "t1");
    f.edit(original, "oops, ignore that", "t2");

    auto edited = f.from_timeline(original);
    ASSERT_TRUE(edited.has_value());
    ASSERT_TRUE(edited->unsigned_data.has_value());
    ASSERT_TRUE(edited->unsigned_data->data.contains("bsfchat.original_content"))
        << "the probe cannot see the bundle it must check is gone";

    ASSERT_TRUE(IsOk(f.redact(original, "r1")));

    auto gone = f.from_timeline(original);
    ASSERT_TRUE(gone.has_value());
    EXPECT_FALSE(gone->unsigned_data.has_value())
        << "unsigned.bsfchat.original_content still carries the pre-edit text";
    EXPECT_FALSE(f.timeline_contains(kSecret));
}

// ── The FTS index ─────────────────────────────────────────────────────────

// Content that lives in an index as well as a row needs both cleared. The index
// only ever holds the original's row (a replacement is never indexed as itself,
// or an edited message would be two hits), so the row-level fix carries it —
// but "carries it" is a claim, and this is the test that makes it one.
TEST(RedactionResidue, SearchForgetsBothVersionsOfARedactedMessage) {
    ResidueFixture f;
    if (!f.store->search_index_available()) GTEST_SKIP() << "build has no FTS5";

    auto original = f.send("pristine rutabaga", "t1");
    f.edit(original, "revised lychee", "t2");
    ASSERT_EQ(f.search_hits("lychee"), 1) << "search does not track the edit";
    ASSERT_EQ(f.search_hits("rutabaga"), 0) << "search still matches the pre-edit text";

    ASSERT_TRUE(IsOk(f.redact(original, "r1")));

    EXPECT_EQ(f.search_hits("lychee"), 0) << "the edited text is still searchable";
    EXPECT_EQ(f.search_hits("rutabaga"), 0);
    EXPECT_EQ(f.store->count_search_index_rows(), 0)
        << "the index kept a shadow row for a message that no longer has content";
}

// ── B12: the push queue ───────────────────────────────────────────────────

// The queue snapshots the payload at enqueue time, which is right for edits and
// was fatal for redaction: a gateway that was down when the message was sent
// received the full pre-redaction plaintext up to max_attempts later.
TEST(RedactionResidue, RedactionDropsTheQueuedNotification) {
    ResidueFixture f;
    f.register_pusher("bob", "bob-phone");
    f.store->set_room_notify_level(f.bob, f.room, "all");

    auto original = f.send(kSecret, "t1");
    ASSERT_EQ(f.store->count_queued_pushes(), 1) << "nothing was queued; the probe proves nothing";

    ASSERT_TRUE(IsOk(f.redact(original, "r1")));
    EXPECT_EQ(f.store->count_queued_pushes(), 0)
        << "the pre-redaction plaintext is still queued for delivery";

    f.push->drain_once();
    EXPECT_EQ(f.gateway.call_count(), 0u);
    EXPECT_FALSE(f.gateway.any_body_contains(kSecret))
        << "a redacted message's text left the server after the redaction";
}

// A pusher that no longer exists must not keep receiving what was queued for
// it: deleting it left rows that still POSTed to the old gateway URL.
TEST(RedactionResidue, DeletingAPusherDropsItsQueuedNotifications) {
    ResidueFixture f;
    f.register_pusher("bob", "bob-phone");
    f.store->set_room_notify_level(f.bob, f.room, "all");
    f.send(kSecret, "t1");
    ASSERT_EQ(f.store->count_queued_pushes(), 1);

    f.store->delete_pusher(f.bob, "com.bsfchat.app", "bob-phone");
    EXPECT_EQ(f.store->count_queued_pushes(), 0)
        << "queued notifications outlived the pusher they were addressed to";

    f.push->drain_once();
    EXPECT_EQ(f.gateway.call_count(), 0u);
}

// The queue-time half of the race. Enqueue is the LAST thing the send path
// does, and the event is already visible to /sync by then, so a redaction can
// slip in between and find no rows to delete. This is what stops the send path
// from queueing a notification for a message that is already gone.
TEST(RedactionResidue, APushIsNotEnqueuedForAnAlreadyRedactedEvent) {
    ResidueFixture f;
    auto original = f.send(kSecret, "t1");
    ASSERT_TRUE(IsOk(f.redact(original, "r1")));

    SqliteStore::QueuedPush q;
    q.user_id = f.bob;
    q.app_id = "com.bsfchat.app";
    q.pushkey = "bob-phone";
    q.url = ResidueFixture::kGatewayUrl;
    q.event_id = original;
    q.payload = json{{"notification", {{"content", {{"body", kSecret}}}}}}.dump();
    f.store->enqueue_pushes({q});

    EXPECT_EQ(f.store->count_queued_pushes(), 0)
        << "a notification was queued for a message that had already been redacted";
}

// The dispatch-time half, which is the one that cannot be raced. Reaching it
// requires a queue row whose event is redacted, which the fixed code no longer
// produces — so the redaction is performed with raw SQL, standing in for the
// row an older build left behind or a future enqueue path that forgets. A push
// already handed to a gateway cannot be recalled; this is the last moment it
// can be stopped.
TEST(RedactionResidue, AQueuedPushForARedactedEventIsDroppedInsteadOfDelivered) {
    const std::string path = temp_db_path("dispatch-gate");
    std::filesystem::remove(path);
    {
        ResidueFixture f(path);
        f.register_pusher("bob", "bob-phone");
        f.store->set_room_notify_level(f.bob, f.room, "all");
        auto original = f.send(kSecret, "t1");
        ASSERT_EQ(f.store->count_queued_pushes(), 1);

        raw_exec(path, "UPDATE events SET content = '{}', redacted_by = '@alice:test' "
                       "WHERE event_id = '" + original + "'");

        f.push->drain_once();
        EXPECT_EQ(f.gateway.call_count(), 0u)
            << "the worker delivered a notification for a redacted message";
        EXPECT_EQ(f.store->count_queued_pushes(), 0)
            << "the row was skipped but left behind to be retried";
    }
    std::filesystem::remove(path);
}

// Upgrade path. Every deployment already contains messages that were redacted
// by the old code and still carry their edits, and nobody redacts a message
// twice — so the fix alone leaves the existing residue exactly where it is.
TEST(RedactionResidue, EarlierRedactionsAreRepairedOnUpgrade) {
    const std::string path = temp_db_path("v20-repair");
    std::filesystem::remove(path);
    std::string original;
    std::string replacement;
    {
        ResidueFixture f(path);
        original = f.send("nothing to see", "t1");
        replacement = f.edit(original, kSecret, "t2");
    }

    // Exactly what the pre-fix redact_event() did: strip the row it was given
    // and nothing else. Then rewind the schema so the upgrade runs again.
    raw_exec(path, "UPDATE events SET content = '{}', edited_by = NULL, "
                   "redacted_by = '@alice:test' WHERE event_id = '" + original + "'");
    raw_exec(path, "PRAGMA user_version = 19");

    {
        ResidueFixture f(path, /*seed=*/false);
        auto left_behind = f.from_timeline(replacement);
        ASSERT_TRUE(left_behind.has_value());
        EXPECT_EQ(left_behind->content.data.value("body", ""), "")
            << "the upgrade left an old redaction's edit readable";
        EXPECT_FALSE(f.timeline_contains(kSecret));
        EXPECT_TRUE(f.store->is_event_redacted(replacement));
        // The relation survives, so a client can still tell what it edited.
        EXPECT_EQ(left_behind->content.data["m.relates_to"].value("event_id", ""), original);
    }
    std::filesystem::remove(path);
}
