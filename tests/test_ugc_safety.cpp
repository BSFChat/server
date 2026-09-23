// Blocking, reporting and self-service account deletion (schema v29).
//
// The App Store (guideline 1.2, user-generated content) and Google Play's UGC
// policy both require a chat app to let a person block another person and
// report content; guideline 5.1.1(v) requires in-app account deletion. This
// file is the proof that the server halves of all three do what they claim.
//
// The properties under test, in the order they appear below:
//   1. The ignore list round-trips through account data, and the projection the
//      enforcement actually reads agrees with the document that was PUT.
//   2. Account data is private: no account can read or write another's, and a
//      404 for an absent document is distinguishable from an empty one.
//   3. A malformed ignore list is REFUSED, not stored — an unenforceable block
//      is worse than a visible error.
//   4. Events from an ignored user are filtered out of /sync and /messages, and
//      STATE events are not, because dropping those breaks room state.
//   5. Blocking is invisible to the blocked party: nothing they can request
//      differs, in either direction.
//   6. A DM invite from an ignored user is not delivered, and the inviter's
//      request still succeeds.
//   7. A report is stored, audited, attributed to the EVENT's sender rather
//      than to anything the reporter claimed, and rate-limited.
//   8. The report queue is gated at SERVER scope — a per-channel override that
//      grants MANAGE_SERVER inside a channel must not unlock it.
//   9. Reporting does not become an event-existence oracle.
//  10. Deactivation revokes tokens, erases the profile, leaves every room, and
//      is refused without the current password.

#include <gtest/gtest.h>

#include "api/AccountDataHandler.h"
#include "api/AuthHandler.h"
#include "api/InputLimits.h"
#include "api/EventHandler.h"
#include "api/ReportHandler.h"
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
            ("bsfchat-ugc-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

// httplib leaves status at -1 until the response is written, so a handler that
// succeeded typically never touches it.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

template <typename Handler, typename Method>
httplib::Response call(Handler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
}

json body_json(const httplib::Response& res) {
    auto parsed = json::parse(res.body, nullptr, false);
    return parsed.is_discarded() ? json::object() : parsed;
}

ServerRole role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

// A test clock the rate limiters take, so a limit can be hit and then outlived
// without sleeping through the window.
struct TestClock {
    std::shared_ptr<int64_t> now = std::make_shared<int64_t>(0);
    LimiterClock fn() const {
        auto n = now;
        return [n] { return *n; };
    }
    void advance(int64_t ms) { *now += ms; }
};

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

    // Written straight into server_state rather than through
    // write_server_scoped_state, so fixture setup lands no audit records and
    // every test starts from an empty log.
    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        // MANAGE_SERVER without ADMINISTRATOR, so the report-queue gate is
        // exercised on its own flag rather than on the god-mode short-circuit.
        content.roles.push_back(role("serveradmin", 90,
                                     permission::kEveryoneDefault | permission::kManageServer));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 4));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);

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
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, user_id,
                            std::string(event_type::kRoomMember), user_id,
                            json{{"membership", membership::kJoin}}.dump(), 1001);
    }

    std::string say(const std::string& room_id, const std::string& sender,
                    const std::string& text) {
        auto event_id = generate_event_id("test");
        store->insert_event(event_id, room_id, sender, std::string(event_type::kRoomMessage),
                            std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", text}}.dump(), 2000);
        return event_id;
    }

    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target, j.dump(),
                            1002);
    }

    std::vector<SqliteStore::AuditRecord> records() {
        return store->list_audit_records(limits::kMaxAuditLimit, std::nullopt).records;
    }
};

std::string account_data_path(const std::string& user_id, const std::string& type) {
    return "/_matrix/client/v3/user/" + user_id + "/account_data/" + type;
}

std::string report_event_path(const std::string& room_id, const std::string& event_id) {
    return "/_matrix/client/v3/rooms/" + room_id + "/report/" + event_id;
}

std::string report_user_path(const std::string& user_id) {
    return "/_matrix/client/v3/users/" + user_id + "/report";
}

const std::string kReportsPath = "/_matrix/client/v3/bsfchat/reports";

// The document shape Matrix defines for a block list.
std::string ignore_document(const std::vector<std::string>& users) {
    json ignored = json::object();
    for (const auto& u : users) ignored[u] = json::object();
    return json{{account_data_type::kIgnoredUsersKey, ignored}}.dump();
}

// Every message body in `user`'s timeline for `room`, from a full initial sync.
std::vector<std::string> sync_bodies(SyncEngine& sync, const std::string& user,
                                     const std::string& room) {
    auto response = sync.handle_sync(user, "", 0);
    std::vector<std::string> out;
    auto it = response.rooms.join.find(room);
    if (it == response.rooms.join.end()) return out;
    for (const auto& ev : it->second.timeline.events) {
        if (ev.type != std::string(event_type::kRoomMessage)) continue;
        out.push_back(ev.content.data.value("body", ""));
    }
    return out;
}

std::vector<std::string> messages_bodies(EventHandler& handler, const std::string& room,
                                         const std::string& token) {
    auto res = call(handler, &EventHandler::handle_room_messages,
                    "/_matrix/client/v3/rooms/" + room + "/messages", token);
    std::vector<std::string> out;
    if (!IsOk(res)) return out;
    for (const auto& ev : body_json(res).value("chunk", json::array())) {
        if (ev.value("type", "") != std::string(event_type::kRoomMessage)) continue;
        out.push_back(ev.value("content", json::object()).value("body", ""));
    }
    return out;
}

// ── 1. The ignore list round-trips, document and projection agree ─────────

TEST(UgcBlocking, IgnoreListRoundTripsThroughAccountData) {
    Fixture f("roundtrip");
    f.seed_roles();
    auto alice = f.add_user("alice");
    f.add_user("spammer");
    f.add_user("other");

    AccountDataHandler handler(*f.store, *f.sync, f.config);

    // Nothing written yet: 404, which is what lets a client tell "no block
    // list" from "an empty block list" and decide whether to upload its own.
    auto missing = call(handler, &AccountDataHandler::handle_get_account_data,
                        account_data_path(alice, account_data_type::kIgnoredUserList),
                        "token-alice");
    EXPECT_EQ(missing.status, 404);

    auto put = call(handler, &AccountDataHandler::handle_put_account_data,
                    account_data_path(alice, account_data_type::kIgnoredUserList),
                    "token-alice", ignore_document({"@spammer:test", "@other:test"}));
    ASSERT_TRUE(IsOk(put));

    auto got = call(handler, &AccountDataHandler::handle_get_account_data,
                    account_data_path(alice, account_data_type::kIgnoredUserList),
                    "token-alice");
    ASSERT_TRUE(IsOk(got));
    auto ignored = body_json(got).at(account_data_type::kIgnoredUsersKey);
    EXPECT_TRUE(ignored.contains("@spammer:test"));
    EXPECT_TRUE(ignored.contains("@other:test"));

    // The PROJECTION, not a re-parse of the document. This is what the /sync
    // and /messages filters actually consult, so a test that only checked the
    // document would pass while the enforcement did nothing.
    auto projected = f.store->get_ignored_users(alice);
    EXPECT_EQ(projected, (std::vector<std::string>{"@other:test", "@spammer:test"}));
    EXPECT_TRUE(f.store->is_ignoring(alice, "@spammer:test"));
    EXPECT_FALSE(f.store->is_ignoring("@spammer:test", alice));
}

TEST(UgcBlocking, UnblockingIsAFullReplacementAndClearsTheProjection) {
    Fixture f("unblock");
    f.seed_roles();
    auto alice = f.add_user("alice");
    f.add_user("spammer");

    AccountDataHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({"@spammer:test"}))));
    ASSERT_TRUE(f.store->is_ignoring(alice, "@spammer:test"));

    // An unblock is an absence, not a delta — the one direction a diff-based
    // projection would get wrong.
    ASSERT_TRUE(IsOk(call(handler, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({}))));
    EXPECT_FALSE(f.store->is_ignoring(alice, "@spammer:test"));
    EXPECT_TRUE(f.store->get_ignored_users(alice).empty());
}

TEST(UgcBlocking, ArbitraryAccountDataTypesAreStoredVerbatim) {
    Fixture f("verbatim");
    f.seed_roles();
    auto alice = f.add_user("alice");

    AccountDataHandler handler(*f.store, *f.sync, f.config);
    const std::string doc = R"({"theme":"dark","nested":{"a":[1,2,3]}})";
    ASSERT_TRUE(IsOk(call(handler, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, "com.example.prefs"), "token-alice", doc)));

    auto got = call(handler, &AccountDataHandler::handle_get_account_data,
                    account_data_path(alice, "com.example.prefs"), "token-alice");
    ASSERT_TRUE(IsOk(got));
    EXPECT_EQ(body_json(got), json::parse(doc));
    // A type the server does not read must not have produced ignore rows.
    EXPECT_TRUE(f.store->get_ignored_users(alice).empty());
}

// ── 2. Account data is private ────────────────────────────────────────────

TEST(UgcBlocking, NobodyCanReadOrWriteAnotherAccountsAccountData) {
    Fixture f("private");
    f.seed_roles();
    auto alice = f.add_user("alice");
    f.add_user("spammer");
    // An ADMINISTRATOR, to pin that there is no permission which unlocks this.
    f.add_user("root", {std::string(permission::role_id::kAdmin)});

    AccountDataHandler handler(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(handler, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({"@spammer:test"}))));

    // The blocked account cannot read the list naming it. This is THE property
    // the whole endpoint exists to keep — a block whose subject can read it
    // tells them they were blocked and by whom.
    auto peek = call(handler, &AccountDataHandler::handle_get_account_data,
                     account_data_path(alice, account_data_type::kIgnoredUserList),
                     "token-spammer");
    EXPECT_EQ(peek.status, 403);
    EXPECT_EQ(peek.body.find("@spammer:test"), std::string::npos)
        << "the refusal echoed the block list back";

    // Nor can an administrator.
    auto admin_peek = call(handler, &AccountDataHandler::handle_get_account_data,
                           account_data_path(alice, account_data_type::kIgnoredUserList),
                           "token-root");
    EXPECT_EQ(admin_peek.status, 403);

    // Nor write one on somebody else's behalf.
    auto forge = call(handler, &AccountDataHandler::handle_put_account_data,
                      account_data_path(alice, account_data_type::kIgnoredUserList),
                      "token-spammer", ignore_document({}));
    EXPECT_EQ(forge.status, 403);
    EXPECT_TRUE(f.store->is_ignoring(alice, "@spammer:test"))
        << "another account cleared alice's block list";
}

// ── 3. A malformed ignore list is refused, not stored ─────────────────────

TEST(UgcBlocking, MalformedIgnoreListsAreRefusedRatherThanStoredUnenforced) {
    Fixture f("malformed");
    f.seed_roles();
    auto alice = f.add_user("alice");

    AccountDataHandler handler(*f.store, *f.sync, f.config);
    const auto path = account_data_path(alice, account_data_type::kIgnoredUserList);

    struct Case {
        const char* name;
        std::string body;
    };
    const Case cases[] = {
        {"not an object", R"([1,2,3])"},
        {"ignored_users is not an object",
         json{{account_data_type::kIgnoredUsersKey, "spammer"}}.dump()},
        {"entry is not a user id", ignore_document({"spammer"})},
        {"ignoring yourself", ignore_document({"@alice:test"})},
    };
    for (const auto& c : cases) {
        auto res = call(handler, &AccountDataHandler::handle_put_account_data, path,
                        "token-alice", c.body);
        EXPECT_EQ(res.status, 400) << c.name;
    }

    // Nothing was stored by any of them: a refused PUT must not leave a
    // half-applied block list behind.
    EXPECT_TRUE(f.store->get_ignored_users(alice).empty());
    EXPECT_FALSE(f.store->get_account_data(alice, account_data_type::kIgnoredUserList));
}

TEST(UgcBlocking, TheIgnoreListHasACeiling) {
    Fixture f("ceiling");
    f.seed_roles();
    auto alice = f.add_user("alice");

    std::vector<std::string> many;
    many.reserve(input_limits::kMaxIgnoredUsers + 1);
    for (size_t i = 0; i <= input_limits::kMaxIgnoredUsers; ++i) {
        many.push_back("@u" + std::to_string(i) + ":test");
    }

    AccountDataHandler handler(*f.store, *f.sync, f.config);
    auto res = call(handler, &AccountDataHandler::handle_put_account_data,
                    account_data_path(alice, account_data_type::kIgnoredUserList),
                    "token-alice", ignore_document(many));
    EXPECT_EQ(res.status, 400);
    EXPECT_TRUE(f.store->get_ignored_users(alice).empty());
}

// ── 4. Ignored users are filtered from /sync and /messages ────────────────

TEST(UgcBlocking, IgnoredUsersEventsAreFilteredFromSyncAndMessages) {
    Fixture f("filter");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");
    auto carol = f.add_user("carol");

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);
    f.join(room, carol);

    f.say(room, carol, "hello from carol");
    f.say(room, spammer, "BUY MY COIN");
    f.say(room, alice, "hello from alice");

    EventHandler events(*f.store, *f.sync, f.config);

    // Before the block, everything is visible.
    EXPECT_EQ(sync_bodies(*f.sync, alice, room).size(), 3u);
    EXPECT_EQ(messages_bodies(events, room, "token-alice").size(), 3u);

    AccountDataHandler account_data(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(account_data, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({spammer}))));

    // Initial sync.
    auto after_sync = sync_bodies(*f.sync, alice, room);
    EXPECT_EQ(after_sync.size(), 2u);
    for (const auto& body : after_sync) EXPECT_NE(body, "BUY MY COIN");

    // /messages — back-pagination. An ignore that held on /sync and not here
    // would be undone by scrolling up, which is the first thing a client does
    // when a channel is opened.
    auto after_messages = messages_bodies(events, room, "token-alice");
    EXPECT_EQ(after_messages.size(), 2u);
    for (const auto& body : after_messages) EXPECT_NE(body, "BUY MY COIN");

    // An incremental sync from before the messages landed: the delta path has
    // its own scan and its own filter.
    auto baseline = f.sync->handle_sync(alice, "", 0);
    f.say(room, spammer, "STILL BUYING");
    f.say(room, carol, "ignore that");
    auto delta = f.sync->handle_sync(alice, baseline.next_batch, 0);
    ASSERT_TRUE(delta.rooms.join.count(room));
    for (const auto& ev : delta.rooms.join.at(room).timeline.events) {
        EXPECT_NE(ev.content.data.value("body", ""), "STILL BUYING");
    }
}

TEST(UgcBlocking, StateEventsFromAnIgnoredUserAreStillDelivered) {
    Fixture f("state");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);

    AccountDataHandler account_data(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(account_data, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({spammer}))));

    // The room's own description of itself is not the sender's content.
    // Dropping the ignored account's m.room.member would empty it out of
    // alice's member list, and dropping a name it happened to set would rename
    // the channel to nothing in her client.
    auto response = f.sync->handle_sync(alice, "", 0);
    ASSERT_TRUE(response.rooms.join.count(room));
    bool saw_member = false;
    for (const auto& ev : response.rooms.join.at(room).state.events) {
        if (ev.type == std::string(event_type::kRoomMember) && ev.state_key == spammer) {
            saw_member = true;
        }
    }
    EXPECT_TRUE(saw_member) << "the ignored account vanished from the member list";
}

TEST(UgcBlocking, UnreadAndHighlightCountsSkipIgnoredSenders) {
    Fixture f("badges");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");
    auto carol = f.add_user("carol");

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);
    f.join(room, carol);

    // One message and one direct mention from each.
    f.say(room, spammer, "spam");
    f.say(room, carol, "hello");
    auto mention = [&](const std::string& sender) {
        auto event_id = generate_event_id("test");
        auto pos = f.store->insert_event(
            event_id, room, sender, std::string(event_type::kRoomMessage), std::nullopt,
            json{{"msgtype", "m.text"}, {"body", "@alice"},
                 {"m.mentions", {{"user_ids", json::array({alice})}}}}.dump(), 2100);
        f.store->record_mentions(event_id, room, sender, pos, {alice});
    };
    mention(spammer);
    mention(carol);

    EXPECT_EQ(f.store->count_unread(alice, room), 4);
    EXPECT_EQ(f.store->count_unread_mentions(alice, room), 2);
    EXPECT_EQ(f.store->get_unread_mention_counts(alice)[room], 2);

    AccountDataHandler account_data(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(account_data, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({spammer}))));

    // A badge is a claim that there is something in there to read, and the
    // blocked account's messages are exactly what /sync will never show her —
    // so a count that included them could never be cleared by reading.
    EXPECT_EQ(f.store->count_unread(alice, room), 2);
    EXPECT_EQ(f.store->count_unread_mentions(alice, room), 1);
    EXPECT_EQ(f.store->get_unread_mention_counts(alice)[room], 1);

    // Nobody else's badges moved. Carol sent two of the four messages and her
    // own never counted, so two is what she saw before alice blocked anyone and
    // two is what she sees after — a block is one reader's filter and not a
    // property of the room.
    EXPECT_EQ(f.store->count_unread(carol, room), 2);
    EXPECT_FALSE(f.store->is_ignoring(carol, spammer));
}

// ── 5. Blocking is invisible to the blocked party ─────────────────────────

TEST(UgcBlocking, TheBlockedPartyCannotTellTheyHaveBeenBlocked) {
    Fixture f("invisible");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);
    f.say(room, alice, "from alice");
    f.say(room, spammer, "from spammer");

    EventHandler events(*f.store, *f.sync, f.config);

    const auto before_sync = sync_bodies(*f.sync, spammer, room);
    const auto before_messages = messages_bodies(events, room, "token-spammer");

    AccountDataHandler account_data(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(account_data, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({spammer}))));

    // The blocked account's own view of the world is byte-for-byte what it was.
    // The block is one-directional and private: it filters what ALICE is shown
    // and changes nothing the spammer can observe.
    EXPECT_EQ(sync_bodies(*f.sync, spammer, room), before_sync);
    EXPECT_EQ(messages_bodies(events, room, "token-spammer"), before_messages);

    // Their own message is still in their own timeline — a block does not
    // silently swallow the sender's copy.
    EXPECT_NE(std::find(before_sync.begin(), before_sync.end(), "from spammer"),
              before_sync.end());

    // And sending still works, with no error and no hint.
    auto more = f.say(room, spammer, "still here");
    EXPECT_FALSE(more.empty());
    EXPECT_TRUE(f.store->get_event_by_id(more).has_value());
}

// ── 6. Invites from an ignored user are not delivered ─────────────────────

TEST(UgcBlocking, InvitesFromAnIgnoredUserAreNotDelivered) {
    Fixture f("invites");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");
    auto carol = f.add_user("carol");

    AccountDataHandler account_data(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(account_data, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({spammer}))));

    // Two DMs, one from each. Both are written exactly as the invite path
    // writes them — the block is applied at DELIVERY, so the row and the event
    // exist in both cases and the inviter's request succeeded in both cases.
    auto invite_from = [&](const std::string& inviter) {
        auto room = generate_room_id("test");
        f.store->create_room(room, inviter);
        f.store->set_membership(room, inviter, std::string(membership::kJoin));
        f.store->set_membership(room, alice, std::string(membership::kInvite));
        f.store->insert_event(generate_event_id("test"), room, inviter,
                              std::string(event_type::kRoomMember), alice,
                              json{{"membership", membership::kInvite}}.dump(), 3000);
        return room;
    };
    auto spam_room = invite_from(spammer);
    auto carol_room = invite_from(carol);

    // The spammer's invite is on disk and its sender is legible — nothing was
    // refused, which is what keeps the block undetectable from their side.
    EXPECT_EQ(f.store->get_invite_sender(spam_room, alice), spammer);
    EXPECT_EQ(f.store->get_membership(spam_room, alice), std::string(membership::kInvite));

    auto response = f.sync->handle_sync(alice, "", 0);
    EXPECT_EQ(response.rooms.invite.count(spam_room), 0u)
        << "an invite from a blocked account was delivered";
    EXPECT_EQ(response.rooms.invite.count(carol_room), 1u)
        << "an invite from an unblocked account was suppressed";
}

// ── 7. Reports are stored, attributed and audited ─────────────────────────

TEST(UgcReporting, AReportIsStoredAndAuditedAgainstTheEventsSender) {
    Fixture f("report");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");
    f.add_user("bystander");

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);
    auto event_id = f.say(room, spammer, "BUY MY COIN");

    ReportHandler handler(*f.store, f.config);
    auto res = call(handler, &ReportHandler::handle_report_event,
                    report_event_path(room, event_id), "token-alice",
                    json{{"score", -100}, {"reason", "spam"}}.dump());
    ASSERT_TRUE(IsOk(res));

    auto page = f.store->list_content_reports(10);
    ASSERT_EQ(page.reports.size(), 1u);
    const auto& r = page.reports.front();
    EXPECT_EQ(r.reporter, alice);
    EXPECT_EQ(r.target_user, spammer);
    EXPECT_EQ(r.event_sender, spammer);
    EXPECT_EQ(r.room_id, room);
    EXPECT_EQ(r.event_id, event_id);
    EXPECT_EQ(r.score, -100);
    EXPECT_EQ(r.reason, "spam");
    // The snapshot is what makes the report survive the redaction it is
    // usually asking for.
    EXPECT_NE(r.event_snapshot.find("BUY MY COIN"), std::string::npos);

    auto audit = f.records();
    ASSERT_EQ(audit.size(), 1u);
    EXPECT_EQ(audit.front().action, std::string(audit_action::kContentReport));
    EXPECT_EQ(audit.front().actor, alice);
    EXPECT_EQ(audit.front().target_user, spammer);
    EXPECT_EQ(audit.front().target_room, room);
    EXPECT_EQ(audit.front().target_key, event_id);
    // The reported CONTENT is deliberately not in the audit log, which has no
    // delete path — only the reporter's own words.
    EXPECT_EQ(audit.front().after_json.find("BUY MY COIN"), std::string::npos);
    EXPECT_EQ(audit.front().reason, "spam");
}

TEST(UgcReporting, TheReportedEventSurvivesItsOwnRedaction) {
    Fixture f("survives");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);
    auto event_id = f.say(room, spammer, "BUY MY COIN");

    ReportHandler handler(*f.store, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ReportHandler::handle_report_event,
                          report_event_path(room, event_id), "token-alice",
                          json{{"reason", "spam"}}.dump())));

    // The usual outcome of a report is that the thing reported is destroyed.
    // The report has to outlive it, or the record is a pointer to nothing.
    ASSERT_TRUE(f.store->redact_event(event_id, alice));
    auto page = f.store->list_content_reports(10);
    ASSERT_EQ(page.reports.size(), 1u);
    EXPECT_NE(page.reports.front().event_snapshot.find("BUY MY COIN"), std::string::npos);
}

TEST(UgcReporting, AUserLevelReportNeedsNoSharedRoom) {
    Fixture f("userreport");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");

    ReportHandler handler(*f.store, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ReportHandler::handle_report_user,
                          report_user_path(spammer), "token-alice",
                          json{{"reason", "harassment in a DM I left"}}.dump())));

    auto page = f.store->list_content_reports(10);
    ASSERT_EQ(page.reports.size(), 1u);
    EXPECT_EQ(page.reports.front().target_user, spammer);
    EXPECT_TRUE(page.reports.front().room_id.empty());
    EXPECT_TRUE(page.reports.front().event_id.empty());

    // Yourself, and an account nobody holds, are both refused — neither belongs
    // in a queue a person has to read.
    EXPECT_EQ(call(handler, &ReportHandler::handle_report_user, report_user_path(alice),
                   "token-alice").status, 400);
    EXPECT_EQ(call(handler, &ReportHandler::handle_report_user,
                   report_user_path("@nobody:test"), "token-alice").status, 404);
}

TEST(UgcReporting, ReportsAreRateLimitedPerAccount) {
    Fixture f("ratelimit");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto spammer = f.add_user("spammer");

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);
    f.join(room, bob);
    auto event_id = f.say(room, spammer, "BUY MY COIN");

    TestClock clock;
    ReportHandler handler(*f.store, f.config, clock.fn());

    const int limit = f.config.send_limits.report_limit;
    for (int i = 0; i < limit; ++i) {
        ASSERT_TRUE(IsOk(call(handler, &ReportHandler::handle_report_event,
                              report_event_path(room, event_id), "token-alice")))
            << "refused at attempt " << i;
    }
    auto refused = call(handler, &ReportHandler::handle_report_event,
                        report_event_path(room, event_id), "token-alice");
    EXPECT_EQ(refused.status, 429);
    EXPECT_NE(refused.get_header_value("Retry-After"), "");

    // Keyed on the account, so exhausting one budget does not spend anyone
    // else's — the property that keeps a limit from turning into an outage.
    EXPECT_TRUE(IsOk(call(handler, &ReportHandler::handle_report_event,
                          report_event_path(room, event_id), "token-bob")));

    // And the window passes.
    clock.advance(f.config.send_limits.window_seconds * 1000LL + 1);
    EXPECT_TRUE(IsOk(call(handler, &ReportHandler::handle_report_event,
                          report_event_path(room, event_id), "token-alice")));
}

// ── 8. The report queue is gated at SERVER scope ──────────────────────────

TEST(UgcReporting, TheQueueIsGatedAtServerScope) {
    Fixture f("queuegate");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto spammer = f.add_user("spammer");
    auto admin = f.add_user("admin", {"serveradmin"});

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);
    f.join(room, admin);
    auto event_id = f.say(room, spammer, "BUY MY COIN");

    ReportHandler handler(*f.store, f.config);
    ASSERT_TRUE(IsOk(call(handler, &ReportHandler::handle_report_event,
                          report_event_path(room, event_id), "token-alice",
                          json{{"reason", "spam"}}.dump())));

    // An ordinary member cannot read the queue, and the refusal carries none of
    // it.
    auto refused = call(handler, &ReportHandler::handle_list_reports, kReportsPath,
                        "token-alice");
    EXPECT_EQ(refused.status, 403);
    EXPECT_EQ(refused.body.find("BUY MY COIN"), std::string::npos);

    // A per-channel ALLOW override granting MANAGE_SERVER inside one channel
    // must NOT unlock a server-wide queue. This is the escalation shape the
    // empty room id in the handler exists to prevent, and the reason it is
    // pinned here as well as on the audit log.
    f.set_override(room, spammer, permission::kManageServer, permission::Flags{0});
    auto still_refused = call(handler, &ReportHandler::handle_list_reports, kReportsPath,
                              "token-spammer");
    EXPECT_EQ(still_refused.status, 403);

    // The real holder reads it.
    auto page = call(handler, &ReportHandler::handle_list_reports, kReportsPath, "token-admin");
    ASSERT_TRUE(IsOk(page));
    auto body = body_json(page);
    ASSERT_EQ(body.value("reports", json::array()).size(), 1u);
    EXPECT_EQ(body["reports"][0]["target_user"], spammer);
    EXPECT_EQ(body["total"], 1);
}

// ── 9. Reporting is not an event-existence oracle ─────────────────────────

TEST(UgcReporting, ReportingDoesNotDiscloseWhetherAnEventExists) {
    Fixture f("oracle");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto outsider = f.add_user("outsider");
    auto spammer = f.add_user("spammer");

    auto room = f.add_channel(alice, "general");
    f.join(room, spammer);
    auto real_event = f.say(room, spammer, "BUY MY COIN");

    // A second channel the outsider IS in, so they get past the membership
    // check and reach the part that must not distinguish.
    auto other_room = f.add_channel(outsider, "lobby");

    ReportHandler handler(*f.store, f.config);

    // Not a member of the room named in the path.
    auto not_a_member = call(handler, &ReportHandler::handle_report_event,
                             report_event_path(room, real_event), "token-outsider");
    // A real event id, but reported against a room it is not in.
    auto wrong_room = call(handler, &ReportHandler::handle_report_event,
                           report_event_path(other_room, real_event), "token-outsider");
    // An event id nobody holds.
    auto fictional = call(handler, &ReportHandler::handle_report_event,
                          report_event_path(other_room, "$nothing:test"), "token-outsider");

    EXPECT_EQ(not_a_member.status, 404);
    EXPECT_EQ(wrong_room.status, 404);
    EXPECT_EQ(fictional.status, 404);
    // Byte-identical, which is the actual requirement: a difference in wording
    // is a difference an attacker can read.
    EXPECT_EQ(not_a_member.body, fictional.body);
    EXPECT_EQ(wrong_room.body, fictional.body);

    // And none of them filed anything.
    EXPECT_EQ(f.store->list_content_reports(10).reports.size(), 0u);
}

// ── 10. Account deactivation ──────────────────────────────────────────────

TEST(UgcDeactivation, DeactivationRevokesTokensErasesProfileAndLeavesEveryRoom) {
    Fixture f("deactivate");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto room = f.add_channel(bob, "general");
    f.join(room, alice);
    f.store->set_display_name(alice, "Alice A");
    f.store->set_avatar_url(alice, "mxc://test/abc");

    AccountDataHandler account_data(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(account_data, &AccountDataHandler::handle_put_account_data,
                          account_data_path(alice, account_data_type::kIgnoredUserList),
                          "token-alice", ignore_document({bob}))));

    AuthHandler auth(*f.store, *f.sync, f.config);

    // Without the current password: a 401 carrying the user-interactive auth
    // flows, not a deletion. A token proves a client holds a token, not that
    // the owner is present, and this is the one irreversible thing an account
    // can do to itself.
    auto challenged = call(auth, &AuthHandler::handle_deactivate_account,
                           "/_matrix/client/v3/account/deactivate", "token-alice");
    EXPECT_EQ(challenged.status, 401);
    EXPECT_NE(challenged.body.find("m.login.password"), std::string::npos);
    EXPECT_FALSE(f.store->get_user_deactivated_at(alice).has_value());

    // With the wrong one: refused, and still not deactivated.
    auto wrong = call(auth, &AuthHandler::handle_deactivate_account,
                      "/_matrix/client/v3/account/deactivate", "token-alice",
                      json{{"auth", {{"type", "m.login.password"}, {"password", "nope"}}}}.dump());
    EXPECT_EQ(wrong.status, 403);
    EXPECT_FALSE(f.store->get_user_deactivated_at(alice).has_value());

    auto ok = call(auth, &AuthHandler::handle_deactivate_account,
                   "/_matrix/client/v3/account/deactivate", "token-alice",
                   json{{"auth", {{"type", "m.login.password"}, {"password", "password"}}}}.dump());
    ASSERT_TRUE(IsOk(ok));

    EXPECT_TRUE(f.store->get_user_deactivated_at(alice).has_value());
    // The token is gone, so every authenticated route refuses on its own.
    EXPECT_FALSE(f.store->get_user_by_token("token-alice").has_value());
    // Personal data is gone.
    EXPECT_FALSE(f.store->get_display_name(alice).has_value());
    EXPECT_FALSE(f.store->get_avatar_url(alice).has_value());
    EXPECT_FALSE(f.store->get_account_data(alice, account_data_type::kIgnoredUserList));
    EXPECT_TRUE(f.store->get_ignored_users(alice).empty());
    // Password login can never work again, whatever a future handler does —
    // the filter is in the store's WHERE clause.
    EXPECT_FALSE(f.store->get_password_hash(alice).has_value());
    // Out of every room, as a leave and not a deleted row.
    EXPECT_EQ(f.store->get_membership(room, alice), std::string(membership::kLeave));
    EXPECT_TRUE(f.store->get_joined_rooms(alice).empty());
    // And the room was told, so nobody is left rendering a departed account.
    bool saw_leave = false;
    for (const auto& ev : f.store->get_state_events(room)) {
        if (ev.type == std::string(event_type::kRoomMember) && ev.state_key == alice) {
            saw_leave = ev.content.data.value("membership", "") == membership::kLeave;
        }
    }
    EXPECT_TRUE(saw_leave);

    // Exactly one audit record, naming the account on both sides so either
    // filter finds it.
    auto audit = f.records();
    ASSERT_EQ(audit.size(), 1u);
    EXPECT_EQ(audit.front().action, std::string(audit_action::kAccountDeactivate));
    EXPECT_EQ(audit.front().actor, alice);
    EXPECT_EQ(audit.front().target_user, alice);
}

TEST(UgcDeactivation, AutoJoinNeverBringsADeactivatedAccountBack) {
    Fixture f("autojoin");
    f.seed_roles();
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    ASSERT_TRUE(f.store->deactivate_user(alice, 1234));

    // A channel created AFTER the deactivation has no membership row for the
    // departed account at all, which reads as "never considered" — and
    // backfill_auto_join runs at every boot. Without the guard in
    // join_user_to_room this is where a deleted account comes back, with a
    // fresh m.room.member event announcing its arrival.
    auto room = f.add_channel(bob, "new-channel");
    f.store->insert_event(generate_event_id("test"), room, bob,
                          std::string(event_type::kRoomType), std::string(""),
                          json{{"type", room_type::kText}}.dump(), 1003);
    backfill_auto_join(*f.store, *f.sync, f.config);

    EXPECT_FALSE(f.store->find_membership(room, alice).has_value())
        << "a deactivated account was force-joined into a new channel";
    EXPECT_TRUE(f.store->get_joined_rooms(alice).empty());
}

TEST(UgcDeactivation, DeactivationIsIdempotentAndAuditedOnce) {
    Fixture f("idempotent");
    f.seed_roles();
    auto alice = f.add_user("alice");

    EXPECT_TRUE(f.store->deactivate_user(alice, 1000));
    EXPECT_FALSE(f.store->deactivate_user(alice, 2000));
    // The first timestamp stands: "when did this account go" must not be
    // rewritten by a retry.
    EXPECT_EQ(f.store->get_user_deactivated_at(alice), 1000);
}

// ── The migration itself ──────────────────────────────────────────────────

TEST(UgcSchema, V29AppliesAndTheNewTablesArePresent) {
    Fixture f("schema");
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(f.db_path.c_str(), &db), SQLITE_OK);
    EXPECT_EQ(get_schema_version(db), kTargetSchemaVersion);
    EXPECT_GE(kTargetSchemaVersion, 29);

    for (const char* table : {"account_data", "ignored_users", "content_reports"}) {
        sqlite3_stmt* stmt = nullptr;
        const std::string sql =
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='" +
            std::string(table) + "'";
        ASSERT_EQ(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
        EXPECT_EQ(sqlite3_column_int(stmt, 0), 1) << table;
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
}

} // namespace
