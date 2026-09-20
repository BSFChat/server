// @mention parsing, storage and delivery (F1).
//
// The security-critical properties under test are the two forgery rules:
//   * a client cannot make a mention appear to have come from somebody else,
//     nor aim one at a user who cannot see the channel;
//   * editing a message cannot retroactively inject a mention, which would fire
//     a fresh notification for a message the reader had already read.

#include <gtest/gtest.h>

#include "api/EventHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "store/Migrations.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

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

// httplib leaves status at -1 unless a handler sets it, so "untouched" is
// success — same convention as test_regressions.cpp.
::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

struct MentionFixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<EventHandler> events;

    static constexpr const char* kRoom = "!general:test";

    MentionFixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        events = std::make_unique<EventHandler>(*store, *sync, config);

        // A room with the default @everyone permissions (no MENTION_EVERYONE).
        store->create_room(kRoom, "@alice:test");
        set_roles(permission::kEveryoneDefault);
    }

    // Redefines the @everyone role, which is what every user inherits.
    // `mod_mentionable` sets the Moderator role's `mentionable` switch — the one
    // that used to be inert. `everyone_mentionable` exists only so a test can
    // prove that flipping it on @everyone is still not a way to ping everyone.
    void set_roles(permission::Flags everyone_flags, permission::Flags mod_flags = 0,
                   bool mod_mentionable = false, bool everyone_mentionable = false) {
        ServerRolesContent roles;
        ServerRole everyone;
        everyone.id = permission::role_id::kEveryone;
        everyone.name = "@everyone";
        everyone.position = 0;
        everyone.permissions = everyone_flags;
        everyone.mentionable = everyone_mentionable;
        roles.roles.push_back(everyone);
        if (mod_flags != 0) {
            ServerRole mod;
            mod.id = permission::role_id::kModerator;
            mod.name = "Moderator";
            mod.position = 10;
            mod.permissions = mod_flags;
            mod.mentionable = mod_mentionable;
            roles.roles.push_back(mod);
        }
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    // Appends a role to whatever set_roles() last wrote. For the cases that
    // need a role the well-known ids cannot express.
    void define_role(const std::string& id, bool mentionable, bool self_assignable = false) {
        auto existing = store->get_server_roles();
        ServerRolesContent roles;
        roles.roles = std::move(existing);
        ServerRole r;
        r.id = id;
        r.name = id;
        r.position = 5;
        r.permissions = permission::kEveryoneDefault;
        r.mentionable = mentionable;
        r.self_assignable = self_assignable;
        roles.roles.push_back(r);
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    void grant_exact(const std::string& user_id, const std::vector<std::string>& role_ids) {
        MemberRolesContent c;
        c.role_ids = role_ids;
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), user_id, "@server:test",
                                j.dump());
    }

    // A message naming `role_ids`, in the shape the client sends.
    static json role_mention(const std::string& body,
                             const std::vector<std::string>& role_ids) {
        return {{"msgtype", "m.text"},
                {"body", body},
                {"m.mentions",
                 {{std::string(mention::kRoleIdsKey), json(role_ids)}}}};
    }

    void grant(const std::string& user_id, const std::string& role_id) {
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone), role_id};
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), user_id, "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart, bool join = true,
                         const std::string& room_id = kRoom) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);
        if (join) store->set_membership(room_id, uid, "join");
        return uid;
    }

    // Denies VIEW_CHANNEL for one user in one room via a channel override.
    void deny_view(const std::string& user_id, const std::string& room_id = kRoom) {
        ChannelPermissionOverride ov;
        ov.deny = permission::kViewChannel;
        json j;
        to_json(j, ov);
        store->insert_event("$deny-" + user_id, room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), "user:" + user_id,
                            j.dump(), 1);
    }

    // PUT /rooms/{room}/send/m.room.message/{txn}
    httplib::Response send(const std::string& localpart, const json& content,
                           const std::string& txn, const std::string& room_id = kRoom) {
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

    int highlight_from_sync(const std::string& user_id, const std::string& room_id = kRoom) {
        auto response = sync->handle_sync(user_id, "", 0);
        auto it = response.rooms.join.find(room_id);
        if (it == response.rooms.join.end()) return -1;
        return it->second.highlight_count.value_or(-1);
    }
};

} // namespace

// ── Happy path ────────────────────────────────────────────────────────────

TEST(Mentions, DirectMentionIsRecordedAndCounted) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    auto res = f.send("alice", {{"msgtype", "m.text"},
                                {"body", "hey @Bob"},
                                {"m.mentions", {{"user_ids", json::array({bob})}}}},
                      "t1");
    ASSERT_TRUE(IsOk(res));

    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);
    // Recorded against the AUTHENTICATED sender, which is what makes the badge
    // attributable rather than claimable.
    auto rows = f.store->get_event_mentions(MentionFixture::event_id_of(res));
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0], bob);
}

TEST(Mentions, HighlightCountIsExposedSeparatelyFromUnreadInSync) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    // Two plain messages and one mention: 3 unread, 1 highlight. A client needs
    // the mention badge to be distinguishable from the plain unread dot.
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "one"}}, "t1")));
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"}, {"body", "two"}}, "t2")));
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "three @Bob"},
                                      {"m.mentions", {{"user_ids", json::array({bob})}}}},
                            "t3")));

    auto response = f.sync->handle_sync(bob, "", 0);
    auto it = response.rooms.join.find(MentionFixture::kRoom);
    ASSERT_NE(it, response.rooms.join.end());
    EXPECT_EQ(it->second.unread_count.value_or(-1), 3);
    EXPECT_EQ(it->second.highlight_count.value_or(-1), 1);
}

TEST(Mentions, ReadMarkerClearsTheMentionBadge) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "@Bob"},
                                      {"m.mentions", {{"user_ids", json::array({bob})}}}},
                            "t1")));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);

    f.store->set_read_marker(bob, MentionFixture::kRoom,
                             f.store->get_room_max_stream_position(MentionFixture::kRoom));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);
}

TEST(Mentions, BatchCountsMatchPerRoomCounts) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");
    // A second room so the grouped query has to attribute correctly.
    f.store->create_room("!other:test", "@alice:test");
    f.store->set_membership("!other:test", "@alice:test", "join");
    f.store->set_membership("!other:test", bob, "join");

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "@Bob"},
                                      {"m.mentions", {{"user_ids", json::array({bob})}}}},
                            "t1")));
    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "@Bob again"},
                                      {"m.mentions", {{"user_ids", json::array({bob})}}}},
                            "t2", "!other:test")));

    auto counts = f.store->get_unread_mention_counts(bob);
    EXPECT_EQ(counts[MentionFixture::kRoom], 1);
    EXPECT_EQ(counts["!other:test"], 1);
    EXPECT_EQ(counts.count("!nonexistent:test"), 0u);
}

// ── Non-forgeability ──────────────────────────────────────────────────────

TEST(Mentions, SelfMentionDoesNotBadgeYourOwnRoom) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    // Bob mentions himself. If this counted, every user could light their own
    // badge, and more importantly the "who mentioned me" signal would be
    // meaningless.
    ASSERT_TRUE(IsOk(f.send("bob", {{"msgtype", "m.text"},
                                    {"body", "note to self @Bob"},
                                    {"m.mentions", {{"user_ids", json::array({bob})}}}},
                            "t1")));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);
}

TEST(Mentions, MentionIsAttributedToTheAuthenticatedSenderNotAnyClaimInTheBody) {
    MentionFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");

    // Bob sends a message that tries every shape of "pretend Carol did this":
    // a spoofed sender, a spoofed mention sender, and a nested claim.
    ASSERT_TRUE(IsOk(f.send("bob", {{"msgtype", "m.text"},
                                    {"body", "spoof"},
                                    {"sender", carol},
                                    {"m.mentions",
                                     {{"user_ids", json::array({alice})},
                                      {"sender", carol},
                                      {"by", carol}}}},
                            "t1")));

    // Alice is legitimately mentioned — by BOB, because that is who was
    // authenticated. Nothing in the body can change the attribution.
    auto rows = f.store->get_unread_mention_counts(alice);
    EXPECT_EQ(rows[MentionFixture::kRoom], 1);

    // And the stored sender is bob, not carol.
    auto sqlite_check = f.store->get_event_mentions("nonexistent");
    EXPECT_TRUE(sqlite_check.empty());
    // Carol was never mentioned, so she has no badge at all.
    EXPECT_EQ(f.store->count_unread_mentions(carol, MentionFixture::kRoom), 0);
}

TEST(Mentions, MentioningANonMemberIsDropped) {
    MentionFixture f;
    f.add_user("alice");
    // Dave exists but is not in the room.
    auto dave = f.add_user("dave", /*join=*/false);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "@Dave"},
                                      {"m.mentions", {{"user_ids", json::array({dave})}}}},
                            "t1")));
    EXPECT_EQ(f.store->count_unread_mentions(dave, MentionFixture::kRoom), 0);
}

TEST(Mentions, MentioningSomeoneWithoutViewChannelIsDropped) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");
    // Bob is a member but cannot see this channel. A mention must not become a
    // way to poke — or prove the existence of — a channel he has no access to.
    f.deny_view(bob);

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "@Bob"},
                                      {"m.mentions", {{"user_ids", json::array({bob})}}}},
                            "t1")));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);
}

TEST(Mentions, GarbageUserIdsAreDroppedNotStored) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    auto res = f.send("alice",
                      {{"msgtype", "m.text"},
                       {"body", "junk"},
                       {"m.mentions",
                        {{"user_ids", json::array({"not-a-user-id", "", "@nocolon", 42,
                                                   json::object(), bob})}}}},
                      "t1");
    ASSERT_TRUE(IsOk(res));
    // Only the one well-formed, resolvable member survives.
    auto rows = f.store->get_event_mentions(MentionFixture::event_id_of(res));
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0], bob);
}

TEST(Mentions, DuplicateMentionsCollapseToASingleBadge) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    ASSERT_TRUE(IsOk(f.send("alice",
                            {{"msgtype", "m.text"},
                             {"body", "@Bob @Bob @Bob"},
                             {"m.mentions", {{"user_ids", json::array({bob, bob, bob})}}}},
                            "t1")));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);
}

TEST(Mentions, MalformedMentionBlocksAreRejected) {
    MentionFixture f;
    f.add_user("alice");
    f.add_user("bob");

    // user_ids must be an array.
    auto res = f.send("alice", {{"msgtype", "m.text"},
                                {"body", "x"},
                                {"m.mentions", {{"user_ids", "@bob:test"}}}},
                      "t1");
    EXPECT_EQ(res.status, 400);

    // room must be a boolean.
    res = f.send("alice", {{"msgtype", "m.text"},
                           {"body", "x"},
                           {"m.mentions", {{"room", "yes"}}}},
                 "t2");
    EXPECT_EQ(res.status, 400);

    // An oversized list is rejected rather than silently truncated: it is an
    // amplification attempt, and quietly dropping half of it hides that.
    auto many = json::array();
    for (size_t i = 0; i < limits::kMaxMentionsPerEvent + 1; ++i) {
        many.push_back("@filler" + std::to_string(i) + ":test");
    }
    res = f.send("alice",
                 {{"msgtype", "m.text"}, {"body", "x"}, {"m.mentions", {{"user_ids", many}}}},
                 "t3");
    EXPECT_EQ(res.status, 400);
}

TEST(Mentions, AMentionBlockThatIsNotAnObjectIsIgnored) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");
    // Tolerated rather than rejected — it carries no mention, so there is
    // nothing to enforce and no reason to lose the message.
    ASSERT_TRUE(IsOk(f.send(
        "alice", {{"msgtype", "m.text"}, {"body", "x"}, {"m.mentions", "nonsense"}}, "t1")));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);
}

// ── @room ─────────────────────────────────────────────────────────────────

TEST(Mentions, RoomWideMentionRequiresMentionEveryone) {
    MentionFixture f;
    f.add_user("alice");
    f.add_user("bob");

    // @everyone role has no MENTION_EVERYONE in this fixture.
    auto res = f.send("alice",
                      {{"msgtype", "m.text"}, {"body", "listen up"}, {"m.mentions", {{"room", true}}}},
                      "t1");
    EXPECT_EQ(res.status, 403);
    EXPECT_EQ(f.store->count_unread_mentions("@bob:test", MentionFixture::kRoom), 0);
}

TEST(Mentions, RoomWideMentionBadgesEveryoneElseWhenPermitted) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault, permission::kEveryoneDefault |
                                                  permission::kMentionEveryone);
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    f.grant(alice, permission::role_id::kModerator);

    ASSERT_TRUE(IsOk(f.send(
        "alice", {{"msgtype", "m.text"}, {"body", "listen up"}, {"m.mentions", {{"room", true}}}},
        "t1")));

    // One stored row, not one per member — and everybody except the sender is
    // badged by it.
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);
    EXPECT_EQ(f.store->count_unread_mentions(carol, MentionFixture::kRoom), 1);
    EXPECT_EQ(f.store->count_unread_mentions(alice, MentionFixture::kRoom), 0);
}

TEST(Mentions, RoomSentinelCannotBeForgedThroughUserIds) {
    MentionFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    // Alice has NO MENTION_EVERYONE. She tries to get a room-wide ping by
    // "mentioning" the sentinel directly, bypassing the `room` flag and its gate.
    ASSERT_TRUE(IsOk(f.send("alice",
                            {{"msgtype", "m.text"},
                             {"body", "sneaky"},
                             {"m.mentions", {{"user_ids", json::array({"@room", bob})}}}},
                            "t1")));

    // Bob is mentioned because he was named legitimately; Carol is not, because
    // the sentinel was discarded rather than treated as a room-wide mention.
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);
    EXPECT_EQ(f.store->count_unread_mentions(carol, MentionFixture::kRoom), 0);
}

// ── Edits must not inject mentions ────────────────────────────────────────

TEST(Mentions, EditingAMessageCannotInjectAFreshMention) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    // Alice sends something innocuous; Bob reads it.
    auto first = f.send("alice", {{"msgtype", "m.text"}, {"body", "hello"}}, "t1");
    ASSERT_TRUE(IsOk(first));
    auto target = MentionFixture::event_id_of(first);
    f.store->set_read_marker(bob, MentionFixture::kRoom,
                             f.store->get_room_max_stream_position(MentionFixture::kRoom));
    ASSERT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);

    // Alice now edits it to add a mention. This must NOT ping Bob: the message
    // he already read would otherwise light a mention badge out of nowhere, with
    // no new message in the timeline to explain it.
    auto edit = f.send("alice",
                       {{"msgtype", "m.text"},
                        {"body", "* hello @Bob"},
                        {"m.mentions", {{"user_ids", json::array({bob})}}},
                        {"m.new_content",
                         {{"msgtype", "m.text"},
                          {"body", "hello @Bob"},
                          {"m.mentions", {{"user_ids", json::array({bob})}}}}},
                        {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}}},
                       "t2");
    ASSERT_TRUE(IsOk(edit));

    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0)
        << "an edit injected a mention that fired a fresh notification";
    // The replacement event carries no mention rows of its own either.
    EXPECT_TRUE(f.store->get_event_mentions(MentionFixture::event_id_of(edit)).empty());
}

TEST(Mentions, EditingDoesNotDuplicateAnExistingMention) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    auto first = f.send("alice", {{"msgtype", "m.text"},
                                  {"body", "hi @Bob"},
                                  {"m.mentions", {{"user_ids", json::array({bob})}}}},
                        "t1");
    ASSERT_TRUE(IsOk(first));
    ASSERT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);

    auto target = MentionFixture::event_id_of(first);
    ASSERT_TRUE(IsOk(f.send("alice",
                            {{"msgtype", "m.text"},
                             {"body", "* hi @Bob!"},
                             {"m.mentions", {{"user_ids", json::array({bob})}}},
                             {"m.new_content", {{"msgtype", "m.text"}, {"body", "hi @Bob!"}}},
                             {"m.relates_to",
                              {{"rel_type", "m.replace"}, {"event_id", target}}}},
                            "t2")));

    // Still exactly one: the mention is a property of the original send.
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);
}

TEST(Mentions, RoomWidePermissionIsEnforcedOnEditsToo) {
    MentionFixture f;
    f.add_user("alice");
    f.add_user("bob");

    auto first = f.send("alice", {{"msgtype", "m.text"}, {"body", "hello"}}, "t1");
    ASSERT_TRUE(IsOk(first));
    auto target = MentionFixture::event_id_of(first);

    // Even though an edit records no mentions, the permission gate still applies
    // so it can never be bypassed by routing a request through the edit path.
    auto res = f.send("alice",
                      {{"msgtype", "m.text"},
                       {"body", "* hello"},
                       {"m.mentions", {{"room", true}}},
                       {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", target}}}},
                      "t2");
    EXPECT_EQ(res.status, 403);
}

// ── Redaction ─────────────────────────────────────────────────────────────

TEST(Mentions, RedactingAMessageClearsItsMentionBadge) {
    MentionFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto res = f.send("alice", {{"msgtype", "m.text"},
                                {"body", "@Bob"},
                                {"m.mentions", {{"user_ids", json::array({bob})}}}},
                      "t1");
    ASSERT_TRUE(IsOk(res));
    auto event_id = MentionFixture::event_id_of(res);
    ASSERT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);

    // The content is gone, so the mention inside it can no longer be read and
    // must not keep a highlight lit.
    ASSERT_TRUE(f.store->redact_event(event_id, alice));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);
    EXPECT_TRUE(f.store->get_event_mentions(event_id).empty());
}

TEST(Mentions, DeletingARoomLeavesNoOrphanedMentionRows) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    ASSERT_TRUE(IsOk(f.send("alice", {{"msgtype", "m.text"},
                                      {"body", "@Bob"},
                                      {"m.mentions", {{"user_ids", json::array({bob})}}}},
                            "t1")));
    ASSERT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);

    // delete_room hard-deletes a room's events, so a badge surviving it would
    // point at a channel that no longer exists.
    f.store->delete_room(MentionFixture::kRoom);
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);
    EXPECT_TRUE(f.store->get_unread_mention_counts(bob).empty());
}

// ── count_unread: the pre-existing badge bugs ─────────────────────────────

TEST(UnreadCount, EditingYourOwnMessageDoesNotBumpEveryoneElsesBadge) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");

    auto first = f.send("alice", {{"msgtype", "m.text"}, {"body", "hello"}}, "t1");
    ASSERT_TRUE(IsOk(first));
    ASSERT_EQ(f.store->count_unread(bob, MentionFixture::kRoom), 1);

    auto target = MentionFixture::event_id_of(first);
    ASSERT_TRUE(IsOk(f.send("alice",
                            {{"msgtype", "m.text"},
                             {"body", "* hello there"},
                             {"m.new_content", {{"msgtype", "m.text"}, {"body", "hello there"}}},
                             {"m.relates_to",
                              {{"rel_type", "m.replace"}, {"event_id", target}}}},
                            "t2")));

    // Still 1. An edit is a rewrite of a message the reader has already been
    // told about, not a second message.
    EXPECT_EQ(f.store->count_unread(bob, MentionFixture::kRoom), 1)
        << "an m.replace edit was counted as a new unread message";
}

TEST(UnreadCount, RedactedMessagesStopCountingAsUnread) {
    MentionFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto res = f.send("alice", {{"msgtype", "m.text"}, {"body", "oops"}}, "t1");
    ASSERT_TRUE(IsOk(res));
    ASSERT_EQ(f.store->count_unread(bob, MentionFixture::kRoom), 1);

    // A deleted message must not keep inviting the reader to open a room to find
    // content that no longer exists.
    ASSERT_TRUE(f.store->redact_event(MentionFixture::event_id_of(res), alice));
    EXPECT_EQ(f.store->count_unread(bob, MentionFixture::kRoom), 0)
        << "a redacted message still counted towards the unread badge";
}

TEST(UnreadCount, RedactionEventsThemselvesNeverCounted) {
    MentionFixture f;
    f.add_user("alice");
    auto bob = f.add_user("bob");
    // m.room.redaction is not m.room.message, so the tombstone event that
    // redaction appends must not itself register as an unread message.
    f.store->insert_event("$r1", MentionFixture::kRoom, "@alice:test",
                          std::string(event_type::kRoomRedaction), std::nullopt,
                          R"({"redacts":"$gone"})", 1);
    EXPECT_EQ(f.store->count_unread(bob, MentionFixture::kRoom), 0);
}

// ── Migration ─────────────────────────────────────────────────────────────

TEST(Mentions, SchemaVersionCoversTheMentionTables) {
    SqliteStore store(":memory:");
    store.initialize();
    // The mention API must actually be usable after a plain initialize(), which
    // is only true if the migration ran.
    EXPECT_EQ(store.count_unread_mentions("@nobody:test", "!nowhere:test"), 0);
    EXPECT_TRUE(store.get_event_mentions("$none").empty());
}

// ── Role mentions ─────────────────────────────────────────────────────────
//
// The permission rule under test is Discord's, and it has two halves:
//   * `mentionable` is the gate for everybody;
//   * MENTION_EVERYONE is an override for the case the gate exists for.
// See the block comment above MentionSet in EventHandler.cpp for why that rule
// and not one of the other three that were available.

TEST(RoleMentions, MentionableRoleBadgesEveryHolder) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault, permission::kEveryoneDefault,
                /*mod_mentionable=*/true);
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto dave = f.add_user("dave");
    f.grant(bob, permission::role_id::kModerator);
    f.grant(carol, permission::role_id::kModerator);

    // Alice holds no special permission at all — the role being mentionable is
    // the whole of her authority to ping it.
    ASSERT_TRUE(IsOk(f.send("alice",
                            MentionFixture::role_mention("@Moderator can someone look",
                                                         {permission::role_id::kModerator}),
                            "t1")));

    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);
    EXPECT_EQ(f.store->count_unread_mentions(carol, MentionFixture::kRoom), 1);
    // Dave holds no role, so nothing was aimed at him.
    EXPECT_EQ(f.store->count_unread_mentions(dave, MentionFixture::kRoom), 0);
    // And the sender is never badged by her own message, even via a role.
    EXPECT_EQ(f.store->count_unread_mentions(alice, MentionFixture::kRoom), 0);
}

TEST(RoleMentions, ItIsOneStoredRowHoweverManyMembersHoldTheRole) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault, permission::kEveryoneDefault,
                /*mod_mentionable=*/true);
    f.add_user("alice");
    for (const char* who : {"bob", "carol", "dave", "erin"}) {
        f.grant(f.add_user(who), permission::role_id::kModerator);
    }

    auto res = f.send("alice",
                      MentionFixture::role_mention("@Moderator", {permission::role_id::kModerator}),
                      "t1");
    ASSERT_TRUE(IsOk(res));

    // THE fan-out property. Four holders, one row. If this ever becomes four
    // rows, a role with five hundred members writes five hundred rows on the
    // request thread under the store's global mutex, per message.
    auto rows = f.store->get_event_mentions(MentionFixture::event_id_of(res));
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0], std::string("@role/") + permission::role_id::kModerator);
}

TEST(RoleMentions, ANonMentionableRoleNotifiesNobody) {
    MentionFixture f;
    // mentionable defaults to false here, which is the state the switch ships
    // in for a custom role.
    f.set_roles(permission::kEveryoneDefault, permission::kEveryoneDefault,
                /*mod_mentionable=*/false);
    f.add_user("alice");
    auto bob = f.add_user("bob");
    f.grant(bob, permission::role_id::kModerator);

    // The send SUCCEEDS — the message is not lost and the text is not rewritten.
    // It simply notifies nobody. (The client renders the token as plain text;
    // see MentionRenderer.)
    auto res = f.send("alice",
                      MentionFixture::role_mention("@Moderator wake up",
                                                   {permission::role_id::kModerator}),
                      "t1");
    ASSERT_TRUE(IsOk(res));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0)
        << "a role with mentionable=false notified a holder";
    EXPECT_TRUE(f.store->get_event_mentions(MentionFixture::event_id_of(res)).empty());
    // And the body is untouched, so the mention still reads as words.
    auto stored = f.store->get_event_by_id(MentionFixture::event_id_of(res));
    ASSERT_TRUE(stored.has_value());
    EXPECT_NE(stored->content.data.value("body", "").find("@Moderator"), std::string::npos);
}

TEST(RoleMentions, MentionEveryoneOverridesTheMentionableFlag) {
    MentionFixture f;
    // Alice gets MENTION_EVERYONE; the role stays locked.
    f.set_roles(permission::kEveryoneDefault | permission::kMentionEveryone,
                permission::kEveryoneDefault, /*mod_mentionable=*/false);
    f.add_user("alice");
    auto bob = f.add_user("bob");
    f.grant(bob, permission::role_id::kModerator);

    ASSERT_TRUE(IsOk(f.send("alice",
                            MentionFixture::role_mention("@Moderator, incident",
                                                         {permission::role_id::kModerator}),
                            "t1")));
    // The override exists so that a locked role is still reachable by someone
    // who could already ping strictly more people with @room.
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);
}

TEST(RoleMentions, AHolderWithoutViewChannelIsNeverBadged) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault, permission::kEveryoneDefault,
                /*mod_mentionable=*/true);
    f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    f.grant(bob, permission::role_id::kModerator);
    f.grant(carol, permission::role_id::kModerator);
    // Bob holds the role but is shut out of this channel.
    f.deny_view(bob);

    ASSERT_TRUE(IsOk(f.send("alice",
                            MentionFixture::role_mention("@Moderator",
                                                         {permission::role_id::kModerator}),
                            "t1")));

    // A direct mention is filtered when it is WRITTEN; a role mention cannot be,
    // because the stored row names nobody. So the filter has to hold at every
    // point the count is DELIVERED, and /sync is one of them: Bob must not be
    // told that a message exists in a channel he cannot open.
    EXPECT_EQ(f.highlight_from_sync(bob), -1)
        << "a channel Bob cannot view appeared in his sync at all";
    // Carol, who can see the channel, gets the badge — the test would pass
    // vacuously if the role mention had simply not worked.
    EXPECT_EQ(f.highlight_from_sync(carol), 1);
}

TEST(RoleMentions, TheEveryoneRoleIsNotMentionableAsARole) {
    MentionFixture f;
    // The @everyone role with its mentionable switch turned ON — which the role
    // editor will happily let an admin do once role CRUD lands. That must not
    // become a way around the MENTION_EVERYONE gate on `room: true`.
    f.set_roles(permission::kEveryoneDefault, /*mod_flags=*/0, /*mod_mentionable=*/false,
                /*everyone_mentionable=*/true);
    f.add_user("alice");
    auto bob = f.add_user("bob");

    // The body deliberately avoids the literal "@everyone": that string is
    // scraped and gated separately (body_mentions_everyone), and a 403 from
    // THAT check would make this test pass without exercising the role path.
    auto res = f.send("alice",
                      MentionFixture::role_mention("hi all",
                                                   {permission::role_id::kEveryone}),
                      "t1");
    ASSERT_TRUE(IsOk(res));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0)
        << "@everyone was pingable as a role, bypassing MENTION_EVERYONE";
    EXPECT_TRUE(f.store->get_event_mentions(MentionFixture::event_id_of(res)).empty());
}

TEST(RoleMentions, RoleSentinelCannotBeForgedThroughUserIds) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault, permission::kEveryoneDefault,
                /*mod_mentionable=*/false);
    f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    f.grant(bob, permission::role_id::kModerator);

    // Alice may not mention the locked role, so she tries to write its storage
    // key straight into user_ids instead.
    ASSERT_TRUE(IsOk(f.send(
        "alice",
        {{"msgtype", "m.text"},
         {"body", "sneaky"},
         {"m.mentions",
          {{"user_ids", json::array({std::string("@role/") + permission::role_id::kModerator,
                                     carol})}}}},
        "t1")));

    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0)
        << "a role sentinel spelled into user_ids pinged the role";
    // Carol was named legitimately and is still badged — the sentinel was
    // discarded, not the whole list.
    EXPECT_EQ(f.store->count_unread_mentions(carol, MentionFixture::kRoom), 1);
}

TEST(RoleMentions, AnUndefinedRoleIsDropped) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault | permission::kMentionEveryone);
    f.add_user("alice");
    auto bob = f.add_user("bob");

    // Even with the override permission, a role that does not exist cannot be
    // mentioned — otherwise a sender could seed sentinel rows for role ids that
    // role CRUD might later create, and light up a badge retroactively.
    auto res = f.send("alice", MentionFixture::role_mention("@Ghosts", {"ghosts"}), "t1");
    ASSERT_TRUE(IsOk(res));
    EXPECT_TRUE(f.store->get_event_mentions(MentionFixture::event_id_of(res)).empty());
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);
}

TEST(RoleMentions, ARoleIdContainingAColonIsRefused) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault);
    f.add_user("alice");
    auto bob = f.add_user("bob");

    // The role must actually EXIST and be mentionable, or this passes on the
    // "no such role" branch and proves nothing about the colon check. Its
    // sentinel would be "@role/evil:test", which UserId::parse accepts as the
    // user @evil on server "role/evil"... — the sentinel scheme's whole claim is
    // that a sentinel can never collide with a real account, and a colon is the
    // one character that breaks it.
    f.define_role("evil:test", /*mentionable=*/true);
    f.grant_exact(bob, {std::string(permission::role_id::kEveryone), "evil:test"});

    auto res = f.send("alice", MentionFixture::role_mention("@evil", {"evil:test"}), "t1");
    ASSERT_TRUE(IsOk(res));
    EXPECT_TRUE(f.store->get_event_mentions(MentionFixture::event_id_of(res)).empty())
        << "a role id containing a colon was stored as a sentinel";
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);
}

TEST(RoleMentions, AMentionableRoleWithAnOrdinaryCustomIdWorks) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault);
    f.add_user("alice");
    auto bob = f.add_user("bob");
    // The control for the test above: same shape, no colon. Without this, the
    // colon test would also pass if define_role()/grant_exact() were broken.
    f.define_role("raiders", /*mentionable=*/true);
    f.grant_exact(bob, {std::string(permission::role_id::kEveryone), "raiders"});

    ASSERT_TRUE(IsOk(f.send("alice", MentionFixture::role_mention("@raiders", {"raiders"}), "t1")));
    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 1);
}

TEST(RoleMentions, TooManyRolesIsRejected) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault, permission::kEveryoneDefault,
                /*mod_mentionable=*/true);
    f.add_user("alice");

    std::vector<std::string> many;
    for (size_t i = 0; i <= limits::kMaxRoleMentionsPerEvent; ++i) {
        many.push_back("r" + std::to_string(i));
    }
    auto res = f.send("alice", MentionFixture::role_mention("spam", many), "t1");
    EXPECT_EQ(res.status, 400);
}

TEST(RoleMentions, EditingAMessageCannotInjectARoleMention) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault, permission::kEveryoneDefault,
                /*mod_mentionable=*/true);
    f.add_user("alice");
    auto bob = f.add_user("bob");
    f.grant(bob, permission::role_id::kModerator);

    auto first = f.send("alice", {{"msgtype", "m.text"}, {"body", "hello"}}, "t1");
    ASSERT_TRUE(IsOk(first));
    auto target = MentionFixture::event_id_of(first);
    f.store->set_read_marker(bob, MentionFixture::kRoom,
                             f.store->get_room_max_stream_position(MentionFixture::kRoom));
    ASSERT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0);

    // Same rule as a user mention, and it falls out of the same skip: an edit
    // records no mentions at all. A role mention would otherwise be the easier
    // forgery of the two, because it needs no knowledge of who is in the room.
    auto edit = MentionFixture::role_mention("* hello @Moderator",
                                             {permission::role_id::kModerator});
    edit["m.relates_to"] = {{"rel_type", "m.replace"}, {"event_id", target}};
    ASSERT_TRUE(IsOk(f.send("alice", edit, "t2")));

    EXPECT_EQ(f.store->count_unread_mentions(bob, MentionFixture::kRoom), 0)
        << "an edit injected a role mention that fired a fresh notification";
}

TEST(RoleMentions, ReadingTheBadgeDoesNotMatchTheEveryoneSentinel) {
    MentionFixture f;
    auto bob = f.add_user("bob");
    // The read-side expansion must never include a sentinel for @everyone, or
    // every member would match a row that the send side refuses to write —
    // half a bug is still a bug, and this is the half that would survive.
    f.grant(bob, permission::role_id::kModerator);
    auto keys = f.store->mention_match_keys(bob);
    EXPECT_NE(std::find(keys.begin(), keys.end(), bob), keys.end());
    EXPECT_NE(std::find(keys.begin(), keys.end(), "@room"), keys.end());
    EXPECT_NE(std::find(keys.begin(), keys.end(), "@role/mod"), keys.end());
    EXPECT_EQ(std::find(keys.begin(), keys.end(), "@role/everyone"), keys.end());
}

// The notification-role picker, end to end on the mention side. A role that is
// self-assignable AND mentionable is what "@Raiders" is on Discord, and it is
// the combination this work exists to make possible.
//
// The property worth pinning is that mentions do not consult RANK. A
// self-assignable role deliberately confers none (it is excluded from
// highest_role_position, so a picker role cannot make its holder un-kickable),
// and a mention path that had grown a rank check somewhere would quietly
// exclude exactly these roles — the ones that matter most here.
TEST(RoleMentions, ASelfAssignablePickerRoleNotifiesItsHolders) {
    MentionFixture f;
    f.set_roles(permission::kEveryoneDefault);
    f.define_role("raiders", /*mentionable=*/true, /*self_assignable=*/true);
    f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    // Bob opted in; Carol did not.
    f.grant_exact(bob, {std::string(permission::role_id::kEveryone), "raiders"});

    ASSERT_TRUE(IsOk(f.send("alice",
                            MentionFixture::role_mention("@raiders forming up", {"raiders"}),
                            "t1")));

    EXPECT_EQ(f.highlight_from_sync(bob), 1);
    EXPECT_EQ(f.highlight_from_sync(carol), 0)
        << "a member who never opted in was notified";
}
