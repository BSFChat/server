// Redaction is for messages, not for room state.
//
// handle_redact strips a target's content to '{}' and leaves the row in place.
// For a state event that row is still the CURRENT state for its (type,
// state_key), so redacting one is a state write — and it is a state write that
// skips every check handle_set_state makes. The sharpest instance:
// get_channel_overrides() reads a '{}' override as allow=0/deny=0 and drops it,
// so MANAGE_MESSAGES — "delete other people's messages" — was enough to delete
// a channel's permission overrides: un-hide a private channel, lift a mute,
// with no containment or rank check and no audit record.
//
// Each test below was confirmed to fail before the fix.

#include <gtest/gtest.h>

#include "api/EventHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <memory>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
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
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<EventHandler> events;
    std::string room = "!private:test";
    std::string mod;
    std::string member;

    Fixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        events = std::make_unique<EventHandler>(*store, *sync, config, nullptr);

        // A moderator: may delete other people's messages, may NOT manage roles
        // or channels. That is exactly the grant the defect turned into both.
        ServerRolesContent roles;
        roles.roles.push_back(role(permission::role_id::kEveryone, 0,
                                   permission::kEveryoneDefault));
        roles.roles.push_back(role("mod", 10,
                                   permission::kEveryoneDefault | permission::kManageMessages));
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());

        store->create_room(room, "@server:test");
        mod = add_user("mod", {"mod"});
        member = add_user("member", {});
    }

    std::string add_user(const std::string& localpart, const std::vector<std::string>& extra) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        store->set_membership(room, uid, std::string(membership::kJoin));
        return uid;
    }

    std::string set_state(const std::string& type, const std::string& state_key,
                          const json& content) {
        auto id = generate_event_id("test");
        store->insert_event(id, room, "@server:test", type, state_key, content.dump(), 1000);
        return id;
    }

    httplib::Response redact(const std::string& token, const std::string& target,
                             const std::string& txn) {
        httplib::Request req;
        req.path = "/_matrix/client/v3/rooms/" + room + "/redact/" + target + "/" + txn;
        req.body = "{}";
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        events->handle_redact(req, res);
        return res;
    }

    bool can(const std::string& user, permission::Flags flag) {
        PermissionsEngine perms(*store, config);
        return permission::has(perms.compute(user, room), flag);
    }
};

json override_content(permission::Flags allow, permission::Flags deny) {
    ChannelPermissionOverride ov;
    ov.allow = allow;
    ov.deny = deny;
    json j;
    to_json(j, ov);
    return j;
}

} // namespace

TEST(StateRedaction, ManageMessagesCannotDeleteAChannelMute) {
    Fixture f;
    const auto ov = f.set_state(std::string(event_type::kChannelPermissions),
                                "user:" + f.member,
                                override_content(0, permission::kSendMessages));
    ASSERT_FALSE(f.can(f.member, permission::kSendMessages))
        << "the mute must be in force, or this proves nothing";

    auto res = f.redact("token-mod", ov, "t1");

    EXPECT_FALSE(IsOk(res)) << "redacting a state event must be refused";
    EXPECT_FALSE(f.can(f.member, permission::kSendMessages))
        << "a moderator with MANAGE_MESSAGES lifted a mute by redacting it";
}

TEST(StateRedaction, ManageMessagesCannotUnhideAPrivateChannel) {
    Fixture f;
    const auto ov = f.set_state(std::string(event_type::kChannelPermissions),
                                std::string("role:") + permission::role_id::kEveryone,
                                override_content(0, permission::kViewChannel));
    // The moderator needs to see the channel to act in it at all.
    f.set_state(std::string(event_type::kChannelPermissions), "role:mod",
                override_content(permission::kViewChannel, 0));
    ASSERT_FALSE(f.can(f.member, permission::kViewChannel));

    auto res = f.redact("token-mod", ov, "t1");

    EXPECT_FALSE(IsOk(res));
    EXPECT_FALSE(f.can(f.member, permission::kViewChannel))
        << "a private channel became visible to everyone via /redact";
}

TEST(StateRedaction, AStateEventCannotBeSelfRedactedEither) {
    // The self-redact branch is unconditional, so the sender of a state event
    // must not be able to strip it either — that is how a room's type, name or
    // a kick marker would be edited without handle_set_state's checks.
    Fixture f;
    const auto ev = f.set_state(std::string(event_type::kRoomType), "",
                                json{{"type", "voice"}});
    // Re-sent as the moderator, so the self branch is the one exercised.
    auto id = generate_event_id("test");
    f.store->insert_event(id, f.room, f.mod, std::string(event_type::kRoomName), std::string(""),
                          json{{"name", "general"}}.dump(), 1001);

    EXPECT_FALSE(IsOk(f.redact("token-mod", id, "t1")));
    EXPECT_FALSE(IsOk(f.redact("token-mod", ev, "t2")));
}

TEST(StateRedaction, MessagesAreStillRedactable) {
    // Control: the refusal is about state, not about redaction.
    Fixture f;
    auto id = generate_event_id("test");
    f.store->insert_event(id, f.room, f.member, std::string(event_type::kRoomMessage),
                          std::nullopt, json{{"msgtype", "m.text"}, {"body", "hi"}}.dump(), 1000);

    EXPECT_TRUE(IsOk(f.redact("token-mod", id, "t1")));
    auto ev = f.store->get_event_by_id(id);
    ASSERT_TRUE(ev.has_value());
    EXPECT_TRUE(ev->content.data.empty()) << ev->content.data.dump();
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACH_FILES is judged on what the message BECOMES, not only on what it was.
//
// The store resolves an edit by replacing the original's content wholesale with
// m.new_content, so `{"msgtype":"m.text", "m.new_content":{"msgtype":"m.image"}}`
// turns a text message into an attachment everyone is served. The gate read only
// the top-level msgtype — the same one-level-down gap renderable_text() closed
// for EMBED_LINKS and MENTION_EVERYONE.

namespace {

httplib::Response send_as(Fixture& f, const std::string& token, const json& content,
                          const std::string& txn) {
    httplib::Request req;
    req.path = "/_matrix/client/v3/rooms/" + f.room + "/send/m.room.message/" + txn;
    req.body = content.dump();
    req.set_header("Authorization", "Bearer " + token);
    httplib::Response res;
    f.events->handle_send_event(req, res);
    return res;
}

} // namespace

TEST(EditAttachment, AnEditCannotTurnTextIntoAnAttachmentWithoutAttachFiles) {
    Fixture f;
    f.set_state(std::string(event_type::kChannelPermissions), "user:" + f.member,
                override_content(0, permission::kAttachFiles));
    ASSERT_FALSE(f.can(f.member, permission::kAttachFiles));
    ASSERT_TRUE(f.can(f.member, permission::kSendMessages));

    auto orig = send_as(f, "token-member", json{{"msgtype", "m.text"}, {"body", "hi"}}, "t1");
    ASSERT_TRUE(IsOk(orig)) << orig.body;
    const auto orig_id = json::parse(orig.body).value("event_id", "");

    // Control: the direct route is refused.
    auto direct = send_as(f, "token-member", json{{"msgtype", "m.image"}, {"body", "x"}}, "t2");
    ASSERT_EQ(direct.status, 403) << direct.body;

    auto edit = send_as(f, "token-member",
                        json{{"msgtype", "m.text"},
                             {"body", "* x"},
                             {"m.new_content", {{"msgtype", "m.image"}, {"body", "x"}}},
                             {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", orig_id}}}},
                        "t3");
    EXPECT_EQ(edit.status, 403) << edit.body;
    EXPECT_NE(edit.body.find("attach files"), std::string::npos) << edit.body;
}

TEST(EditAttachment, ATextEditIsStillAllowed) {
    Fixture f;
    f.set_state(std::string(event_type::kChannelPermissions), "user:" + f.member,
                override_content(0, permission::kAttachFiles));
    auto orig = send_as(f, "token-member", json{{"msgtype", "m.text"}, {"body", "hi"}}, "t1");
    ASSERT_TRUE(IsOk(orig)) << orig.body;
    const auto orig_id = json::parse(orig.body).value("event_id", "");

    auto edit = send_as(f, "token-member",
                        json{{"msgtype", "m.text"},
                             {"body", "* hello"},
                             {"m.new_content", {{"msgtype", "m.text"}, {"body", "hello"}}},
                             {"m.relates_to", {{"rel_type", "m.replace"}, {"event_id", orig_id}}}},
                        "t2");
    EXPECT_TRUE(IsOk(edit)) << edit.body;
}
