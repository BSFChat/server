// Server findings from AUDIT-3-2026-11-19 (functional pass): stored-state
// validation (fix-first #3), self-assignable roles (#10), and the smaller
// server items in the audit's Server section.

#include <gtest/gtest.h>

#include "api/AccountDataHandler.h"
#include "api/AuthHandler.h"
#include "api/EventHandler.h"
#include "api/MassMention.h"
#include "api/ProfileHandler.h"
#include "api/RoleHandler.h"
#include "api/RoomHandler.h"
#include "api/SearchHandler.h"
#include "api/TypingHandler.h"
#include "api/StateContentRules.h"
#include "api/VoiceHandler.h"
#include "audit/AuditLog.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "auth/RoomVisibility.h"
#include "core/Config.h"
#include "http/JsonIo.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <memory>
#include <regex>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

const std::string kRooms = "/_matrix/client/v3/rooms/";

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

::testing::AssertionResult HasStatus(const httplib::Response& res, int status) {
    const int got = res.status == -1 ? 200 : res.status;
    if (got == status) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected " << status << ", got " << got
                                         << ", body: " << res.body;
}

std::string errcode(const httplib::Response& res) {
    auto j = json::parse(res.body, nullptr, false);
    return j.is_object() ? j.value("errcode", "") : "";
}

std::string error_text(const httplib::Response& res) {
    auto j = json::parse(res.body, nullptr, false);
    return j.is_object() ? j.value("error", "") : "";
}

struct Fixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<RoomHandler> rooms;
    std::unique_ptr<EventHandler> events;
    std::unique_ptr<RoleHandler> roles;
    std::unique_ptr<VoiceHandler> voice;
    std::unique_ptr<SearchHandler> search;
    std::unique_ptr<AccountDataHandler> account;
    std::unique_ptr<ProfileHandler> profile;
    std::string admin, mod, alice, bob, room;

    Fixture() {
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        seed_roles();
        rooms = std::make_unique<RoomHandler>(*store, *sync, config);
        events = std::make_unique<EventHandler>(*store, *sync, config);
        roles = std::make_unique<RoleHandler>(*store, *sync, config);
        voice = std::make_unique<VoiceHandler>(*store, *sync, config);
        search = std::make_unique<SearchHandler>(*store, config);
        account = std::make_unique<AccountDataHandler>(*store, *sync, config);
        profile = std::make_unique<ProfileHandler>(*store, *sync, config);

        admin = add_user("admin", std::string(permission::role_id::kAdmin));
        mod = add_user("mod", std::string(permission::role_id::kModerator));
        alice = add_user("alice");
        bob = add_user("bob");
        room = add_channel(admin, "text");
        for (const auto& u : {mod, alice, bob}) join(room, u);
    }

    void seed_roles(std::vector<ServerRole> extra = {}) {
        ServerRolesContent c;
        const auto add = [&](std::string_view id, int position, permission::Flags flags) {
            ServerRole r;
            r.id = std::string(id);
            r.name = r.id;
            r.position = position;
            r.permissions = flags;
            c.roles.push_back(r);
        };
        add(permission::role_id::kEveryone, 0, permission::kEveryoneDefault);
        add(permission::role_id::kModerator, 10,
            permission::kEveryoneDefault | permission::kKickMembers | permission::kBanMembers |
                permission::kManageChannels | permission::kManageRoles);
        add(permission::role_id::kAdmin, 100, permission::kAllFlags);
        for (auto& r : extra) c.roles.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart, const std::string& extra_role = "") {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev-" + localpart);
        set_roles(uid, extra_role.empty() ? std::vector<std::string>{}
                                          : std::vector<std::string>{extra_role});
        return uid;
    }

    void set_roles(const std::string& uid, std::vector<std::string> extra) {
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (auto& r : extra) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
    }

    void join(const std::string& room_id, const std::string& user) {
        store->set_membership(room_id, user, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, user,
                            std::string(event_type::kRoomMember), user,
                            json{{"membership", membership::kJoin}}.dump(), 1001);
    }

    // State written behind the handlers' back, as an older build that did not
    // check shapes could have stored it.
    void raw_state(const std::string& room_id, std::string_view type, const std::string& key,
                   const json& content) {
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(type), key, content.dump(), 1002);
    }

    std::string add_channel(const std::string& creator, const std::string& type,
                            const std::string& join_rule = "public") {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        join(room_id, creator);
        raw_state(room_id, event_type::kRoomType, "", json{{"type", type}});
        raw_state(room_id, event_type::kRoomJoinRules, "", json{{"join_rule", join_rule}});
        raw_state(room_id, event_type::kRoomName, "", json{{"name", type + "-room"}});
        if (type == "voice") {
            raw_state(room_id, event_type::kRoomVoice, "",
                      json{{"enabled", true}, {"max_participants", 0}});
        }
        return room_id;
    }

    void override_directly(const std::string& room_id, const std::string& target,
                           permission::Flags allow, permission::Flags deny) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        raw_state(room_id, event_type::kChannelPermissions, target, j);
    }

    void ignore(const std::string& who, const std::string& whom) {
        f_ignore(*store, who, whom);
    }

    static void f_ignore(SqliteStore& st, const std::string& who, const std::string& whom) {
        st.set_account_data(who, account_data_type::kIgnoredUserList,
                            json{{"ignored_users", {{whom, json::object()}}}}.dump(),
                            std::vector<std::string>{whom}, 1);
    }

    template <typename Handler, typename Method>
    httplib::Response call_on(Handler& h, Method method, const std::string& path,
                              const std::string& who, const std::string& body = "",
                              httplib::Params params = {}) {
        httplib::Request req;
        req.path = path;
        req.body = body;
        req.params = std::move(params);
        if (!who.empty()) req.set_header("Authorization", "Bearer token-" + who);
        httplib::Response res;
        (h.*method)(req, res);
        return res;
    }

    template <typename Method>
    httplib::Response call(Method method, const std::string& path, const std::string& who,
                           const std::string& body = "") {
        return call_on(*rooms, method, path, who, body);
    }

    httplib::Response put_state(const std::string& room_id, std::string_view type,
                                const std::string& key, const json& content,
                                const std::string& who = "admin") {
        return call(&RoomHandler::handle_set_state,
                    kRooms + room_id + "/state/" + std::string(type) +
                        (key.empty() ? "" : "/" + key),
                    who, content.dump());
    }

    httplib::Response send(const std::string& room_id, const std::string& who,
                           const json& content, const std::string& type = "m.room.message") {
        static int txn = 0;
        return call_on(*events, &EventHandler::handle_send_event,
                       kRooms + room_id + "/send/" + type + "/t" + std::to_string(++txn), who,
                       content.dump());
    }

    std::string send_text(const std::string& room_id, const std::string& who,
                          const std::string& body) {
        auto res = send(room_id, who, json{{"msgtype", "m.text"}, {"body", body}});
        EXPECT_TRUE(IsOk(res));
        return json::parse(res.body).value("event_id", "");
    }
};

} // namespace

// ── #3: stored-state shapes ───────────────────────────────────────────────

TEST(StateShape, WrongTypesAreRefusedNamingTheField) {
    Fixture f;
    struct Case {
        std::string_view type;
        json content;
        std::string field;
    };
    const std::vector<Case> cases = {
        {event_type::kRoomType, {{"type", 5}}, "type"},
        {event_type::kRoomType, {{"type", "lounge"}}, "type"},
        {event_type::kRoomName, {{"name", 5}}, "name"},
        {event_type::kRoomTopic, {{"topic", json::array()}}, "topic"},
        {event_type::kRoomJoinRules, {{"join_rule", 5}}, "join_rule"},
        {event_type::kRoomCategory, {{"parent_id", 5}}, "parent_id"},
        {event_type::kRoomCategory, {{"order", "1"}}, "order"},
        {event_type::kRoomVoice, {{"enabled", "yes"}}, "enabled"},
        {event_type::kRoomVoice, {{"max_participants", -5}}, "max_participants"},
        {event_type::kRoomPinnedEvents, {{"pinned", "$x"}}, "pinned"},
        {event_type::kRoomPowerLevels, {{"ban", "50"}}, "ban"},
        {event_type::kRoomPowerLevels, {{"users", {{"@a:test", "x"}}}}, "users"},
        {event_type::kRoomAvatar, {{"url", 7}}, "url"},
        {event_type::kChannelSettings, {{"slowmode_seconds", -1}}, "slowmode_seconds"},
        {event_type::kServerInfo, {{"name", 1}}, "name"},
        {event_type::kServerScreenShare, {{"max_fps", "30"}}, "max_fps"},
    };
    for (const auto& c : cases) {
        auto res = f.put_state(f.room, c.type, "", c.content);
        EXPECT_TRUE(HasStatus(res, 400)) << c.type << " " << c.content.dump();
        EXPECT_EQ(errcode(res), "M_BAD_JSON") << c.type;
        EXPECT_NE(error_text(res).find(c.field), std::string::npos)
            << c.type << ": " << error_text(res);
    }
    // And a non-object.
    auto res = f.call(&RoomHandler::handle_set_state,
                      kRooms + f.room + "/state/" + std::string(event_type::kRoomTopic), "admin",
                      "[1]");
    EXPECT_TRUE(HasStatus(res, 400));
}

TEST(StateShape, WellFormedContentIsStillAccepted) {
    Fixture f;
    EXPECT_TRUE(IsOk(f.put_state(f.room, event_type::kRoomTopic, "", {{"topic", "hi"}})));
    EXPECT_TRUE(IsOk(f.put_state(f.room, event_type::kRoomName, "", {{"name", "general"}})));
    EXPECT_TRUE(IsOk(f.put_state(f.room, event_type::kRoomJoinRules, "",
                                 {{"join_rule", "invite"}})));
    EXPECT_TRUE(IsOk(f.put_state(f.room, event_type::kRoomPinnedEvents, "",
                                 {{"pinned", json::array()}})));
    EXPECT_TRUE(IsOk(f.put_state(f.room, event_type::kServerScreenShare, "",
                                 {{"max_quality", 2}, {"allow_lossless", false}})));
}

TEST(StateShape, RoleDocumentFieldsAreTypeChecked) {
    Fixture f;
    auto res = f.put_state(f.room, event_type::kServerRoles, "",
                           {{"roles", json::array({{{"id", 5}, {"name", "x"}}})}});
    EXPECT_TRUE(HasStatus(res, 400));
    EXPECT_NE(error_text(res).find("id"), std::string::npos);
    res = f.put_state(f.room, event_type::kMemberRoles, f.alice, {{"role_ids", "everyone"}});
    EXPECT_TRUE(HasStatus(res, 400));
}

TEST(StoredState, ALegacyIllTypedRoomTypeIsReadAsNotACategory) {
    Fixture f;
    f.raw_state(f.room, event_type::kRoomType, "", {{"type", 5}});
    EXPECT_NO_THROW(EXPECT_FALSE(is_category_room(*f.store, f.room)));
    PermissionsEngine perms(*f.store, f.config);
    EXPECT_NO_THROW(visible_joined_rooms(*f.store, perms, f.alice));
}

TEST(StoredState, ALegacyIllTypedRoomCanStillBeDeleted) {
    Fixture f;
    f.raw_state(f.room, event_type::kRoomType, "", {{"type", 5}});
    f.raw_state(f.room, event_type::kRoomName, "", {{"name", json::array()}});
    f.raw_state(f.room, event_type::kRoomCategory, "", {{"parent_id", 3}});
    EXPECT_NO_THROW(audit_room_deletion(*f.store, f.admin, f.room));
    EXPECT_TRUE(IsOk(f.call(&RoomHandler::handle_delete_room, kRooms + f.room, "admin")));
    EXPECT_FALSE(f.store->room_exists(f.room));
}

TEST(StoredState, AnIllTypedJoinRuleReadsAsInviteAndDoesNotThrow) {
    Fixture f;
    auto other = f.add_channel(f.admin, "text");
    f.raw_state(other, event_type::kRoomJoinRules, "", {{"join_rule", 5}});
    httplib::Response res;
    EXPECT_NO_THROW(res = f.call(&RoomHandler::handle_join, kRooms + other + "/join", "bob"));
    EXPECT_TRUE(HasStatus(res, 403)) << "an unreadable rule must read as the restrictive one";
}

TEST(StoredState, OneMalformedRoleDoesNotCostTheRest) {
    Fixture f;
    json doc = json::parse(*f.store->get_server_state(std::string(event_type::kServerRoles), ""));
    doc["roles"].push_back({{"id", "broken"}, {"name", 5}});
    doc["roles"].push_back("not an object");
    f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                              doc.dump());
    std::vector<ServerRole> roles;
    EXPECT_NO_THROW(roles = f.store->get_server_roles());
    EXPECT_EQ(roles.size(), 3u);
    PermissionsEngine perms(*f.store, f.config);
    EXPECT_TRUE(perms.can(f.admin, "", permission::kAdministrator));
}

TEST(TypeErrorBackstop, OnlyABodyThisThreadParsedIsTheCallersFault) {
    clear_request_body_mark();
    const std::string body = R"({"a":5})";
    EXPECT_FALSE(type_error_is_bad_request_body(302, body)) << "nothing parsed it";
    (void)parse_request_json(body);
    EXPECT_TRUE(type_error_is_bad_request_body(302, body));
    EXPECT_TRUE(type_error_is_bad_request_body(306, body));
    EXPECT_FALSE(type_error_is_bad_request_body(316, body)) << "UTF-8 on dump is ours";

    const std::string other = R"({"a":5})";
    EXPECT_FALSE(type_error_is_bad_request_body(302, other)) << "a different request's body";
    EXPECT_FALSE(type_error_is_bad_request_body(302, std::string())) << "no body at all";
    clear_request_body_mark();
    EXPECT_FALSE(type_error_is_bad_request_body(302, body));
}

// ── #10: self-assignable roles and role-manager refusals ──────────────────

namespace {

ServerRole opt_in_role(const std::string& id) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = 1;
    r.permissions = 0;
    r.self_assignable = true;
    return r;
}

httplib::Response claim(Fixture& f, const std::string& who, const std::string& role_id) {
    return f.call_on(*f.roles, &RoleHandler::handle_add_self_role,
                     std::string(api_path::kSelfRoles) + "/" + role_id, who);
}

} // namespace

TEST(SelfAssignableRoles, ARoleWhoseOverrideOpensAPrivateChannelCannotBeClaimed) {
    Fixture f;
    f.seed_roles({opt_in_role("pingme"), opt_in_role("staffdoor")});
    auto priv = f.add_channel(f.admin, "text");
    f.join(priv, f.alice);
    f.override_directly(priv, "role:everyone", 0, permission::kViewChannel);
    f.override_directly(priv, "role:staffdoor", permission::kViewChannel, 0);

    EXPECT_TRUE(HasStatus(claim(f, "alice", "staffdoor"), 403));
    EXPECT_NE(f.store->get_member_role_ids(f.alice).size(), 2u);
    EXPECT_TRUE(IsOk(claim(f, "alice", "pingme"))) << "a role with no overrides is still opt-in";
}

TEST(SelfAssignableRoles, OnlyAnAdministratorMayGiveOneAChannelAllow) {
    Fixture f;
    f.seed_roles({opt_in_role("pingme")});
    ChannelPermissionOverride ov;
    ov.allow = permission::kViewChannel;
    json body;
    to_json(body, ov);
    auto res = f.put_state(f.room, event_type::kChannelPermissions, "role:pingme", body, "mod");
    EXPECT_TRUE(HasStatus(res, 403));
    EXPECT_NE(error_text(res).find("self-assignable"), std::string::npos) << error_text(res);
    EXPECT_TRUE(IsOk(f.put_state(f.room, event_type::kChannelPermissions, "role:pingme", body)));
}

TEST(RoleAssignment, ANonAdminRoleManagerMayEchoTheirOwnAssignment) {
    Fixture f;
    auto res = f.put_state(f.room, event_type::kMemberRoles, f.mod,
                           {{"role_ids", {"everyone", "moderator"}}}, "mod");
    EXPECT_TRUE(IsOk(res));
    // ...and still cannot promote themselves.
    res = f.put_state(f.room, event_type::kMemberRoles, f.mod,
                      {{"role_ids", {"everyone", "moderator", "admin"}}}, "mod");
    EXPECT_TRUE(HasStatus(res, 403));
}

TEST(RoleAssignment, ATargetWithChannelAccessTheActorLacksGetsThePreciseReason) {
    Fixture f;
    auto priv = f.add_channel(f.admin, "text");
    f.join(priv, f.alice);
    f.override_directly(priv, "role:everyone", 0, permission::kViewChannel);
    f.override_directly(priv, "user:" + f.alice, permission::kViewChannel, 0);

    auto res = f.put_state(f.room, event_type::kMemberRoles, f.alice,
                           {{"role_ids", {"everyone"}}}, "mod");
    EXPECT_TRUE(HasStatus(res, 403));
    EXPECT_EQ(error_text(res).find("ranked at or above"), std::string::npos) << error_text(res);
    EXPECT_NE(error_text(res).find("channel"), std::string::npos) << error_text(res);
}

// ── DMs and invites to accounts that cannot take part ─────────────────────

namespace {

httplib::Response create_dm(Fixture& f, const std::string& who, const std::string& peer) {
    return f.call(&RoomHandler::handle_create_room, "/_matrix/client/v3/createRoom", who,
                  json{{"is_direct", true}, {"invite", json::array({peer})}}.dump());
}

} // namespace

TEST(DirectMessages, ToAMissingBannedOrDeactivatedPeerAreRefused) {
    Fixture f;
    EXPECT_TRUE(HasStatus(create_dm(f, "alice", "@nobody:test"), 404));

    auto carol = f.add_user("carol");
    f.store->set_server_ban(carol, f.admin, "spam", 1);
    EXPECT_TRUE(HasStatus(create_dm(f, "alice", carol), 403));

    auto dave = f.add_user("dave");
    ASSERT_TRUE(f.store->deactivate_user(dave, 1));
    EXPECT_TRUE(HasStatus(create_dm(f, "alice", dave), 403));

    EXPECT_TRUE(f.store->get_direct_rooms(f.alice).empty()) << "a fake DM was created";
    EXPECT_TRUE(IsOk(create_dm(f, "alice", f.bob)));
}

TEST(DirectMessages, SomebodyYouIgnoreCannotForceJoinYouIntoADm) {
    Fixture f;
    f.ignore(f.bob, f.alice);
    EXPECT_TRUE(HasStatus(create_dm(f, "alice", f.bob), 403));
    EXPECT_TRUE(IsOk(create_dm(f, "bob", f.alice))) << "the ignorer may still open one";
}

TEST(Invites, ADeactivatedAccountCannotBeInvited) {
    Fixture f;
    auto priv = f.add_channel(f.admin, "text", "invite");
    auto dave = f.add_user("dave");
    ASSERT_TRUE(f.store->deactivate_user(dave, 1));
    auto res = f.call(&RoomHandler::handle_invite, kRooms + priv + "/invite", "admin",
                      json{{"user_id", dave}}.dump());
    EXPECT_TRUE(HasStatus(res, 403));
    EXPECT_NE(f.store->get_membership(priv, dave), "invite");
}

// ── Mass mentions are tokens, not substrings ─────────────────────────────

TEST(MassMention, MatchesTheTokenTheClientRenders) {
    EXPECT_TRUE(text_mentions_everyone("@everyone look", false));
    EXPECT_TRUE(text_mentions_everyone("hey @here!", false));
    EXPECT_TRUE(text_mentions_everyone("(@Room)", false));
    EXPECT_TRUE(text_mentions_everyone("<b>@everyone</b> look here", true));

    EXPECT_FALSE(text_mentions_everyone("mail ops@hereford.example", false));
    EXPECT_FALSE(text_mentions_everyone("@heretic and @everyones", false));
    EXPECT_FALSE(text_mentions_everyone("use `@everyone` to ping", false));
    EXPECT_FALSE(text_mentions_everyone("```\n@here\n```", false));
    EXPECT_FALSE(text_mentions_everyone("see https://x.example/@everyone", false));
    EXPECT_FALSE(text_mentions_everyone("<code>@everyone</code>", true));
    EXPECT_FALSE(text_mentions_everyone("<pre><code>@here</code></pre>", true));
    EXPECT_FALSE(text_mentions_everyone("<a href=\"x\">@room</a>", true));
    EXPECT_TRUE(text_mentions_everyone("`code` then @here", false));
    EXPECT_TRUE(text_mentions_everyone("an `unclosed @here", false));
}

TEST(MassMention, AnEmailAddressIsNotRefusedAsAMassMention) {
    Fixture f;
    auto res = f.send(f.room, "alice",
                      {{"msgtype", "m.text"}, {"body", "write to ops@hereford.example"}});
    EXPECT_TRUE(IsOk(res));
    res = f.send(f.room, "alice", {{"msgtype", "m.text"}, {"body", "`@everyone` is how"}});
    EXPECT_TRUE(IsOk(res));
    res = f.send(f.room, "alice", {{"msgtype", "m.text"}, {"body", "@everyone wake up"}});
    EXPECT_TRUE(HasStatus(res, 403));
}

// ── Ignore covers search and typing ───────────────────────────────────────

TEST(Ignore, SearchLeavesOutWhatIgnoredUsersSent) {
    Fixture f;
    if (!f.store->search_index_available()) GTEST_SKIP() << "SQLite without FTS5";
    f.send_text(f.room, "bob", "pineapple from bob");
    f.send_text(f.room, "mod", "pineapple from mod");
    f.ignore(f.alice, f.bob);

    json body;
    body["search_categories"]["room_events"] = {{"search_term", "pineapple"}};
    auto res = f.call_on(*f.search, &SearchHandler::handle_search,
                         "/_matrix/client/v3/search", "alice", body.dump());
    ASSERT_TRUE(IsOk(res));
    const auto cat = json::parse(res.body)["search_categories"]["room_events"];
    EXPECT_EQ(cat["count"], 1);
    ASSERT_EQ(cat["results"].size(), 1u);
    EXPECT_EQ(cat["results"][0]["result"]["sender"], f.mod);
}

TEST(Ignore, TypingFromAnIgnoredUserIsLeftOutForTheIgnorer) {
    Fixture f;
    TypingHandler typing(*f.store, *f.sync, f.config);
    static const std::regex re(R"(/_matrix/client/v3/rooms/([^/]+)/typing/(.+))");
    httplib::Request req;
    req.path = kRooms + f.room + "/typing/" + f.bob;
    req.body = json{{"typing", true}, {"timeout", 30000}}.dump();
    req.set_header("Authorization", "Bearer token-bob");
    ASSERT_TRUE(std::regex_match(req.path, req.matches, re));
    httplib::Response res;
    typing.handle_typing(req, res);
    ASSERT_TRUE(IsOk(res));

    f.ignore(f.alice, f.bob);
    EXPECT_TRUE(typing.get_typing_users_for(f.room, f.alice).empty());
    EXPECT_EQ(typing.get_typing_users_for(f.room, f.mod).size(), 1u);
}

// ── The read marker goes where the client says ────────────────────────────

namespace {

httplib::Response read_marker(Fixture& f, const std::string& who, const json& body) {
    return f.call_on(*f.events, &EventHandler::handle_read_marker,
                     kRooms + f.room + "/read_marker", who, body.dump());
}

} // namespace

TEST(ReadMarker, ANamedEventMarksUpToThatEventNotTheLatest) {
    Fixture f;
    const auto first = f.send_text(f.room, "bob", "one");
    f.send_text(f.room, "bob", "two");
    const auto first_pos = f.store->get_event_stream_position(f.room, first);
    ASSERT_TRUE(first_pos);

    ASSERT_TRUE(IsOk(read_marker(f, "alice", {{"m.fully_read", first}})));
    EXPECT_EQ(f.store->get_read_marker(f.alice, f.room), *first_pos);

    ASSERT_TRUE(IsOk(read_marker(f, "alice", json::object())));
    EXPECT_EQ(f.store->get_read_marker(f.alice, f.room),
              f.store->get_room_max_stream_position(f.room))
        << "{} still means everything";
}

TEST(ReadMarker, TheReceiptAloneMovesItToo) {
    Fixture f;
    const auto first = f.send_text(f.room, "bob", "one");
    f.send_text(f.room, "bob", "two");
    ASSERT_TRUE(IsOk(read_marker(f, "alice", {{"m.read", first}})));
    EXPECT_EQ(f.store->get_read_marker(f.alice, f.room),
              *f.store->get_event_stream_position(f.room, first));
}

TEST(ReadMarker, ANonStringMarkerIsRefused) {
    Fixture f;
    auto res = read_marker(f, "alice", {{"m.fully_read", 5}});
    EXPECT_TRUE(HasStatus(res, 400));
    EXPECT_EQ(errcode(res), "M_BAD_JSON");
    EXPECT_TRUE(HasStatus(read_marker(f, "alice", {{"last_read_pos", "9"}}), 400));
}

// ── /messages tokens ──────────────────────────────────────────────────────

namespace {

httplib::Response messages(Fixture& f, const std::string& who, httplib::Params params) {
    return f.call_on(*f.events, &EventHandler::handle_room_messages,
                     kRooms + f.room + "/messages", who, "", std::move(params));
}

} // namespace

TEST(Messages, ASyncNextBatchIsAcceptedAsFrom) {
    Fixture f;
    f.send_text(f.room, "bob", "older");
    const auto token = f.sync->handle_sync(f.alice, "", 0).next_batch;
    f.send_text(f.room, "bob", "newer");

    auto res = messages(f, "alice", {{"from", token}, {"dir", "b"}, {"limit", "50"}});
    ASSERT_TRUE(IsOk(res));
    const auto j = json::parse(res.body);
    EXPECT_TRUE(j.contains("start"));
    bool saw_older = false, saw_newer = false;
    for (const auto& ev : j["chunk"]) {
        const auto body = ev["content"].value("body", "");
        saw_older |= body == "older";
        saw_newer |= body == "newer";
    }
    EXPECT_TRUE(saw_older);
    EXPECT_FALSE(saw_newer) << "back-pagination from a sync token went past it";

    res = messages(f, "alice", {{"from", token}, {"dir", "f"}});
    ASSERT_TRUE(IsOk(res));
    const auto fwd = json::parse(res.body)["chunk"];
    ASSERT_FALSE(fwd.empty());
    EXPECT_EQ(fwd.back()["content"].value("body", ""), "newer");
}

TEST(Messages, GarbageTokensAndDirectionsAreRefused) {
    Fixture f;
    EXPECT_TRUE(HasStatus(messages(f, "alice", {{"from", "garbage"}}), 400));
    EXPECT_TRUE(HasStatus(messages(f, "alice", {{"from", "sabc"}}), 400));
    EXPECT_TRUE(HasStatus(messages(f, "alice", {{"dir", "x"}}), 400));
    // A token minted for somebody else does not parse for this caller.
    const auto bobs = f.sync->handle_sync(f.bob, "", 0).next_batch;
    EXPECT_TRUE(HasStatus(messages(f, "alice", {{"from", bobs}}), 400));
}

TEST(Messages, StartIsAlwaysPresent) {
    Fixture f;
    f.send_text(f.room, "bob", "hi");
    for (const char* dir : {"b", "f"}) {
        auto res = messages(f, "alice", {{"dir", dir}});
        ASSERT_TRUE(IsOk(res));
        EXPECT_TRUE(json::parse(res.body).contains("start")) << dir;
    }
}

// ── Categories ────────────────────────────────────────────────────────────

namespace {

httplib::Response move(Fixture& f, const std::string& room_id, const json& parent) {
    return f.call(&RoomHandler::handle_move_channel, kRooms + room_id + "/category", "admin",
                  json{{"parent_id", parent}}.dump());
}

CategoryContent placement(Fixture& f, const std::string& room_id) {
    CategoryContent c;
    auto ev = f.store->get_state_event(room_id, std::string(event_type::kRoomCategory), "");
    if (ev) from_json(ev->content.data, c);
    return c;
}

} // namespace

TEST(Categories, NoSelfParentingAndNoCategoryUnderACategoryOnAnyPath) {
    Fixture f;
    auto cat1 = f.add_channel(f.admin, "category");
    auto cat2 = f.add_channel(f.admin, "category");

    EXPECT_TRUE(HasStatus(move(f, cat1, cat1), 400));
    EXPECT_TRUE(HasStatus(move(f, cat1, cat2), 400));
    EXPECT_TRUE(HasStatus(
        f.put_state(cat1, event_type::kRoomCategory, "", {{"parent_id", cat1}}), 400));
    EXPECT_TRUE(HasStatus(
        f.put_state(cat1, event_type::kRoomCategory, "", {{"parent_id", cat2}}), 400));
    auto res = f.call(&RoomHandler::handle_create_room, "/_matrix/client/v3/createRoom",
                      "admin",
                      json{{"name", "sub"}, {"is_category", true}, {"parent_id", cat1}}.dump());
    EXPECT_TRUE(HasStatus(res, 400));

    // A filed channel cannot become a category in place either.
    ASSERT_TRUE(IsOk(move(f, f.room, cat1)));
    EXPECT_TRUE(HasStatus(f.put_state(f.room, event_type::kRoomType, "", {{"type", "category"}}),
                          400));
}

TEST(Categories, AMissingParentIsNotFoundOnEveryPath) {
    Fixture f;
    const std::string nowhere = "!nowhere:test";
    auto res = move(f, f.room, nowhere);
    EXPECT_TRUE(HasStatus(res, 404));
    EXPECT_EQ(errcode(res), "M_NOT_FOUND");
    res = f.put_state(f.room, event_type::kRoomCategory, "", {{"parent_id", nowhere}});
    EXPECT_TRUE(HasStatus(res, 404));
    EXPECT_EQ(errcode(res), "M_NOT_FOUND");
    res = f.call(&RoomHandler::handle_create_room, "/_matrix/client/v3/createRoom", "admin",
                 json{{"name", "x"}, {"parent_id", nowhere}}.dump());
    EXPECT_TRUE(HasStatus(res, 404));
    EXPECT_EQ(errcode(res), "M_NOT_FOUND");
}

TEST(Categories, UnfilingKeepsTheOrder) {
    Fixture f;
    auto cat = f.add_channel(f.admin, "category");
    ASSERT_TRUE(IsOk(f.put_state(f.room, event_type::kRoomCategory, "",
                                 {{"parent_id", cat}, {"order", 7}})));
    ASSERT_TRUE(IsOk(move(f, f.room, nullptr)));
    EXPECT_EQ(placement(f, f.room).parent_id, "");
    EXPECT_EQ(placement(f, f.room).order, 7);
}

TEST(Categories, DeletingACategoryUnfilesItsChildren) {
    Fixture f;
    auto cat = f.add_channel(f.admin, "category");
    ASSERT_TRUE(IsOk(f.put_state(f.room, event_type::kRoomCategory, "",
                                 {{"parent_id", cat}, {"order", 3}})));
    ASSERT_TRUE(IsOk(f.call(&RoomHandler::handle_delete_room, kRooms + cat, "admin")));
    EXPECT_EQ(placement(f, f.room).parent_id, "") << "a dangling parent_id was left behind";
    EXPECT_EQ(placement(f, f.room).order, 3);
}
