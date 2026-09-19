// Category rooms and VIEW_CHANNEL.
//
// A category used to be exempt from VIEW_CHANNEL outright — `is_category_room()
// || perms.can(..., kViewChannel)` — at three enforcement sites, and
// `bsfchat.room.type` was an ordinary room-scope MANAGE_CHANNELS write. Since
// every account is force-joined into every channel on this data model, one PUT
// retyping a private channel as a category published its whole state, member
// list and timeline into every user's /sync, reversibly and with no audit
// record.
//
// The properties under test, in the order they appear below:
//   1. A category a user cannot VIEW_CHANNEL contributes a sidebar STUB to
//      /sync — m.room.name, bsfchat.room.type, bsfchat.room.category and
//      nothing else. No timeline, no member list, no topic, no prev_batch, no
//      unread or highlight counts.
//   2. The same rule on the incremental path: a message sent into a category
//      never reaches a viewer without VIEW_CHANNEL, while a rename does.
//   3. A user who DOES hold VIEW_CHANNEL on a category still sees all of it —
//      the exemption was narrowed, not the ordinary rule.
//   4. /rooms/{id}/state, /state/{type} and /members carry no exemption at all
//      and refuse: they answer with whole state and whole member lists, which
//      is not a sidebar requirement and not something a stub can express.
//   5. bsfchat.room.type is evaluated at SERVER scope, so a per-channel
//      MANAGE_CHANNELS grant confers nothing, and it additionally requires
//      VIEW_CHANNEL on the room being restructured.
//   6. Converting a room INTO a category is refused when it holds message
//      history or a VIEW_CHANNEL denial.
//   7. Every accepted type change is audited, in both directions; a refused
//      one writes nothing and changes nothing.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "audit/AuditLog.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "identity/Nickname.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <set>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

// The audit action is spelled literally rather than via audit_action::, so this
// file compiles against the pre-fix tree too. A test that cannot be built
// cannot be confirmed to fail before the fix.
constexpr const char* kRoomTypeSetAction = "room.type.set";

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-category-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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

// A 403 refused for the REASON given, not merely a 403. Every gate on this path
// refuses with a 403, so a test that only asserts the status passes when the
// request is stopped by a different rule than the one under test — which is
// exactly how a scope regression hides.
::testing::AssertionResult IsForbiddenBecause(const httplib::Response& res,
                                              const std::string& needle) {
    if (res.status != 403) {
        return ::testing::AssertionFailure() << "expected 403, got status " << res.status
                                             << ", body: " << res.body;
    }
    if (res.body.find(needle) == std::string::npos) {
        return ::testing::AssertionFailure()
               << "403 for the wrong reason: expected a message containing \"" << needle
               << "\", got: " << res.body;
    }
    return ::testing::AssertionSuccess();
}

template <typename Method>
httplib::Response call(RoomHandler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
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
    std::string db_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    int64_t ts = 1000;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        seed_roles();
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    // Written straight into server_state rather than through the handler so
    // fixture setup lands no audit records: the "a refused conversion writes
    // nothing" assertions start from an empty log.
    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        // The "builder": MANAGE_CHANNELS server-wide and nothing else beyond
        // @everyone. This is the role the audits' attacker holds, and it is a
        // deliberately-granted non-admin role, not an oversight.
        content.roles.push_back(role("builder", 10,
                                     permission::kEveryoneDefault | permission::kManageChannels));
        // Grants nothing beyond @everyone. Needed wherever a test must show
        // that a PER-CHANNEL grant of MANAGE_CHANNELS confers nothing.
        content.roles.push_back(role("plain", 5, permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
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

        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    void state(const std::string& room_id, const std::string& sender, std::string_view type,
               const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ++ts);
    }

    // A room typed `room_type`, with a name and a place in the sidebar.
    std::string add_room(const std::string& creator, const std::string& name,
                         const std::string& room_type) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        state(room_id, creator, event_type::kRoomType, "", json{{"type", room_type}});
        state(room_id, creator, event_type::kRoomCategory, "",
              json{{"parent_id", ""}, {"order", 7}});
        return room_id;
    }

    // Force-joined, which on this data model is what every user is to every
    // channel — it carries no privacy meaning at all.
    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        state(room_id, user_id, event_type::kRoomMember, user_id,
              member_event_content(*store, user_id, std::string(membership::kJoin)));
    }

    void message(const std::string& room_id, const std::string& sender, const std::string& body) {
        store->insert_event(generate_event_id("test"), room_id, sender,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", body}}.dump(), ++ts);
    }

    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny = 0) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        state(room_id, "@server:test", event_type::kChannelPermissions, target, j);
    }

    std::vector<SqliteStore::AuditRecord> records() {
        return store->list_audit_records(limits::kMaxAuditLimit, std::nullopt).records;
    }

    std::string room_type_of(const std::string& room_id) {
        auto ev = store->get_state_event(room_id, std::string(event_type::kRoomType), "");
        return ev ? ev->content.data.value("type", "") : "";
    }
};

std::set<std::string> state_types(const JoinedRoom& room) {
    std::set<std::string> types;
    for (const auto& ev : room.state.events) types.insert(ev.type);
    return types;
}

const std::string kRoomsPrefix = "/_matrix/client/v3/rooms/";

std::string state_path(const std::string& room) { return kRoomsPrefix + room + "/state"; }
std::string members_path(const std::string& room) { return kRoomsPrefix + room + "/members"; }
std::string state_event_path(const std::string& room, std::string_view type) {
    return kRoomsPrefix + room + "/state/" + std::string(type);
}
std::string room_type_body(const std::string& type) { return json{{"type", type}}.dump(); }

} // namespace

// ══ 1. The sync stub: a category is named, not opened ═════════════════════

TEST(CategoryVisibility, DeniedUserGetsSidebarStubOnly) {
    Fixture f("stub-initial");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto category = f.add_room(admin, "Leadership", "category");
    f.join(category, bob);
    f.state(category, admin, event_type::kRoomTopic, "", json{{"topic", "secret plans"}});
    f.message(category, admin, "the quiet part out loud");

    // @everyone DENY VIEW_CHANNEL is how a private channel is spelled here.
    f.set_override(category, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_FALSE(perms.can(bob, category, permission::kViewChannel))
        << "the deny override did not apply; the test proves nothing";

    auto resp = f.sync->handle_sync(bob, "", 0);
    ASSERT_EQ(resp.rooms.join.count(category), 1u)
        << "the sidebar node itself must survive, or categories vanish for their children";

    const auto& room = resp.rooms.join.at(category);
    EXPECT_EQ(state_types(room),
              (std::set<std::string>{std::string(event_type::kRoomName),
                                     std::string(event_type::kRoomType),
                                     std::string(event_type::kRoomCategory)}))
        << "the stub must carry exactly what the client's sidebar model reads";
    EXPECT_TRUE(room.timeline.events.empty()) << "a category's timeline is not sidebar data";
    EXPECT_FALSE(room.timeline.prev_batch.has_value())
        << "a prev_batch is an invitation to back-paginate a channel you cannot read";
    EXPECT_FALSE(room.timeline.limited);
    EXPECT_FALSE(room.unread_count.has_value())
        << "an unread count is a message-volume oracle on a hidden channel";
    EXPECT_FALSE(room.highlight_count.has_value());
}

TEST(CategoryVisibility, DeniedUserGetsNoTimelineIncrementally) {
    Fixture f("stub-incremental");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto category = f.add_room(admin, "Leadership", "category");
    f.join(category, bob);
    f.set_override(category, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);

    auto since = f.sync->handle_sync(bob, "", 0).next_batch;

    f.message(category, admin, "still the quiet part");
    f.state(category, admin, event_type::kRoomTopic, "", json{{"topic", "also secret"}});
    // A rename DOES have to reach him: it is the sidebar label.
    f.state(category, admin, event_type::kRoomName, "", json{{"name", "Leadership II"}});
    f.sync->notify_new_event();

    auto resp = f.sync->handle_sync(bob, since, 0);
    ASSERT_EQ(resp.rooms.join.count(category), 1u) << "the rename must be delivered";

    const auto& room = resp.rooms.join.at(category);
    EXPECT_TRUE(room.timeline.events.empty())
        << "EventHandler has no notion of categories, so a category accepts messages like any "
           "other room; sync must not fan them out to users who cannot view it";
    EXPECT_EQ(state_types(room), (std::set<std::string>{std::string(event_type::kRoomName)}));
    EXPECT_FALSE(room.unread_count.has_value());
}

TEST(CategoryVisibility, RetypedPrivateChannelSpillsNothing) {
    // The escalation both audits described, end to end: a real private channel
    // with real history, retyped as a category.
    Fixture f("retype-spill");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory", {"builder"});

    auto channel = f.add_room(admin, "staff-only", "text");
    f.join(channel, mallory);
    f.message(channel, admin, "we are letting Mallory go on Friday");
    f.set_override(channel, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);

    // Before the flip, the channel is correctly invisible.
    ASSERT_EQ(f.sync->handle_sync(mallory, "", 0).rooms.join.count(channel), 0u);

    // The flip, written directly: this asserts on the SYNC side of the fix
    // regardless of whether the handler would now refuse the request (which is
    // the subject of the conversion tests below).
    f.state(channel, admin, event_type::kRoomType, "", json{{"type", "category"}});

    auto resp = f.sync->handle_sync(mallory, "", 0);
    ASSERT_EQ(resp.rooms.join.count(channel), 1u);
    const auto& room = resp.rooms.join.at(channel);
    EXPECT_TRUE(room.timeline.events.empty()) << "the channel's history must not be published";
    EXPECT_EQ(state_types(room).count(std::string(event_type::kRoomMember)), 0u)
        << "nor its member list";
    EXPECT_EQ(state_types(room).count(std::string(event_type::kChannelPermissions)), 0u)
        << "nor the override that was hiding it";
}

TEST(CategoryVisibility, PermittedUserStillSeesTheWholeCategory) {
    // The exemption was narrowed; the ordinary rule was not. A user who holds
    // VIEW_CHANNEL on a category gets it as an ordinary room.
    Fixture f("stub-permitted");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto category = f.add_room(admin, "Leadership", "category");
    f.join(category, bob);
    f.state(category, admin, event_type::kRoomTopic, "", json{{"topic", "visible"}});
    f.message(category, admin, "hello");

    auto resp = f.sync->handle_sync(bob, "", 0);
    ASSERT_EQ(resp.rooms.join.count(category), 1u);
    const auto& room = resp.rooms.join.at(category);
    // The initial-sync timeline is the last N events of every type, so the
    // assertion is on the message being there rather than on a count.
    bool saw_message = false;
    for (const auto& ev : room.timeline.events) {
        if (ev.type == event_type::kRoomMessage) saw_message = true;
    }
    EXPECT_TRUE(saw_message);
    EXPECT_EQ(state_types(room).count(std::string(event_type::kRoomTopic)), 1u);
    EXPECT_EQ(state_types(room).count(std::string(event_type::kRoomMember)), 1u);
    EXPECT_TRUE(room.unread_count.has_value());
}

TEST(CategoryVisibility, DeniedNonCategoryRoomStaysEntirelyHidden) {
    // Guard against the fix being implemented as "everything gets a stub".
    Fixture f("plain-hidden");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto channel = f.add_room(admin, "staff-only", "text");
    f.join(channel, bob);
    f.set_override(channel, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);

    EXPECT_EQ(f.sync->handle_sync(bob, "", 0).rooms.join.count(channel), 0u);
}

// ══ 2. The read endpoints carry no exemption ══════════════════════════════

TEST(CategoryVisibility, StateAndMembersRefuseOnAHiddenCategory) {
    Fixture f("read-endpoints");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto category = f.add_room(admin, "Leadership", "category");
    f.join(category, bob);
    f.set_override(category, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_EQ(call(handler, &RoomHandler::handle_room_state, state_path(category), "token-bob")
                  .status,
              403);
    EXPECT_EQ(call(handler, &RoomHandler::handle_room_state_event,
                   state_event_path(category, event_type::kRoomName), "token-bob")
                  .status,
              403);
    EXPECT_EQ(
        call(handler, &RoomHandler::handle_room_members, members_path(category), "token-bob").status,
        403);
}

TEST(CategoryVisibility, StateAndMembersStillAnswerForAPermittedUser) {
    Fixture f("read-endpoints-ok");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto category = f.add_room(admin, "Leadership", "category");
    f.join(category, bob);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(
        IsOk(call(handler, &RoomHandler::handle_room_state, state_path(category), "token-bob")));
    EXPECT_TRUE(IsOk(
        call(handler, &RoomHandler::handle_room_members, members_path(category), "token-bob")));
}

// ══ 3. The conversion gate ════════════════════════════════════════════════

TEST(CategoryVisibility, PerChannelManageChannelsDoesNotConferRetype) {
    // The natural way to give somebody their own channel is an allow override
    // on that channel. It must not be a lever on the server's channel tree.
    Fixture f("retype-scope");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory", {"plain"});

    auto channel = f.add_room(admin, "projects", "text");
    f.join(channel, mallory);
    f.set_override(channel, "user:" + mallory, permission::kManageChannels);

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(mallory, channel, permission::kManageChannels))
        << "override did not apply at channel scope; the test proves nothing";
    ASSERT_FALSE(perms.can(mallory, std::string(), permission::kManageChannels));

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(
        call(handler, &RoomHandler::handle_set_state,
             state_event_path(channel, event_type::kRoomType), "token-mallory",
             room_type_body("category")),
        "Insufficient permissions"));
    EXPECT_EQ(f.room_type_of(channel), "text");
    EXPECT_TRUE(f.records().empty());
}

TEST(CategoryVisibility, RetypeRequiresViewChannelOnTheTargetRoom) {
    // A server-wide MANAGE_CHANNELS holder is a builder, not an administrator.
    // Deny is user-scoped here so the @everyone-deny refusal below cannot be
    // what stops the request.
    Fixture f("retype-view");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory", {"builder"});

    auto channel = f.add_room(admin, "leadership", "text");
    f.join(channel, mallory);
    f.set_override(channel, "user:" + mallory, 0, permission::kViewChannel);

    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(mallory, std::string(), permission::kManageChannels))
        << "the actor must clear the permission gate, or this tests the wrong rule";

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_set_state,
                                        state_event_path(channel, event_type::kRoomType),
                                        "token-mallory", room_type_body("category")),
                                   "No access to this channel"));
    EXPECT_EQ(f.room_type_of(channel), "text");
    EXPECT_TRUE(f.records().empty());
}

TEST(CategoryVisibility, RetypeRefusedOnAChannelWithHistory) {
    // Actor is an administrator, so the only thing that can refuse this is the
    // history rule itself.
    Fixture f("retype-history");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto channel = f.add_room(admin, "general", "text");
    f.message(channel, admin, "a conversation happened here");

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_set_state,
                                        state_event_path(channel, event_type::kRoomType),
                                        "token-admin", room_type_body("category")),
                                   "message history"));
    EXPECT_EQ(f.room_type_of(channel), "text");
    EXPECT_TRUE(f.records().empty());
}

TEST(CategoryVisibility, RetypeRefusedOnARestrictedButEmptyChannel) {
    // Empty room, administrator actor: the override rule is the only thing
    // left that can refuse. An override outlives emptiness — somebody
    // configured this room's visibility on purpose, and a rule about sidebars
    // must not be allowed to overrule them.
    Fixture f("retype-override");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto channel = f.add_room(admin, "leadership", "text");
    f.set_override(channel, std::string("role:") + permission::role_id::kEveryone, 0,
                   permission::kViewChannel);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_set_state,
                                        state_event_path(channel, event_type::kRoomType),
                                        "token-admin", room_type_body("category")),
                                   "VIEW_CHANNEL restriction"));
    EXPECT_EQ(f.room_type_of(channel), "text");
    EXPECT_TRUE(f.records().empty());
}

TEST(CategoryVisibility, RetypeAllowedOnAnEmptyUnrestrictedRoomAndAudited) {
    Fixture f("retype-allowed");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_room(admin, "Projects", "text");

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_event_path(room, event_type::kRoomType), "token-admin",
                          room_type_body("category"))));
    EXPECT_EQ(f.room_type_of(room), "category");

    auto recs = f.records();
    ASSERT_EQ(recs.size(), 1u);
    EXPECT_EQ(recs[0].action, kRoomTypeSetAction);
    EXPECT_EQ(recs[0].actor, admin);
    EXPECT_EQ(recs[0].target_room, room);
    EXPECT_EQ(json::parse(recs[0].before_json).value("type", ""), "text");
    EXPECT_EQ(json::parse(recs[0].after_json).value("type", ""), "category");
}

TEST(CategoryVisibility, ConvertingBackToAChannelIsAlsoAudited) {
    // Convert, read the sync, convert back was the whole manoeuvre. A log that
    // recorded only the outbound leg would show a channel that had always been
    // a channel.
    Fixture f("retype-reverse");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_room(admin, "Projects", "category");

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_event_path(room, event_type::kRoomType), "token-admin",
                          room_type_body("text"))));
    EXPECT_EQ(f.room_type_of(room), "text");

    auto recs = f.records();
    ASSERT_EQ(recs.size(), 1u);
    EXPECT_EQ(recs[0].action, kRoomTypeSetAction);
    EXPECT_EQ(json::parse(recs[0].before_json).value("type", ""), "category");
    EXPECT_EQ(json::parse(recs[0].after_json).value("type", ""), "text");
}

TEST(CategoryVisibility, AnUnchangedTypeWriteRecordsNothing) {
    // Matches every other audit writer: a no-op write is not an event in the
    // history of the server, and a log full of them is a log nobody reads.
    Fixture f("retype-noop");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto room = f.add_room(admin, "Projects", "text");

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsOk(call(handler, &RoomHandler::handle_set_state,
                          state_event_path(room, event_type::kRoomType), "token-admin",
                          room_type_body("text"))));
    EXPECT_TRUE(f.records().empty());
}
