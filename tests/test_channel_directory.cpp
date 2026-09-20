// The channel directory: GET /_matrix/client/v3/bsfchat/channels.
//
// There was no way to discover a channel. /joined_rooms starts from membership,
// so a caller could enumerate only what somebody had already put it in, and an
// integration bot on a fresh install could therefore not offer an operator a
// list of channels to send alerts to. This endpoint answers the other question:
// which channels EXIST on this server that this caller may be told about.
//
// That makes it the most dangerous kind of endpoint on this data model. A
// private channel here is a PUBLIC room that every account is force-joined into,
// carrying an `@everyone DENY VIEW_CHANNEL` override — so every user holds a
// membership row for every private channel, and a directory that filtered on
// membership, or on the room's `visibility`, or on join_rules, would publish the
// complete list of the server's private channels to everyone on it. See
// docs/membership-vs-visibility.md.
//
// The properties below, in order. The first six are the security half and each
// one is written to go red against the naive implementation (filter on
// is_room_member, the way /joined_rooms once did):
//
//   1. A user denied VIEW_CHANNEL does not learn a private channel exists from
//      ANY field of the response — not its id anywhere in the body, not the
//      number of entries, and not from a gap in the ordering. Asserted by
//      scanning the serialised body for the id and by pinning the exact key set
//      of every entry, because "we did not put it in room_id" is not the same
//      claim as "it is not in the response".
//   2. The denial is a real permission evaluation and not a blanket hide: a
//      user-specific ALLOW override reinstates the channel for that one user,
//      which is the precedence chain the endpoint has to honour rather than
//      short-circuit.
//   3. Direct messages are never listed, to anybody, INCLUDING their own
//      participants. This is not tidiness: PermissionsEngine::compute() clears
//      channel overrides on a DM, so a DM that reached a VIEW_CHANNEL filter
//      would pass it for every account on the server (@everyone carries
//      VIEW_CHANNEL by default) and the directory would publish every private
//      conversation on the instance.
//   4. `category_id` never names a room the caller was not shown. create_room
//      accepts any existing room id as `parent_id` and only handle_move_channel
//      checks that it is a category, so a channel really can carry a private
//      channel as its parent.
//   5. sort_order is not on the wire. It is assigned per category with gaps, so
//      publishing it would let a caller read the gaps and count what was
//      filtered out of their own response.
//   6. Bots and humans get the same answer. A special case in a security filter
//      is a second filter that only one class of caller ever exercises.
//
// Then the half that would hurt more if it broke — the controls. Every one of
// them is asserted with an ORDINARY MEMBER holding only kEveryoneDefault, never
// with an admin, because ADMINISTRATOR short-circuits every flag and proves
// nothing about the gate:
//
//   7. A caller that is a member of NOTHING still gets the public channels, with
//      joined = false. This is the whole feature: without it a bot still cannot
//      discover anywhere to post.
//   8. A category the caller cannot VIEW_CHANNEL is still listed, as a named
//      container — the same exemption /sync applies, so the directory and the
//      sidebar agree about what containers exist.
//   9. Ordering is total and useful: top-level entries by (order, room_id), each
//      category's children immediately after it.
//  10. No token is 401.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "auth/RoomVisibility.h"
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

#include <algorithm>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

// The path comes from the protocol constant, not from a literal copied out of
// the handler: the point of the test is that the route a client is told to call
// is the route that got registered.
const std::string kDirectoryPath = std::string(api_path::kChannelDirectory);

// Every key an entry is allowed to carry. Pinned as a set rather than checked
// field by field, because the property in §1 is about what the response does
// NOT contain — a later field added without thought (a topic, a member count, a
// sort_order) fails this rather than sailing through a per-field check.
const std::set<std::string> kAllowedEntryKeys = {"room_id", "name", "type", "category_id",
                                                 "joined"};

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-chandir-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
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
    std::unique_ptr<RoomHandler> rooms;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        rooms = std::make_unique<RoomHandler>(*store, *sync, config);

        ServerRolesContent content;
        content.roles.push_back(
            role(std::string(permission::role_id::kEveryone), 0, permission::kEveryoneDefault));
        content.roles.push_back(
            role(std::string(permission::role_id::kAdmin), 100, permission::kAllFlags));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    ~Fixture() {
        rooms.reset();
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    void assign_roles(const std::string& uid, const std::vector<std::string>& extra_roles) {
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev");
        assign_roles(uid, extra_roles);
        return uid;
    }

    // A real bot account: kind = 'bot' in `users` plus its `bots` row. Created
    // through the store's own constructor rather than faked with a bot_-prefixed
    // human, so §6 is comparing what the server actually treats as a bot.
    std::string add_bot(const std::string& localpart, const std::string& owner) {
        std::string uid = "@" + localpart + ":test";
        SqliteStore::BotRecord bot;
        bot.user_id = uid;
        bot.display_name = localpart;
        bot.owner_id = owner;
        bot.created_at = 1000;
        bot.created_by = owner;
        EXPECT_TRUE(store->create_bot(bot));
        store->store_access_token("token-" + localpart, uid, "dev");
        assign_roles(uid, {});
        return uid;
    }

    // A channel as the client actually creates one: public join rules, so
    // auto-join force-joins everybody, plus a bsfchat.room.type.
    std::string add_channel(const std::string& creator, const std::string& name,
                            std::string_view type = room_type::kText) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", std::string(type)}}.dump(), 1001);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomJoinRules), std::string(""),
                            json{{"join_rule", "public"}}.dump(), 1002);
        return room_id;
    }

    // A DM, created the way handle_create_room creates one: is_direct on the
    // room row, and both participants joined.
    std::string add_dm(const std::string& a, const std::string& b) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, a, /*is_direct=*/true);
        store->set_membership(room_id, a, std::string(membership::kJoin));
        store->set_membership(room_id, b, std::string(membership::kJoin));
        return room_id;
    }

    void file_under(const std::string& room_id, const std::string& parent_id, int order) {
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kRoomCategory), std::string(""),
                            json{{"parent_id", parent_id}, {"order", order}}.dump(), 1006);
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
    }

    void set_override(const std::string& room_id, const std::string& target,
                      permission::Flags allow, permission::Flags deny = 0) {
        ChannelPermissionOverride ov;
        ov.allow = allow;
        ov.deny = deny;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), target, j.dump(), 1004);
    }

    // "Make this channel private", as ChannelSettings.qml defines it: deny
    // VIEW_CHANNEL to @everyone. There is no other marker to test against.
    void make_private(const std::string& room_id) {
        set_override(room_id, std::string("role:") + permission::role_id::kEveryone, 0,
                     permission::kViewChannel);
    }
};

struct Directory {
    int status = 0;
    std::string raw;   // the serialised body, for the "appears nowhere" scan
    json body;
};

Directory directory(RoomHandler& handler, const std::string& token) {
    httplib::Request req;
    req.path = kDirectoryPath;
    if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
    httplib::Response res;
    handler.handle_channel_directory(req, res);
    Directory out;
    // httplib leaves status at -1 on a handler that never set it, which is the
    // success path here.
    out.status = res.status == -1 ? 200 : res.status;
    out.raw = res.body;
    out.body = json::parse(res.body, nullptr, false);
    return out;
}

std::vector<std::string> room_ids(const Directory& d) {
    std::vector<std::string> ids;
    for (const auto& e : d.body.at("channels")) ids.push_back(e.at("room_id").get<std::string>());
    return ids;
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

// The §1 assertion, factored out because it is the point of the whole file: a
// room the caller may not see must not be derivable from the response AT ALL.
// The substring scan over the serialised body is deliberately blunt — it catches
// the id turning up in a field nobody thought to check, which is how the
// /joined_rooms leak's second half survived the first fix.
void assert_absent(const Directory& d, const std::string& room_id) {
    EXPECT_EQ(d.raw.find(room_id), std::string::npos)
        << "room id " << room_id << " appears in the directory body: " << d.raw;
    for (const auto& e : d.body.at("channels")) {
        for (auto it = e.begin(); it != e.end(); ++it) {
            EXPECT_TRUE(kAllowedEntryKeys.count(it.key()) > 0)
                << "unexpected field '" << it.key() << "' in a directory entry";
        }
    }
}

} // namespace

// ── 1. the leak ──────────────────────────────────────────────────────────────
//
// `bob` is a joined member of the private channel — on this data model he has to
// be — and must still not be told it exists. A directory that filtered on
// membership returns it to him, which is what makes this the test that has to go
// red against the naive implementation.
TEST(ChannelDirectory, DeniedUserLearnsNothingAboutAPrivateChannel) {
    Fixture f("denied");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto open_room = f.add_channel(alice, "general");
    auto secret = f.add_channel(alice, "staff-only");
    f.make_private(secret);
    // Force-joined into both, exactly as auto-join would have left him.
    f.join(open_room, bob);
    f.join(secret, bob);

    auto d = directory(*f.rooms, "token-bob");
    ASSERT_EQ(d.status, 200);
    auto ids = room_ids(d);

    EXPECT_TRUE(contains(ids, open_room));
    assert_absent(d, secret);
    // The count is a field too: one visible channel, not two-minus-one-hidden.
    EXPECT_EQ(ids.size(), 1u);

    // ...and the channel really is there for someone who may see it, so the
    // test is not passing because the directory is empty.
    auto admin_ids = room_ids(directory(*f.rooms, "token-alice"));
    EXPECT_TRUE(contains(admin_ids, secret));
}

// ── 2. a real permission evaluation, not a blanket hide ──────────────────────
TEST(ChannelDirectory, UserSpecificAllowOverrideReinstatesTheChannel) {
    Fixture f("allow");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");

    auto secret = f.add_channel(alice, "staff-only");
    f.make_private(secret);
    f.set_override(secret, "user:" + bob, permission::kViewChannel);

    EXPECT_TRUE(contains(room_ids(directory(*f.rooms, "token-bob")), secret));
    // carol is identical to bob in every respect except the override.
    auto carols = directory(*f.rooms, "token-carol");
    assert_absent(carols, secret);
}

// A role-scoped ALLOW is the other half of the precedence chain, and it is the
// one the product actually uses: "private channel visible to @moderators".
TEST(ChannelDirectory, RoleAllowOverrideReinstatesTheChannel) {
    Fixture f("roleallow");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});

    ServerRolesContent content;
    content.roles.push_back(
        role(std::string(permission::role_id::kEveryone), 0, permission::kEveryoneDefault));
    content.roles.push_back(role("mod", 50, permission::kEveryoneDefault));
    content.roles.push_back(
        role(std::string(permission::role_id::kAdmin), 100, permission::kAllFlags));
    json j;
    to_json(j, content);
    f.store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test", j.dump());

    auto mod = f.add_user("mod_user", {"mod"});
    auto plain = f.add_user("plain");

    auto secret = f.add_channel(alice, "staff-only");
    f.make_private(secret);
    f.set_override(secret, "role:mod", permission::kViewChannel);

    EXPECT_TRUE(contains(room_ids(directory(*f.rooms, "token-mod_user")), secret));
    assert_absent(directory(*f.rooms, "token-plain"), secret);
}

// ── 3. direct messages ───────────────────────────────────────────────────────
//
// The directory sweeps every room on the server, so a DM only stays out of it
// because it is excluded before any permission is evaluated. If it were not,
// compute() would clear its (nonexistent) overrides, @everyone's VIEW_CHANNEL
// would pass, and every private conversation on the instance would be listed to
// every account. Asserted for a NON-participant and for a PARTICIPANT: the
// second is the one that catches "filter DMs by membership" as the fix.
TEST(ChannelDirectory, DirectMessagesAreNeverListed) {
    Fixture f("dm");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");

    auto open_room = f.add_channel(alice, "general");
    auto dm = f.add_dm(alice, carol);

    assert_absent(directory(*f.rooms, "token-bob"), dm);
    assert_absent(directory(*f.rooms, "token-alice"), dm);
    assert_absent(directory(*f.rooms, "token-carol"), dm);
    EXPECT_TRUE(contains(room_ids(directory(*f.rooms, "token-carol")), open_room));
}

// ── 4. category_id cannot name an invisible room ─────────────────────────────
//
// handle_create_room validates only that `parent_id` names an EXISTING room, so
// a channel can be filed under a private channel. Echoing that id back would
// leak the very room the filter above removed.
TEST(ChannelDirectory, CategoryIdNeverNamesARoomTheCallerCannotSee) {
    Fixture f("badparent");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto secret = f.add_channel(alice, "staff-only");
    f.make_private(secret);
    auto child = f.add_channel(alice, "alerts");
    f.file_under(child, secret, 0);

    auto d = directory(*f.rooms, "token-bob");
    auto ids = room_ids(d);
    EXPECT_TRUE(contains(ids, child));
    assert_absent(d, secret);
    for (const auto& e : d.body.at("channels")) {
        if (e.at("room_id") != child) continue;
        EXPECT_FALSE(e.contains("category_id"))
            << "the child kept a category_id naming a channel its viewer cannot see";
    }
}

// ── 5. the ordering carries no count ─────────────────────────────────────────
//
// Three channels in one category at orders 0, 1 and 2, with the middle one
// private. The response must be dense: if the raw sort_order reached the wire,
// or if a placeholder were emitted, the gap at 1 would tell bob exactly how many
// channels were filtered out of his own answer.
TEST(ChannelDirectory, OrderingDoesNotDiscloseWhatWasFiltered) {
    Fixture f("gaps");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto cat = f.add_channel(alice, "Team", room_type::kCategory);
    auto first = f.add_channel(alice, "first");
    auto hidden = f.add_channel(alice, "hidden");
    auto last = f.add_channel(alice, "last");
    f.file_under(first, cat, 0);
    f.file_under(hidden, cat, 1);
    f.file_under(last, cat, 2);
    f.make_private(hidden);

    auto d = directory(*f.rooms, "token-bob");
    assert_absent(d, hidden);
    EXPECT_EQ(room_ids(d), (std::vector<std::string>{cat, first, last}));

    // The same shape a server on which `hidden` never existed would produce.
    // Stated as an explicit key-set assertion so that adding an "order" or a
    // "position" later fails here rather than in production.
    for (const auto& e : d.body.at("channels")) {
        EXPECT_FALSE(e.contains("order"));
        EXPECT_FALSE(e.contains("sort_order"));
        EXPECT_FALSE(e.contains("position"));
        EXPECT_FALSE(e.contains("index"));
    }
}

// Belt and braces on the same property from the other direction: the entry for a
// channel carries no volume or population signal about a channel at all.
TEST(ChannelDirectory, AnEntryCarriesNoReconnaissanceFields) {
    Fixture f("fields");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.store->insert_event(generate_event_id("test"), room, alice,
                          std::string(event_type::kRoomTopic), std::string(""),
                          json{{"topic", "the secret topic"}}.dump(), 1010);

    auto d = directory(*f.rooms, "token-bob");
    ASSERT_EQ(d.body.at("channels").size(), 1u);
    const auto& e = d.body.at("channels")[0];
    EXPECT_EQ(e.at("room_id"), room);
    EXPECT_EQ(e.at("name"), "general");
    EXPECT_EQ(e.at("type"), std::string(room_type::kText));
    EXPECT_FALSE(e.contains("topic"));
    EXPECT_FALSE(e.contains("member_count"));
    EXPECT_FALSE(e.contains("num_joined_members"));
    EXPECT_FALSE(e.contains("creator"));
    EXPECT_EQ(d.raw.find("the secret topic"), std::string::npos);
    for (auto it = e.begin(); it != e.end(); ++it) {
        EXPECT_TRUE(kAllowedEntryKeys.count(it.key()) > 0) << "unexpected field " << it.key();
    }
}

// ── 6. bots and humans get the same answer ───────────────────────────────────
TEST(ChannelDirectory, ABotAndAHumanWithTheSameRolesGetIdenticalAnswers) {
    Fixture f("bots");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto human = f.add_user("human");
    auto bot = f.add_bot("bot_alerts", alice);

    auto cat = f.add_channel(alice, "Team", room_type::kCategory);
    auto open_room = f.add_channel(alice, "general");
    auto voice = f.add_channel(alice, "Lounge", room_type::kVoice);
    auto secret = f.add_channel(alice, "staff-only");
    f.file_under(open_room, cat, 0);
    f.make_private(secret);

    auto human_d = directory(*f.rooms, "token-human");
    auto bot_d = directory(*f.rooms, "token-bot_alerts");
    ASSERT_EQ(bot_d.status, 200);
    assert_absent(bot_d, secret);
    // The membership field is the one thing that legitimately differs, so
    // compare the channel SET rather than the raw bodies.
    EXPECT_EQ(room_ids(human_d), room_ids(bot_d));
    EXPECT_TRUE(contains(room_ids(bot_d), voice));
}

// ── 7. the feature: a caller that is a member of nothing ─────────────────────
//
// The control that matters most. A bot is excluded from auto-join, so on a fresh
// install it holds no membership row anywhere — and if the directory answered
// from membership it would answer "nothing", which is the bug this endpoint
// exists to fix. `joined` reports the truth without gating on it.
TEST(ChannelDirectory, ACallerThatIsAMemberOfNothingStillSeesTheChannels) {
    Fixture f("nonmember");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bot = f.add_bot("bot_alerts", alice);

    auto open_room = f.add_channel(alice, "general");
    ASSERT_FALSE(f.store->is_room_member(open_room, bot));

    auto d = directory(*f.rooms, "token-bot_alerts");
    ASSERT_EQ(d.body.at("channels").size(), 1u);
    EXPECT_EQ(d.body.at("channels")[0].at("room_id"), open_room);
    EXPECT_FALSE(d.body.at("channels")[0].at("joined").get<bool>());

    // And once it is put in, the same entry says so — the field tracks
    // membership and nothing else.
    f.join(open_room, bot);
    auto after = directory(*f.rooms, "token-bot_alerts");
    EXPECT_TRUE(after.body.at("channels")[0].at("joined").get<bool>());
}

// An ORDINARY member holding only kEveryoneDefault sees the public channels.
// Asserting this with an admin would prove nothing: ADMINISTRATOR short-circuits
// every flag, so a gate tightened to MANAGE_CHANNELS would still look green.
TEST(ChannelDirectory, AnOrdinaryMemberSeesThePublicChannels) {
    Fixture f("ordinary");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto a = f.add_channel(alice, "general");
    auto b = f.add_channel(alice, "random");

    auto ids = room_ids(directory(*f.rooms, "token-bob"));
    EXPECT_TRUE(contains(ids, a));
    EXPECT_TRUE(contains(ids, b));
}

// ── 8. categories ────────────────────────────────────────────────────────────
//
// A category the caller cannot VIEW_CHANNEL is still named, matching /sync's
// stub: the sidebar has to draw the container even when its children are hidden,
// and the directory must name the same set of containers or a channel's
// category_id would point at something the caller was never shown. What the
// entry discloses is a name and a position — no timeline, no roster, no counts,
// which is exactly what the stub rule already allows.
TEST(ChannelDirectory, ADeniedCategoryIsStillNamedAsAContainer) {
    Fixture f("category");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto cat = f.add_channel(alice, "Team", room_type::kCategory);
    f.make_private(cat);
    auto child = f.add_channel(alice, "general");
    f.file_under(child, cat, 0);

    auto d = directory(*f.rooms, "token-bob");
    auto ids = room_ids(d);
    EXPECT_TRUE(contains(ids, cat));
    EXPECT_TRUE(contains(ids, child));
    for (const auto& e : d.body.at("channels")) {
        if (e.at("room_id") != cat) continue;
        EXPECT_EQ(e.at("type"), std::string(room_type::kCategory));
        EXPECT_EQ(e.at("name"), "Team");
    }
    // The child names it, because the caller was shown it.
    for (const auto& e : d.body.at("channels")) {
        if (e.at("room_id") != child) continue;
        EXPECT_EQ(e.value("category_id", std::string()), cat);
    }
}

// The exemption is for LISTING and nothing else: a category still refuses to
// hand over its state, so being named in the directory is not a way in. This is
// the invariant that stops the exemption from becoming a hole.
TEST(ChannelDirectory, BeingNamedInTheDirectoryIsNotAccessToTheRoom) {
    Fixture f("noaccess");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto cat = f.add_channel(alice, "Team", room_type::kCategory);
    f.make_private(cat);

    ASSERT_TRUE(contains(room_ids(directory(*f.rooms, "token-bob")), cat));

    httplib::Request req;
    req.path = "/_matrix/client/v3/rooms/" + cat + "/state";
    req.set_header("Authorization", "Bearer token-bob");
    httplib::Response res;
    f.rooms->handle_room_state(req, res);
    EXPECT_EQ(res.status, 403);
}

// ── 9. ordering ──────────────────────────────────────────────────────────────
TEST(ChannelDirectory, ChildrenFollowTheirCategoryInOrder) {
    Fixture f("ordering");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto cat_a = f.add_channel(alice, "A", room_type::kCategory);
    auto cat_b = f.add_channel(alice, "B", room_type::kCategory);
    f.file_under(cat_a, "", 0);
    f.file_under(cat_b, "", 1);

    auto a1 = f.add_channel(alice, "a1");
    auto a2 = f.add_channel(alice, "a2");
    auto b1 = f.add_channel(alice, "b1");
    f.file_under(a1, cat_a, 0);
    f.file_under(a2, cat_a, 1);
    f.file_under(b1, cat_b, 0);

    // Uncategorized, and deliberately created last: it must sort by its order
    // (0, the default) and its room id, not by creation time.
    auto loose = f.add_channel(alice, "loose");

    auto ids = room_ids(directory(*f.rooms, "token-bob"));
    auto pos = [&](const std::string& id) {
        return std::find(ids.begin(), ids.end(), id) - ids.begin();
    };
    EXPECT_EQ(pos(a1), pos(cat_a) + 1);
    EXPECT_EQ(pos(a2), pos(cat_a) + 2);
    EXPECT_EQ(pos(b1), pos(cat_b) + 1);
    EXPECT_LT(pos(cat_a), pos(cat_b));
    EXPECT_TRUE(contains(ids, loose));

    // Total and stable: the same call twice is the same list.
    EXPECT_EQ(ids, room_ids(directory(*f.rooms, "token-bob")));
}

// ── 10. auth ─────────────────────────────────────────────────────────────────
TEST(ChannelDirectory, RequiresAToken) {
    Fixture f("auth");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    f.add_channel(alice, "general");

    EXPECT_EQ(directory(*f.rooms, "").status, 401);
    EXPECT_EQ(directory(*f.rooms, "not-a-real-token").status, 401);
}
