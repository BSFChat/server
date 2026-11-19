// POST /createRoom validates its whole body before it writes anything
// (audit 2026-11-15, R-4).
//
// It used to create the room, emit create/join/join-rules/name/type, and only
// THEN read parent_id with get<std::string>() and sort_order with
// value("sort_order", 0) — both of which throw on the wrong JSON type. So
// {"parent_id": 5} or {"sort_order": "1"} answered 500 and left a committed,
// half-built public channel behind (which backfill_auto_join then force-joined
// everyone into), and a parent_id naming no room did the same with a 400.

#include <gtest/gtest.h>

#include "api/RoomHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-createroom-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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
    int64_t ts = 1000;

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
        content.roles.push_back(role(permission::role_id::kEveryone, 0,
                                     permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
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

    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomCreate, "", json{{"creator", creator}});
        state(room_id, creator, event_type::kRoomMember, creator, json{{"membership", "join"}});
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        state(room_id, creator, event_type::kRoomType, "", json{{"type", "text"}});
        state(room_id, creator, event_type::kRoomJoinRules, "",
              json{{"join_rule", join_rule::kPublic}});
        return room_id;
    }

    void state(const std::string& room_id, const std::string& sender,
               std::string_view type, const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ts++);
        sync->notify_new_event();
    }

    void join_member(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        state(room_id, user_id, event_type::kRoomMember, user_id, json{{"membership", "join"}});
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

    httplib::Response call(void (RoomHandler::*method)(const httplib::Request&,
                                                       httplib::Response&),
                           const std::string& path, const std::string& token,
                           const std::string& body = "") {
        httplib::Request req;
        req.path = path;
        req.body = body;
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        ((*rooms).*method)(req, res);
        return res;
    }

    httplib::Response leave(const std::string& room_id, const std::string& token) {
        return call(&RoomHandler::handle_leave,
                    "/_matrix/client/v3/rooms/" + room_id + "/leave", token, "{}");
    }

    httplib::Response kick(const std::string& room_id, const std::string& token,
                           const std::string& target) {
        return call(&RoomHandler::handle_kick, "/_matrix/client/v3/rooms/" + room_id + "/kick",
                    token, json{{"user_id", target}}.dump());
    }

    httplib::Response delete_room(const std::string& room_id, const std::string& token) {
        return call(&RoomHandler::handle_delete_room, "/_matrix/client/v3/rooms/" + room_id,
                    token);
    }

    // A token at the current head, minted the way the client gets one.
    std::string token_now(const std::string& user_id) {
        return sync->handle_sync(user_id, "", 0).next_batch;
    }
};

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

} // namespace

namespace {

httplib::Response create(Fixture& f, const std::string& token, const std::string& body) {
    return f.call(&RoomHandler::handle_create_room, "/_matrix/client/v3/createRoom", token,
                  body);
}

} // namespace

TEST(CreateRoomValidation, WrongTypesAreRefusedBeforeAnythingIsWritten) {
    Fixture f("types");
    f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto parent = f.add_channel("@alice:test", "parent");
    const auto rooms_before = f.store->list_room_directory_rows().size();
    const auto head_before = f.store->get_current_stream_position();

    const std::vector<json> bad = {
        json{{"name", "x"}, {"parent_id", 5}},
        json{{"name", "x"}, {"parent_id", nullptr}},
        json{{"name", "x"}, {"parent_id", parent}, {"sort_order", "1"}},
        json{{"name", "x"}, {"sort_order", 1.5}},
        json{{"name", 7}},
        json{{"topic", json::array()}},
        json{{"name", "x"}, {"visibility", 1}},
        json{{"name", "x"}, {"visibility", nullptr}},
        json{{"name", "x"}, {"is_category", "yes"}},
        json{{"name", "x"}, {"voice", 1}},
        json{{"name", "x"}, {"voice", true}, {"max_voice_participants", "10"}},
        json{{"name", "x"}, {"invite", "@bob:test"}},
        json{{"name", "x"}, {"invite", json::array({1})}},
        json{{"name", "x"}, {"is_direct", "true"}},
        json::array({1, 2}),
    };
    for (const auto& body : bad) {
        auto res = create(f, "token-alice", body.dump());
        EXPECT_EQ(res.status, 400) << body.dump();
    }
    EXPECT_EQ(f.store->list_room_directory_rows().size(), rooms_before)
        << "a refused body still created a room";
    EXPECT_EQ(f.store->get_current_stream_position(), head_before)
        << "a refused body still wrote events";
}

TEST(CreateRoomValidation, AMissingParentIsRefusedBeforeTheRoomExists) {
    Fixture f("no-parent");
    f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    const auto rooms_before = f.store->list_room_directory_rows().size();

    auto res = create(f, "token-alice",
                      json{{"name", "orphan"}, {"parent_id", "!nowhere:test"}}.dump());
    // 404 M_NOT_FOUND, the same answer the other two filing routes give
    // (audit 3); it was 400 here.
    EXPECT_EQ(res.status, 404);
    EXPECT_EQ(f.store->list_room_directory_rows().size(), rooms_before)
        << "the half-built channel is back";
}

TEST(CreateRoomValidation, AWellFormedBodyStillWorks) {
    Fixture f("ok");
    f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto parent = f.add_channel("@alice:test", "parent");
    // A parent must be a category (audit 2-2026-11-18 S2-6).
    f.state(parent, "@alice:test", event_type::kRoomType, "", json{{"type", "category"}});

    auto res = create(f, "token-alice",
                      json{{"name", "child"}, {"parent_id", parent}, {"sort_order", 3},
                           {"topic", nullptr}, {"visibility", "public"}}
                          .dump());
    ASSERT_TRUE(IsOk(res)) << res.body;
    auto room_id = json::parse(res.body).at("room_id").get<std::string>();
    auto category = f.store->get_state_event(room_id, std::string(event_type::kRoomCategory), "");
    ASSERT_TRUE(category.has_value());
    EXPECT_EQ(category->content.data.value("parent_id", ""), parent);
    EXPECT_EQ(category->content.data.value("order", -1), 3);
}
