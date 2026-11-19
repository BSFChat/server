// Audit 3 (2026-11-19), the sync / ops half of the server findings: access
// gained mid-session, voice state and the visibility generation, per-device
// presence restatement, the auth fast path, the initial-sync gate, typing from
// ignored users. Each block names the finding it pins.
//
// File databases, as in test_sync_fanout.cpp: the reader pool only exists for
// an on-disk WAL database.

#include <gtest/gtest.h>

#include "api/PresenceHandler.h"
#include "api/SyncHandler.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "store/SqliteStore.h"
#include "sync/InitialSyncGate.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <regex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

using clk = std::chrono::steady_clock;

int64_t ms_since(clk::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - start).count();
}

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-audit3b-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
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
    int64_t ts = 1000;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);

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
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 4));
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

    // A message, committed and announced the way EventHandler does it.
    void say(const std::string& room_id, const std::string& sender, const std::string& body) {
        store->insert_event(generate_event_id("test"), room_id, sender,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", body}}.dump(), ts++);
        sync->notify_new_event();
    }

    std::string token_now(const std::string& user_id) {
        return sync->handle_sync(user_id, "", 0).next_batch;
    }
};

bool timeline_has(const SyncResponse& r, const std::string& room_id, const std::string& body) {
    auto it = r.rooms.join.find(room_id);
    if (it == r.rooms.join.end()) return false;
    for (const auto& ev : it->second.timeline.events) {
        if (ev.content.data.value("body", "") == body) return true;
    }
    return false;
}

} // namespace

// ── The reader pool ─────────────────────────────────────────────────────────

// ── Presence rig ──────────────────────────────────────────────────────────

namespace {

struct PresenceRig {
    Fixture& f;
    PresenceHandler presence;
    SyncHandler handler;

    explicit PresenceRig(Fixture& fx)
        : f(fx), presence(*fx.store, *fx.sync, fx.config), handler(*fx.store, *fx.sync, fx.config) {
        handler.set_presence_handler(&presence);
    }

    // One /sync through the handler; `since` empty for an initial sync.
    json poll(const std::string& localpart, const std::string& since, int timeout_ms = 0) {
        httplib::Request req;
        req.path = "/_matrix/client/v3/sync";
        if (!since.empty()) req.params.emplace("since", since);
        req.params.emplace("timeout", std::to_string(timeout_ms));
        req.set_header("Authorization", "Bearer token-" + localpart);
        httplib::Response res;
        handler.handle_sync(req, res);
        EXPECT_TRUE(res.status == -1 || res.status == 200) << res.status << " " << res.body;
        return json::parse(res.body);
    }

    void put(const std::string& localpart, const std::string& state) {
        static const std::regex re(R"(/_matrix/client/v3/presence/([^/]+)/status)");
        const std::string uid = "@" + localpart + ":test";
        httplib::Request req;
        req.path = "/_matrix/client/v3/presence/" + uid + "/status";
        req.body = json{{"presence", state}}.dump();
        req.set_header("Authorization", "Bearer token-" + localpart);
        ASSERT_TRUE(std::regex_match(req.path, req.matches, re));
        httplib::Response res;
        presence.handle_put_presence(req, res);
        ASSERT_TRUE(res.status == -1 || res.status == 200) << res.status << " " << res.body;
    }
};

std::set<std::string> presence_senders(const json& body) {
    std::set<std::string> out;
    for (const auto& ev : body.value("presence", json::object()).value("events", json::array())) {
        out.insert(ev.value("sender", ""));
    }
    return out;
}

std::string presence_of(const json& body, const std::string& uid) {
    for (const auto& ev : body.value("presence", json::object()).value("events", json::array())) {
        if (ev.value("sender", "") == uid) return ev["content"].value("presence", "");
    }
    return "";
}

} // namespace

// ── Voice/call state does not move the visibility generation ────────────────

TEST(VisibilityGeneration, InertStateDoesNotMoveItAndVisibilityStateDoes) {
    Fixture f("generation-inert");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);

    auto moved = [&](auto&& write) {
        const auto before = f.store->visibility_generation();
        write();
        return f.store->visibility_generation() != before;
    };
    EXPECT_FALSE(moved([&] {
        f.state(room, bob, event_type::kCallMember, bob,
                json{{"memberships", json::array({json{{"call_id", ""}}})}});
    })) << "a push-to-talk press must not invalidate every visibility cache";
    EXPECT_FALSE(moved([&] { f.state(room, alice, event_type::kRoomVoice, "", json{{"x", 1}}); }));
    EXPECT_FALSE(moved([&] { f.state(room, alice, event_type::kRoomTopic, "", json{{"topic", "t"}}); }));
    EXPECT_FALSE(moved([&] { f.state(room, alice, event_type::kRoomName, "", json{{"name", "n"}}); }));
    EXPECT_FALSE(moved([&] {
        f.state(room, alice, event_type::kRoomPinnedEvents, "", json{{"pinned", json::array()}});
    }));

    // A message, and redacting one, change nobody's visibility either.
    const std::string msg = generate_event_id("test");
    f.store->insert_event(msg, room, alice, std::string(event_type::kRoomMessage), std::nullopt,
                          json{{"msgtype", "m.text"}, {"body", "hi"}}.dump(), f.ts++);
    EXPECT_FALSE(moved([&] { f.store->redact_event(msg, alice); }));

    // ...while the things that do decide visibility still move it.
    EXPECT_TRUE(moved([&] { f.set_override(room, "user:" + bob, 0, permission::kViewChannel); }));
    EXPECT_TRUE(moved([&] {
        f.state(room, bob, event_type::kRoomMember, bob, json{{"membership", "join"}});
    }));
    EXPECT_TRUE(moved([&] { f.state(room, alice, event_type::kRoomType, "", json{{"type", "text"}}); }));
    const std::string ov = generate_event_id("test");
    f.store->insert_event(ov, room, alice, std::string(event_type::kChannelPermissions),
                          std::string("user:" + bob), json{{"allow", 0}, {"deny", 0}}.dump(),
                          f.ts++);
    EXPECT_TRUE(moved([&] { f.store->redact_event(ov, alice); }))
        << "redacting an override can restore access";
}

TEST(VisibilityGeneration, AVoiceStateChangeDoesNotForceAFullPresenceRestatement) {
    Fixture f("generation-voice-presence");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    PresenceRig rig(f);

    rig.presence.touch(bob);
    f.say(room, bob, "move the head past the stamps");
    auto since = rig.poll("alice", "")["next_batch"].get<std::string>();

    // bob joins the call: m.call.member, a state event, wakes alice's poll.
    f.state(room, bob, event_type::kCallMember, bob,
            json{{"memberships", json::array({json{{"call_id", ""}}})}});
    auto woken = rig.poll("alice", since);
    ASSERT_TRUE(woken["rooms"]["join"].contains(room));
    EXPECT_EQ(presence_senders(woken), std::set<std::string>{alice})
        << "voice state forced a full presence restatement (visibility generation bumped)";
}
