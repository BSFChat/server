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
#include "http/HttpServer.h"
#include "cli/AdminCli.h"
#include "core/DatabaseLock.h"
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
#include <fstream>
#include <sstream>
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

// ── Access gained without a join carries the room's state ───────────────────

namespace {

bool state_has(const SyncResponse& r, const std::string& room_id, std::string_view type) {
    auto it = r.rooms.join.find(room_id);
    if (it == r.rooms.join.end()) return false;
    for (const auto& ev : it->second.state.events) {
        if (ev.type == type) return true;
    }
    return false;
}

void grant_admin(Fixture& f, const std::string& uid) {
    MemberRolesContent c;
    c.role_ids = {std::string(permission::role_id::kEveryone),
                  std::string(permission::role_id::kAdmin)};
    json j;
    to_json(j, c);
    f.store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                              j.dump());
}

} // namespace

TEST(SyncAccessGained, AnOverrideGrantRestatesTheRoomsState) {
    Fixture f("gain-override");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "staff");
    f.join_member(room, bob);
    f.set_override(room, "user:" + bob, 0, permission::kViewChannel);
    auto since = f.token_now(bob);

    f.set_override(room, "user:" + bob, 0, 0);
    auto r = f.sync->handle_sync(bob, since, 0);
    ASSERT_TRUE(r.rooms.join.count(room)) << "the newly visible room is not in the response";
    EXPECT_TRUE(state_has(r, room, event_type::kRoomName)) << "no name: the client shows the id";
    EXPECT_TRUE(state_has(r, room, event_type::kRoomCreate));
    EXPECT_TRUE(state_has(r, room, event_type::kRoomType));

    // Restated once, not on every poll.
    auto again = f.sync->handle_sync(bob, r.next_batch, 0);
    EXPECT_FALSE(state_has(again, room, event_type::kRoomName));
}

TEST(SyncAccessGained, ARoleGrantWithNoRoomEventRestatesTheRoomsState) {
    Fixture f("gain-role");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "staff");
    f.join_member(room, bob);
    f.set_override(room, "user:" + bob, 0, permission::kViewChannel);
    auto since = f.token_now(bob);

    grant_admin(f, bob);  // server_state only: nothing lands on the event stream
    auto r = f.sync->handle_sync(bob, since, 0);
    EXPECT_TRUE(state_has(r, room, event_type::kRoomName));
    EXPECT_TRUE(state_has(r, room, event_type::kRoomCreate));
}

TEST(SyncAccessGained, EveryDeviceIsToldNotOnlyTheFirstToPoll) {
    Fixture f("gain-devices");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "staff");
    f.join_member(room, bob);
    f.set_override(room, "user:" + bob, 0, permission::kViewChannel);
    auto phone = f.sync->handle_sync(bob, "", 0, "phone").next_batch;
    auto desk = f.sync->handle_sync(bob, "", 0, "desk").next_batch;

    grant_admin(f, bob);
    EXPECT_TRUE(state_has(f.sync->handle_sync(bob, phone, 0, "phone"), room,
                          event_type::kRoomName));
    EXPECT_TRUE(state_has(f.sync->handle_sync(bob, desk, 0, "desk"), room,
                          event_type::kRoomName))
        << "the second device lost the room to the first one's poll";
}

TEST(SyncAccessGained, AccessRestoredAfterNoAccessRestatesTheRoom) {
    Fixture f("gain-restore");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "staff");
    f.join_member(room, bob);
    auto since = f.token_now(bob);

    f.set_override(room, "user:" + bob, 0, permission::kViewChannel);
    auto lost = f.sync->handle_sync_full(bob, since, 0);
    ASSERT_EQ(lost.leave.count(room), 1u);
    EXPECT_EQ(lost.leave.at(room).reason, "no_access");

    f.set_override(room, "user:" + bob, 0, 0);
    auto back = f.sync->handle_sync_full(bob, lost.response.next_batch, 0);
    EXPECT_EQ(back.leave.count(room), 0u);
    EXPECT_TRUE(state_has(back.response, room, event_type::kRoomName));
    EXPECT_TRUE(state_has(back.response, room, event_type::kRoomCreate));
}

// ── The forced full presence restatement is owed per device ─────────────────

TEST(SyncPresencePerDevice, EveryDeviceGetsTheFullRestatementAfterAPeerChange) {
    Fixture f("presence-devices");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    f.store->store_access_token("token-alice2", alice, "dev2");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");
    auto room = f.add_channel(alice, "general");
    f.join_member(room, bob);
    PresenceRig rig(f);

    rig.presence.touch(bob);
    rig.presence.touch(carol);  // online, but not alice's peer yet
    f.say(room, bob, "x");
    auto since1 = rig.poll("alice", "")["next_batch"].get<std::string>();
    auto since2 = rig.poll("alice2", "")["next_batch"].get<std::string>();

    f.join_member(room, carol);  // a new peer: new visibility generation
    f.say(room, bob, "y");
    auto first = rig.poll("alice", since1);
    EXPECT_TRUE(presence_senders(first).count(carol));
    auto second = rig.poll("alice2", since2);
    EXPECT_TRUE(presence_senders(second).count(carol))
        << "the first device's poll used up the restatement the second one was owed";
}

// ── A failed pooled read is not "invalid token" ─────────────────────────────

TEST(AuthFastPath, APooledReadErrorFallsBackInsteadOfAnswering401) {
    Fixture f("auth-fallback");
    auto bob = f.add_user("bob");
    ASSERT_GT(f.store->reader_connections_for_test(), 0u);
    f.store->fail_pooled_auth_reads_for_test(true);
    EXPECT_EQ(f.store->get_user_by_token("token-bob"), std::optional<std::string>(bob))
        << "a database blip on the pooled reader was reported as an invalid token";
    EXPECT_EQ(f.store->get_user_by_token("token-nobody"), std::nullopt);
    f.store->fail_pooled_auth_reads_for_test(false);
    EXPECT_EQ(f.store->get_user_by_token("token-bob"), std::optional<std::string>(bob));
    EXPECT_EQ(f.store->get_user_by_token("token-nobody"), std::nullopt);
}

// ── Variable IN lists do not flood the pooled statement cache ───────────────

TEST(StoreStatementCache, InListsOfEveryLengthTakeOnlyAFewSlots) {
    Fixture f("stmt-cache");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    std::vector<std::string> rooms;
    for (int i = 0; i < 40; ++i) rooms.push_back(f.add_channel(alice, "c" + std::to_string(i)));

    const auto before = f.store->cached_reader_statements_for_test();
    for (size_t n = 1; n <= rooms.size(); ++n) {
        std::vector<std::string> some(rooms.begin(), rooms.begin() + static_cast<long>(n));
        auto members = f.store->get_joined_members_of_rooms(some);
        ASSERT_EQ(members, std::vector<std::string>{alice}) << "padding changed the answer";
    }
    // Lengths 1..40 pad to 4, 8, 16, 32, 64.
    EXPECT_LE(f.store->cached_reader_statements_for_test(), before + 5)
        << "one cache slot per IN-list length evicts the hot fixed statements";
}

// ── Initial-sync gate: per account, and garbage since is refused ───────────

TEST(InitialSyncGatePerAccount, OneAccountCannotTakeMoreThanItsShare) {
    InitialSyncGate gate(8, 2);
    auto a1 = gate.enter("@a:test", std::chrono::milliseconds(1000), std::chrono::milliseconds(50));
    auto a2 = gate.enter("@a:test", std::chrono::milliseconds(1000), std::chrono::milliseconds(50));
    ASSERT_TRUE(a1);
    ASSERT_TRUE(a2);
    const auto start = clk::now();
    auto a3 = gate.enter("@a:test", std::chrono::milliseconds(1000), std::chrono::milliseconds(50));
    EXPECT_TRUE(a3.refused()) << "a third concurrent initial sync for one account was admitted";
    EXPECT_FALSE(a3);
    EXPECT_LT(ms_since(start), 900) << "the account limit waits its own patience, not the global";
    // Another account is unaffected.
    auto b1 = gate.enter("@b:test", std::chrono::milliseconds(1000), std::chrono::milliseconds(50));
    EXPECT_TRUE(b1);
    EXPECT_EQ(gate.in_flight(), 3u);
    EXPECT_EQ(gate.in_flight_for("@a:test"), 2u);

    // A freed slot of its own admits the account again.
    a1 = InitialSyncGate::Slot();
    auto a4 = gate.enter("@a:test", std::chrono::milliseconds(1000), std::chrono::milliseconds(50));
    EXPECT_TRUE(a4);
    EXPECT_FALSE(a4.refused());
}

TEST(InitialSyncGatePerAccount, AWaiterIsWokenWhenItsAccountFreesASlot) {
    InitialSyncGate gate(8, 1);
    auto held = gate.enter("@a:test", std::chrono::milliseconds(5000), std::chrono::milliseconds(5000));
    ASSERT_TRUE(held);
    std::thread releaser([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        held = InitialSyncGate::Slot();
    });
    const auto start = clk::now();
    auto next = gate.enter("@a:test", std::chrono::milliseconds(5000), std::chrono::milliseconds(5000));
    releaser.join();
    EXPECT_TRUE(next);
    EXPECT_LT(ms_since(start), 2000);
}

TEST(SyncSinceValidation, AGarbageSinceIs400NotAFullInitialSync) {
    Fixture f("since-garbage");
    auto alice = f.add_user("alice", {std::string(permission::role_id::kAdmin)});
    f.add_channel(alice, "general");
    auto bob = f.add_user("bob");
    SyncHandler handler(*f.store, *f.sync, f.config);

    auto poll = [&](const std::string& token, const std::string& since) {
        httplib::Request req;
        req.path = "/_matrix/client/v3/sync";
        req.params.emplace("since", since);
        req.params.emplace("timeout", "0");
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        handler.handle_sync(req, res);
        return res;
    };
    for (const auto& junk : {"banana", "t_", "t_zzzz", "s", "s-1"}) {
        auto res = poll("token-alice", junk);
        EXPECT_EQ(res.status, 400) << junk;
        EXPECT_EQ(json::parse(res.body).value("errcode", ""), "M_INVALID_PARAM") << junk;
    }
    // Another account's token is not this account's position either.
    auto bobs = f.token_now(bob);
    EXPECT_EQ(poll("token-alice", bobs).status, 400);

    // A real token, and the legacy numeric form, still work.
    auto ok = poll("token-alice", f.token_now(alice));
    EXPECT_TRUE(ok.status == -1 || ok.status == 200) << ok.status << " " << ok.body;
    auto legacy = poll("token-alice", "s" + std::to_string(f.store->get_current_stream_position()));
    EXPECT_TRUE(legacy.status == -1 || legacy.status == 200) << legacy.status;
}

// ── A second server on a taken port fails instead of sharing it ─────────────

TEST(HttpServerBind, ASecondServerOnTheSamePortFailsLoudly) {
    Config cfg = Config::defaults();
    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    HttpServer first(cfg);
    ASSERT_NO_THROW(first.bind());
    ASSERT_GT(first.port(), 0);

    cfg.port = first.port();
    HttpServer second(cfg);
    EXPECT_THROW(second.bind(), std::runtime_error)
        << "SO_REUSEPORT let a second server silently share the first one's port";
}

// ── The admin CLI holds the database lock; the server waits out a probe ─────

TEST(DatabaseLockAudit3, TheAdminCliHoldsTheLockForItsWholeRun) {
    const auto db = temp_db_path("cli-lock");
    const auto toml = db + ".toml";
    remove_db(db);
    std::filesystem::remove(DatabaseLock::lock_path_for(db));
    std::ofstream(toml) << "[server]\nname = \"test\"\nport = 18449\n"
                        << "[database]\npath = \"" << db << "\"\n";

    bool held_during_run = false;
    std::ostringstream out;
    const int code = run_admin_cli({"list-users", "--config", toml}, out,
                                   [&](const std::string&, int) {
                                       // Runs inside the command, after the lock check.
                                       held_during_run = DatabaseLock::held_elsewhere(db);
                                       return false;
                                   });
    EXPECT_EQ(code, 0) << out.str();
    EXPECT_TRUE(held_during_run) << "the CLI checked the lock and let go of it";
    EXPECT_FALSE(DatabaseLock::held_elsewhere(db)) << "and released it when done";

    // A server's lock refuses the CLI outright.
    auto server = DatabaseLock::acquire(db);
    ASSERT_TRUE(server);
    std::ostringstream refused;
    EXPECT_EQ(run_admin_cli({"list-users", "--config", toml}, refused,
                            [](const std::string&, int) { return false; }),
              1);
    server.reset();

    remove_db(db);
    std::filesystem::remove(toml);
    std::filesystem::remove(DatabaseLock::lock_path_for(db));
}

TEST(DatabaseLockAudit3, AServerStartingDuringABriefHoldWaitsInsteadOfFailing) {
    const auto db = temp_db_path("lock-patience");
    std::filesystem::remove(DatabaseLock::lock_path_for(db));
    auto brief = DatabaseLock::acquire(db);
    ASSERT_TRUE(brief);
    std::thread release([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        brief.reset();
    });
    std::unique_ptr<DatabaseLock> server;
    EXPECT_NO_THROW(server = DatabaseLock::acquire(db, std::chrono::seconds(3)));
    release.join();
    EXPECT_TRUE(server);
    server.reset();
    std::filesystem::remove(DatabaseLock::lock_path_for(db));
}
