#include "core/FirstRun.h"

#include "core/Config.h"
#include "core/Logger.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>

#include <chrono>
#include <string>

namespace bsfchat {

namespace {

using json = nlohmann::json;

// Written whatever the outcome, so the "is this server new?" question is asked
// exactly once in the lifetime of a deployment. See FirstRun.h.
constexpr const char* kMarker = "bootstrap.default_channels";

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// The synthetic actor the server already uses for state it writes on its own
// behalf (RoleBootstrap's server-scoped writes, publicize_legacy_channels).
// PermissionsEngine resolves it to kAllFlags and it never holds a membership
// row, so it does not appear in any member list and cannot be an orphan
// membership. Nothing authorises on `rooms.creator` — it is displayed by the
// admin CLI and read by one historical migration — so a non-account creator is
// a cosmetic fact, not a permission one.
std::string server_actor(const Config& config) {
    return "@server:" + config.server_name;
}

void emit(SqliteStore& store, const Config& config, const std::string& room_id,
          std::string_view type, const std::string& state_key, const json& content) {
    // Bare insert_event rather than insert_event_vetted: every event written
    // here is composed from string literals in this file, so there is no
    // caller-supplied content and no media reference for the vetting pass to
    // find.
    store.insert_event(generate_event_id(config.server_name), room_id,
                       server_actor(config), std::string(type), state_key,
                       content.dump(), now_ms());
}

// One channel, shaped exactly as RoomHandler::handle_create_room shapes one.
// Deliberately a copy of that event sequence rather than a call into it: the
// handler is an HTTP endpoint that authenticates, rate-limits and authorises a
// human, and none of those have an answer at boot with no users in the
// database. What has to stay in step is the STATE a channel carries, which is
// the list below — if a channel ever grows a new mandatory state event, it
// belongs in both places.
std::string create_channel(SqliteStore& store, const Config& config,
                           const std::string& name, const std::string& topic,
                           bool voice) {
    const auto room_id = generate_room_id(config.server_name);
    const auto actor = server_actor(config);

    store.create_room(room_id, actor, /*is_direct=*/false);

    emit(store, config, room_id, event_type::kRoomCreate, "",
         json{{"creator", actor}, {"room_version", "10"}});

    // Public, like every channel the client creates. This is also what puts the
    // room in list_public_rooms(), which is what auto-join — on this boot, and
    // for every account registered afterwards — walks.
    emit(store, config, room_id, event_type::kRoomJoinRules, "",
         json{{"join_rule", std::string(join_rule::kPublic)}});

    emit(store, config, room_id, event_type::kRoomName, "", json{{"name", name}});

    if (!topic.empty()) {
        emit(store, config, room_id, event_type::kRoomTopic, "", json{{"topic", topic}});
    }

    if (voice) {
        VoiceChannelContent vc;
        vc.enabled = true;
        vc.max_participants = 0;
        json vj;
        to_json(vj, vc);
        emit(store, config, room_id, event_type::kRoomVoice, "", vj);
    }

    emit(store, config, room_id, event_type::kRoomType, "",
         json{{"type", std::string(voice ? room_type::kVoice : room_type::kText)}});

    return room_id;
}

} // namespace

void bootstrap_default_channels(SqliteStore& store, SyncEngine& sync_engine,
                                const Config& config) {
    auto log = get_logger();

    // The decision is recorded even when the operator has the feature switched
    // off. Otherwise turning it on years later, on a server that had by then
    // been emptied, would create channels on what is plainly not a new
    // deployment — the switch is about what a NEW server gets, and this keeps
    // it that way.
    if (store.get_meta(kMarker)) return;

    if (!config.create_default_channels) {
        store.set_meta(kMarker, "disabled");
        return;
    }

    if (store.has_any_room()) {
        store.set_meta(kMarker, "skipped-existing-rooms");
        return;
    }

    // The topic is the only prose a first user is handed, so it says what the
    // server is rather than how to drive the client: the affordances it would
    // otherwise point at differ between the desktop and phone shells, and a
    // topic that names a button the reader does not have is worse than no
    // topic.
    create_channel(store, config, "general",
                   "Welcome to " + config.server_name +
                       ". This channel was created automatically when the server "
                       "first started — rename it, add more, or delete it.",
                   /*voice=*/false);
    create_channel(store, config, "General Voice", "", /*voice=*/true);

    store.set_meta(kMarker, "created");
    log->info("First run: created default channels (#general, General Voice). "
              "This will not run again.");

    // Callers run backfill_auto_join immediately after this, which joins every
    // existing account and wakes sync itself. The notify here is for the case
    // where it does not — a server with no users has nobody to wake, and a
    // future caller that skips the backfill should still not leave a connected
    // client waiting out its poll before it sees the channels.
    sync_engine.notify_new_event();
}

} // namespace bsfchat
