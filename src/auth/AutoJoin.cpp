#include "auth/AutoJoin.h"

#include "core/Config.h"
#include "core/Logger.h"
#include "identity/Nickname.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>

#include <nlohmann/json.hpp>
#include <chrono>

namespace bsfchat {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Add a user to a single room: update membership + emit m.room.member state event.
// Also marks all pre-existing content as read (so auto-joined users don't see a
// wall of "unread" history they were never around for).
void join_user_to_room(SqliteStore& store, SyncEngine& sync_engine,
                        const Config& config, const std::string& room_id,
                        const std::string& user_id) {
    // Any membership row at all means a decision about this user and this
    // room has already been taken: `join` means they are in, `leave` means
    // they were kicked or chose to go, `ban` and `invite` are equally
    // deliberate. Only a user with NO row has never been considered, and
    // those are the ones auto-join exists for.
    //
    // This used to test is_room_member(), which is `membership = 'join'`
    // only — so a `leave` row read as "not joined yet" and got force-joined.
    // backfill_auto_join runs unconditionally at every boot, so a kick was
    // silently undone by the next restart or deploy, and a user who
    // deliberately left a channel was put back into it the same way. The
    // moderator got no indication either time.
    if (store.find_membership(room_id, user_id).has_value()) return;

    // A server-wide ban wins over every force-join in the server.
    //
    // Placed HERE, at the one function all three auto-join sweeps funnel through
    // (auto_join_public_rooms on registration, auto_join_all_users on channel
    // creation, backfill_auto_join at boot), rather than in each caller. Auto-join
    // is what made the client's ban loop not merely incomplete but self-undoing:
    // creating any public channel force-joined EVERY user on the server into it,
    // banned ones included, so a banned account was silently re-admitted by the
    // next channel anybody made — and the moderator had no way to know.
    if (store.is_server_banned(user_id)) return;

    // Snapshot current max position BEFORE writing the join event — this is the
    // point up to which we consider everything "already read" for this user.
    int64_t mark_pos = store.get_room_max_stream_position(room_id);

    store.set_membership(room_id, user_id, std::string(membership::kJoin));

    // Include the user's current display name + avatar in the member event
    // so clients can render messages with a human-readable name from the
    // very first sync, rather than falling back to the raw @user:host id.
    //
    // Via member_event_content, so the name is the user's NICKNAME where they have
    // one. Without that, every channel created after a nickname was set would
    // force-join its members under their global names and quietly undo it.
    auto content = member_event_content(store, user_id, std::string(membership::kJoin));
    auto event_id = generate_event_id(config.server_name);
    store.insert_event(event_id, room_id, user_id,
                        std::string(event_type::kRoomMember),
                        user_id, content.dump(), now_ms());

    store.set_read_marker(user_id, room_id, mark_pos);
}

} // namespace

void auto_join_public_rooms(SqliteStore& store, SyncEngine& sync_engine,
                             const Config& config, const std::string& user_id) {
    auto public_rooms = store.list_public_rooms();
    if (public_rooms.empty()) return;

    for (const auto& room_id : public_rooms) {
        join_user_to_room(store, sync_engine, config, room_id, user_id);
    }
    // Single notify after all events inserted — wakes all syncs
    sync_engine.notify_new_event();
}

void auto_join_all_users(SqliteStore& store, SyncEngine& sync_engine,
                          const Config& config, const std::string& room_id,
                          const std::string& skip_user_id) {
    auto users = store.list_all_users();
    if (users.empty()) return;

    bool any = false;
    for (const auto& user_id : users) {
        if (user_id == skip_user_id) continue;
        join_user_to_room(store, sync_engine, config, room_id, user_id);
        any = true;
    }
    if (any) sync_engine.notify_new_event();
}

namespace {

// Marker recorded once the historical "make legacy channels public" migration
// has run. A fresh database gets this pre-set by schema migration v1.
constexpr const char* kPublicizeMarker = "migration.publicize_legacy_channels";

void publicize_legacy_channels(SqliteStore& store, const Config& config) {
    // ONE-TIME historical migration, not a boot-time sweep.
    //
    // This used to run on every Server::start(), walking every non-category
    // room and rewriting any non-public join_rule to "public" as
    // @server:<name>. Both DM rooms (created with visibility=private) and
    // deliberately-private channels are non-category, so both were swept up:
    // every restart re-publicized every DM on the instance and silently
    // reverted admins' private-channel settings. It now runs at most once per
    // database, and only over rooms that genuinely predate the Discord-like
    // channel model.
    if (store.get_meta(kPublicizeMarker)) return;

    // Only rooms with no bsfchat.room.type state event qualify: every room
    // created since the Discord-like model landed carries one, so a private
    // room with a type event was made private on purpose. list_legacy_untyped_rooms
    // additionally excludes DMs.
    auto legacy_rooms = store.list_legacy_untyped_rooms();

    int converted = 0;
    for (const auto& room_id : legacy_rooms) {
        auto jr = store.get_state_event(room_id,
            std::string(event_type::kRoomJoinRules), "");
        std::string current_rule = jr ? jr->content.data.value("join_rule", "") : "";
        if (current_rule == "public") continue;

        auto event_id = generate_event_id(config.server_name);
        nlohmann::json content = {{"join_rule", "public"}};
        store.insert_event(event_id, room_id, "@server:" + config.server_name,
            std::string(event_type::kRoomJoinRules), "",
            content.dump(), now_ms());
        ++converted;
    }

    store.set_meta(kPublicizeMarker, "applied");
    if (converted > 0) {
        get_logger()->info(
            "One-time migration: made {} legacy channel(s) public. This will not run again.",
            converted);
    }
}

} // namespace

void backfill_auto_join(SqliteStore& store, SyncEngine& sync_engine,
                         const Config& config) {
    publicize_legacy_channels(store, config);

    // list_public_rooms() excludes categories AND direct rooms, so a DM can
    // never be force-joined here regardless of what join_rules events it
    // carries.
    auto rooms = store.list_public_rooms();
    auto users = store.list_all_users();
    if (rooms.empty() || users.empty()) return;

    int joins = 0;
    for (const auto& room_id : rooms) {
        for (const auto& user_id : users) {
            if (!store.is_room_member(room_id, user_id)) {
                join_user_to_room(store, sync_engine, config, room_id, user_id);
                ++joins;
            }
        }
    }
    if (joins > 0) sync_engine.notify_new_event();
}

} // namespace bsfchat
