#include "auth/AutoJoin.h"

#include "core/Config.h"
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
void join_user_to_room(SqliteStore& store, SyncEngine& sync_engine,
                        const Config& config, const std::string& room_id,
                        const std::string& user_id) {
    // Skip if already joined
    if (store.is_room_member(room_id, user_id)) return;

    store.set_membership(room_id, user_id, std::string(membership::kJoin));

    nlohmann::json content = {{"membership", membership::kJoin}};
    auto event_id = generate_event_id(config.server_name);
    store.insert_event(event_id, room_id, user_id,
                        std::string(event_type::kRoomMember),
                        user_id, content.dump(), now_ms());
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

void backfill_auto_join(SqliteStore& store, SyncEngine& sync_engine,
                         const Config& config) {
    // First, convert all non-category rooms to public.
    // Channels were historically created as private; this makes them accessible
    // to everyone as the Discord-like model expects.
    auto all_rooms = store.list_all_non_category_rooms();
    for (const auto& room_id : all_rooms) {
        auto jr = store.get_state_event(room_id,
            std::string(event_type::kRoomJoinRules), "");
        std::string current_rule = jr ? jr->content.data.value("join_rule", "") : "";
        if (current_rule != "public") {
            auto event_id = generate_event_id(config.server_name);
            nlohmann::json content = {{"join_rule", "public"}};
            store.insert_event(event_id, room_id, "@server:" + config.server_name,
                std::string(event_type::kRoomJoinRules), "",
                content.dump(),
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
        }
    }

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
