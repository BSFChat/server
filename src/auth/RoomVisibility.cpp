#include "auth/RoomVisibility.h"

#include "auth/Permissions.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

namespace bsfchat {

bool is_category_room(SqliteStore& store, const std::string& room_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kRoomType), "");
    if (!ev) return false;
    return ev->content.data.value("type", "") == "category";
}

bool can_view_room(SqliteStore& store, PermissionsEngine& perms,
                   const std::string& user_id, const std::string& room_id) {
    // VIEW_CHANNEL first, category second — the order is a query count, not a
    // preference. Both terms cost one read under the store's global mutex, and
    // the permission check passes for almost every room, so leading with it
    // means the category lookup only runs for the handful that were denied.
    // The other order pays for both on every room in the list.
    return perms.can(user_id, room_id, permission::kViewChannel) ||
           is_category_room(store, room_id);
}

std::vector<std::string> visible_joined_rooms(SqliteStore& store, PermissionsEngine& perms,
                                              const std::string& user_id) {
    auto rooms = store.get_joined_rooms(user_id);
    std::vector<std::string> visible;
    visible.reserve(rooms.size());
    for (auto& room_id : rooms) {
        if (!can_view_room(store, perms, user_id, room_id)) continue;
        visible.push_back(std::move(room_id));
    }
    return visible;
}

} // namespace bsfchat
