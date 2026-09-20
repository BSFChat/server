#include "auth/RoomVisibility.h"

#include "auth/Permissions.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <algorithm>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

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

namespace {

// One row plus the ordering key that never leaves this file. See the header:
// publishing sort_order would publish the gaps in it, and the gaps are the
// channels this caller was not allowed to see.
struct Candidate {
    ChannelDirectoryEntry entry;
    std::string parent_id;   // as stored, before it is checked against the visible set
    int sort_order = 0;
};

bool before(const Candidate& a, const Candidate& b) {
    return std::tie(a.sort_order, a.entry.room_id) < std::tie(b.sort_order, b.entry.room_id);
}

} // namespace

std::vector<ChannelDirectoryEntry> visible_channel_directory(SqliteStore& store,
                                                             PermissionsEngine& perms,
                                                             const std::string& user_id) {
    // One query for the room rows and one for the caller's memberships. Asking
    // the store per room instead would put the directory's cost on the store
    // mutex rather than on this loop.
    auto rows = store.list_room_directory_rows();
    const auto joined_list = store.get_joined_rooms(user_id);
    const std::unordered_set<std::string> joined(joined_list.begin(), joined_list.end());

    // THE FILTER. Everything below this loop is presentation: a room that does
    // not pass here never becomes a candidate, so no later step can put it back
    // and none of them has to remember not to.
    //
    // Note what is NOT consulted: membership. `joined` is read for the entry's
    // own field afterwards and never here — on this server every account is
    // force-joined into every channel including the private ones, so filtering
    // on it would hand the caller the complete list of what is hidden from
    // them. See docs/membership-vs-visibility.md.
    std::vector<Candidate> candidates;
    candidates.reserve(rows.size());
    for (auto& row : rows) {
        if (!can_view_room(store, perms, user_id, row.room_id)) continue;
        Candidate c;
        c.entry.room_id = row.room_id;
        c.entry.name = std::move(row.name);
        c.entry.type = row.type;
        c.entry.joined = joined.count(row.room_id) > 0;
        c.parent_id = std::move(row.parent_id);
        c.sort_order = row.sort_order;
        candidates.push_back(std::move(c));
    }

    // Which of the candidates are categories, i.e. which parents are allowed to
    // resolve. Built from the candidate set rather than from the store, so a
    // parent that was filtered out cannot be named by a child that was not:
    // create_room accepts ANY existing room id as `parent_id` and only
    // handle_move_channel checks that it is a category, so a channel really can
    // carry a parent that is a private channel, and echoing that id back would
    // leak exactly the room this endpoint spent the loop above hiding.
    std::unordered_set<std::string> visible_categories;
    for (const auto& c : candidates) {
        if (c.entry.type == room_type::kCategory) visible_categories.insert(c.entry.room_id);
    }

    // A category is never filed under a category: one level, so the flatten
    // below terminates and a parent cycle cannot be expressed.
    for (auto& c : candidates) {
        if (c.entry.type == room_type::kCategory) continue;
        if (visible_categories.count(c.parent_id) == 0) continue;
        c.entry.category_id = c.parent_id;
    }

    std::vector<Candidate> top_level;
    std::unordered_map<std::string, std::vector<Candidate>> children;
    for (auto& c : candidates) {
        if (c.entry.category_id.empty()) {
            top_level.push_back(std::move(c));
        } else {
            children[c.entry.category_id].push_back(std::move(c));
        }
    }

    std::sort(top_level.begin(), top_level.end(), before);
    for (auto& [_, kids] : children) std::sort(kids.begin(), kids.end(), before);

    std::vector<ChannelDirectoryEntry> out;
    out.reserve(candidates.size());
    for (auto& c : top_level) {
        const bool is_category = c.entry.type == room_type::kCategory;
        const std::string room_id = c.entry.room_id;
        out.push_back(std::move(c.entry));
        if (!is_category) continue;
        auto kids = children.find(room_id);
        if (kids == children.end()) continue;
        for (auto& k : kids->second) out.push_back(std::move(k.entry));
    }
    return out;
}

} // namespace bsfchat
