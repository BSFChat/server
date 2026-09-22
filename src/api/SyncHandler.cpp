#include "api/SyncHandler.h"
#include "api/TypingHandler.h"
#include "api/PresenceHandler.h"
#include "auth/Permissions.h"
#include "auth/RoomVisibility.h"
#include "core/Config.h"
#include "http/JsonIo.h"
#include "http/Middleware.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <algorithm>
#include <optional>
#include <set>

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

namespace bsfchat {

using json = nlohmann::json;

SyncHandler::SyncHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void SyncHandler::handle_sync(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    std::string since;
    if (req.has_param("since")) since = req.get_param_value("since");

    int timeout = limits::kDefaultSyncTimeoutMs;
    if (req.has_param("timeout")) {
        // Unguarded std::stoi threw straight out of the handler on any
        // malformed query param (`?timeout=abc`, `?timeout=99999999999999`).
        try {
            timeout = std::stoi(req.get_param_value("timeout"));
        } catch (const std::exception&) {
            timeout = limits::kDefaultSyncTimeoutMs;
        }
        timeout = std::clamp(timeout, 0, limits::kMaxSyncTimeoutMs);
    }

    // Only an incremental sync with a timeout can park; an initial sync and a
    // timeout=0 poll return at once and need no slot. Over the per-account cap
    // the poll is answered immediately instead of parked — see
    // sync/ParkedSyncGate.h for why that and not a 429. The slot lives until
    // this function returns, i.e. for exactly as long as the worker is held.
    ParkedSyncGate::Slot parked_slot;
    if (!since.empty() && timeout > 0) {
        parked_slot = parked_.try_park(*user_id);
        if (!parked_slot) timeout = 0;
    }

    auto response = sync_engine_.handle_sync(*user_id, since, timeout);

    // Joined-room list is fetched once and shared by the typing and presence
    // passes below — this used to be queried twice per poll.
    //
    // VISIBLE joined rooms, not joined rooms. SyncEngine filters
    // response.rooms.join by VIEW_CHANNEL, and the typing pass below then adds
    // rooms back into that same map — so an unfiltered list here handed the
    // caller the room id of every private channel they are denied, the moment
    // anybody typed in one, undoing the filter the sync itself had just
    // applied. The presence pass carries no room ids, but there is no reason to
    // derive who the caller "shares a room with" from rooms they cannot see.
    //
    // One engine spans both passes and the whole list; see
    // auth/RoomVisibility.h for why per-room construction is the expensive way
    // to write this.
    std::vector<std::string> joined_rooms;
    std::optional<PermissionsEngine> perms;
    if (typing_handler_ || presence_handler_) {
        perms.emplace(store_, config_);
        joined_rooms = visible_joined_rooms(store_, *perms, *user_id);
    }

    // Inject typing indicators into joined rooms
    if (typing_handler_) {
        // Add typing info to rooms already in the response
        for (auto& [room_id, joined] : response.rooms.join) {
            // Being IN rooms.join is not the same as being allowed to see what
            // happens inside. SyncEngine exempts categories from VIEW_CHANNEL
            // so the sidebar can still render the container node, so a room the
            // caller is denied can legitimately be sitting in this map — and a
            // denied category is meant to be a name-and-ordering stub, nothing
            // more. Attaching "X is typing" to it hands the caller live
            // activity from inside a room whose contents are the thing being
            // withheld, which is precisely what the stub exists to prevent.
            //
            // kViewChannel is asked directly rather than through can_view_room,
            // for the reason that helper's own header gives: its category
            // exemption is a rule about LISTING a room, not about acting or
            // observing inside one, and a typing indicator is activity inside
            // one. Same gate and same shape as PUT /rooms/{id}/typing/{user},
            // which refuses to let a denied user publish the indicator in the
            // first place; this is the read half of that write.
            if (!perms->can(*user_id, room_id, permission::kViewChannel)) continue;

            auto typing_users = typing_handler_->get_typing_users(room_id);
            if (!typing_users.empty()) {
                RoomEvent typing_event;
                typing_event.type = std::string(event_type::kTyping);
                typing_event.content.data = {{"user_ids", typing_users}};
                joined.ephemeral = EphemeralEvents{};
                joined.ephemeral->events.push_back(std::move(typing_event));
            }
        }

        // Also add rooms where someone is typing but no timeline events occurred
        for (const auto& room_id : joined_rooms) {
            if (response.rooms.join.count(room_id)) continue; // already handled
            auto typing_users = typing_handler_->get_typing_users(room_id);
            if (!typing_users.empty()) {
                JoinedRoom joined;
                RoomEvent typing_event;
                typing_event.type = std::string(event_type::kTyping);
                typing_event.content.data = {{"user_ids", typing_users}};
                joined.ephemeral = EphemeralEvents{};
                joined.ephemeral->events.push_back(std::move(typing_event));
                response.rooms.join[room_id] = std::move(joined);
            }
        }
    }

    // Inject presence events for every user the requester shares a
    // room with. Matrix delivers presence at the top level (not
    // per-room) and the client folds it into a global user→state
    // map, so we collect distinct user-ids across all joined rooms
    // and emit one m.presence event per known peer.
    if (presence_handler_) {
        // Drop entries nobody has refreshed in a long time; entries_ is an
        // in-memory map that otherwise grew without bound and kept anyone who
        // ever went "online" online forever, until the process restarted.
        presence_handler_->sweep_expired();

        // Only people who are actually there.
        //
        // get_room_members() returns every row in room_members with no
        // membership predicate — that is correct for GET /rooms/{id}/members,
        // which is a roster endpoint and is supposed to report 'leave' and
        // 'ban' as memberships. It is wrong here: presence is a statement that
        // a person is around, and this pass was making it about accounts that
        // had left, been kicked, or been SERVER-BANNED, complete with
        // last_active_ago. The last of those contradicts the ban projection
        // outright, which goes out of its way to blank a banned user's own
        // sync (SyncEngine::handle_sync).
        //
        // Both halves are needed and neither is redundant. The membership
        // filter is the ordinary case. is_server_banned() is the backstop for
        // the same reason SyncEngine keeps its own copy of that check: the ban
        // projection rewrites the membership rows, so a crash between the
        // ban-list write and the projection leaves a 'join' row behind, and
        // this should fail closed on it.
        //
        // The co-membership scoping around this is separately meaningless
        // while auto-join force-joins everyone into every channel, so nothing
        // here is a live disclosure today. It is the mechanism that per-
        // channel-visible user lists would be built on, and a filter that is
        // wrong now would be a bypass then.
        std::set<std::string> seen;
        for (const auto& room_id : joined_rooms) {
            auto members = store_.get_room_members(room_id);
            for (const auto& [m_uid, m_state] : members) {
                if (m_uid == *user_id) continue;
                if (m_state != membership::kJoin) continue;
                seen.insert(m_uid);
            }
        }
        // Touch ourselves so other peers see us as recently-active
        // simply by virtue of having opened a sync stream.
        presence_handler_->touch(*user_id);
        seen.insert(*user_id);

        PresenceEvents pe;
        for (const auto& uid : seen) {
            auto entry = presence_handler_->get_for(uid);
            if (!entry) continue;
            // After get_for(), not before, and not up in the membership loop.
            // This is a per-user store read on the endpoint every client polls
            // continuously: up there it would run once per (user, room) pair,
            // here it runs at most once per peer who is actually online, which
            // on any real deployment is a small fraction of the member set.
            if (store_.is_server_banned(uid)) continue;
            RoomEvent ev;
            ev.type = std::string(event_type::kPresence);
            ev.sender = uid;
            json content = {{"presence", entry->presence}};
            if (!entry->status_msg.empty()) {
                content["status_msg"] = entry->status_msg;
            }
            // Optional last_active_ago in ms — clients use this to
            // render "5 min ago" hints. We compute against the
            // entry's last_active_at in the steady_clock domain.
            auto ago = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - entry->last_active_at).count();
            if (ago >= 0) content["last_active_ago"] = ago;
            ev.content.data = std::move(content);
            pe.events.push_back(std::move(ev));
        }
        if (!pe.events.empty()) response.presence = std::move(pe);
    }

    // Lenient serialisation. This response is assembled from OTHER accounts'
    // data — their presence, their messages, their state — and the strict
    // dump() throws on any invalid UTF-8 anywhere in it; the throw escaped as a
    // 500, so one bad string from one account made /sync fail for everyone
    // who shared a room with it (audit S1). The server no longer manufactures
    // such strings (PresenceHandler, core/Utf8.h), and this makes sure no
    // single field can ever again take the whole poll down with it: a bad byte
    // becomes U+FFFD in one field of one event.
    json resp;
    to_json(resp, response);
    res.set_content(dump_response_json(resp), "application/json");
}

} // namespace bsfchat
