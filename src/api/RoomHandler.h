#pragma once

#include <httplib.h>
#include <nlohmann/json_fwd.hpp>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

// Which moderation act a request is, as DECLARED by the endpoint it arrived at.
//
// kInfer is for the generic PUT /rooms/{id}/state/m.room.member/{user} route,
// which is the only caller that genuinely does not know: a Matrix client sends a
// target membership and the meaning comes from where the target currently stands.
// Every dedicated endpoint declares itself, because inference there is unsafe —
// POST /rooms/{id}/kick against an already-banned user reads as "set leave on a
// banned user", which is the wire shape of an UNBAN.
enum class MembershipAction { kInfer, kKick, kBan, kUnban, kInvite };

class RoomHandler {
public:
    RoomHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

    void handle_create_room(const httplib::Request& req, httplib::Response& res);
    void handle_join(const httplib::Request& req, httplib::Response& res);
    void handle_leave(const httplib::Request& req, httplib::Response& res);
    // DELETE /_matrix/client/v3/rooms/{id}. Requires MANAGE_CHANNELS.
    // Destructive — removes the room and every event in it.
    void handle_delete_room(const httplib::Request& req, httplib::Response& res);
    void handle_joined_rooms(const httplib::Request& req, httplib::Response& res);

    // GET /_matrix/client/v3/bsfchat/channels — the channel directory.
    //
    // The complement of handle_joined_rooms, and the reason it had to exist:
    // /joined_rooms answers only "where am I", so nothing on this server could
    // answer "where COULD I be". An integration bot could not offer an operator
    // a list of channels to send alerts to until somebody had already put it in
    // the channel, and the documented way to do that — invite the bot — has no
    // UI in the desktop client, so the documented path could not be walked.
    //
    // Authentication is the whole of the authorization: any account may ask,
    // and what it gets back is filtered per room by its own VIEW_CHANNEL. There
    // is no directory permission to hold, because a directory permission would
    // be a second answer to "may this account know this channel exists" sitting
    // beside the real one.
    void handle_channel_directory(const httplib::Request& req, httplib::Response& res);
    void handle_room_state(const httplib::Request& req, httplib::Response& res);
    void handle_room_state_event(const httplib::Request& req, httplib::Response& res);
    void handle_room_members(const httplib::Request& req, httplib::Response& res);
    void handle_kick(const httplib::Request& req, httplib::Response& res);
    void handle_ban(const httplib::Request& req, httplib::Response& res);
    // POST /rooms/{roomId}/unban. Added alongside the audit log: the client has
    // always called this path and the server never served it, so a ban could be
    // recorded but never lifted.
    void handle_unban(const httplib::Request& req, httplib::Response& res);
    void handle_invite(const httplib::Request& req, httplib::Response& res);

    // GET /_matrix/client/v3/bsfchat/server_bans — the server-wide ban list.
    //
    // Server-scoped, so it lives here rather than under /rooms/{id}/ despite the
    // path: SqliteStore::list_server_bans had no route and no caller at all, which
    // meant a client could only reconstruct the ban list from the membership rows
    // its own sync happened to surface. A user banned while holding no membership
    // row in any synced room was therefore invisible in the client's bans tab and
    // could not be unbanned from it — the same blind spot the server-wide ban list
    // exists to close, reappearing on the read side.
    //
    // Gated on BAN_MEMBERS at SERVER scope, which is exactly what ban_intent() and
    // unban_intent() require of the writes. Deliberately not MANAGE_SERVER: a
    // moderator who may place and lift bans but may not see the list cannot use
    // the tab the list is for, and would be reduced to guessing user ids. Reading
    // who is banned is strictly less than the power to ban them.
    void handle_list_server_bans(const httplib::Request& req, httplib::Response& res);
    void handle_set_state(const httplib::Request& req, httplib::Response& res);
    void handle_move_channel(const httplib::Request& req, httplib::Response& res);
    void handle_set_order(const httplib::Request& req, httplib::Response& res);

private:
    // Returns the id of the event actually stored. Callers that echo an
    // event_id back to the client MUST use this value — generating a second id
    // for the response hands the client an id that isn't in the database.
    std::string emit_state_event(const std::string& room_id, const std::string& sender,
                                 const std::string& event_type, const std::string& state_key,
                                 const nlohmann::json& content);

    // The outcome of a moderation request. `ok == false` means NOTHING was
    // written — no membership row, no event, no audit record — and
    // (status, message) is the refusal to hand the client.
    struct ModerationResult {
        bool ok = false;
        int status = 403;
        std::string message;
        std::string event_id;  // the member event in `room_id`, when one was written
    };

    // THE single implementation of "a moderator changes somebody else's
    // membership". POST /rooms/{id}/kick, /ban, /unban and
    // PUT /rooms/{id}/state/m.room.member/{user} all route through here.
    //
    // POST /rooms/{id}/invite does NOT, and the list above used to say it did.
    // That endpoint answers seven situations the client tells apart by errcode
    // and joins a bot outright rather than inviting it, none of which this
    // function models, so it keeps its own body — which is exactly why the ONE
    // rule it shares with this path, the direct-room rule below, is read off
    // the intent instead of written out at both ends.
    //
    // They used to be five separate implementations of the same decision, and
    // they drifted exactly as far apart as you would expect: the state-PUT route
    // wrote the m.room.member event but never the membership row (so a ban placed
    // there left the user fully joined server-side), gated a BAN on KICK_MEMBERS,
    // and for a while skipped the rank check the others had. Adding the ban list
    // to four copies would have produced a fifth divergence, so the copies are
    // gone instead.
    //
    // Performs, in order: transition validation, the direct-room rule, permission
    // evaluation at the correct scope, the rank check where one applies, the
    // server ban-list write, the membership projection across every room, the
    // member event(s), and the audit record. `reason` may be empty.
    //
    // The direct-room rule is carried by the intent
    // (MembershipIntent::direct_room_refusal), so an invite or a kick is refused
    // in a DM while a ban and an unban — which are acts on the account, not on
    // the room — still reach it. POST /rooms/{id}/invite does not route through
    // here, and asks that same field rather than deciding for itself.
    ModerationResult apply_membership_moderation(const std::string& actor,
                                                 const std::string& room_id,
                                                 const std::string& target_user,
                                                 const std::string& target_membership,
                                                 const std::string& reason,
                                                 MembershipAction declared);

    // Writes `membership` for `target_user` in EVERY room they have a membership
    // row in, plus `origin_room` — the step the client's loop over synced rooms
    // could never get right. `only_when` filters which existing rows are touched
    // ("" = all of them). Returns the event id written in `origin_room`.
    std::string project_membership_everywhere(const std::string& actor,
                                              const std::string& origin_room,
                                              const std::string& target_user,
                                              const std::string& membership,
                                              const std::string& reason,
                                              const std::string& only_when);

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
