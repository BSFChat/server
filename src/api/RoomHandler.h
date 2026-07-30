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
    // membership". POST /rooms/{id}/kick, /ban, /unban, /invite and
    // PUT /rooms/{id}/state/m.room.member/{user} all route through here.
    //
    // They used to be five separate implementations of the same decision, and
    // they drifted exactly as far apart as you would expect: the state-PUT route
    // wrote the m.room.member event but never the membership row (so a ban placed
    // there left the user fully joined server-side), gated a BAN on KICK_MEMBERS,
    // and for a while skipped the rank check the others had. Adding the ban list
    // to four copies would have produced a fifth divergence, so the copies are
    // gone instead.
    //
    // Performs, in order: transition validation, permission evaluation at the
    // correct scope, the rank check where one applies, the server ban-list write,
    // the membership projection across every room, the member event(s), and the
    // audit record. `reason` may be empty.
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
