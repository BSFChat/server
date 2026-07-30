#pragma once

#include <httplib.h>
#include <nlohmann/json_fwd.hpp>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

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

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
