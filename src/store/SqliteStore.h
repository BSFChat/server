#pragma once

#include <bsfchat/MatrixTypes.h>
#include <sqlite3.h>

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <cstdint>

namespace bsfchat {

class SqliteStore {
public:
    explicit SqliteStore(const std::string& db_path);
    ~SqliteStore();

    SqliteStore(const SqliteStore&) = delete;
    SqliteStore& operator=(const SqliteStore&) = delete;

    void initialize();

    // Users
    bool create_user(const std::string& user_id, const std::string& password_hash);
    std::optional<std::string> get_password_hash(const std::string& user_id);
    bool user_exists(const std::string& user_id);
    bool username_exists(const std::string& localpart);

    // Access tokens
    void store_access_token(const std::string& token, const std::string& user_id, const std::string& device_id);
    std::optional<std::string> get_user_by_token(const std::string& token);
    void delete_access_token(const std::string& token);
    void delete_all_tokens_for_user(const std::string& user_id);

    // Users
    std::vector<std::string> list_all_users();

    // Rooms
    std::string create_room(const std::string& room_id, const std::string& creator);
    bool room_exists(const std::string& room_id);
    // Remove a room and everything that references it (events, members,
    // read markers). Destructive; intended for admin-driven channel deletion.
    void delete_room(const std::string& room_id);
    std::vector<std::string> get_joined_rooms(const std::string& user_id);
    bool is_room_member(const std::string& room_id, const std::string& user_id);
    std::vector<std::string> list_public_rooms();
    std::vector<std::string> list_all_non_category_rooms();

    // Room membership
    void set_membership(const std::string& room_id, const std::string& user_id, const std::string& membership);
    std::string get_membership(const std::string& room_id, const std::string& user_id);
    std::vector<std::pair<std::string, std::string>> get_room_members(const std::string& room_id);

    // Events
    int64_t insert_event(const std::string& event_id, const std::string& room_id,
                         const std::string& sender, const std::string& event_type,
                         const std::optional<std::string>& state_key,
                         const std::string& content_json, int64_t origin_server_ts);

    // Returns (events, next_from_token). next_from_token is the stream
    // position of the oldest row in this batch for dir="b" / newest for
    // dir="f"; encode it as "s<pos>" and pass back as `from` on the next
    // page request. nullopt when there are no more rows in that direction.
    std::pair<std::vector<RoomEvent>, std::optional<int64_t>>
    get_room_events_paginated(const std::string& room_id, int limit,
                              const std::string& direction = "b",
                              const std::optional<std::string>& from = std::nullopt);

    std::vector<RoomEvent> get_room_events(const std::string& room_id, int limit, const std::string& direction = "b",
                                            const std::optional<std::string>& from = std::nullopt);

    std::vector<RoomEvent> get_state_events(const std::string& room_id);
    std::optional<RoomEvent> get_state_event(const std::string& room_id, const std::string& event_type, const std::string& state_key);
    std::optional<RoomEvent> get_event_by_id(const std::string& event_id);

    // Sync
    std::vector<RoomEvent> get_events_since(const std::string& user_id, int64_t since_position, int limit = 1000);
    int64_t get_current_stream_position();
    int64_t get_room_max_stream_position(const std::string& room_id);

    // Permissions / roles (reads)
    // Returns the latest bsfchat.server.roles content across all rooms, empty if unset.
    std::vector<ServerRole> get_server_roles();
    // Role IDs assigned to the given user (latest bsfchat.member.roles), empty if none.
    std::vector<std::string> get_member_role_ids(const std::string& user_id);
    // All per-channel allow/deny overrides for the room, keyed by target ("role:..." / "user:...").
    std::map<std::string, ChannelPermissionOverride> get_channel_overrides(const std::string& room_id);
    // Per-channel slowmode, in seconds. 0 = disabled.
    int get_channel_slowmode(const std::string& room_id);
    // Timestamp (origin_server_ts, ms) of the user's most recent m.room.message in the room, 0 if none.
    int64_t get_last_message_ts(const std::string& user_id, const std::string& room_id);
    // For startup bootstrap: (user_id, created_at) ordered ascending by created_at.
    std::vector<std::pair<std::string, int64_t>> list_users_with_created_at();

    // Read markers
    // Upserts (user_id, room_id) marker. Only moves forward (monotonic).
    void set_read_marker(const std::string& user_id, const std::string& room_id, int64_t stream_pos);
    int64_t get_read_marker(const std::string& user_id, const std::string& room_id);
    // Counts m.room.message events in room where stream_position > marker AND sender != user_id.
    int count_unread(const std::string& user_id, const std::string& room_id);

    // Profile
    void set_display_name(const std::string& user_id, const std::string& display_name);
    void set_avatar_url(const std::string& user_id, const std::string& avatar_url);
    std::optional<std::string> get_display_name(const std::string& user_id);
    std::optional<std::string> get_avatar_url(const std::string& user_id);

    // Media
    struct MediaMeta {
        std::string media_id;
        std::string uploader;
        std::string content_type;
        std::string filename;
        int64_t file_size;
        std::string file_path;
    };

    void insert_media(const std::string& media_id, const std::string& uploader,
                      const std::string& content_type, const std::string& filename,
                      int64_t file_size, const std::string& file_path);
    std::optional<MediaMeta> get_media(const std::string& media_id);
    bool delete_media(const std::string& media_id);

private:
    void exec(const std::string& sql);
    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};

} // namespace bsfchat
