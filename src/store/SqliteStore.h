#pragma once

#include <bsfchat/MatrixTypes.h>
#include <sqlite3.h>

#include <memory>
#include <mutex>
#include <optional>
#include <string>
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

    // Rooms
    std::string create_room(const std::string& room_id, const std::string& creator);
    bool room_exists(const std::string& room_id);
    std::vector<std::string> get_joined_rooms(const std::string& user_id);
    bool is_room_member(const std::string& room_id, const std::string& user_id);

    // Room membership
    void set_membership(const std::string& room_id, const std::string& user_id, const std::string& membership);
    std::string get_membership(const std::string& room_id, const std::string& user_id);
    std::vector<std::pair<std::string, std::string>> get_room_members(const std::string& room_id);

    // Events
    int64_t insert_event(const std::string& event_id, const std::string& room_id,
                         const std::string& sender, const std::string& event_type,
                         const std::optional<std::string>& state_key,
                         const std::string& content_json, int64_t origin_server_ts);

    std::vector<RoomEvent> get_room_events(const std::string& room_id, int limit, const std::string& direction = "b",
                                            const std::optional<std::string>& from = std::nullopt);

    std::vector<RoomEvent> get_state_events(const std::string& room_id);
    std::optional<RoomEvent> get_state_event(const std::string& room_id, const std::string& event_type, const std::string& state_key);

    // Sync
    std::vector<RoomEvent> get_events_since(const std::string& user_id, int64_t since_position, int limit = 1000);
    int64_t get_current_stream_position();

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
