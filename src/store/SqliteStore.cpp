#include "store/SqliteStore.h"
#include "core/Logger.h"

#include <bsfchat/Constants.h>

#include <nlohmann/json.hpp>
#include <stdexcept>

namespace bsfchat {

namespace {

struct StmtDeleter {
    void operator()(sqlite3_stmt* stmt) {
        if (stmt) sqlite3_finalize(stmt);
    }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

StmtPtr prepare(sqlite3* db, const std::string& sql) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("SQL prepare error: ") + sqlite3_errmsg(db) + " [" + sql + "]");
    }
    return StmtPtr(stmt);
}

} // namespace

SqliteStore::SqliteStore(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error(std::string("Failed to open database: ") + sqlite3_errmsg(db_));
    }
    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA foreign_keys=ON");
    exec("PRAGMA busy_timeout=5000");
}

SqliteStore::~SqliteStore() {
    if (db_) sqlite3_close(db_);
}

void SqliteStore::exec(const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("SQL exec error: " + msg);
    }
}

void SqliteStore::initialize() {
    std::lock_guard lock(mutex_);

    exec(R"(
        CREATE TABLE IF NOT EXISTS users (
            user_id         TEXT PRIMARY KEY,
            password_hash   TEXT NOT NULL,
            display_name    TEXT,
            avatar_url      TEXT,
            created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS access_tokens (
            token       TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(user_id),
            device_id   TEXT NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS rooms (
            room_id     TEXT PRIMARY KEY,
            creator     TEXT NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS room_members (
            room_id     TEXT NOT NULL REFERENCES rooms(room_id),
            user_id     TEXT NOT NULL,
            membership  TEXT NOT NULL DEFAULT 'join',
            updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
            PRIMARY KEY (room_id, user_id)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS events (
            event_id            TEXT PRIMARY KEY,
            room_id             TEXT NOT NULL REFERENCES rooms(room_id),
            sender              TEXT NOT NULL,
            event_type          TEXT NOT NULL,
            state_key           TEXT,
            content             TEXT NOT NULL,
            origin_server_ts    INTEGER NOT NULL,
            stream_position     INTEGER NOT NULL UNIQUE
        )
    )");

    exec("CREATE INDEX IF NOT EXISTS idx_events_room_stream ON events(room_id, stream_position)");
    exec("CREATE INDEX IF NOT EXISTS idx_events_room_type_state ON events(room_id, event_type, state_key) WHERE state_key IS NOT NULL");
    exec("CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id, membership)");

    exec(R"(
        CREATE TABLE IF NOT EXISTS read_markers (
            user_id         TEXT NOT NULL,
            room_id         TEXT NOT NULL,
            last_read_pos   INTEGER NOT NULL,
            PRIMARY KEY (user_id, room_id)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS media (
            media_id        TEXT PRIMARY KEY,
            uploader        TEXT NOT NULL,
            content_type    TEXT NOT NULL,
            filename        TEXT,
            file_size       INTEGER NOT NULL,
            file_path       TEXT NOT NULL,
            created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
        )
    )");
}

// Users

bool SqliteStore::create_user(const std::string& user_id, const std::string& password_hash) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "INSERT OR IGNORE INTO users (user_id, password_hash) VALUES (?, ?)");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

std::optional<std::string> SqliteStore::get_password_hash(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT password_hash FROM users WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

bool SqliteStore::user_exists(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM users WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

bool SqliteStore::username_exists(const std::string& localpart) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM users WHERE user_id LIKE '@' || ? || ':%'");
    sqlite3_bind_text(stmt.get(), 1, localpart.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

// Access tokens

void SqliteStore::store_access_token(const std::string& token, const std::string& user_id, const std::string& device_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "INSERT INTO access_tokens (token, user_id, device_id) VALUES (?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, device_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::optional<std::string> SqliteStore::get_user_by_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT user_id FROM access_tokens WHERE token = ?");
    sqlite3_bind_text(stmt.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

void SqliteStore::delete_access_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM access_tokens WHERE token = ?");
    sqlite3_bind_text(stmt.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

void SqliteStore::delete_all_tokens_for_user(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM access_tokens WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

// Rooms

std::string SqliteStore::create_room(const std::string& room_id, const std::string& creator) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "INSERT INTO rooms (room_id, creator) VALUES (?, ?)");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, creator.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to create room: ") + sqlite3_errmsg(db_));
    }
    return room_id;
}

void SqliteStore::delete_room(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    // foreign_keys=ON means rooms can't be deleted while events or members
    // reference them — delete the dependents first, wrapped in a transaction
    // so we don't end up with a half-removed room.
    exec("BEGIN IMMEDIATE");
    try {
        auto run = [&](const char* sql) {
            auto s = prepare(db_, sql);
            sqlite3_bind_text(s.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(s.get());
        };
        run("DELETE FROM read_markers WHERE room_id = ?");
        run("DELETE FROM events WHERE room_id = ?");
        run("DELETE FROM room_members WHERE room_id = ?");
        run("DELETE FROM rooms WHERE room_id = ?");
        exec("COMMIT");
    } catch (...) {
        exec("ROLLBACK");
        throw;
    }
}

bool SqliteStore::room_exists(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM rooms WHERE room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

std::vector<std::string> SqliteStore::get_joined_rooms(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT room_id FROM room_members WHERE user_id = ? AND membership = 'join'");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

std::vector<std::string> SqliteStore::list_all_users() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT user_id FROM users");
    std::vector<std::string> users;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        users.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return users;
}

std::vector<std::string> SqliteStore::list_all_non_category_rooms() {
    std::lock_guard lock(mutex_);
    const char* sql = R"(
        SELECT r.room_id FROM rooms r
        WHERE COALESCE((
            SELECT json_extract(content, '$.type')
            FROM events
            WHERE room_id = r.room_id
              AND event_type = 'bsfchat.room.type'
              AND state_key = ''
            ORDER BY stream_position DESC LIMIT 1
        ), '') != 'category'
    )";
    auto stmt = prepare(db_, sql);
    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

std::vector<std::string> SqliteStore::list_public_rooms() {
    std::lock_guard lock(mutex_);
    // Return rooms where the latest m.room.join_rules state event has join_rule == "public"
    // AND the latest bsfchat.room.type (if any) is NOT "category".
    const char* sql = R"(
        SELECT r.room_id FROM rooms r
        WHERE (
            SELECT json_extract(content, '$.join_rule')
            FROM events
            WHERE room_id = r.room_id
              AND event_type = 'm.room.join_rules'
              AND state_key = ''
            ORDER BY stream_position DESC LIMIT 1
        ) = 'public'
        AND COALESCE((
            SELECT json_extract(content, '$.type')
            FROM events
            WHERE room_id = r.room_id
              AND event_type = 'bsfchat.room.type'
              AND state_key = ''
            ORDER BY stream_position DESC LIMIT 1
        ), '') != 'category'
    )";
    auto stmt = prepare(db_, sql);
    std::vector<std::string> rooms;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        rooms.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    }
    return rooms;
}

bool SqliteStore::is_room_member(const std::string& room_id, const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ? AND membership = 'join'");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

// Room membership

void SqliteStore::set_membership(const std::string& room_id, const std::string& user_id, const std::string& membership) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO room_members (room_id, user_id, membership, updated_at) VALUES (?, ?, ?, strftime('%s','now') * 1000) "
        "ON CONFLICT(room_id, user_id) DO UPDATE SET membership = excluded.membership, updated_at = excluded.updated_at");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, membership.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::string SqliteStore::get_membership(const std::string& room_id, const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT membership FROM room_members WHERE room_id = ? AND user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return "leave";
}

std::vector<std::pair<std::string, std::string>> SqliteStore::get_room_members(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT user_id, membership FROM room_members WHERE room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<std::pair<std::string, std::string>> members;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        members.emplace_back(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1))
        );
    }
    return members;
}

// Events

int64_t SqliteStore::insert_event(const std::string& event_id, const std::string& room_id,
                                   const std::string& sender, const std::string& event_type,
                                   const std::optional<std::string>& state_key,
                                   const std::string& content_json, int64_t origin_server_ts) {
    std::lock_guard lock(mutex_);

    // Get next stream position
    auto pos_stmt = prepare(db_, "SELECT COALESCE(MAX(stream_position), 0) + 1 FROM events");
    sqlite3_step(pos_stmt.get());
    int64_t stream_pos = sqlite3_column_int64(pos_stmt.get(), 0);

    auto stmt = prepare(db_,
        "INSERT INTO events (event_id, room_id, sender, event_type, state_key, content, origin_server_ts, stream_position) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, sender.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, event_type.c_str(), -1, SQLITE_TRANSIENT);
    if (state_key) {
        sqlite3_bind_text(stmt.get(), 5, state_key->c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt.get(), 5);
    }
    sqlite3_bind_text(stmt.get(), 6, content_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 7, origin_server_ts);
    sqlite3_bind_int64(stmt.get(), 8, stream_pos);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to insert event: ") + sqlite3_errmsg(db_));
    }

    return stream_pos;
}

std::vector<RoomEvent> SqliteStore::get_room_events(const std::string& room_id, int limit,
                                                     const std::string& direction,
                                                     const std::optional<std::string>& from) {
    std::lock_guard lock(mutex_);

    std::string sql = "SELECT event_id, room_id, sender, event_type, state_key, content, origin_server_ts "
                      "FROM events WHERE room_id = ?";

    if (from) {
        // from is a stream position token like "s42"
        int64_t pos = 0;
        if (from->size() > 1 && (*from)[0] == 's') {
            pos = std::stoll(from->substr(1));
        }
        if (direction == "b") {
            sql += " AND stream_position < ? ORDER BY stream_position DESC";
        } else {
            sql += " AND stream_position > ? ORDER BY stream_position ASC";
        }
    } else {
        if (direction == "b") {
            sql += " ORDER BY stream_position DESC";
        } else {
            sql += " ORDER BY stream_position ASC";
        }
    }
    sql += " LIMIT ?";

    auto stmt = prepare(db_, sql);
    int idx = 1;
    sqlite3_bind_text(stmt.get(), idx++, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (from) {
        int64_t pos = 0;
        if (from->size() > 1 && (*from)[0] == 's') {
            pos = std::stoll(from->substr(1));
        }
        sqlite3_bind_int64(stmt.get(), idx++, pos);
    }
    sqlite3_bind_int(stmt.get(), idx, limit);

    std::vector<RoomEvent> events;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        RoomEvent ev;
        ev.event_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        ev.room_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        ev.sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        ev.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        if (sqlite3_column_type(stmt.get(), 4) != SQLITE_NULL) {
            ev.state_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        }
        ev.content.data = nlohmann::json::parse(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5)));
        ev.origin_server_ts = sqlite3_column_int64(stmt.get(), 6);
        events.push_back(std::move(ev));
    }
    return events;
}

std::vector<RoomEvent> SqliteStore::get_state_events(const std::string& room_id) {
    std::lock_guard lock(mutex_);

    // Get the latest state event for each (event_type, state_key) pair
    auto stmt = prepare(db_,
        "SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content, e.origin_server_ts "
        "FROM events e "
        "INNER JOIN (SELECT event_type, state_key, MAX(stream_position) as max_pos "
        "            FROM events WHERE room_id = ? AND state_key IS NOT NULL "
        "            GROUP BY event_type, state_key) latest "
        "ON e.event_type = latest.event_type AND e.state_key = latest.state_key AND e.stream_position = latest.max_pos "
        "WHERE e.room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<RoomEvent> events;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        RoomEvent ev;
        ev.event_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        ev.room_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        ev.sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        ev.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        if (sqlite3_column_type(stmt.get(), 4) != SQLITE_NULL) {
            ev.state_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        }
        ev.content.data = nlohmann::json::parse(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5)));
        ev.origin_server_ts = sqlite3_column_int64(stmt.get(), 6);
        events.push_back(std::move(ev));
    }
    return events;
}

std::optional<RoomEvent> SqliteStore::get_event_by_id(const std::string& event_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT event_id, room_id, sender, event_type, state_key, content, origin_server_ts "
        "FROM events WHERE event_id = ? LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, event_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;

    RoomEvent ev;
    ev.event_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    ev.room_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
    ev.sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
    ev.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
    if (sqlite3_column_type(stmt.get(), 4) != SQLITE_NULL) {
        ev.state_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
    }
    ev.content.data = nlohmann::json::parse(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5)));
    ev.origin_server_ts = sqlite3_column_int64(stmt.get(), 6);
    return ev;
}

std::optional<RoomEvent> SqliteStore::get_state_event(const std::string& room_id,
                                                       const std::string& event_type,
                                                       const std::string& state_key) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT event_id, room_id, sender, event_type, state_key, content, origin_server_ts "
        "FROM events WHERE room_id = ? AND event_type = ? AND state_key = ? "
        "ORDER BY stream_position DESC LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, state_key.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        RoomEvent ev;
        ev.event_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        ev.room_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        ev.sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        ev.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        if (sqlite3_column_type(stmt.get(), 4) != SQLITE_NULL) {
            ev.state_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        }
        ev.content.data = nlohmann::json::parse(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5)));
        ev.origin_server_ts = sqlite3_column_int64(stmt.get(), 6);
        return ev;
    }
    return std::nullopt;
}

// Sync

std::vector<RoomEvent> SqliteStore::get_events_since(const std::string& user_id, int64_t since_position, int limit) {
    std::lock_guard lock(mutex_);

    auto stmt = prepare(db_,
        "SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content, e.origin_server_ts "
        "FROM events e "
        "INNER JOIN room_members rm ON e.room_id = rm.room_id AND rm.user_id = ? AND rm.membership = 'join' "
        "WHERE e.stream_position > ? "
        "ORDER BY e.stream_position ASC "
        "LIMIT ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, since_position);
    sqlite3_bind_int(stmt.get(), 3, limit);

    std::vector<RoomEvent> events;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        RoomEvent ev;
        ev.event_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        ev.room_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        ev.sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        ev.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        if (sqlite3_column_type(stmt.get(), 4) != SQLITE_NULL) {
            ev.state_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        }
        ev.content.data = nlohmann::json::parse(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5)));
        ev.origin_server_ts = sqlite3_column_int64(stmt.get(), 6);
        events.push_back(std::move(ev));
    }
    return events;
}

int64_t SqliteStore::get_current_stream_position() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT COALESCE(MAX(stream_position), 0) FROM events");
    sqlite3_step(stmt.get());
    return sqlite3_column_int64(stmt.get(), 0);
}

int64_t SqliteStore::get_room_max_stream_position(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT COALESCE(MAX(stream_position), 0) FROM events WHERE room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return sqlite3_column_int64(stmt.get(), 0);
}

// Read markers

void SqliteStore::set_read_marker(const std::string& user_id, const std::string& room_id, int64_t stream_pos) {
    std::lock_guard lock(mutex_);
    // Upsert, but only move forward. ON CONFLICT uses MAX(existing, new).
    auto stmt = prepare(db_,
        "INSERT INTO read_markers (user_id, room_id, last_read_pos) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id, room_id) DO UPDATE SET last_read_pos = "
        "CASE WHEN excluded.last_read_pos > read_markers.last_read_pos "
        "THEN excluded.last_read_pos ELSE read_markers.last_read_pos END");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, stream_pos);
    sqlite3_step(stmt.get());
}

int64_t SqliteStore::get_read_marker(const std::string& user_id, const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT last_read_pos FROM read_markers WHERE user_id = ? AND room_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return sqlite3_column_int64(stmt.get(), 0);
    }
    return 0;
}

int SqliteStore::count_unread(const std::string& user_id, const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT COUNT(*) FROM events "
        "WHERE room_id = ? AND event_type = 'm.room.message' "
        "AND sender != ? "
        "AND stream_position > COALESCE("
        "  (SELECT last_read_pos FROM read_markers WHERE user_id = ? AND room_id = ?), 0)");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, room_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return sqlite3_column_int(stmt.get(), 0);
    }
    return 0;
}

// Permissions / roles

std::vector<ServerRole> SqliteStore::get_server_roles() {
    std::lock_guard lock(mutex_);
    // Latest bsfchat.server.roles event globally (regardless of room).
    std::string type(event_type::kServerRoles);
    auto stmt = prepare(db_,
        "SELECT content FROM events "
        "WHERE event_type = ? AND state_key = '' "
        "ORDER BY stream_position DESC LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, type.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return {};
    auto json = nlohmann::json::parse(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)), nullptr, false);
    if (json.is_discarded()) return {};
    ServerRolesContent content;
    from_json(json, content);
    return content.roles;
}

std::vector<std::string> SqliteStore::get_member_role_ids(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    std::string type(event_type::kMemberRoles);
    auto stmt = prepare(db_,
        "SELECT content FROM events "
        "WHERE event_type = ? AND state_key = ? "
        "ORDER BY stream_position DESC LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return {};
    auto json = nlohmann::json::parse(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)), nullptr, false);
    if (json.is_discarded()) return {};
    MemberRolesContent content;
    from_json(json, content);
    return content.role_ids;
}

std::map<std::string, ChannelPermissionOverride>
SqliteStore::get_channel_overrides(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    // Latest event per state_key for this room and type.
    std::string type(event_type::kChannelPermissions);
    auto stmt = prepare(db_,
        "SELECT e.state_key, e.content FROM events e "
        "INNER JOIN (SELECT state_key, MAX(stream_position) AS mp FROM events "
        "            WHERE room_id = ? AND event_type = ? AND state_key IS NOT NULL "
        "            GROUP BY state_key) latest "
        "ON e.state_key = latest.state_key AND e.stream_position = latest.mp "
        "WHERE e.room_id = ? AND e.event_type = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, type.c_str(), -1, SQLITE_TRANSIENT);

    std::map<std::string, ChannelPermissionOverride> overrides;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        std::string key = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        auto json = nlohmann::json::parse(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1)), nullptr, false);
        if (json.is_discarded()) continue;
        ChannelPermissionOverride ov;
        from_json(json, ov);
        if (ov.allow == 0 && ov.deny == 0) continue; // skip empty
        overrides[std::move(key)] = ov;
    }
    return overrides;
}

int SqliteStore::get_channel_slowmode(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    std::string type(event_type::kChannelSettings);
    auto stmt = prepare(db_,
        "SELECT content FROM events "
        "WHERE room_id = ? AND event_type = ? AND state_key = '' "
        "ORDER BY stream_position DESC LIMIT 1");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, type.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return 0;
    auto json = nlohmann::json::parse(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)), nullptr, false);
    if (json.is_discarded()) return 0;
    return json.value("slowmode_seconds", 0);
}

int64_t SqliteStore::get_last_message_ts(const std::string& user_id, const std::string& room_id) {
    std::lock_guard lock(mutex_);
    std::string type(event_type::kRoomMessage);
    auto stmt = prepare(db_,
        "SELECT MAX(origin_server_ts) FROM events "
        "WHERE room_id = ? AND sender = ? AND event_type = ?");
    sqlite3_bind_text(stmt.get(), 1, room_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, type.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return 0;
    if (sqlite3_column_type(stmt.get(), 0) == SQLITE_NULL) return 0;
    return sqlite3_column_int64(stmt.get(), 0);
}

std::vector<std::pair<std::string, int64_t>> SqliteStore::list_users_with_created_at() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT user_id, created_at FROM users ORDER BY created_at ASC");
    std::vector<std::pair<std::string, int64_t>> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        out.emplace_back(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)),
            sqlite3_column_int64(stmt.get(), 1));
    }
    return out;
}

// Profile

void SqliteStore::set_display_name(const std::string& user_id, const std::string& display_name) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE users SET display_name = ? WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, display_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

void SqliteStore::set_avatar_url(const std::string& user_id, const std::string& avatar_url) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE users SET avatar_url = ? WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, avatar_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::optional<std::string> SqliteStore::get_display_name(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT display_name FROM users WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW && sqlite3_column_type(stmt.get(), 0) != SQLITE_NULL) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

std::optional<std::string> SqliteStore::get_avatar_url(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT avatar_url FROM users WHERE user_id = ?");
    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW && sqlite3_column_type(stmt.get(), 0) != SQLITE_NULL) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    return std::nullopt;
}

// Media

void SqliteStore::insert_media(const std::string& media_id, const std::string& uploader,
                                const std::string& content_type, const std::string& filename,
                                int64_t file_size, const std::string& file_path) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO media (media_id, uploader, content_type, filename, file_size, file_path) "
        "VALUES (?, ?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, media_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, uploader.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, content_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 5, file_size);
    sqlite3_bind_text(stmt.get(), 6, file_path.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("Failed to insert media: ") + sqlite3_errmsg(db_));
    }
}

std::optional<SqliteStore::MediaMeta> SqliteStore::get_media(const std::string& media_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT media_id, uploader, content_type, filename, file_size, file_path "
        "FROM media WHERE media_id = ?");
    sqlite3_bind_text(stmt.get(), 1, media_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        MediaMeta meta;
        meta.media_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        meta.uploader = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        meta.content_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        auto fn = sqlite3_column_text(stmt.get(), 3);
        meta.filename = fn ? reinterpret_cast<const char*>(fn) : "";
        meta.file_size = sqlite3_column_int64(stmt.get(), 4);
        meta.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5));
        return meta;
    }
    return std::nullopt;
}

bool SqliteStore::delete_media(const std::string& media_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM media WHERE media_id = ?");
    sqlite3_bind_text(stmt.get(), 1, media_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
    return sqlite3_changes(db_) > 0;
}

} // namespace bsfchat
