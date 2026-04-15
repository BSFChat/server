#pragma once

#include <string>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

// Add a user to all existing public rooms on the server.
// Emits m.room.member events so other clients see the join via sync.
void auto_join_public_rooms(SqliteStore& store, SyncEngine& sync_engine,
                             const Config& config, const std::string& user_id);

// Add all existing server users (except skip_user_id, who is usually already a member)
// to a newly-created room. Emits m.room.member events for each.
void auto_join_all_users(SqliteStore& store, SyncEngine& sync_engine,
                          const Config& config, const std::string& room_id,
                          const std::string& skip_user_id);

// Backfill: ensure every user is a member of every public room.
// Safe to run repeatedly (skips users already joined). Intended for
// server startup to retroactively add users who registered before auto-join existed.
void backfill_auto_join(SqliteStore& store, SyncEngine& sync_engine,
                         const Config& config);

} // namespace bsfchat
