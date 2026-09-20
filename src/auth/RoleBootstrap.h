#pragma once

#include <string>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

// Runs on startup and after each registration. Seeds the default roles
// (@everyone, Moderator, Admin) if none exist, then ensures every registered
// user has a role assignment. The oldest-registered user gets the admin role;
// everyone else gets @everyone only. Idempotent — safe to call repeatedly.
void bootstrap_roles(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

// Writes a piece of SERVER-WIDE state (bsfchat.server.roles /
// bsfchat.member.roles).
//
// The authoritative copy goes into the server_state table, which no room
// deletion can touch. `mirror_room`, when non-empty and still present, also
// receives a normal state event so clients keep learning about the change
// through /sync — that mirror is delivery only and is never read back.
// `sender` defaults to the synthetic @server:<name> actor when empty.
// The room server-scoped state is MIRRORED into, so clients keep learning about
// role changes through /sync. Presentation only: authority lives in the
// server_state table, and this returning empty (a server with no channels yet)
// costs nothing but a client refresh. Exposed because every writer of
// server-scoped state needs the same answer, and two callers picking different
// mirror rooms would leave clients reading whichever stale copy their sync
// happened to carry.
//
// PINNED, once chosen. The choice used to be recomputed on every write as
// list_all_non_category_rooms().front() — a scan with no ORDER BY, so "front"
// is whatever SQLite happened to return. That is stable enough in practice
// until a channel is deleted or the query plan changes, and then the mirror
// silently MIGRATES to a different room: new role writes land in a room some
// clients are not in, while the events in the old room stay exactly as they
// were. Those clients keep a stale role document forever, with no error and
// nothing to resync against — the desktop client's latest-wins guards
// (applyServerRolesEvent / applyMemberRolesEvent) cannot help, because the
// newer event never reaches them at all.
//
// So the answer is recorded in `meta` the first time it is asked for and reused
// after that. Upgrading changes nothing: the first call pins whatever the old
// expression would have returned anyway. The pin is dropped only if that room
// stops existing, which is the one case where a move is unavoidable.
//
// This does NOT make the choice a good one — it is still an arbitrary channel,
// and every member of it receives role events for the whole server, including
// assignments relating to channels they cannot see. Pinning stops the room
// MOVING; it does not stop it being the wrong room.
//
// What the mirror is still for, now that GET /bsfchat/permissions/{userId}
// exists: the desktop client, and only the desktop client. It renders role
// colours, hoisting and the self-role picker from these events and has no other
// source for another member's assignment — the new endpoint answers one user's
// effective MASK, which is the right shape for an integration deciding whether
// to obey somebody and the wrong shape for a member list. So the mirror cannot
// be retired here. The replacement is a bulk read of the role ids held by the
// members of a room the caller can see, at which point the member.roles half of
// the mirror can go and the server.roles half is already covered by
// GET /bsfchat/roles. See docs/bots.md §11.
std::string pick_server_state_mirror_room(SqliteStore& store);

void write_server_scoped_state(SqliteStore& store, const Config& config,
                                const std::string& evt_type, const std::string& state_key,
                                const std::string& content_json,
                                const std::string& mirror_room,
                                const std::string& sender = std::string());

} // namespace bsfchat
