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
void write_server_scoped_state(SqliteStore& store, const Config& config,
                                const std::string& evt_type, const std::string& state_key,
                                const std::string& content_json,
                                const std::string& mirror_room,
                                const std::string& sender = std::string());

} // namespace bsfchat
