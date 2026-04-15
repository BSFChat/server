#pragma once

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

// Runs on startup. Seeds the default roles (@everyone, Moderator, Admin) if
// none exist, then ensures every registered user has a bsfchat.member.roles
// event. The oldest-registered user gets the admin role; everyone else gets
// @everyone only. Idempotent — safe to call on every boot.
void bootstrap_roles(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

} // namespace bsfchat
