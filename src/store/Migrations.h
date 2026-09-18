#pragma once

#include <sqlite3.h>

#include <cstdint>

namespace bsfchat {

// Versioned schema migrations.
//
// Historically the schema was created inline in SqliteStore::initialize() with
// `CREATE TABLE IF NOT EXISTS` only, which meant any column added later would
// silently never appear on an existing deployment — the first query touching it
// would throw out of sqlite3_prepare_v2(). This runner fixes that.
//
// The version is stored in SQLite's built-in `PRAGMA user_version` (an integer
// in the database header, no extra table, no chance of the version row itself
// being missing). Steps are applied in ascending order inside a transaction,
// and user_version is bumped after each one.
//
// Adding a migration:
//   1. Append a step to kMigrations in Migrations.cpp.
//   2. Bump kTargetSchemaVersion.
//   3. Never edit or renumber an existing step — deployments have already run it.

// The schema version this build expects.
inline constexpr int kTargetSchemaVersion = 18;

// Reads `PRAGMA user_version`.
int get_schema_version(sqlite3* db);

// Applies every migration step above the database's current version.
// `fresh_database` is true when the caller determined this database had no
// tables before initialize() ran — used to skip one-time data migrations that
// only make sense for pre-existing deployments.
// Throws std::runtime_error on failure (after rolling back the failing step).
void run_migrations(sqlite3* db, bool fresh_database);

} // namespace bsfchat
