#pragma once

namespace bsfchat {

class SqliteStore;

// Currently migrations are handled inline in SqliteStore::initialize().
// This header exists as a future extension point for versioned migrations.

} // namespace bsfchat
