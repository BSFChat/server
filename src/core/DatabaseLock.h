#pragma once

#include <memory>
#include <string>

namespace bsfchat {

// One server process per database (audit 2-2026-11-18 S2-10).
//
// Two processes on one database file each hand out event stream positions
// from their own in-memory counter, so they collide on the next write; SQLite's
// own locking is per transaction and does not stop it. With SO_REUSEPORT a
// second server even binds the same port happily, so the admin CLI's
// "is something listening" probe cannot catch it either.
//
// The guard is an advisory flock() on `<database>.lock`, taken before the
// database is opened and held for the life of the process. The kernel drops it
// when the process exits however it exits, so a crash never leaves a stale
// lock to clear by hand. It is per open file, so a second acquire in the SAME
// process conflicts too (which is what the tests rely on).
class DatabaseLock {
public:
    ~DatabaseLock();
    DatabaseLock(const DatabaseLock&) = delete;
    DatabaseLock& operator=(const DatabaseLock&) = delete;

    // Takes the lock for `database_path`, or throws std::runtime_error with an
    // operator-facing message when another process holds it. Returns null for
    // an in-memory database (":memory:" or empty), which nothing can share.
    static std::unique_ptr<DatabaseLock> acquire(const std::string& database_path);

    // True when another holder has the lock right now. Probes without keeping
    // it; for the admin CLI's stopped-server check.
    static bool held_elsewhere(const std::string& database_path);

    static std::string lock_path_for(const std::string& database_path);

private:
    explicit DatabaseLock(int fd) : fd_(fd) {}
    int fd_ = -1;
};

} // namespace bsfchat
