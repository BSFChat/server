#include "core/DatabaseLock.h"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

namespace bsfchat {

namespace {

bool in_memory(const std::string& path) {
    return path.empty() || path == ":memory:" || path.rfind("file::memory:", 0) == 0;
}

int open_lock_file(const std::string& lock_path) {
    const int fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        throw std::runtime_error("Cannot open database lock file " + lock_path + ": " +
                                 std::strerror(errno));
    }
    return fd;
}

std::string read_holder(int fd) {
    char buf[32] = {};
    const auto n = ::pread(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return {};
    std::string s(buf, static_cast<std::size_t>(n));
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
}

} // namespace

std::string DatabaseLock::lock_path_for(const std::string& database_path) {
    return database_path + ".lock";
}

std::unique_ptr<DatabaseLock> DatabaseLock::acquire(const std::string& database_path,
                                                   std::chrono::milliseconds patience) {
    if (in_memory(database_path)) return nullptr;
    const std::string lock_path = lock_path_for(database_path);
    const int fd = open_lock_file(lock_path);
    const auto deadline = std::chrono::steady_clock::now() + patience;
    int rc = 0;
    int err = 0;
    for (;;) {
        rc = ::flock(fd, LOCK_EX | LOCK_NB);
        err = errno;
        if (rc == 0 || err != EWOULDBLOCK || std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (rc != 0) {
        const std::string holder = read_holder(fd);
        ::close(fd);
        if (err == EWOULDBLOCK) {
            throw std::runtime_error(
                "Another bsfchat-server process (or admin command)" +
                (holder.empty() ? std::string() : " (pid " + holder + ")") +
                " is already using " + database_path + " (lock: " + lock_path +
                "). Two servers on one database collide on event stream positions; stop the "
                "other one first.");
        }
        throw std::runtime_error("Cannot lock " + lock_path + ": " + std::strerror(err));
    }
    // Informational only: the flock is the lock, the pid is for the message.
    const std::string pid = std::to_string(::getpid()) + "\n";
    if (::ftruncate(fd, 0) == 0) {
        [[maybe_unused]] auto written = ::pwrite(fd, pid.data(), pid.size(), 0);
    }
    return std::unique_ptr<DatabaseLock>(new DatabaseLock(fd));
}

bool DatabaseLock::held_elsewhere(const std::string& database_path) {
    if (in_memory(database_path)) return false;
    const std::string lock_path = lock_path_for(database_path);
    const int fd = ::open(lock_path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) return false;  // no lock file: no server has run here
    const bool held = ::flock(fd, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK;
    ::close(fd);  // releases the probe's lock if it got one
    return held;
}

DatabaseLock::~DatabaseLock() {
    if (fd_ >= 0) ::close(fd_);  // closing the descriptor releases the flock
}

} // namespace bsfchat
