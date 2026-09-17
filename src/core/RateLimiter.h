#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bsfchat {

// Monotonic milliseconds. Injectable so tests can move time instead of
// sleeping through a lockout.
using LimiterClock = std::function<int64_t()>;

// steady_clock, not system_clock: an NTP step or an operator fixing the date
// must not be able to end a lockout early or extend one by hours.
int64_t limiter_steady_now_ms();

// Sliding-window rate limiter keyed by an arbitrary string (a client address,
// or a fixed key for a server-wide cap). Ported from the identity service's
// core/RateLimiter, with two changes: it reports how long until a slot frees
// (so a 429 can carry an honest Retry-After), and it prunes itself on use
// instead of relying on a background sweeper this server does not have.
//
// In-memory and per-process, which is the whole deployment model here. It is
// not a substitute for an edge limit if the server is ever run replicated.
class RateLimiter {
public:
    // max_events <= 0 disables the limiter: acquire() always succeeds.
    RateLimiter(int max_events, std::chrono::seconds window,
                LimiterClock clock = limiter_steady_now_ms);

    // Records an attempt. Returns 0 if it is within the limit, otherwise the
    // number of milliseconds until the oldest recorded attempt leaves the
    // window (always > 0). A refused attempt is not recorded, so hammering a
    // closed limiter does not push the reopening further away.
    int64_t acquire(const std::string& key);

    // Number of keys currently tracked. For tests of the pruning bound.
    size_t size();

private:
    void prune_locked(int64_t now);

    int max_events_;
    int64_t window_ms_;
    LimiterClock clock_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::deque<int64_t>> events_;
    int64_t last_prune_ = 0;
};

// Counts failures for a key and locks it out for a period once a threshold is
// crossed. Used to make credential guessing expensive.
class FailureTracker {
public:
    // max_failures <= 0 disables the tracker: nothing is ever locked.
    FailureTracker(int max_failures, std::chrono::seconds lockout,
                   LimiterClock clock = limiter_steady_now_ms);

    // Milliseconds remaining on an active lockout, or 0 when not locked.
    int64_t locked_for(const std::string& key);

    // Records a failure; returns true if the key is now locked out.
    bool record_failure(const std::string& key);

    // Clears the failure history for a key (call on success).
    void clear(const std::string& key);

    size_t size();

private:
    struct Entry {
        int failures = 0;
        int64_t locked_until = 0;
        int64_t last_failure = 0;
    };

    void prune_locked(int64_t now);

    int max_failures_;
    int64_t lockout_ms_;
    LimiterClock clock_;
    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    int64_t last_prune_ = 0;
};

} // namespace bsfchat
