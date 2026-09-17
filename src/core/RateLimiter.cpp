#include "core/RateLimiter.h"

#include <iterator>

namespace bsfchat {

namespace {

// Hard ceiling on tracked keys. Keys are attacker-chosen (source addresses,
// submitted usernames), so without a bound the maps are a memory-exhaustion
// vector in their own right. Pruning normally keeps them far below this; if a
// flood of distinct keys outruns it, the history is dropped wholesale. That
// fails OPEN for one window — deliberately: failing closed would turn the
// limiter into the denial of service it exists to prevent.
constexpr size_t kMaxTrackedKeys = 100'000;

} // namespace

int64_t limiter_steady_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

RateLimiter::RateLimiter(int max_events, std::chrono::seconds window, LimiterClock clock)
    : max_events_(max_events)
    , window_ms_(std::chrono::duration_cast<std::chrono::milliseconds>(window).count())
    , clock_(std::move(clock)) {}

int64_t RateLimiter::acquire(const std::string& key) {
    if (max_events_ <= 0) return 0;

    std::lock_guard lock(mutex_);
    const auto now = clock_();
    prune_locked(now);

    auto& q = events_[key];
    const auto cutoff = now - window_ms_;
    while (!q.empty() && q.front() <= cutoff) q.pop_front();

    if (static_cast<int>(q.size()) >= max_events_) {
        return q.front() + window_ms_ - now;
    }
    q.push_back(now);
    return 0;
}

size_t RateLimiter::size() {
    std::lock_guard lock(mutex_);
    return events_.size();
}

void RateLimiter::prune_locked(int64_t now) {
    if (events_.size() >= kMaxTrackedKeys) {
        events_.clear();
        last_prune_ = now;
        return;
    }
    // Once per window is enough to bound the map at "keys seen in the last
    // two windows", and keeps the sweep off the per-request path.
    if (now - last_prune_ < window_ms_) return;
    last_prune_ = now;

    const auto cutoff = now - window_ms_;
    for (auto it = events_.begin(); it != events_.end();) {
        auto& q = it->second;
        while (!q.empty() && q.front() <= cutoff) q.pop_front();
        it = q.empty() ? events_.erase(it) : std::next(it);
    }
}

FailureTracker::FailureTracker(int max_failures, std::chrono::seconds lockout, LimiterClock clock)
    : max_failures_(max_failures)
    , lockout_ms_(std::chrono::duration_cast<std::chrono::milliseconds>(lockout).count())
    , clock_(std::move(clock)) {}

int64_t FailureTracker::locked_for(const std::string& key) {
    if (max_failures_ <= 0) return 0;

    std::lock_guard lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end()) return 0;

    const auto now = clock_();
    if (it->second.locked_until > now) return it->second.locked_until - now;
    // Lockout elapsed — start the counter over rather than letting the attacker
    // resume from max_failures - 1.
    if (it->second.locked_until != 0) entries_.erase(it);
    return 0;
}

bool FailureTracker::record_failure(const std::string& key) {
    if (max_failures_ <= 0) return false;

    std::lock_guard lock(mutex_);
    const auto now = clock_();
    prune_locked(now);

    auto& e = entries_[key];

    // Forget stale failure history so an honest user who mistypes once a week
    // is not gradually locked out.
    if (e.last_failure != 0 && now - e.last_failure > lockout_ms_) {
        e.failures = 0;
        e.locked_until = 0;
    }

    e.failures += 1;
    e.last_failure = now;
    if (e.failures >= max_failures_) {
        e.locked_until = now + lockout_ms_;
        return true;
    }
    return false;
}

void FailureTracker::clear(const std::string& key) {
    std::lock_guard lock(mutex_);
    entries_.erase(key);
}

size_t FailureTracker::size() {
    std::lock_guard lock(mutex_);
    return entries_.size();
}

void FailureTracker::prune_locked(int64_t now) {
    if (entries_.size() >= kMaxTrackedKeys) {
        entries_.clear();
        last_prune_ = now;
        return;
    }
    if (now - last_prune_ < lockout_ms_) return;
    last_prune_ = now;

    for (auto it = entries_.begin(); it != entries_.end();) {
        const bool expired = it->second.locked_until <= now &&
                             (now - it->second.last_failure) > lockout_ms_;
        it = expired ? entries_.erase(it) : std::next(it);
    }
}

} // namespace bsfchat
