#include "core/RateLimiter.h"

#include <iterator>

namespace bsfchat {

namespace {

// Hard ceiling on tracked keys. Keys are attacker-chosen (source addresses,
// submitted usernames), so without a bound the maps are a memory-exhaustion
// vector in their own right. Pruning normally keeps them far below this.
//
// What happens AT the bound is the part that matters, and it used to be wrong
// (security-audit-2026-09 finding S5). Both maps were clear()ed wholesale the
// moment they reached it — deliberately, on the theory that failing open for
// one window beat failing closed. But "open" meant every in-force lockout on
// the server, including the one on the account actually being brute-forced,
// was discarded with its counter reset to zero; and the flush was cheap to
// trigger, because the tracker is keyed on the SUBMITTED username, so 100k
// junk identifiers bought a clean slate against every account at once.
//
// Now each map evicts one entry per new key once full, and never clears:
//
//  * RateLimiter evicts its least recently SEEN key. A refused attempt still
//    counts as "seen", so a key under active attack stays hot and keeps its
//    window; what goes is the address that has been quiet the longest.
//  * FailureTracker evicts the stalest key that is merely counting failures,
//    and a LOCKED key only when there is nothing else — a lockout is the
//    protection itself, whereas a forgotten partial count only delays one.
//
// Still fails open in the one sense that is unavoidable with bounded memory: a
// cold enough entry can be pushed out. It no longer fails open for anyone who
// is currently locked out or being actively rate-limited.
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

    auto it = events_.find(key);
    if (it == events_.end()) {
        if (events_.size() >= kMaxTrackedKeys && !lru_.empty()) {
            erase_locked(events_.find(lru_.back()));
        }
        lru_.push_front(key);
        it = events_.emplace(key, Entry{{}, lru_.begin()}).first;
    } else {
        lru_.splice(lru_.begin(), lru_, it->second.lru);
    }

    auto& q = it->second.times;
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

void RateLimiter::erase_locked(std::unordered_map<std::string, Entry>::iterator it) {
    if (it == events_.end()) return;
    lru_.erase(it->second.lru);
    events_.erase(it);
}

void RateLimiter::prune_locked(int64_t now) {
    // Once per window is enough to bound the map at "keys seen in the last
    // two windows", and keeps the sweep off the per-request path.
    if (now - last_prune_ < window_ms_) return;
    last_prune_ = now;

    const auto cutoff = now - window_ms_;
    for (auto it = events_.begin(); it != events_.end();) {
        auto& q = it->second.times;
        while (!q.empty() && q.front() <= cutoff) q.pop_front();
        if (q.empty()) {
            auto dead = it++;
            erase_locked(dead);
        } else {
            ++it;
        }
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
    if (it->second.locked_until != 0) erase_locked(it);
    return 0;
}

bool FailureTracker::record_failure(const std::string& key) {
    if (max_failures_ <= 0) return false;

    std::lock_guard lock(mutex_);
    const auto now = clock_();
    prune_locked(now);

    auto it = entries_.find(key);
    if (it == entries_.end()) {
        if (entries_.size() >= kMaxTrackedKeys) evict_one_locked();
        counting_.push_front(key);
        Entry fresh;
        fresh.pos = counting_.begin();
        it = entries_.emplace(key, fresh).first;
    }
    auto& e = it->second;

    // Forget stale failure history so an honest user who mistypes once a week
    // is not gradually locked out.
    if (e.last_failure != 0 && now - e.last_failure > lockout_ms_) {
        e.failures = 0;
        e.locked_until = 0;
    }

    e.failures += 1;
    e.last_failure = now;
    const bool locked = e.failures >= max_failures_;
    if (locked) e.locked_until = now + lockout_ms_;

    // File the entry at the front of the list its state now belongs in.
    auto& from = e.in_locked ? locked_ : counting_;
    auto& to = locked ? locked_ : counting_;
    to.splice(to.begin(), from, e.pos);
    e.in_locked = locked;
    return locked;
}

void FailureTracker::clear(const std::string& key) {
    std::lock_guard lock(mutex_);
    erase_locked(entries_.find(key));
}

size_t FailureTracker::size() {
    std::lock_guard lock(mutex_);
    return entries_.size();
}

void FailureTracker::erase_locked(std::unordered_map<std::string, Entry>::iterator it) {
    if (it == entries_.end()) return;
    (it->second.in_locked ? locked_ : counting_).erase(it->second.pos);
    entries_.erase(it);
}

void FailureTracker::evict_one_locked() {
    // The stalest counting entry; a lockout only when no counting entry is
    // left at all. See kMaxTrackedKeys.
    auto& victims = counting_.empty() ? locked_ : counting_;
    if (victims.empty()) return;
    erase_locked(entries_.find(victims.back()));
}

void FailureTracker::prune_locked(int64_t now) {
    if (now - last_prune_ < lockout_ms_) return;
    last_prune_ = now;

    for (auto it = entries_.begin(); it != entries_.end();) {
        const bool expired = it->second.locked_until <= now &&
                             (now - it->second.last_failure) > lockout_ms_;
        if (expired) {
            auto dead = it++;
            erase_locked(dead);
        } else {
            ++it;
        }
    }
}

} // namespace bsfchat
