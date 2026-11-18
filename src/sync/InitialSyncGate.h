#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>

namespace bsfchat {

// Caps how many initial (since-less) /syncs build at once (audit
// 2-2026-11-18, S2-4).
//
// An initial sync materialises every visible room's state and last timeline
// page, then the whole response again as a JSON DOM: a few hundred KB to a few
// MB per request. After a restart or a network blip every client asks for one
// at the same moment, and 200 at once measured 1.1 GB of RSS on a host whose
// memory is shared with other services. Run a handful at a time instead; the
// rest wait their turn, which costs them little because each one finishes
// faster without the other 199 contending for the same cores and store.
//
// NEVER REFUSES. A request that has waited `patience` proceeds without a slot:
// the gate exists to flatten a spike, and an initial sync that fails or
// returns 429 would only be retried — the same work plus a backoff for the
// user. With a sane patience, overrunning the cap needs the system to be
// stuck already, and then one more request is not what matters.
class InitialSyncGate {
public:
    explicit InitialSyncGate(std::size_t max_in_flight) : max_(max_in_flight) {}

    // RAII: holds one slot while alive. An empty Slot (timed out) holds none.
    class Slot {
    public:
        Slot() = default;
        Slot(Slot&& o) noexcept : gate_(o.gate_) { o.gate_ = nullptr; }
        Slot& operator=(Slot&& o) noexcept {
            if (this != &o) {
                release();
                gate_ = o.gate_;
                o.gate_ = nullptr;
            }
            return *this;
        }
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot() { release(); }

        explicit operator bool() const { return gate_ != nullptr; }

    private:
        friend class InitialSyncGate;
        explicit Slot(InitialSyncGate* g) : gate_(g) {}
        void release() {
            if (gate_) gate_->release();
            gate_ = nullptr;
        }
        InitialSyncGate* gate_ = nullptr;
    };

    Slot enter(std::chrono::milliseconds patience) {
        std::unique_lock lock(mutex_);
        if (!freed_.wait_for(lock, patience, [this] { return in_flight_ < max_; })) {
            return {};
        }
        ++in_flight_;
        return Slot(this);
    }

    // For tests.
    std::size_t in_flight() {
        std::lock_guard lock(mutex_);
        return in_flight_;
    }

private:
    void release() {
        {
            std::lock_guard lock(mutex_);
            --in_flight_;
        }
        freed_.notify_one();
    }

    const std::size_t max_;
    std::mutex mutex_;
    std::condition_variable freed_;
    std::size_t in_flight_ = 0;
};

} // namespace bsfchat
