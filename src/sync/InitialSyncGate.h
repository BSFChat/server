#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

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
// NEVER REFUSES ON THE GLOBAL CAP. A request that has waited `patience` proceeds without a slot:
// the gate exists to flatten a spike, and an initial sync that fails or
// returns 429 would only be retried — the same work plus a backoff for the
// user. With a sane patience, overrunning the cap needs the system to be
// stuck already, and then one more request is not what matters.
//
// PER ACCOUNT TOO (audit 3, 2026-11-19). The global cap alone let one account
// fill every slot — and garbage `since` tokens used to be served as initial
// syncs without passing the gate at all (SyncHandler now answers those 400).
// An account may hold `max_per_account` slots; a request beyond that waits
// `account_patience` for one of its own to free and is then REFUSED (the
// caller answers 429), the one case where the gate refuses: a client of its
// own does not run more than one initial sync per device at a time, so a
// pile-up on one account is a client bug or abuse, and holding a worker
// thread for each would let it starve everyone else.
class InitialSyncGate {
public:
    explicit InitialSyncGate(std::size_t max_in_flight, std::size_t max_per_account = 0)
        : max_(max_in_flight), max_per_account_(max_per_account) {}

    // RAII: holds what it was granted while alive — an account slot and/or a
    // global slot. `operator bool` is the global slot; refused() means the
    // account was over its limit and nothing was granted.
    class Slot {
    public:
        Slot() = default;
        Slot(Slot&& o) noexcept
            : gate_(o.gate_), account_(std::move(o.account_)), global_(o.global_),
              refused_(o.refused_) {
            o.gate_ = nullptr;
            o.global_ = false;
        }
        Slot& operator=(Slot&& o) noexcept {
            if (this != &o) {
                release();
                gate_ = o.gate_;
                account_ = std::move(o.account_);
                global_ = o.global_;
                refused_ = o.refused_;
                o.gate_ = nullptr;
                o.global_ = false;
            }
            return *this;
        }
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot() { release(); }

        explicit operator bool() const { return global_; }
        bool refused() const { return refused_; }

    private:
        friend class InitialSyncGate;
        void release() {
            if (gate_) gate_->release(account_, global_);
            gate_ = nullptr;
            global_ = false;
        }
        InitialSyncGate* gate_ = nullptr;
        std::string account_;  // empty: holds no account slot
        bool global_ = false;
        bool refused_ = false;
    };

    // Global cap only.
    Slot enter(std::chrono::milliseconds patience) { return enter({}, patience, patience); }

    // The account's own limit first (waiting up to `account_patience`, then
    // refused), then the global cap (waiting out the rest of `patience`, then
    // proceeding without a global slot). An empty account, or a gate built
    // without a per-account limit, skips the first step.
    Slot enter(const std::string& account, std::chrono::milliseconds patience,
               std::chrono::milliseconds account_patience) {
        const auto start = std::chrono::steady_clock::now();
        Slot slot;
        slot.gate_ = this;
        std::unique_lock lock(mutex_);
        if (!account.empty() && max_per_account_ > 0) {
            if (!freed_.wait_until(lock, start + account_patience, [&] {
                    auto it = per_account_.find(account);
                    return it == per_account_.end() || it->second < max_per_account_;
                })) {
                slot.gate_ = nullptr;
                slot.refused_ = true;
                return slot;
            }
            ++per_account_[account];
            slot.account_ = account;
        }
        if (freed_.wait_until(lock, start + patience, [this] { return in_flight_ < max_; })) {
            ++in_flight_;
            slot.global_ = true;
        }
        return slot;
    }

    // For tests.
    std::size_t in_flight() {
        std::lock_guard lock(mutex_);
        return in_flight_;
    }
    std::size_t in_flight_for(const std::string& account) {
        std::lock_guard lock(mutex_);
        auto it = per_account_.find(account);
        return it == per_account_.end() ? 0 : it->second;
    }

private:
    void release(const std::string& account, bool global) {
        {
            std::lock_guard lock(mutex_);
            if (global) --in_flight_;
            if (!account.empty()) {
                auto it = per_account_.find(account);
                if (it != per_account_.end() && --it->second == 0) per_account_.erase(it);
            }
        }
        // All, not one: waiters wait on different predicates (an account's
        // limit, the global cap), and waking the wrong single one loses the
        // wake for the right one.
        freed_.notify_all();
    }

    const std::size_t max_;
    const std::size_t max_per_account_;
    std::mutex mutex_;
    std::condition_variable freed_;
    std::size_t in_flight_ = 0;
    std::unordered_map<std::string, std::size_t> per_account_;
};

} // namespace bsfchat
