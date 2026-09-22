#pragma once

#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bsfchat {

// Caps how many /sync long polls one ACCOUNT may have parked at once
// (security-audit-2026-09 finding S7).
//
// httplib runs a whole keep-alive connection on one pool task, so a parked
// /sync holds a worker thread for up to kMaxSyncTimeoutMs (300 s). The pool
// grows to max_workers (512), and a banned account's sync already returns
// without parking, but nothing stopped ONE ordinary account from opening
// hundreds of connections and parking a long poll on each: a handful of
// accounts could hold most of the pool, and the next message send would queue
// behind them — the exact 28-second stall the max_workers change was made to
// end, reintroduced on purpose.
//
// Per account rather than per token because tokens are free: logging in again
// mints another one, so a per-token cap is no cap. The limit is generous for a
// real person — one long poll per signed-in device, plus the overlap while a
// client reconnects and its previous poll has not yet noticed the socket is
// gone.
//
// Past the cap the request is NOT refused: it is served with timeout 0, i.e.
// answered at once with whatever is already there, exactly like a poll that
// found data waiting. A client that is merely over-eager still makes progress
// and stays correct; what it cannot do is hold another worker while it waits.
// Refusing (429) instead would put a legitimate client with one stale extra
// connection into backoff and delay its messages, for no gain over answering.
class ParkedSyncGate {
public:
    explicit ParkedSyncGate(std::size_t max_per_account) : max_(max_per_account) {}

    // RAII: holds one parked slot for an account while alive.
    class Slot {
    public:
        Slot() = default;
        Slot(Slot&& o) noexcept : gate_(o.gate_), key_(std::move(o.key_)) { o.gate_ = nullptr; }
        Slot& operator=(Slot&& o) noexcept {
            if (this != &o) {
                release();
                gate_ = o.gate_;
                key_ = std::move(o.key_);
                o.gate_ = nullptr;
            }
            return *this;
        }
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot() { release(); }

        explicit operator bool() const { return gate_ != nullptr; }

    private:
        friend class ParkedSyncGate;
        Slot(ParkedSyncGate* g, std::string k) : gate_(g), key_(std::move(k)) {}
        void release() {
            if (gate_) gate_->release(key_);
            gate_ = nullptr;
        }
        ParkedSyncGate* gate_ = nullptr;
        std::string key_;
    };

    // A granted slot, or an empty one when the account is already at the cap.
    Slot try_park(const std::string& account) {
        std::lock_guard lock(mutex_);
        auto& n = parked_[account];
        if (n >= max_) {
            if (n == 0) parked_.erase(account);  // max_ == 0: never leave a zero row
            return {};
        }
        ++n;
        return Slot(this, account);
    }

    // For tests.
    std::size_t parked_for(const std::string& account) {
        std::lock_guard lock(mutex_);
        auto it = parked_.find(account);
        return it == parked_.end() ? 0 : it->second;
    }

private:
    void release(const std::string& account) {
        std::lock_guard lock(mutex_);
        auto it = parked_.find(account);
        if (it == parked_.end()) return;
        // Rows are erased at zero so the map is bounded by accounts currently
        // polling, not by every account that ever did.
        if (--it->second == 0) parked_.erase(it);
    }

    const std::size_t max_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::size_t> parked_;
};

} // namespace bsfchat
