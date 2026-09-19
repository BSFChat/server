#pragma once

#include <bsfchat/MatrixTypes.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace bsfchat {

class SqliteStore;
struct Config;

class SyncEngine {
public:
    SyncEngine(SqliteStore& store, const Config& config);

    // Notify that a new event was inserted. Wakes all waiting sync requests.
    void notify_new_event();

    // Notify that ephemeral (EDU) state changed — typing, presence. These
    // insert no event, so the stream position is unchanged and a waiter
    // blocked on it would never wake; the sync predicate watches a separate
    // counter that this bumps.
    void notify_ephemeral();

    // Handle a /sync request. Blocks up to timeout_ms if no new events.
    //
    // since_token is an OPAQUE token this engine minted — "t_<32 hex>", see
    // sync/SyncToken.h — or the legacy "s{stream_position}" form, still
    // accepted on read so an upgrade does not force every client on the
    // deployment into a full initial sync at once. Empty means initial sync,
    // and so does anything unrecognised.
    SyncResponse handle_sync(const std::string& user_id,
                              const std::string& since_token,
                              int timeout_ms);

    // Test seam. Runs inside build_incremental_sync, in the instant after the
    // scan (and the stream head that goes with it) has been taken and before
    // anything is built from it — i.e. exactly the window in which a racing
    // insert used to be lost, or held back until some later event woke the
    // poll. Tests use it to land an event there deterministically instead of
    // trying to hit the window with sleeps. Never set in production.
    void set_post_scan_hook_for_test(std::function<void()> hook);

private:
    SyncResponse build_initial_sync(const std::string& user_id);
    // `out_covered_pos`, when given, receives the stream position this scan is
    // known to have covered: every event at or below it has been offered to
    // this user. It is what next_batch is built from, and what a wait must
    // compare the stream head against — re-reading the head after the scan
    // instead is how an event that landed during the scan ends up neither
    // delivered nor waited for.
    SyncResponse build_incremental_sync(const std::string& user_id, int64_t since_pos,
                                        int64_t* out_covered_pos = nullptr);

    // The key next_batch is built with, derived from this deployment's instance
    // secret on first use and cached for the process. Lazy rather than
    // constructed eagerly because the secret is generated on first use too, and
    // a SyncEngine is built before anything has asked for a token.
    const std::vector<unsigned char>& token_key();
    // "t_<32 hex>" naming `position` for `user_id`. Every next_batch this
    // engine emits goes through here — including the banned-account reply,
    // which does not build a sync at all.
    std::string mint_token(const std::string& user_id, int64_t position);
    // The position a caller's token names, or 0 for an unrecognised one. Zero
    // is a full replay of what THAT caller may see and has always been how a
    // malformed token was treated; /sync has never answered 400 for one.
    int64_t parse_token(const std::string& user_id, const std::string& token);

    SqliteStore& store_;
    const Config& config_;
    std::once_flag token_key_once_;
    std::vector<unsigned char> token_key_;
    std::mutex wait_mutex_;
    std::condition_variable new_event_cv_;
    // Both are written only while holding wait_mutex_. Mutating them outside
    // the lock loses a notification that lands between a waiter's predicate
    // check and its block, costing that client up to a full poll timeout.
    std::atomic<int64_t> current_position_{0};
    std::atomic<uint64_t> ephemeral_seq_{0};
    // Set once before any sync runs, by tests only.
    std::function<void()> post_scan_hook_for_test_;
};

} // namespace bsfchat
