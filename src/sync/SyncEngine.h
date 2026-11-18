#pragma once

#include <bsfchat/MatrixTypes.h>

#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace bsfchat {

class SqliteStore;
struct Config;

// One entry of /sync's rooms.leave section (audit 2026-11-15, R-1): "drop this
// room". Every key in the section means exactly that, whatever the reason.
//
// NOT IN THE PROTOCOL TYPES YET. bsfchat-protocol's SyncResponse has no leave
// field and CI builds this server against protocol main, so the section is
// carried beside the response and written into the serialised JSON by
// attach_leave_section() below. Fold it into SyncResponse (as
// rooms.leave: map<room_id, LeftRoom>) the next time protocol is released,
// and delete the side channel.
struct LeftRoom {
    // "leave" | "kick" | "ban" | "deleted" | "no_access". On the wire as
    // `bsfchat.reason`.
    std::string reason;
    // The reader's own m.room.member leave/ban event, when there is one. Empty
    // for "deleted" and "no_access", and for a departure whose member event had
    // not been written yet when the response was built.
    std::vector<RoomEvent> timeline;
};
using LeftRooms = std::map<std::string, LeftRoom>;

// A /sync answer: the protocol response plus the sections the protocol type
// cannot carry yet.
struct SyncResult {
    SyncResponse response;
    LeftRooms leave;
    // For SyncHandler's presence pass (S2-4): the stream position the
    // caller's token named when this response returned because something
    // happened, so only presence that changed since then need be restated;
    // -1 (restate every peer) for an initial sync, an idle timeout reply and
    // a timeout=0 poll. See PresenceHandler::live_for_sync().
    int64_t presence_since = -1;
};

// Writes `leave` into a serialised /sync response as
//   "rooms": { "leave": { "<room_id>": {
//       "bsfchat.reason": "...",
//       "timeline": { "events": [ ... ] } } } }
// No-op when `leave` is empty, so a response with nothing to drop is
// byte-identical to what this server sent before the section existed.
// Temporary — see LeftRoom.
void attach_leave_section(nlohmann::json& response_json, const LeftRooms& leave);

class SyncEngine {
public:
    SyncEngine(SqliteStore& store, const Config& config);

    // Notify that a new event was inserted. Wakes all waiting sync requests.
    void notify_new_event();

    // Notify that ephemeral (EDU) state changed — typing, presence. These
    // insert no event, so the stream position is unchanged and a waiter
    // blocked on it would never wake; the sync predicate watches a separate
    // counter that this bumps.
    //
    // BROADCAST: every parked poll on the server returns, and each one then
    // runs a full pass. Prefer notify_ephemeral_for() whenever the change
    // concerns a known set of accounts; this remains for a change whose
    // audience cannot be named, and for tests.
    void notify_ephemeral();

    // The same, scoped (audit 2026-11-15, R-2): only polls parked by one of
    // `user_ids` return. The caller names everyone the change can be visible
    // to — a SUPERSET is always safe, a missing account is a change that
    // account waits a whole timeout for:
    //   * read marker, account data: the writing account (its other devices);
    //   * typing in a room: every joined member of that room;
    //   * presence: every account sharing a joined room with the subject, and
    //     the subject.
    void notify_ephemeral_for(const std::vector<std::string>& user_ids);
    void notify_ephemeral_for(const std::string& user_id);

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
    // The same, plus rooms.leave. What SyncHandler serves; handle_sync() is
    // this with the leave section dropped, kept so the many callers that only
    // read the protocol response do not have to change.
    SyncResult handle_sync_full(const std::string& user_id,
                                const std::string& since_token,
                                int timeout_ms);

    // Test seam. Runs inside build_incremental_sync, in the instant after the
    // scan (and the stream head that goes with it) has been taken and before
    // anything is built from it — i.e. exactly the window in which a racing
    // insert used to be lost, or held back until some later event woke the
    // poll. Tests use it to land an event there deterministically instead of
    // trying to hit the window with sleeps. Never set in production.
    void set_post_scan_hook_for_test(std::function<void()> hook);

    // Per-(account, room) visibility answers carried ACROSS polls (S2-4),
    // keyed on SqliteStore::visibility_generation() exactly like
    // SyncHandler's restate cache: every write that can change a room's
    // VIEW_CHANNEL answer or its category-ness bumps the generation, and a
    // stale generation drops the lot. Without it each woken poll re-ran a
    // permission evaluation (roles, member roles, overrides, room type) per
    // room in its delta — once per parked poll per message.
    //
    // Values are the .cpp's RoomView. Public only so the free helper there can
    // reach it; nothing outside SyncEngine.cpp touches it.
    struct ViewCache {
        std::mutex mutex;
        uint64_t generation = UINT64_MAX;
        std::unordered_map<std::string, int> views;  // "<user>\x1f<room>" -> RoomView
    };

private:
    SyncResponse build_initial_sync(const std::string& user_id);
    // `out_covered_pos`, when given, receives the stream position this scan is
    // known to have covered: every event at or below it has been offered to
    // this user. It is what next_batch is built from, and what a wait must
    // compare the stream head against — re-reading the head after the scan
    // instead is how an event that landed during the scan ends up neither
    // delivered nor waited for.
    //
    // `out_truncated`, when given, is set when the scan stopped at its row
    // limit, i.e. there are certainly more rows past `out_covered_pos` this
    // user has not been offered yet.
    SyncResult build_incremental_sync(const std::string& user_id, int64_t since_pos,
                                      int64_t* out_covered_pos = nullptr,
                                      bool* out_truncated = nullptr);

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
    // Scoped ephemeral changes: the clock value of the latest change that
    // concerns each account. Values come from `user_ephemeral_clock_`, which
    // only ever increases, so a waiter compares its entry snapshot with `!=`
    // and can never be fooled by a reset. Rows are never erased for the same
    // reason; the map is bounded by the number of accounts. Both guarded by
    // wait_mutex_ — the same rule as the two counters above.
    std::unordered_map<std::string, uint64_t> user_ephemeral_seq_;
    uint64_t user_ephemeral_clock_ = 0;
    // Caller must hold wait_mutex_. 0 for an account never notified.
    uint64_t user_ephemeral_seq_locked(const std::string& user_id) const;
    ViewCache view_cache_;
    // Set once before any sync runs, by tests only.
    std::function<void()> post_scan_hook_for_test_;
};

} // namespace bsfchat
