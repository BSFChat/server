#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <thread>

namespace bsfchat {

class SqliteStore;
class MediaStorage;
struct Config;

// Deletes media objects nothing references any more.
//
// ── What was wrong ────────────────────────────────────────────────────────
// Media had no erasure path at all. SqliteStore::delete_media and
// MediaStorage::remove both existed and both had zero callers in src/.
// redact_event() strips the mxc out of the event content and drops the ACL
// row, so the object stops being *reachable* through the product — but the
// bytes stayed on disk and stayed served, indefinitely, to anyone who had
// noted the id before the deletion. Deleting the whole channel did not help
// either. So:
//
//   Alice posts an image. Bob notes the mxc. Alice deletes the message; her
//   client says "deleted" and she believes the image is gone. Bob replays the
//   URL and gets 200, forever.
//
// "Delete" that does not delete is the worst kind of privacy control, because
// the person relying on it stops looking for another one. Separately,
// data/media/ grew monotonically for the life of a deployment: every upload
// that was never sent, every attachment in every deleted channel, all of it.
//
// ── Why a sweep and not a delete at the redaction site ────────────────────
// Spelled out at SqliteStore::find_orphaned_media, which is the query this
// runs. The short version: a blob is a file and a redaction is a transaction,
// no unlink() can be rolled back, one object can be referenced from several
// rooms so no single site can answer "is this unreferenced now", and only a
// sweep collects uploads that were never attached to anything.
//
// ── Ordering, and what a crash leaves behind ──────────────────────────────
// Blob first, then the row. That order is deliberate and it is the safe one:
//
//   * blob then row, interrupted → the row survives with no bytes behind it.
//     The object 404s, the next sweep finds the row again and removes it.
//     Recoverable, and it never serves anything.
//   * row then blob, interrupted → the bytes survive with nothing pointing at
//     them. Nothing will ever find them again, because the sweep's own input
//     is the media table. That is a permanent leak of the exact data the
//     sweep exists to destroy.
//
// So the failure mode is "a dead row for one interval", not "an undeletable
// orphan forever".
//
// ── Dry run ───────────────────────────────────────────────────────────────
// `media_reaper_dry_run` defaults to TRUE, and it should stay that way for
// one release. This is the first code in this server that deletes user data
// from disk on a timer; an operator should be able to read a log of what it
// WOULD have removed, against their own corpus, before arming it. sweep_once()
// returns the same count either way, and logs every candidate at info in dry
// run, so "what would this have done last night" is a grep.
class MediaReaper {
public:
    MediaReaper(SqliteStore& store, const Config& config,
                std::shared_ptr<MediaStorage> storage);
    ~MediaReaper();

    MediaReaper(const MediaReaper&) = delete;
    MediaReaper& operator=(const MediaReaper&) = delete;

    void start();
    void stop();

    // One pass. Returns how many objects were collected — or, in dry run,
    // would have been. Public so tests can drive it without a thread, and so
    // the sweep can be exercised against a storage double.
    //
    // `now_ms` is injectable for the same reason: the grace period is measured
    // in hours and a test must not sleep one out.
    size_t sweep_once(int64_t now_ms = 0);

    // Largest number of objects one pass will collect. A backlog is worked
    // through over successive passes rather than in one that holds the store's
    // mutex for minutes.
    static constexpr int kMaxPerSweep = 500;

private:
    SqliteStore& store_;
    const Config& config_;
    std::shared_ptr<MediaStorage> storage_;

    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_ = false;
};

} // namespace bsfchat
