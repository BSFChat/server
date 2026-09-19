#include "storage/MediaReaper.h"

#include "core/Config.h"
#include "core/Logger.h"
#include "storage/MediaStorage.h"
#include "store/SqliteStore.h"

#include <exception>
#include <utility>

namespace bsfchat {

namespace {

int64_t now_ms_now() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // namespace

MediaReaper::MediaReaper(SqliteStore& store, const Config& config,
                         std::shared_ptr<MediaStorage> storage)
    : store_(store), config_(config), storage_(std::move(storage)) {}

MediaReaper::~MediaReaper() { stop(); }

size_t MediaReaper::sweep_once(int64_t now_ms) {
    auto log = get_logger();
    if (now_ms == 0) now_ms = now_ms_now();

    const int64_t grace_ms =
        static_cast<int64_t>(config_.media_orphan_grace_hours) * 3600 * 1000;
    const int64_t cutoff = now_ms - grace_ms;

    std::vector<SqliteStore::MediaMeta> orphans;
    try {
        orphans = store_.find_orphaned_media(config_.server_name, cutoff, kMaxPerSweep);
    } catch (const std::exception& e) {
        log->error("Media reaper: could not list orphans: {}", e.what());
        return 0;
    }
    if (orphans.empty()) return 0;

    const bool dry_run = config_.media_reaper_dry_run;
    size_t collected = 0;
    int64_t bytes = 0;

    for (const auto& meta : orphans) {
        if (dry_run) {
            // The whole point of dry run is that this line is greppable
            // against a real corpus before anything is armed. Uploader and
            // size are there so an operator can recognise what they are
            // looking at; the filename is NOT logged, because a filename is
            // user content and this runs at info.
            log->info("Media reaper (dry run): would delete {} ({} bytes, {}, uploaded by {})",
                      meta.media_id, meta.file_size, meta.content_type, meta.uploader);
            ++collected;
            bytes += meta.file_size;
            continue;
        }

        // Blob before row. See the header: the interrupted-halfway case has to
        // leave a dead row (recoverable, serves nothing) rather than an
        // unreferenced blob (permanent, and it is the data we are here to
        // destroy).
        bool removed = false;
        try {
            removed = storage_->remove(meta.media_id);
        } catch (const std::exception& e) {
            log->error("Media reaper: could not remove blob {}: {}", meta.media_id, e.what());
            continue;
        }
        if (!removed) {
            // The bytes are already gone — a previous pass that died between
            // the two steps, or an operator with a shovel. The row is still
            // wrong and still has to go, so this is not a failure; falling
            // through is what makes the crash case self-healing.
            log->warn("Media reaper: blob {} was already absent; removing its row", meta.media_id);
        }

        try {
            store_.delete_media(meta.media_id);
        } catch (const std::exception& e) {
            log->error("Media reaper: removed blob {} but its row survives: {}",
                       meta.media_id, e.what());
            continue;
        }
        ++collected;
        bytes += meta.file_size;
    }

    if (collected > 0) {
        log->info("Media reaper: {} {} unreferenced object(s), {} bytes",
                  dry_run ? "would collect" : "collected", collected, bytes);
    }
    // A full sweep means there is more waiting; say so, because the gap
    // between "the reaper ran" and "the disk stopped growing" is otherwise a
    // mystery on a deployment with a large backlog.
    if (orphans.size() >= static_cast<size_t>(kMaxPerSweep)) {
        log->info("Media reaper: hit the {}-object per-sweep cap; more remain for the next pass",
                  kMaxPerSweep);
    }
    return collected;
}

void MediaReaper::start() {
    if (thread_.joinable()) return;

    auto log = get_logger();
    if (!config_.media_reaper_enabled) {
        log->info("Media reaper: disabled by configuration; unreferenced media will accumulate");
        return;
    }
    // Loud, once, at startup. An operator who has not read the config needs to
    // know from the log whether anything is actually being deleted tonight.
    if (config_.media_reaper_dry_run) {
        log->info("Media reaper: DRY RUN — every {} min it will log what it would delete "
                  "(orphan grace {} h) and delete nothing. Set media_reaper_dry_run = false "
                  "to arm it.",
                  config_.media_reaper_interval_minutes, config_.media_orphan_grace_hours);
    } else {
        log->info("Media reaper: ARMED — every {} min, objects unreferenced for {} h are "
                  "deleted from storage permanently",
                  config_.media_reaper_interval_minutes, config_.media_orphan_grace_hours);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = false;
    }
    thread_ = std::thread([this] {
        const auto interval =
            std::chrono::minutes(config_.media_reaper_interval_minutes);
        std::unique_lock<std::mutex> lock(mutex_);
        // Unlike the voice reaper, this one WAITS before its first pass. There
        // is nothing time-critical about collecting an orphan, and a sweep
        // competing with auto-join backfill and role bootstrap for the store's
        // single global mutex would make every client's first sync of a
        // restart slower for no benefit.
        while (!stop_) {
            cv_.wait_for(lock, interval, [this] { return stop_; });
            if (stop_) break;
            lock.unlock();
            try {
                sweep_once();
            } catch (const std::exception& e) {
                get_logger()->error("Media reaper: sweep failed: {}", e.what());
            }
            lock.lock();
        }
    });
}

void MediaReaper::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

} // namespace bsfchat
