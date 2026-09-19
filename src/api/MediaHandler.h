#pragma once

#include "store/SqliteStore.h"
#include "core/SendLimiter.h"

#include <httplib.h>
#include <memory>
#include <optional>
#include <string>

namespace bsfchat {

class MediaStorage;
struct Config;

class MediaHandler {
public:
    // `clock` is injectable so tests can move time instead of sleeping out a
    // rate-limit window.
    MediaHandler(SqliteStore& store, const Config& config,
                 std::shared_ptr<MediaStorage> storage,
                 LimiterClock clock = limiter_steady_now_ms);

    void handle_upload(const httplib::Request& req, httplib::Response& res);
    void handle_download(const httplib::Request& req, httplib::Response& res);

private:
    std::string generate_media_id() const;
    // Resolves the caller from either the Authorization header or an
    // ?access_token= query param (image/video widgets can't set headers).
    std::optional<std::string> authenticate_media(const httplib::Request& req);

    // May `user_id` have the bytes of `media_id`?
    //
    // Media carries no room of its own — POST /upload has no room in it — so
    // the answer comes from the events that NAME the object: VIEW_CHANNEL in
    // any room where one survives. Uploader and profile-avatar are the two
    // explicit exceptions; everything else with no room recorded is refused,
    // because "unattached" must never be read as "public".
    bool may_download(const std::string& user_id, const std::string& media_id,
                      const SqliteStore::MediaMeta& meta);

    SqliteStore& store_;
    const Config& config_;
    std::shared_ptr<MediaStorage> storage_;
    // Per-account upload ceiling. An upload is the largest unit of work an
    // authenticated caller can ask for — a whole file into storage, kept — so
    // it gets the tightest of the three budgets.
    SendLimiter limits_;
};

} // namespace bsfchat
