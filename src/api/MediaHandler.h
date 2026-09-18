#pragma once

#include "core/SendLimiter.h"

#include <httplib.h>
#include <memory>
#include <optional>
#include <string>

namespace bsfchat {

class SqliteStore;
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

    SqliteStore& store_;
    const Config& config_;
    std::shared_ptr<MediaStorage> storage_;
    // Per-account upload ceiling. An upload is the largest unit of work an
    // authenticated caller can ask for — a whole file into storage, kept — so
    // it gets the tightest of the three budgets.
    SendLimiter limits_;
};

} // namespace bsfchat
