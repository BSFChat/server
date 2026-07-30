#pragma once

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
    MediaHandler(SqliteStore& store, const Config& config,
                 std::shared_ptr<MediaStorage> storage);

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
};

} // namespace bsfchat
