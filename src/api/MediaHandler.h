#pragma once

#include <httplib.h>
#include <memory>

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

    SqliteStore& store_;
    const Config& config_;
    std::shared_ptr<MediaStorage> storage_;
};

} // namespace bsfchat
