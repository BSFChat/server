#include "api/MediaHandler.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "storage/MediaStorage.h"
#include "store/SqliteStore.h"

#include <nlohmann/json.hpp>
#include <openssl/rand.h>

#include <iomanip>
#include <sstream>

namespace bsfchat {

MediaHandler::MediaHandler(SqliteStore& store, const Config& config,
                           std::shared_ptr<MediaStorage> storage)
    : store_(store), config_(config), storage_(std::move(storage)) {
}

std::string MediaHandler::generate_media_id() const {
    unsigned char bytes[16];
    RAND_bytes(bytes, sizeof(bytes));
    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

void MediaHandler::handle_upload(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    // Authenticate
    auto auth_header = req.get_header_value("Authorization");
    auto user_id = authenticate(store_, auth_header);
    if (!user_id) {
        res.status = 401;
        res.set_content(R"({"errcode":"M_UNKNOWN_TOKEN","error":"Invalid or missing access token"})",
                        "application/json");
        return;
    }

    // Check content length
    auto body = req.body;
    size_t max_bytes = config_.max_upload_size_mb * 1024 * 1024;
    if (body.size() > max_bytes) {
        res.status = 413;
        nlohmann::json err;
        err["errcode"] = "M_TOO_LARGE";
        err["error"] = "Upload exceeds maximum allowed size";
        res.set_content(err.dump(), "application/json");
        return;
    }

    if (body.empty()) {
        res.status = 400;
        res.set_content(R"({"errcode":"M_NOT_JSON","error":"No file data provided"})",
                        "application/json");
        return;
    }

    // Get content type and filename
    auto content_type = req.get_header_value("Content-Type");
    if (content_type.empty()) {
        content_type = "application/octet-stream";
    }

    std::string filename;
    if (req.has_param("filename")) {
        filename = req.get_param_value("filename");
    }

    // Generate media ID and store
    auto media_id = generate_media_id();

    try {
        auto file_path = storage_->upload(media_id, body, content_type, filename);

        // Store metadata in database
        store_.insert_media(media_id, *user_id, content_type, filename,
                           static_cast<int64_t>(body.size()), file_path);

        // Build content URI
        std::string content_uri = "mxc://" + config_.server_name + "/" + media_id;

        nlohmann::json response;
        response["content_uri"] = content_uri;
        res.set_content(response.dump(), "application/json");
        res.status = 200;

        log->info("Media uploaded: {} by {} ({} bytes, {})",
                  media_id, *user_id, body.size(), content_type);
    } catch (const std::exception& e) {
        log->error("Media upload failed: {}", e.what());
        res.status = 500;
        res.set_content(R"({"errcode":"M_UNKNOWN","error":"Failed to store media"})",
                        "application/json");
    }
}

void MediaHandler::handle_download(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    // Extract serverName and mediaId from path
    // Pattern: /_matrix/media/v3/download/{serverName}/{mediaId}
    // or:      /_matrix/media/v3/download/{serverName}/{mediaId}/{fileName}
    auto match_count = req.matches.size();
    if (match_count < 3) {
        res.status = 400;
        res.set_content(R"({"errcode":"M_NOT_FOUND","error":"Invalid media path"})",
                        "application/json");
        return;
    }

    std::string server_name = req.matches[1];
    std::string media_id = req.matches[2];
    std::string requested_filename;
    if (match_count >= 4) {
        requested_filename = req.matches[3];
    }

    // Only serve media from our server
    if (server_name != config_.server_name) {
        res.status = 404;
        res.set_content(R"({"errcode":"M_NOT_FOUND","error":"Media not found on this server"})",
                        "application/json");
        return;
    }

    // Look up metadata
    auto meta = store_.get_media(media_id);
    if (!meta) {
        res.status = 404;
        res.set_content(R"({"errcode":"M_NOT_FOUND","error":"Media not found"})",
                        "application/json");
        return;
    }

    // Download from storage
    auto result = storage_->download(media_id);
    if (!result) {
        log->error("Media {} found in DB but missing from storage", media_id);
        res.status = 404;
        res.set_content(R"({"errcode":"M_NOT_FOUND","error":"Media file not found"})",
                        "application/json");
        return;
    }

    auto& [data, content_type] = *result;

    // Determine filename for Content-Disposition
    std::string filename = requested_filename.empty() ? meta->filename : requested_filename;
    if (!filename.empty()) {
        res.set_header("Content-Disposition", "inline; filename=\"" + filename + "\"");
    }

    // Serve via a content provider so httplib handles HTTP Range
    // requests natively. AVFoundation on macOS / Media Foundation on
    // Windows / GStreamer on Linux all issue `Range:` requests for
    // video streaming and refuse to play if the server doesn't respond
    // with `206 Partial Content` — the previous `set_content` path
    // returned a plain 200 every time, which manifested to users as
    // "Failed to load media" on every video/audio attachment.
    //
    // The captured `data` is an std::string of bytes; we move it into
    // the lambda's shared state and hand slices to the sink on demand.
    auto payload = std::make_shared<std::string>(std::move(data));
    res.set_header("Accept-Ranges", "bytes");
    res.set_content_provider(
        payload->size(),
        content_type,
        [payload](size_t offset, size_t length, httplib::DataSink& sink) {
            if (offset < payload->size()) {
                size_t end = std::min(offset + length, payload->size());
                sink.write(payload->data() + offset, end - offset);
            }
            sink.done();
            return true;
        });
}

} // namespace bsfchat
