#include "api/MediaHandler.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "storage/MediaStorage.h"
#include "store/SqliteStore.h"

#include <nlohmann/json.hpp>
#include <openssl/rand.h>

#include <algorithm>
#include <cstddef>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

namespace bsfchat {

namespace {

// Bytes read from storage — and handed to the socket — per content-provider
// invocation. httplib's write_content() loop re-invokes the provider with an
// advanced offset until the whole requested window has been written, so a
// provider is free to satisfy only part of the window per call. That makes THIS
// the peak buffer a download holds: not the object size, and not the requested
// range length. `Range: bytes=0-49999999` on a 50 MB object streams in 64 KB
// steps rather than allocating 50 MB.
constexpr size_t kDownloadChunkBytes = 64 * 1024;

// Cap on ranges in one Range header. A multi-range request becomes a
// multipart/byteranges response, costing one storage read per range plus
// framing httplib sizes up front; httplib's own cap (CPPHTTPLIB_RANGE_MAX_COUNT
// = 1024) is far more fan-out than any media client asks for, and is a cheap
// request-amplification lever. RFC 9110 s14.2 explicitly permits rejecting a
// Range header that asks for many small ranges, so reject past this with 416.
constexpr size_t kMaxRangeCount = 4;

// Mirror of httplib's detail::range_error() normalisation (see
// `inline bool range_error` in httplib.h). httplib re-derives and validates
// these ranges itself *after* the handler returns, and answers 416 with no
// Content-Range header — which RFC 9110 s15.5.17 requires so a client can
// learn the real length. We therefore make the same determination here, up
// front, and emit the properly-formed 416 ourselves. Deliberately bug-for-bug
// compatible: notably a suffix range longer than the object (`bytes=-999` on a
// 10-byte object) is unsatisfiable to httplib, so it is unsatisfiable here too,
// rather than being clamped to the whole object.
bool range_satisfiable(const httplib::Range& r, size_t content_length) {
    auto len = static_cast<ssize_t>(content_length);
    ssize_t first = r.first;
    ssize_t last = r.second;

    if (first == -1 && last == -1) {
        first = 0;
        last = len;
    }
    if (first == -1) {
        // Suffix form (`bytes=-N`): the last N bytes. N == 0 lands on
        // first == len, which fails the ordering check below — correct, there
        // is no such thing as a satisfiable zero-length range.
        first = len - last;
        last = len - 1;
    }
    if (last == -1 || last >= len) {
        // Open-ended form (`bytes=N-`), or a last-pos past the end: RFC 9110
        // s14.1.2 says clamp to the remainder of the representation.
        last = len - 1;
    }

    return 0 <= first && first <= last && last <= len - 1;
}

// True when httplib would reject the whole Range header. Also replicates
// httplib's "no more than two overlapping ranges" DoS guard so that every 416
// we can foresee is one we emit with a Content-Range.
bool ranges_unsatisfiable(const httplib::Ranges& ranges, size_t content_length) {
    if (ranges.size() > kMaxRangeCount) {
        return true;
    }

    std::vector<std::pair<ssize_t, ssize_t>> seen;
    size_t overlapping = 0;

    for (const auto& r : ranges) {
        if (!range_satisfiable(r, content_length)) {
            return true;
        }

        auto len = static_cast<ssize_t>(content_length);
        ssize_t first = r.first;
        ssize_t last = r.second;
        if (first == -1) {
            first = len - last;
            last = len - 1;
        }
        if (last == -1 || last >= len) {
            last = len - 1;
        }

        for (const auto& prev : seen) {
            if (!(last < prev.first || first > prev.second)) {
                if (++overlapping > 2) {
                    return true;
                }
                break;
            }
        }
        seen.emplace_back(first, last);
    }

    return false;
}

} // namespace

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

    // No copy: `auto body = req.body` duplicated the entire upload, doubling
    // peak memory for every request. MediaStorage::upload takes a const ref.
    //
    // Note this size check is a backstop only — by the time a handler runs,
    // httplib has already buffered the whole request body. The real cap is
    // Server::set_payload_max_length(), configured from max_upload_size_mb, so
    // an oversized POST is rejected while streaming instead of after it has
    // been fully materialised in memory.
    const std::string& body = req.body;
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

std::optional<std::string> MediaHandler::authenticate_media(const httplib::Request& req) {
    // Header first — that's what every other endpoint uses.
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (user_id) return user_id;

    // Fall back to ?access_token=, the legacy Matrix media auth mechanism.
    // Media URLs are handed straight to image/video widgets, which cannot
    // attach an Authorization header, so this is the only way an authenticated
    // download can work from a plain <img>-style consumer.
    if (req.has_param("access_token")) {
        return store_.get_user_by_token(req.get_param_value("access_token"));
    }
    return std::nullopt;
}

void MediaHandler::handle_download(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    // Media ids are 128-bit random, so an unauthenticated download is
    // capability-URL security: no revocation, no per-room ACL, and the URL
    // leaks through any surface that records it. When require_media_auth is
    // on, a valid access token is required.
    //
    // Defaults ON. The desktop client appends ?access_token= to every media
    // URL it builds (client/src/util/MediaUrl.h) because QML Image.source
    // cannot attach an Authorization header. A deployment fronting clients
    // older than that has to set [media] require_auth = false.
    if (config_.require_media_auth && !authenticate_media(req)) {
        res.status = 401;
        res.set_content(R"({"errcode":"M_UNKNOWN_TOKEN","error":"Invalid or missing access token"})",
                        "application/json");
        return;
    }

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

    // Size and content type only — NOT the bytes. The previous implementation
    // called storage_->download(), which materialises the entire object as a
    // std::string, and then let httplib slice a range out of it: a 1-byte
    // `Range:` request on a 50 MB video allocated 50 MB, and a client seeking
    // around a video multiplied that per request.
    auto info = storage_->stat(media_id);
    if (!info) {
        log->error("Media {} found in DB but missing from storage", media_id);
        res.status = 404;
        res.set_content(R"({"errcode":"M_NOT_FOUND","error":"Media file not found"})",
                        "application/json");
        return;
    }

    std::string content_type = info->content_type;
    if (content_type.empty()) {
        content_type = meta->content_type;
    }
    if (content_type.empty()) {
        content_type = "application/octet-stream";
    }

    // Determine filename for Content-Disposition
    std::string filename = requested_filename.empty() ? meta->filename : requested_filename;
    if (!filename.empty()) {
        res.set_header("Content-Disposition", "inline; filename=\"" + filename + "\"");
    }

    res.set_header("Accept-Ranges", "bytes");

    // httplib parses the Range header before dispatch (a syntactically
    // malformed one is answered 416 without ever reaching this handler, so
    // nothing here can throw on one) and leaves the parsed, un-normalised
    // ranges in req.ranges. What it does not do is attach a Content-Range to
    // its own 416, so satisfiability is checked here.
    if (!req.ranges.empty() && ranges_unsatisfiable(req.ranges, info->size)) {
        res.status = 416;
        res.set_header("Content-Range", "bytes */" + std::to_string(info->size));
        res.set_content(R"({"errcode":"M_UNKNOWN","error":"Requested range not satisfiable"})",
                        "application/json");
        return;
    }

    // Serve via a content provider so httplib handles HTTP Range
    // requests natively. AVFoundation on macOS / Media Foundation on
    // Windows / GStreamer on Linux all issue `Range:` requests for
    // video streaming and refuse to play if the server doesn't respond
    // with `206 Partial Content` — the previous `set_content` path
    // returned a plain 200 every time, which manifested to users as
    // "Failed to load media" on every video/audio attachment.
    //
    // Declaring the full object size (not the range length) is what lets
    // httplib compute `Content-Range` and drive the multipart/byteranges
    // framing; it then calls the provider only for the offsets it actually
    // needs, and the provider reads only those bytes from storage.
    //
    // A zero-length object needs no special case: set_content_provider()
    // installs nothing when the declared length is 0, so httplib answers a
    // plain `Content-Length: 0` and the provider below is never entered with
    // offset == total == 0. MediaRangeHandler.ZeroLengthObjectDoesNotInstall-
    // AContentProvider pins that upstream behaviour, because it is the reason
    // the no-progress guard below cannot fire on legitimate empty media.
    auto storage = storage_;
    auto scratch = std::make_shared<std::string>();
    const size_t total = info->size;
    res.set_content_provider(
        total,
        content_type,
        [storage, media_id, total, scratch](size_t offset, size_t length,
                                            httplib::DataSink& sink) {
            // Known-length variant: httplib tracks completion by byte
            // count and will stop calling us once `content_length` has
            // been sent. Don't call sink.done() — that's for the
            // chunked (unknown-length) overload; calling it here nukes
            // the sink's internal write function and a subsequent
            // invocation crashes with std::bad_function_call.
            if (offset >= total) {
                // Would write nothing; httplib's write loop advances only by
                // bytes written, so returning true here spins forever.
                // Returning false ends the transfer instead.
                return false;
            }

            size_t want = std::min(length, total - offset);
            want = std::min(want, kDownloadChunkBytes);

            // `scratch` is reused across calls, so a long transfer allocates
            // one chunk-sized buffer, not one per chunk.
            if (!storage->download_range(media_id, offset, want, *scratch)) {
                return false;
            }
            if (scratch->empty()) {
                // Short read — the object shrank underneath us. No progress is
                // possible, so stop rather than loop.
                return false;
            }

            sink.write(scratch->data(), std::min(scratch->size(), want));
            return true;
        });
}

} // namespace bsfchat
