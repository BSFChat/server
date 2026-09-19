#include "api/MediaHandler.h"
#include "api/MediaPolicy.h"
#include "auth/Permissions.h"
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
        // M_INVALID_PARAM, not M_NOT_JSON. This endpoint takes a raw binary body —
        // an image, a video, a zip — and never parses JSON at all, so telling a
        // client "your request body is not JSON" pointed at a problem that could
        // not exist and sent anyone debugging it looking for a serialisation bug.
        // The actual fault is a request parameter (the body) being unusable, which
        // is what M_INVALID_PARAM means, and it sits alongside the M_TOO_LARGE
        // above as the other end of the same size check.
        //
        // Safe to change: no client compares against this code. The upload error
        // path is errcode-agnostic — MatrixClient's uploadMedia handler passes the
        // raw response body straight through to a toast without parsing it — and
        // the only errcode comparisons anywhere in the client are on the message
        // send and /sync paths, neither of which this reaches.
        res.status = 400;
        res.set_content(
            MatrixError::invalid_param("No file data provided").to_json().dump(),
            "application/json");
        return;
    }

    // NEVER store the uploader's Content-Type verbatim.
    //
    // This header used to go straight into the media row and straight back out
    // on download, which meant an uploader chose the type their bytes would be
    // served as. `Content-Type: text/html` on a file named `Q3-budget.pdf`, and
    // the victim's browser executed the attacker's page on the chat origin with
    // the victim's access token in location.search. See MediaPolicy.h.
    //
    // normalise_content_type() answers with an allowlisted type whose magic
    // bytes agree with it, or application/octet-stream. The header is now a
    // hint, not a decision.
    auto content_type = media_policy::normalise_content_type(
        req.get_header_value("Content-Type"), body);

    std::string filename;
    if (req.has_param("filename")) {
        filename = req.get_param_value("filename");
    }

    // Generate media ID and store
    auto media_id = generate_media_id();

    try {
        auto file_path = storage_->upload(media_id, body, content_type, filename);

        // Store metadata in database.
        //
        // If this throws, the blob is already written and nothing will ever
        // reference it: there is no orphan reaper (audit B11), so it would sit
        // in data/media/ for the life of the deployment. Undo the upload rather
        // than leak it. Best-effort — a failed remove is worth a log line and
        // nothing more, since the caller is about to get a 500 either way.
        try {
            store_.insert_media(media_id, *user_id, content_type, filename,
                               static_cast<int64_t>(body.size()), file_path);
        } catch (...) {
            try {
                storage_->remove(media_id);
            } catch (const std::exception& e) {
                log->error("Orphaned media blob {}: metadata insert failed and the "
                           "blob could not be removed: {}", media_id, e.what());
            }
            throw;
        }

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

bool MediaHandler::may_download(const std::string& user_id,
                                const std::string& media_id,
                                const SqliteStore::MediaMeta& meta) {
    // 1. The uploader. They supplied the bytes, and this is also what keeps a
    //    freshly uploaded object fetchable in the window between POST /upload
    //    and the PUT /send that attaches it to a room.
    if (meta.uploader == user_id) return true;

    // The whole URI, not the bare id — see SqliteStore::get_media_rooms().
    const std::string mxc_uri = "mxc://" + config_.server_name + "/" + media_id;

    // 2. VIEW_CHANNEL in any room where a surviving event names this object.
    //    One object can legitimately be in several rooms (a forward, a repost),
    //    and access to any one of those rooms is access to the bytes, because
    //    that room's timeline already shows them.
    auto rooms = store_.get_media_rooms(mxc_uri);
    if (!rooms.empty()) {
        PermissionsEngine perms(store_, config_);
        for (const auto& room_id : rooms) {
            if (perms.can(user_id, room_id, permission::kViewChannel)) return true;
        }
        return false;
    }

    // 3. Room-less media. This is the case the fix turns on: "no room recorded"
    //    must mean "nobody", not "everybody", or the backfill gap and every
    //    future ingestion path become the bypass.
    //
    //    The one legitimate room-less class is a profile avatar, which is shown
    //    next to its owner's name everywhere and is already disclosed by
    //    /profile, so any authenticated caller may have it.
    return store_.is_avatar_media(mxc_uri);
}

void MediaHandler::handle_download(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    // Media ids are 128-bit random, but that was the ONLY thing protecting an
    // object: the previous implementation checked "is this a live token for
    // some user" and threw the user id away, so a valid token was a server-wide
    // media capability and locking a channel down did nothing for what was
    // already posted in it (audit B3). The caller is now carried through to
    // may_download() below and checked against VIEW_CHANNEL.
    //
    // require_media_auth defaults ON. With it OFF there is no caller to check,
    // so the per-room ACL cannot apply either — turning it off does not merely
    // drop the token requirement, it drops the channel ACL with it.
    auto caller = authenticate_media(req);
    if (config_.require_media_auth && !caller) {
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

    // Per-room ACL. 404, not 403, and byte-identical to the "no such id" answer
    // above: "this id exists but is not yours" is itself worth knowing, and the
    // existing 404/404 symmetry is what makes a media id un-probeable. Nothing
    // is read from storage before this point, so a refused caller cannot even
    // time the difference against a stat().
    if (caller && !may_download(*caller, media_id, *meta)) {
        log->info("Media {} refused to {}: no VIEW_CHANNEL in any room referencing it",
                  media_id, *caller);
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

    // Whatever the storage backend or an older build recorded, the type served
    // is re-checked against the allowlist here. The upload-side normalisation
    // is the primary gate; this is the one that also covers rows written before
    // it existed, a restored backup, or a hand-edited database.
    if (!media_policy::is_inline_safe(content_type) && content_type != "application/pdf") {
        content_type = "application/octet-stream";
    }

    // Response hardening. Every one of these was absent, which is what turned
    // an attacker-chosen Content-Type into script execution on the chat origin.
    //
    //   nosniff          — without it a browser content-sniffs an
    //                      octet-stream body back up to text/html, which would
    //                      undo the normalisation above on its own.
    //   CSP              — defence in depth for the inline-allowlisted types
    //                      and for any future format that turns out to be
    //                      scriptable. `sandbox` with no tokens denies scripts,
    //                      plugins, forms and same-origin, so even a document
    //                      that does render has no origin to steal from.
    //   frame-ancestors  — media must not be framed by a page that then reads
    //   + X-Frame-Options  it; the legacy header is for anything that predates CSP.
    //   Referrer-Policy  — media URLs carry ?access_token= today (see the
    //                      MediaUrl note in the report); no-referrer stops it
    //                      being handed to whatever the media links out to.
    //   CORP             — with Access-Control-Allow-Origin removed below, this
    //                      is what stops another origin embedding the bytes.
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Content-Security-Policy",
                   "default-src 'none'; sandbox; frame-ancestors 'none'; "
                   "base-uri 'none'; form-action 'none'");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Referrer-Policy", "no-referrer");
    res.set_header("Cross-Origin-Resource-Policy", "same-origin");

    // Server::register_routes() sets `Access-Control-Allow-Origin: *` on every
    // response from a pre-routing handler. On media that is an invitation for
    // any page on the internet to read a logged-in user's attachments with
    // their cookies — erase it here rather than weakening it globally, which is
    // a change other packages own. Erased, not re-set: httplib's headers are a
    // multimap and set_header() appends, so setting it again would emit two.
    //
    // No effect on the desktop client: Qt's network stack does not enforce CORS.
    res.headers.erase("Access-Control-Allow-Origin");

    // Content-Disposition is now ALWAYS present. It used to be emitted only
    // when a filename was known, and always as `inline` — so an upload with no
    // filename got no disposition at all and every browser rendered it in
    // place. `inline` is now reserved for the narrow set of types the client
    // has to render (bitmap images, video, audio); everything else, including
    // every type that normalised to octet-stream, downloads.
    //
    // The filename is attacker-controlled — `requested_filename` is the last
    // path segment of the URL, percent-decoded by httplib before routing — so
    // media_policy::content_disposition() sanitises it. A CR or LF in there
    // would make httplib 0.47 silently DROP the whole header (it validates
    // field values), which is precisely the "no disposition, therefore inline"
    // state an attacker wants back.
    std::string filename = requested_filename.empty() ? meta->filename : requested_filename;
    res.set_header("Content-Disposition",
                   media_policy::content_disposition(
                       media_policy::is_inline_safe(content_type), filename));

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
