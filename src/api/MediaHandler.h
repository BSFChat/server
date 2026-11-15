#pragma once

#include "store/SqliteStore.h"
#include "core/SendLimiter.h"

#include <httplib.h>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

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

    // ── Upload admission, BEFORE the body is read (audit 2026-11-15 S-1) ──
    //
    // httplib buffers a regular handler's whole request body into req.body
    // before the handler runs, and the upload route takes up to
    // max_upload_size_mb. handle_upload used to authenticate only after that,
    // so ~40 concurrent unauthenticated 100 MB POSTs held ~4 GB.
    //
    // Server installs this in httplib's PRE-REQUEST handler for the upload
    // route; httplib 0.47 calls that from dispatch_request() after the route
    // matches and BEFORE read_content(). It refuses, without reading a byte of
    // the body:
    //   * no / invalid token                      → 401
    //   * Content-Length over max_upload_size_mb  → 413 (a chunked or
    //     length-less body is bounded by the transport ceiling,
    //     set_payload_max_length, while it streams)
    //   * the account's upload rate bucket empty  → 429
    //   * kMaxConcurrentUploadsPerAccount already in flight → 429
    //
    // Returns true when the body may be read. On false, `res` holds the
    // refusal. On true it records the caller and an upload slot in
    // res.user_data; the slot is released when httplib destroys `res`, i.e.
    // whether or not the body read and the handler then succeed.
    //
    // handle_upload calls this itself when it finds no admission recorded, so
    // a direct caller (tests) gets the identical checks.
    bool admit_upload(const httplib::Request& req, httplib::Response& res);

    // Uploads one account may have in flight at once. Each one can hold up to
    // max_upload_size_mb in memory while its body is read; the rate bucket
    // bounds how many START per window, this bounds how many are resident.
    static constexpr int kMaxConcurrentUploadsPerAccount = 4;

    void handle_upload(const httplib::Request& req, httplib::Response& res);
    void handle_download(const httplib::Request& req, httplib::Response& res);

    // POST /_matrix/media/v3/ticket  {"mxc_uri": "mxc://…"}
    //
    // Mints a short-lived signed ticket for one object and the calling user,
    // after running the SAME may_download() check the download path runs. The
    // client carries it as `?mt=…&exp=…` on the URL it hands to Image.source
    // and MediaPlayer.source — which cannot set an Authorization header, which
    // is why the session token was in that URL in the first place.
    //
    // Authenticated by the Authorization header ONLY: a ticket cannot mint
    // another ticket, so the TTL is a real bound and not a renewable one.
    //
    // Answers 404 both for "no such object" and "not yours", byte-identical, so
    // this is not an existence oracle for media ids. See MediaTicket.h for what
    // a ticket does and does not commit to.
    void handle_ticket(const httplib::Request& req, httplib::Response& res);

private:
    std::string generate_media_id() const;
    // Resolves the caller from the Authorization header, a signed `?mt=` ticket,
    // or the legacy `?access_token=` query param (image/video widgets can't set
    // headers). `media_id` is the object being fetched: a ticket is scoped to
    // one, so verifying it needs to know which.
    //
    // Resolving a caller is NOT authorizing them. Every path through this
    // returns only an identity; handle_download re-runs may_download() on it.
    std::optional<std::string> authenticate_media(const httplib::Request& req,
                                                  const std::string& media_id);

    // The HMAC key tickets are signed with, derived on first use from this
    // server's own instance secret in server_meta and cached for the process.
    // See MediaTicket.h for the derivation and the reason it is not a config
    // value.
    const std::vector<unsigned char>& ticket_key();
    // config_.media_ticket_ttl_seconds, clamped to the range MediaTicket.h
    // allows.
    int64_t ticket_ttl_seconds() const;

    // May `user_id` have the bytes of `media_id`?
    //
    // Media carries no room of its own — POST /upload has no room in it — so
    // the answer comes from the events that NAME the object: VIEW_CHANNEL in
    // any room where one survives. Uploader and profile-avatar are the two
    // explicit exceptions; everything else with no room recorded is refused,
    // because "unattached" must never be read as "public".
    //
    // A forwarder to MediaAccess::may_read (auth/MediaAccess.h), which is where
    // the rule lives since audit finding F5 — because the WRITE side, the index
    // this read consults, now has to ask the identical question of an event's
    // author before it will record a reference. A read rule and a write rule
    // that merely agree are two rules, and F5 is what happened when they
    // disagreed.
    bool may_download(const std::string& user_id, const std::string& media_id,
                      const SqliteStore::MediaMeta& meta);

    SqliteStore& store_;
    const Config& config_;
    std::shared_ptr<MediaStorage> storage_;
    // Per-account upload ceiling. An upload is the largest unit of work an
    // authenticated caller can ask for — a whole file into storage, kept — so
    // it gets the tightest of the three budgets.
    SendLimiter limits_;

    // In-flight uploads per account. Shared with every slot handed out so a
    // slot can outlive nothing it depends on.
    struct UploadsInFlight {
        std::mutex mu;
        std::unordered_map<std::string, int> by_user;
    };
    std::shared_ptr<UploadsInFlight> uploads_in_flight_ = std::make_shared<UploadsInFlight>();

    std::once_flag ticket_key_once_;
    std::vector<unsigned char> ticket_key_;
};

} // namespace bsfchat
