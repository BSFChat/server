#pragma once

#include "api/UrlPreview.h"
#include "core/RateLimiter.h"
#include "http/OutboundAddress.h"
#include "store/SqliteStore.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace bsfchat {

class MediaStorage;
struct Config;

// GET /_matrix/media/v3/preview_url?url=<u>[&ts=<ms>]
// (alias: /_matrix/client/v1/media/preview_url)
//
// The server fetches a linked page ONCE and gives every client the same
// title / description / image, so no reader's client ever contacts the linked
// site. That makes this the one place the server makes requests to URLs that
// a user chose, which is what the rest of this class is about:
//
//   * URL shape (url_preview::parse_url): http/https, no userinfo, no
//     dotless or internal names, ports from url_preview_allowed_ports.
//   * Address (outbound::refusal): the server resolves the name itself and
//     refuses if ANY returned address is non-global or in the operator's
//     denylist; it then connects to that checked address via
//     set_hostname_addr_map, keeping the original Host header and TLS SNI /
//     certificate name, so a second resolution (DNS rebinding) never happens.
//   * Redirects: at most kMaxRedirects, followed by hand, every hop
//     re-parsed and re-resolved through the same two checks.
//   * Size and time: byte caps enforced in the content receiver while
//     streaming; one deadline across all hops of a fetch.
//   * Type: only text/html (or xhtml) is parsed; image/png|jpeg|gif|webp is
//     the only thing stored, and only when its magic bytes agree.
//   * Load: a per-account rate limit on cache misses, a server-wide cap on
//     fetches in flight (each one holds an HTTP worker) and a per-account
//     share of it, 429 past any; one deadline covers the page AND its image.
//   * Storage: a per-account daily byte budget for stored preview images;
//     past it a preview is still made, without the image.
//   * No cookies, no Authorization, no Referer; a fixed User-Agent.
//
// The og:image is stored in the media repository with uploader
// kUrlPreviewUploader (auth/MediaAccess.h), not as the requesting user.
class UrlPreviewHandler {
public:
    static constexpr int kMaxRedirects = 3;

    using Resolver = std::function<std::vector<outbound::IpAddress>(const std::string& host)>;
    using WallClock = std::function<int64_t()>;

    // TEST-ONLY seams. Production constructs with the default: the system
    // resolver and the full address policy. `allow_loopback` relaxes exactly
    // 127.0.0.0/8 and ::1 so a test can run a local httplib server — every
    // other refused range stays refused — and nothing in src/ sets it.
    struct TestSeams {
        Resolver resolver;
        bool allow_loopback = false;
        WallClock wall_clock;
    };

    UrlPreviewHandler(SqliteStore& store, const Config& config,
                      std::shared_ptr<MediaStorage> storage,
                      LimiterClock clock = limiter_steady_now_ms);
    // Tests only.
    UrlPreviewHandler(SqliteStore& store, const Config& config,
                      std::shared_ptr<MediaStorage> storage, LimiterClock clock,
                      TestSeams seams);

    void handle_preview(const httplib::Request& req, httplib::Response& res);

    // getaddrinfo(), every address returned, IPv4 first.
    static std::vector<outbound::IpAddress> system_resolve(const std::string& host);

private:
    enum class FetchStatus { kOk, kForbidden, kFailed };

    struct Fetched {
        FetchStatus status = FetchStatus::kFailed;
        std::string why;                // for the 400 body / the log; no URL in it
        url_preview::ParsedUrl final_url;
        std::string content_type;       // lowercase mime type, no parameters
        std::string charset;            // from the Content-Type header, if any
        std::string body;
        bool is_html = false;
    };

    // One fetch with redirects. `accept_html` false means only an image will do.
    // `deadline_ms` is on the steady clock and is shared by every fetch one
    // preview makes, so the page and its image together take at most one
    // timeout (audit 2-2026-11-18 S2-7).
    Fetched fetch(const url_preview::ParsedUrl& start, bool accept_html, int64_t deadline_ms);

    // Store an image body as a server-owned media object; returns its media id
    // or empty on failure.
    std::string store_image(const std::string& body, const std::string& content_type);

    // Adds og:image (+ size, dimensions) for an image body to `out`, charging
    // `user_id`'s daily image budget. False (and nothing stored) past it.
    bool attach_image(nlohmann::json& out, std::string& image_mxc, const std::string& body,
                      const std::string& content_type, const std::string& user_id);

    // Bytes `user_id` may still store today; refreshed per 24 h window.
    int64_t image_budget_left(const std::string& user_id);
    void charge_image_budget(const std::string& user_id, int64_t bytes);

    const char* address_refusal(const outbound::IpAddress& a) const;
    bool port_allowed(int port) const;
    int64_t wall_now() const;
    void maybe_prune();

    SqliteStore& store_;
    const Config& config_;
    std::shared_ptr<MediaStorage> storage_;
    LimiterClock clock_;
    TestSeams seams_;

    std::size_t html_cap_;
    std::size_t image_cap_;
    int timeout_ms_;
    int max_concurrent_;
    std::string user_agent_;
    std::vector<outbound::Cidr> denylist_;

    RateLimiter limiter_;
    std::atomic<int> in_flight_{0};

    int max_per_account_;
    int64_t image_bytes_per_day_;
    std::mutex account_mu_;
    std::unordered_map<std::string, int> account_in_flight_;  // guarded by account_mu_
    struct ImageBudget {
        int64_t window_start_ms = 0;
        int64_t used = 0;
    };
    std::unordered_map<std::string, ImageBudget> image_budget_;  // guarded by account_mu_

    std::mutex prune_mu_;
    int64_t last_prune_ms_ = 0;
};

} // namespace bsfchat
