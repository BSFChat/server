#include "api/UrlPreviewHandler.h"

#include "api/MediaPolicy.h"
#include "auth/MediaAccess.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "core/Version.h"
#include "http/Middleware.h"
#include "http/RateLimitResponse.h"
#include "storage/MediaStorage.h"

#include <bsfchat/ErrorCodes.h>

#include <netdb.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <stdexcept>

namespace bsfchat {

namespace {

using url_preview::ParsedUrl;

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

std::string mime_of(const std::string& content_type) {
    std::string m = content_type.substr(0, content_type.find(';'));
    m.erase(std::remove_if(m.begin(), m.end(), [](unsigned char c) { return std::isspace(c); }),
            m.end());
    std::transform(m.begin(), m.end(), m.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return m;
}

bool is_html_type(const std::string& mime) {
    return mime == "text/html" || mime == "application/xhtml+xml";
}

// The only image types stored. Not SVG: an SVG is a document that runs script.
bool is_preview_image_type(const std::string& mime) {
    return mime == "image/png" || mime == "image/jpeg" || mime == "image/gif" ||
           mime == "image/webp";
}

bool is_loopback(const outbound::IpAddress& a) {
    if (!a.v6) return a.bytes[0] == 127;
    for (int i = 0; i < 15; ++i)
        if (a.bytes[i] != 0) return false;
    return a.bytes[15] == 1;
}

std::string random_media_id() {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        throw std::runtime_error("RAND_bytes failed minting a media id");
    }
    static const char* hex = "0123456789abcdef";
    std::string id;
    for (unsigned char b : bytes) {
        id += hex[b >> 4];
        id += hex[b & 0xf];
    }
    return id;
}

std::optional<int> positive_int(const std::optional<std::string>& s) {
    if (!s || s->empty() || s->size() > 6) return std::nullopt;
    if (s->find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
    const int v = std::stoi(*s);
    if (v <= 0 || v > 65535) return std::nullopt;
    return v;
}

int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

}  // namespace

UrlPreviewHandler::UrlPreviewHandler(SqliteStore& store, const Config& config,
                                     std::shared_ptr<MediaStorage> storage, LimiterClock clock)
    : UrlPreviewHandler(store, config, std::move(storage), std::move(clock), TestSeams{}) {}

UrlPreviewHandler::UrlPreviewHandler(SqliteStore& store, const Config& config,
                                     std::shared_ptr<MediaStorage> storage, LimiterClock clock,
                                     TestSeams seams)
    : store_(store),
      config_(config),
      storage_(std::move(storage)),
      clock_(clock),
      seams_(std::move(seams)),
      html_cap_(static_cast<std::size_t>(
          std::clamp<int64_t>(config.url_preview_max_bytes, 64 * 1024, 16 * 1024 * 1024))),
      image_cap_(static_cast<std::size_t>(
          std::clamp<int64_t>(config.url_preview_image_max_bytes, 64 * 1024, 50 * 1024 * 1024))),
      timeout_ms_(std::clamp(config.url_preview_timeout_seconds, 1, 30) * 1000),
      max_concurrent_(std::clamp(config.url_preview_max_concurrent, 1, 64)),
      limiter_(std::clamp(config.url_preview_rate_per_minute, 1, 600), std::chrono::seconds(60),
               clock) {
    for (const auto& entry : config.url_preview_ip_denylist) {
        auto cidr = outbound::parse_cidr(entry);
        // Fail startup: a typo silently dropping a range the operator meant to
        // block is a weaker filter than they think they have.
        if (!cidr) {
            throw std::runtime_error("media.url_preview_ip_denylist: not an address or CIDR: '" +
                                     entry + "'");
        }
        denylist_.push_back(*cidr);
    }
    for (char c : config.url_preview_user_agent) {
        if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7f) user_agent_ += c;
    }
    if (user_agent_.empty()) {
        user_agent_ = "BSFChat-URL-Preview/" + build::version_string() + " (+https://bsfchat.com)";
    }
    if (!seams_.resolver) seams_.resolver = &UrlPreviewHandler::system_resolve;
}

std::vector<outbound::IpAddress> UrlPreviewHandler::system_resolve(const std::string& host) {
    std::vector<outbound::IpAddress> v4, v6;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return {};
    for (auto* ai = res; ai; ai = ai->ai_next) {
        outbound::IpAddress a;
        if (ai->ai_family == AF_INET && ai->ai_addrlen >= sizeof(sockaddr_in)) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(ai->ai_addr);
            std::memcpy(a.bytes.data(), &sin->sin_addr, 4);
            if (std::find_if(v4.begin(), v4.end(), [&](auto& x) { return x.bytes == a.bytes; }) == v4.end())
                v4.push_back(a);
        } else if (ai->ai_family == AF_INET6 && ai->ai_addrlen >= sizeof(sockaddr_in6)) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(ai->ai_addr);
            a.v6 = true;
            std::memcpy(a.bytes.data(), &sin6->sin6_addr, 16);
            if (std::find_if(v6.begin(), v6.end(), [&](auto& x) { return x.bytes == a.bytes; }) == v6.end())
                v6.push_back(a);
        }
    }
    freeaddrinfo(res);
    v4.insert(v4.end(), v6.begin(), v6.end());
    return v4;
}

const char* UrlPreviewHandler::address_refusal(const outbound::IpAddress& a) const {
    if (seams_.allow_loopback && is_loopback(a)) {
        for (const auto& c : denylist_)
            if (c.contains(a)) return "operator denylist";
        return nullptr;
    }
    return outbound::refusal(a, denylist_);
}

bool UrlPreviewHandler::port_allowed(int port) const {
    const auto& ports = config_.url_preview_allowed_ports;
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

int64_t UrlPreviewHandler::wall_now() const {
    if (seams_.wall_clock) return seams_.wall_clock();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void UrlPreviewHandler::maybe_prune() {
    const int64_t now = clock_();
    {
        std::lock_guard lock(prune_mu_);
        if (last_prune_ms_ != 0 && now - last_prune_ms_ < 60LL * 60 * 1000) return;
        last_prune_ms_ = now;
    }
    // Twice the positive TTL: a URI handed out just before expiry keeps
    // resolving for a day after, then the reaper may collect the image.
    store_.prune_url_previews(wall_now() - 2 * url_preview::kPositiveTtlMs);
}

UrlPreviewHandler::Fetched UrlPreviewHandler::fetch(const ParsedUrl& start, bool accept_html) {
    auto log = get_logger();
    Fetched out;
    const int64_t deadline = steady_ms() + timeout_ms_;
    ParsedUrl url = start;

    for (int hop = 0; hop <= kMaxRedirects; ++hop) {
        if (!port_allowed(url.port)) {
            out.status = FetchStatus::kForbidden;
            out.why = "Port not allowed for previews";
            return out;
        }
        std::vector<outbound::IpAddress> addrs;
        if (url.host_is_ipv6) {
            if (auto a = outbound::IpAddress::parse(url.host)) addrs.push_back(*a);
        } else {
            addrs = seams_.resolver(url.host);
        }
        if (addrs.empty()) {
            out.status = FetchStatus::kFailed;
            out.why = "Host did not resolve";
            return out;
        }
        // ANY refused address refuses the host: a name that answers with both
        // a public and an internal address is either misconfigured or an
        // attack, and which one the connection would use is not ours to pick.
        for (const auto& a : addrs) {
            if (const char* r = address_refusal(a)) {
                log->info("URL preview: refused {} -> {} ({})", url.host, a.to_string(), r);
                out.status = FetchStatus::kForbidden;
                out.why = "URL resolves to a forbidden address";
                return out;
            }
        }

        int status = 0;
        std::string location, content_type, body;
        bool html = false, truncated = false, too_large = false, wrong_type = false;
        httplib::Error error = httplib::Error::Unknown;

        // At most two of the checked addresses, in resolver order (IPv4 first),
        // and only on a connect failure — never anything that reached a server.
        for (std::size_t attempt = 0; attempt < std::min<std::size_t>(addrs.size(), 2); ++attempt) {
            const int64_t remaining = deadline - steady_ms();
            if (remaining <= 0) break;
            std::unique_ptr<httplib::ClientImpl> cli;
            if (url.scheme == "https") {
                cli = std::make_unique<httplib::SSLClient>(url.host, url.port);
            } else {
                cli = std::make_unique<httplib::ClientImpl>(url.host, url.port);
            }
            // The connection goes to the address checked above; the Host
            // header and TLS SNI / certificate check keep the original name.
            cli->set_hostname_addr_map({{url.host, addrs[attempt].to_string()}});
            const auto sec = static_cast<time_t>(remaining / 1000);
            const auto usec = static_cast<time_t>((remaining % 1000) * 1000);
            cli->set_connection_timeout(sec, usec);
            cli->set_read_timeout(sec, usec);
            cli->set_write_timeout(sec, usec);
            cli->set_max_timeout(static_cast<time_t>(remaining));
            cli->set_follow_location(false);
            cli->set_keep_alive(false);
            // Already normalised and encoded; httplib's encoder would rewrite '+'.
            cli->set_path_encode(false);

            httplib::Headers headers = {
                {"User-Agent", user_agent_},
                {"Accept", accept_html
                               ? "text/html,application/xhtml+xml;q=0.9,image/*;q=0.8"
                               : "image/png,image/jpeg,image/gif,image/webp"},
            };

            status = 0;
            location.clear();
            content_type.clear();
            body.clear();
            html = truncated = too_large = wrong_type = false;
            std::size_t cap = 0;
            auto result = cli->Get(
                url.path_query, headers,
                [&](const httplib::Response& r) {
                    status = r.status;
                    if (r.status >= 300 && r.status < 400 && r.status != 304) {
                        location = r.get_header_value("Location");
                        return false;
                    }
                    if (r.status != 200) return false;
                    content_type = r.get_header_value("Content-Type");
                    const std::string mime = mime_of(content_type);
                    html = accept_html && is_html_type(mime);
                    if (!html && !is_preview_image_type(mime)) {
                        wrong_type = true;
                        return false;
                    }
                    cap = html ? html_cap_ : image_cap_;
                    if (!html && r.has_header("Content-Length") &&
                        r.get_header_value_u64("Content-Length") > cap) {
                        too_large = true;
                        return false;
                    }
                    return true;
                },
                [&](const char* data, size_t len) {
                    const std::size_t room = cap - body.size();
                    if (len > room) {
                        // HTML: the <head> is what matters; keep the prefix.
                        if (html) {
                            body.append(data, room);
                            truncated = true;
                        } else {
                            too_large = true;
                        }
                        return false;
                    }
                    body.append(data, len);
                    return true;
                });
            error = result.error();
            if (status != 0 || error != httplib::Error::Connection) break;
        }

        if (!location.empty()) {
            auto next = url_preview::resolve_reference(url, location);
            std::string why;
            auto parsed = next ? url_preview::parse_url(*next, &why) : std::nullopt;
            if (!parsed) {
                out.status = FetchStatus::kForbidden;
                out.why = "Redirect to a URL that cannot be previewed";
                return out;
            }
            url = *parsed;
            continue;
        }
        const bool complete = error == httplib::Error::Success || truncated;
        if (status != 200 || wrong_type || too_large || !complete) {
            log->debug("URL preview: fetch from {} failed (status {}, error {})", url.host, status,
                       httplib::to_string(error));
            out.status = FetchStatus::kFailed;
            out.why = "Fetch failed";
            return out;
        }
        out.status = FetchStatus::kOk;
        out.final_url = url;
        out.content_type = mime_of(content_type);
        out.charset = url_preview::charset_from_content_type(content_type);
        out.body = std::move(body);
        out.is_html = html;
        return out;
    }
    out.status = FetchStatus::kFailed;
    out.why = "Too many redirects";
    return out;
}

std::string UrlPreviewHandler::store_image(const std::string& body,
                                           const std::string& content_type) {
    try {
        const std::string media_id = random_media_id();
        const std::string path = storage_->upload(media_id, body, content_type, "");
        try {
            store_.insert_media(media_id, kUrlPreviewUploader, content_type, "",
                                static_cast<int64_t>(body.size()), path);
        } catch (...) {
            try {
                storage_->remove(media_id);
            } catch (...) {
            }
            throw;
        }
        return media_id;
    } catch (const std::exception& e) {
        get_logger()->error("URL preview: failed to store image: {}", e.what());
        return {};
    }
}

bool UrlPreviewHandler::attach_image(nlohmann::json& out, std::string& image_mxc,
                                     const std::string& body, const std::string& content_type) {
    // The header is a claim; the magic bytes decide (api/MediaPolicy.h).
    const std::string sniffed = media_policy::normalise_content_type(content_type, body);
    if (!is_preview_image_type(sniffed)) return false;
    const std::string media_id = store_image(body, sniffed);
    if (media_id.empty()) return false;
    image_mxc = "mxc://" + config_.server_name + "/" + media_id;
    out["og:image"] = image_mxc;
    out["matrix:image:size"] = static_cast<int64_t>(body.size());
    if (auto dims = url_preview::image_dimensions(body)) {
        out["og:image:width"] = dims->first;
        out["og:image:height"] = dims->second;
    }
    return true;
}

void UrlPreviewHandler::handle_preview(const httplib::Request& req, httplib::Response& res) {
    const std::string auth_header = req.get_header_value("Authorization");
    const auto user_id = authenticate(store_, auth_header);
    if (!user_id) {
        send_error(res, 401, auth_error(auth_header));
        return;
    }
    if (!config_.url_preview_enabled) {
        send_error(res, 403, MatrixError::forbidden("URL previews are disabled on this server"));
        return;
    }
    if (!req.has_param("url")) {
        send_error(res, 400, MatrixError::invalid_param("Missing url parameter"));
        return;
    }
    std::string why;
    const auto parsed = url_preview::parse_url(req.get_param_value("url"), &why);
    if (!parsed) {
        send_error(res, 400, MatrixError::invalid_param(why));
        return;
    }
    if (!port_allowed(parsed->port)) {
        send_error(res, 400, MatrixError::invalid_param("Port not allowed for previews"));
        return;
    }
    const std::string key = parsed->normalised();

    // `ts` (the client's "as of" hint) is accepted and ignored: one cached
    // answer per URL.
    if (auto row = store_.get_url_preview(key);
        row && url_preview::cache_fresh(row->fetched_at_ms, wall_now(), !row->response_json)) {
        if (row->response_json) {
            res.status = 200;
            res.set_content(*row->response_json, "application/json");
        } else {
            send_error(res, 404, MatrixError::not_found("Nothing to preview at this URL"));
        }
        return;
    }

    // Charged only on a miss: a cache hit costs one indexed read, a miss is
    // outbound traffic the server performs on this account's behalf.
    if (const auto wait = limiter_.acquire(*user_id)) {
        send_rate_limited(res, wait, "Too many link previews; try again shortly");
        return;
    }
    // Each fetch holds an HTTP worker for up to two timeouts (page + image).
    if (in_flight_.fetch_add(1) >= max_concurrent_) {
        in_flight_.fetch_sub(1);
        send_rate_limited(res, 1000, "The server is busy fetching other previews");
        return;
    }
    struct Slot {
        std::atomic<int>& n;
        ~Slot() { n.fetch_sub(1); }
    } slot{in_flight_};

    maybe_prune();

    Fetched page = fetch(*parsed, true);
    if (page.status == FetchStatus::kForbidden) {
        send_error(res, 400, MatrixError::invalid_param(page.why));
        return;
    }

    nlohmann::json out = nlohmann::json::object();
    std::string image_mxc;
    if (page.status == FetchStatus::kOk && !page.is_html) {
        attach_image(out, image_mxc, page.body, page.content_type);
    } else if (page.status == FetchStatus::kOk) {
        const auto tags = url_preview::parse_html(page.body);
        const std::string charset = !page.charset.empty()
                                        ? page.charset
                                        : tags.charset.value_or("utf-8");
        auto put = [&](const char* field, const std::optional<std::string>& raw, std::size_t max) {
            if (!raw) return;
            if (auto v = url_preview::clean_text(*raw, charset, max)) out[field] = *v;
        };
        put("og:title", tags.title, url_preview::kMaxTitle);
        put("og:description", tags.description, url_preview::kMaxDescription);
        put("og:site_name", tags.site_name, url_preview::kMaxSiteName);
        if (tags.url) {
            auto abs = url_preview::resolve_reference(page.final_url, *tags.url);
            if (auto u = abs ? url_preview::parse_url(*abs) : std::nullopt) out["og:url"] = u->normalised();
        }
        if (tags.image) {
            auto abs = url_preview::resolve_reference(page.final_url, *tags.image);
            if (auto u = abs ? url_preview::parse_url(*abs) : std::nullopt) {
                Fetched img = fetch(*u, false);
                if (img.status == FetchStatus::kOk &&
                    attach_image(out, image_mxc, img.body, img.content_type) &&
                    !out.contains("og:image:width")) {
                    // Header unreadable: fall back to what the page declared.
                    if (auto w = positive_int(tags.image_width)) out["og:image:width"] = *w;
                    if (auto h = positive_int(tags.image_height)) out["og:image:height"] = *h;
                }
            }
        }
    }

    const int64_t now = wall_now();
    if (out.empty()) {
        store_.put_url_preview(key, std::nullopt, "", now);
        send_error(res, 404, MatrixError::not_found("Nothing to preview at this URL"));
        return;
    }
    const std::string body = out.dump();
    store_.put_url_preview(key, body, image_mxc, now);
    res.status = 200;
    res.set_content(body, "application/json");
}

}  // namespace bsfchat
