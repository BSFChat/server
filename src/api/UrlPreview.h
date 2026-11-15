#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

// The pure half of server-side URL previews: URL parsing and normalisation,
// Open Graph extraction, image header sniffing and cache freshness. No I/O, no
// store, no network — everything here is unit-testable in isolation. The
// fetching half (SSRF policy, outbound HTTP, cache, media storage) is
// api/UrlPreviewHandler. See docs/url-previews.md.
namespace bsfchat::url_preview {

// Longest URL accepted from a client, and from a Location header or og:image.
constexpr std::size_t kMaxUrlLength = 2048;

// Field limits, in code points, applied after entity decoding.
constexpr std::size_t kMaxTitle = 300;
constexpr std::size_t kMaxDescription = 1000;
constexpr std::size_t kMaxSiteName = 200;

// Cache lifetimes (see cache_fresh).
constexpr int64_t kPositiveTtlMs = 24LL * 60 * 60 * 1000;
constexpr int64_t kNegativeTtlMs = 60LL * 60 * 1000;

// An absolute http(s) URL, split and normalised.
struct ParsedUrl {
    std::string scheme;      // "http" | "https"
    std::string host;        // lowercase, no trailing dot; IPv6 without brackets
    bool host_is_ipv6 = false;
    int port = 0;            // always explicit (scheme default when absent)
    std::string path_query;  // begins with '/'; fragment removed

    bool default_port() const { return port == (scheme == "https" ? 443 : 80); }
    // scheme://host[:port]/path?query — the cache key and the URL a redirect
    // is resolved against.
    std::string normalised() const;
};

// Parses and normalises `url`. On refusal returns nullopt and, when `why` is
// non-null, a short reason safe to put in an error body.
//
// Refuses: anything but http/https; userinfo ("user:pass@host" — a classic
// parser-differential trick, and credentials we must never send); empty,
// non-ASCII or percent-encoded hosts; dotless names (resolved through the
// deployment's search domain); localhost / .local / .internal / .home.arpa /
// .localdomain names; bad ports; whitespace and control characters; URLs over
// kMaxUrlLength. Non-ASCII bytes and backslashes in the path are
// percent-encoded rather than refused.
//
// IP-literal hosts are accepted here: whether an ADDRESS may be reached is
// decided on the resolved address (http/OutboundAddress.h), which covers every
// spelling of it at once.
std::optional<ParsedUrl> parse_url(std::string_view url, std::string* why = nullptr);

// Resolves a reference found in a page (Location header, og:image, og:url)
// against `base`. Returns an absolute URL string (still to be parse_url()'d),
// or nullopt for an empty or over-long reference.
std::optional<std::string> resolve_reference(const ParsedUrl& base, std::string_view ref);

// What a page says about itself. Raw (undecoded) attribute values; clean_text
// does the decoding so the order of operations is in one place.
struct OgTags {
    std::optional<std::string> title;
    std::optional<std::string> description;
    std::optional<std::string> site_name;
    std::optional<std::string> url;
    std::optional<std::string> image;
    std::optional<std::string> image_width;
    std::optional<std::string> image_height;
    std::optional<std::string> charset;  // from <meta charset> / http-equiv
};

// Single linear pass over `html`. og:* wins, then twitter:*, then <title> and
// <meta name="description">. Comments, <script> and <style> bodies are
// skipped so a tag mentioned inside them does not count. Never throws; garbage
// in is merely fewer tags out.
OgTags parse_html(std::string_view html);

// HTML character references: the common named entities and every numeric
// form. Invalid numeric references become U+FFFD; unknown named ones are left
// as written.
std::string decode_entities(std::string_view s);

// Charset-aware cleanup of one extracted value: transcode (ISO-8859-1 /
// windows-1252 → UTF-8; anything else is treated as UTF-8 with invalid
// sequences replaced), decode entities, drop control characters, collapse
// whitespace, trim, truncate to `max_codepoints`. Empty result → nullopt.
std::optional<std::string> clean_text(std::string_view raw, std::string_view charset,
                                      std::size_t max_codepoints);

// The charset named by a Content-Type header value ("text/html; charset=x").
std::string charset_from_content_type(std::string_view content_type);

// Width and height from a PNG, GIF, JPEG or WebP header, without decoding.
// nullopt when the bytes are none of those or the header is truncated/zero.
std::optional<std::pair<int, int>> image_dimensions(std::string_view data);

// Is a cache row fetched at `fetched_at_ms` still servable at `now_ms`?
// Positive results live kPositiveTtlMs, negative ones kNegativeTtlMs. A row
// from the future (clock stepped back) is treated as stale.
bool cache_fresh(int64_t fetched_at_ms, int64_t now_ms, bool negative);

}  // namespace bsfchat::url_preview
