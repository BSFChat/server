#pragma once

#include <bsfchat/ErrorCodes.h>

#include <httplib.h>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace bsfchat {

struct Config;

// ── Pre-body request guard (security-audit-2026-09 finding S6, and the
//    systemic half of S2) ──────────────────────────────────────────────────
//
// Installed as httplib's pre-REQUEST handler, which runs after a route has
// matched and BEFORE the body is read, so a refusal here costs no buffering at
// all. It applies to every route except the media upload, which is the one
// endpoint that takes a large body and the one that never parses it as JSON.
//
// What it refuses, and why each rule is needed rather than nice:
//
//  * Content-Encoding other than identity → 415. httplib inflates gzip/br/zstd
//    request bodies before handlers see them. It does cap the INFLATED size at
//    the transport ceiling (51 MiB), but that ceiling is sized for media: a
//    52 KB gzip of `[` inflated to 51 MiB of JSON and the parser then took
//    gigabytes to reject it. No client of this API compresses a JSON request
//    — the Qt client, the bot SDK and curl all send them plain — so there is
//    nothing to support and the amplification disappears with the feature.
//
//  * Content-Length above max_json_body_bytes → 413. Before this, only /send
//    had a ceiling (limits.max_event_bytes); every other JSON route accepted
//    up to 51 MiB, and several of them (display name, redaction reason, state
//    writes) turn what they are given into an event every member downloads.
//    The ceiling is the event ceiling itself: nothing a client sends as JSON
//    needs to be larger than the largest event the server will store.
//
//  * A JSON body with no Content-Length (chunked) → 411 Length Required. The
//    length rule above is only a rule if the length is known before reading;
//    a chunked body would be buffered to the 51 MiB transport cap first. Every
//    client this server has sends a Content-Length for a buffered JSON body,
//    and nginx (proxy_request_buffering off, HTTP/1.1 upstream) forwards the
//    client's framing unchanged, so nothing legitimate arrives chunked.
//
// Field-level limits (a display name is not 128 KiB) still live in the
// handlers — see api/InputLimits.h. This is the floor under all of them, and
// the reason a handler that forgets its own limit can no longer be a
// multi-megabyte fan-out.
struct RequestRefusal {
    int status;
    MatrixError error;
};

// The JSON body ceiling for `config`. Exposed for tests and for the one
// handler (/send) that reports its own, more specific 413.
[[nodiscard]] std::size_t max_json_body_bytes(const Config& config);

// nullopt when the request may proceed to have its body read.
[[nodiscard]] std::optional<RequestRefusal> refuse_before_body(const httplib::Request& req,
                                                               const Config& config);

// ── CORS (finding S8) ─────────────────────────────────────────────────────
//
// Every non-media response used to carry `Access-Control-Allow-Origin: *`.
// Nothing needed it: the desktop client is Qt (no CORS enforcement), bots are
// plain HTTP clients, and the identity service's web pages talk only to their
// own origin. The one effect of the wildcard was to let ANY web page read this
// API's responses on behalf of whoever loaded it, the day a browser client
// holds a token — and to let a malicious page probe the API freely today. Auth
// is a bearer header rather than a cookie, which is why the wildcard was not a
// live credential theft; it was still the wrong default for an API that
// returns private data, and legacy `?access_token=` media URLs are exactly the
// credentialed-by-URL case where a wildcard does leak (MediaHandler strips the
// header there for that reason).
//
// Now: no CORS headers at all unless the request's Origin is on
// `server.cors_allowed_origins`, in which case that one origin is reflected
// (with Vary: Origin so a cache cannot hand it to another origin). There is no
// wildcard entry — Config::validate drops "*" with a warning — because the
// point of the list is that a browser client is named before it can read.
void apply_cors_headers(const httplib::Request& req, httplib::Response& res,
                        const std::vector<std::string>& allowed_origins);

} // namespace bsfchat
