#pragma once

#include <string>
#include <string_view>

namespace bsfchat::media_policy {

// What the server is willing to say a media object is, and what it is willing
// to let a browser render in place.
//
// The rule these functions exist to enforce: an uploader must never be able to
// choose a `Content-Type` that makes their bytes *execute* in the chat origin.
// Before this, `handle_upload` stored the request's `Content-Type` header
// verbatim and `handle_download` echoed it back with `Content-Disposition:
// inline`, so an attacker could upload HTML named `Q3-budget.pdf` and have a
// victim's browser run it on the chat origin — with the victim's access token
// sitting in `location.search`, because the client appends it to media URLs.
//
// Two independent gates, because either alone is a single point of failure:
//   1. `normalise_content_type()` at UPLOAD, so nothing dangerous is ever
//      stored. This is the one that also protects objects uploaded before, or
//      through, some future ingestion path.
//   2. `is_inline_safe()` at DOWNLOAD, so even a stored type that somehow got
//      past (1) — a hand-edited database row, a restored backup from an older
//      build) is served as an attachment rather than rendered.

// Canonical stored type for an upload.
//
// `declared` is the uploader's `Content-Type` request header (parameters and
// case are normalised away); `body` is the object's bytes, of which only the
// first few are read.
//
// Returns a type from the storage allowlist, or `application/octet-stream`.
//
// Body sniffing is used to DOWNGRADE, never to reject. A declared type on the
// allowlist is kept only when the magic bytes agree with it; on a mismatch, or
// for a type we cannot sniff, the answer is `application/octet-stream`. That
// asymmetry is deliberate — see the comment on kMagic in the .cpp.
std::string normalise_content_type(std::string_view declared, std::string_view body);

// May this stored type be served `Content-Disposition: inline`?
//
// Strictly narrower than the storage allowlist: it is exactly the set the
// desktop client has to render in place (bitmap images, video, audio) and
// nothing else. Notably NOT `image/svg+xml` — an SVG is an image that executes
// script, so it is neither inline-safe nor storable as an image type at all.
bool is_inline_safe(std::string_view stored_type);

// A complete, well-formed `Content-Disposition` header value.
//
// Always returns something: a media response with no disposition defaults to
// inline in every browser, which is the state this whole package exists to
// remove. `filename` is attacker-controlled (it comes from the upload's
// `?filename=` or from the last path segment of the download URL), so it is
// sanitised here rather than interpolated — a quote would break out of the
// quoted-string, and a CR/LF would make httplib silently DROP the header,
// which would reinstate inline rendering exactly when an attacker wanted it.
std::string content_disposition(bool serve_inline, std::string_view filename);

} // namespace bsfchat::media_policy
