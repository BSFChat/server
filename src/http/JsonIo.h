#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace bsfchat {

// Parsing request bodies and serialising responses, with the two guards the
// September 2026 security audit found missing.
//
// ── Parsing (finding S6) ──────────────────────────────────────────────────
// nlohmann builds a DOM node per `[` / `{`, and a body of N bytes of `[` peaks
// at roughly 70×N resident before the parser gives up on the missing close
// (measured: 1 MB → 70 MB, 10 MB → 723 MB). httplib decompresses gzip/br/zstd
// request bodies before any handler sees them, so a 52 KB gzip upload became
// 51 MiB of `[` and then gigabytes of allocation, per request, on a 64-worker
// pool. RequestGuard now refuses compressed and oversized JSON bodies before
// they are read at all; the depth cap here is the second half: a well-formed
// body cannot be nested deeper than anything this API accepts.

// Deeper than any request this API defines by a wide margin — the deepest real
// shape is an m.new_content / m.relates_to edit, about five levels — and far
// too shallow for the nesting-bomb shape above to cost anything.
inline constexpr std::size_t kMaxJsonNestingDepth = 32;

// Thrown by parse_request_json when a body is nested past the cap. Derives from
// std::invalid_argument so every existing `catch (...)` around a body parse
// turns it into the same 400 M_BAD_JSON a syntax error gets.
struct JsonTooDeep : std::invalid_argument {
    using std::invalid_argument::invalid_argument;
};

// True when `body` opens more than `max_depth` arrays/objects at once. A linear
// scan over the bytes, string-aware (brackets inside a JSON string do not
// count) and allocation-free, so it costs nothing next to the parse it guards.
[[nodiscard]] bool json_nesting_exceeds(std::string_view body,
                                        std::size_t max_depth = kMaxJsonNestingDepth);

// json::parse(body), refusing over-deep input first. Throws exactly what
// json::parse throws for malformed input, or JsonTooDeep. An empty body is
// parsed as-is (i.e. throws), matching json::parse; callers that treat an
// empty body as {} keep doing that themselves.
[[nodiscard]] nlohmann::json parse_request_json(std::string_view body);

// Non-throwing form, for the call sites that used json::parse(..., nullptr,
// false): returns a discarded value on malformed OR over-deep input.
[[nodiscard]] nlohmann::json parse_request_json_or_discarded(std::string_view body);

// ── Serialising (finding S1) ──────────────────────────────────────────────
// dump() with invalid UTF-8 replaced by U+FFFD instead of throwing
// type_error.316. For responses that aggregate OTHER users' data — /sync above
// all — where one bad string anywhere must never turn into a 500 for everyone
// who happens to share a room with its author. That is the defence in depth;
// the primary fix is that the server no longer manufactures invalid strings
// (core/Utf8.h). Output for valid input is byte-identical to dump().
[[nodiscard]] std::string dump_response_json(const nlohmann::json& j);

} // namespace bsfchat
