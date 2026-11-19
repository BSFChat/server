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

// ── Reading fields (audit 2-2026-11-18 S2-3) ──────────────────────────────
// json::value(key, default) throws type_error when the field exists with a
// different type (or `obj` is not an object), and an unchecked one on a request
// body was a 500. These read a field of the wrong type as if it were absent:
// for the call sites below every absent-field path is already a refusal or a
// safe default. Server.cpp's exception handler maps any type_error a handler
// still lets escape to 400 M_BAD_JSON as a backstop.
[[nodiscard]] inline std::string json_string_or(const nlohmann::json& obj, const char* key,
                                                std::string fallback = {}) {
    if (!obj.is_object()) return fallback;
    auto it = obj.find(key);
    return it != obj.end() && it->is_string() ? it->get<std::string>() : fallback;
}

[[nodiscard]] inline bool json_bool_or(const nlohmann::json& obj, const char* key, bool fallback) {
    if (!obj.is_object()) return fallback;
    auto it = obj.find(key);
    return it != obj.end() && it->is_boolean() ? it->get<bool>() : fallback;
}

// ── Which body a type_error came from (audit 3, fix-first #3) ──────────────
// The exception handler used to map every escaping type_error 302/304-306 to
// 400 M_BAD_JSON, on the theory that it was the caller's ill-typed field. It
// was just as often STORED state of the wrong type (a bsfchat.room.type of
// {"type":5}), and then a bodyless GET /sync answered every co-member "400
// Invalid JSON" for something none of them sent. The backstop now needs both:
// the request has a body, and that body was parsed on this thread by
// parse_request_json. Anything else is a server fault: 500 and an error log.
//
// The mark is thread-local (a handler and its exception handler run on the
// same httplib worker) and keyed on the body's buffer, so a stale mark from a
// previous request on the same worker does not match the next one.
void mark_request_body_parsed(std::string_view body) noexcept;
[[nodiscard]] bool request_body_was_parsed(std::string_view body) noexcept;
void clear_request_body_mark() noexcept;

// The backstop's decision, in one place so it is testable without a socket:
// true when `type_error_id` is an ill-typed-field error AND `body` is a
// non-empty request body this thread parsed.
[[nodiscard]] bool type_error_is_bad_request_body(int type_error_id,
                                                  std::string_view body) noexcept;

// ── Serialising (finding S1) ──────────────────────────────────────────────
// dump() with invalid UTF-8 replaced by U+FFFD instead of throwing
// type_error.316. For responses that aggregate OTHER users' data — /sync above
// all — where one bad string anywhere must never turn into a 500 for everyone
// who happens to share a room with its author. That is the defence in depth;
// the primary fix is that the server no longer manufactures invalid strings
// (core/Utf8.h). Output for valid input is byte-identical to dump().
[[nodiscard]] std::string dump_response_json(const nlohmann::json& j);

} // namespace bsfchat
