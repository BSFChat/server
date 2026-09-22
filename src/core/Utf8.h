#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace bsfchat {

// UTF-8 helpers for the places the server shortens or re-checks text that a
// user supplied.
//
// Why this exists (security-audit-2026-09 finding S1): PresenceHandler capped
// status_msg with std::string::resize(80) — a BYTE count. A status of 79 ASCII
// bytes followed by a two-byte character is valid UTF-8 on the wire, but the
// cut landed between the two bytes and stored a string ending in a lone lead
// byte. SyncHandler then copied that string into the presence event of every
// co-member and serialised it with nlohmann's strict dump(), which throws on
// invalid UTF-8; the throw escaped the handler and httplib answered 500. One
// unprivileged PUT took /sync away from everyone who shared a room with the
// sender, renewable every 150 s.
//
// Every string that reaches a handler went through nlohmann::json::parse,
// which REJECTS invalid UTF-8, so request text is always valid on arrival. The
// only way to manufacture an invalid string is for the server to cut one — so
// any server-side shortening of user text goes through truncate_utf8 below,
// never through resize()/substr() on a byte offset.

// True when `s` is well-formed UTF-8: no stray continuation bytes, no truncated
// sequences, no overlong encodings, no surrogates, nothing above U+10FFFF.
// The same definition nlohmann's serialiser enforces, so a string that passes
// here cannot make a strict dump() throw.
[[nodiscard]] bool is_valid_utf8(std::string_view s);

// The longest prefix of `s` that holds at most `max_codepoints` code points and
// ends on a code-point boundary. Code points, not bytes, because the limits this
// serves are user-facing ("80 characters") and a byte limit would give a
// Cyrillic or CJK user a third or a quarter of the room an English user gets.
//
// Never splits a sequence. On input that is not valid UTF-8 (which a caller
// should not have, see above) the result is still valid: a malformed byte is
// dropped rather than copied, so the output can always be serialised strictly.
[[nodiscard]] std::string truncate_utf8(std::string_view s, std::size_t max_codepoints);

} // namespace bsfchat
