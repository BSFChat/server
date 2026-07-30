#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace bsfchat {

class SqliteStore;
struct Config;

// Per-server nicknames — the thing CHANGE_NICKNAME (bit 11) and
// MANAGE_NICKNAMES (bit 12) gate. Both flags predate any nickname feature and so
// enforced nothing; the permission checks live in ProfileHandler, and everything
// here is the supporting machinery they need.
//
// STORAGE. Authority is one column, users.nickname (schema v14). Room state only
// mirrors it. The Matrix-native alternative — "a per-server nickname just IS the
// m.room.member displayname" — is not equivalent in this codebase, because four
// separate paths already rewrite that field from the global profile:
// ProfileHandler::broadcastMemberUpdate, the creator join in
// handle_create_room, the self-membership branch of handle_set_state, and
// AutoJoin's force-join. A nickname living only in room state would be silently
// reverted by an unrelated avatar change or by the next channel that force-joined
// its owner, and a user joining a new channel would arrive under their global
// name. Mirroring outward from one row is the only shape that survives all four.

// Longest nickname accepted, in Unicode code points (not bytes) — the limit a
// user perceives is characters, and counting bytes would reject a short name
// written in a non-Latin script.
inline constexpr std::size_t kMaxNicknameCodepoints = 32;

// The m.room.member content key carrying the nickname alongside the effective
// `displayname`. Present only when a nickname is set, so its absence is
// unambiguous. Clients need this to distinguish "renders as Bob because that is
// their nickname" from "renders as Bob because that is their global name" —
// otherwise no admin UI can offer "clear nickname".
inline constexpr const char* kNicknameContentKey = "bsfchat.nickname";

struct NicknameCheck {
    bool ok = false;
    std::string error;      // message for the 400/403 body when !ok
    std::string normalised; // the value to store when ok
};

// Validates a requested nickname for `target_user`. Rejects, in order: invalid
// UTF-8, control characters, bidi/invisible formatting characters, an MXID-shaped
// value, over-length, and a value that is the localpart of some OTHER registered
// account. Trims surrounding ASCII whitespace first, so " Bob " and "Bob" are the
// same nickname and a name made only of spaces is rejected as empty.
//
// An empty result is never returned as ok: clearing a nickname is a separate
// operation (pass std::nullopt to SqliteStore::set_nickname), not a validated
// empty string.
NicknameCheck validate_nickname(const std::string& raw, const std::string& target_user,
                                const Config& config, SqliteStore& store);

// True when `raw` carries no nickname at all — empty, or only ASCII whitespace.
// Callers treat this as the instruction to CLEAR rather than as a rejection, so
// that emptying the field in a client is how a nickname is removed.
bool is_blank_nickname(const std::string& raw);

// The name other members should see: nickname if set, else the global display
// name, else nullopt (callers fall back to the user id, as clients already do).
std::optional<std::string> effective_display_name(SqliteStore& store,
                                                  const std::string& user_id);

// Builds m.room.member content for `user_id`, with `displayname` set to the
// EFFECTIVE name plus kNicknameContentKey when a nickname is set.
//
// Every emitter of a member event goes through here. That is the point: the
// forged-displayname hole existed because one route wrote the client's body
// verbatim while others built content by hand, and there was no single place that
// defined what a member event's profile fields are allowed to say.
nlohmann::json member_event_content(SqliteStore& store, const std::string& user_id,
                                    const std::string& membership);

} // namespace bsfchat
