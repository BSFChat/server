#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace bsfchat {

// The shape every settable state type must have before it is stored (audit 3,
// fix-first #3).
//
// State content used to be stored as sent once the permission gate passed, and
// every reader — this server's and the clients' — then had to survive whatever
// a MANAGE_CHANNELS holder had typed. Several did not: `bsfchat.room.type
// {"type":5}` on a private channel turned every non-viewer's /sync into a 400,
// and the same pattern blocked deleting and joining rooms. The readers are
// guarded now too; this is the half that stops new bad rows being written.
//
// Returns nullopt when `content` is acceptable for `type`, otherwise a message
// that names the offending field (sent back as 400 M_BAD_JSON). A field that is
// optional may be absent; one that is present must have the right type. Types
// this table does not name are only required to be JSON objects — the closed
// allow-list of settable types lives in RoomHandler::handle_set_state, not here.
[[nodiscard]] std::optional<std::string> state_content_error(std::string_view type,
                                                             const nlohmann::json& content);

// bsfchat.room.type's `type` values. Anything else is refused on write and
// read as "text" (an ordinary channel) by every server-side reader.
[[nodiscard]] bool is_known_room_type(std::string_view type);

} // namespace bsfchat
