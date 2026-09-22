#pragma once

#include <bsfchat/ErrorCodes.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace bsfchat {

// Per-field ceilings for caller text that the server turns into an event.
//
// security-audit-2026-09 finding S2: limits.max_event_bytes guarded /send and
// nothing else. PUT /profile/{me}/displayname stored whatever it was given and
// re-emitted it as an m.room.member event into EVERY channel the account had
// joined, so a 40 MiB display name became an N-channel × 40 MiB burst of
// events, FTS work and sync traffic, repeatable within the profile rate limit.
// A redaction `reason` had the same shape on one room, and so did kick/ban
// reasons and room names and topics.
//
// Two layers now:
//
//  * http/RequestGuard caps every JSON request body at max_event_bytes before
//    it is read — the floor, which also covers any write added later that
//    forgets its own limit.
//  * These field ceilings, checked in the handlers, bound what a single field
//    may fan out. They are BYTES, because what they protect is storage and
//    bandwidth; each is generous for its field so no human hits it.
//
// The refusal is 400 M_INVALID_PARAM naming the field and the limit, the shape
// RoleHandler already uses for an over-long role name. (413 M_TOO_LARGE stays
// reserved for a whole body over the ceiling.)
namespace input_limits {

// Synapse's limit, and a name far longer than any client renders. Also the
// value the Matrix ecosystem has settled on, so a bridge or bot built against
// another server does not meet a surprise here.
inline constexpr std::size_t kMaxDisplayNameBytes = 256;

// A URL, not free text: an mxc:// URI is under 100 bytes. The avatar route also
// requires the URI to name media the caller uploaded, which bounded this by
// accident; this makes it deliberate.
inline constexpr std::size_t kMaxAvatarUrlBytes = 2048;

// Redaction, kick, ban and unban reasons. A sentence or two for the audit log
// and the room — Discord's audit-log reason is 512 characters.
inline constexpr std::size_t kMaxReasonBytes = 1024;

// The Matrix spec says m.room.name SHOULD NOT exceed 255 bytes.
inline constexpr std::size_t kMaxRoomNameBytes = 255;

// Channel topics are shown in a header bar; a long one is a rules post, and
// even that fits in 4 KiB.
inline constexpr std::size_t kMaxRoomTopicBytes = 4096;

// One account-data document. Matrix puts no ceiling on this and the type is
// caller-chosen, so without one an authenticated account owns an unbounded,
// permanently-stored key/value space on somebody else's server — which is a
// storage-exhaustion lever, not a feature. Generous: the largest document this
// server defines is the ignore list, and a thousand user ids is about 40 KiB.
inline constexpr std::size_t kMaxAccountDataBytes = 64 * 1024;

// The `type` segment of an account-data path. It is a map key in a table this
// account can create rows in at will, so it is bounded for the same reason the
// document is.
inline constexpr std::size_t kMaxAccountDataTypeBytes = 255;

// How many accounts one user may ignore.
//
// A ceiling is needed because every entry is a row that the /sync scan's
// NOT EXISTS probe has to be correct against and that the account keeps
// forever. It is deliberately far above any real use: somebody who has blocked
// a thousand people is not being protected by the thousand-and-first, and on a
// self-hosted server of this shape they have blocked most of the members.
inline constexpr std::size_t kMaxIgnoredUsers = 1000;

// The copy of a reported event's content kept with the report.
//
// Bounded because the reporter does not choose it but the REPORTED party does:
// without a ceiling, posting a 16 KiB message (limits::kMaxMessageBodyBytes)
// and getting it reported by a hundred people would store 1.6 MiB. 4 KiB is
// enough for a moderator to see what was said and is a quarter of the largest
// message this server accepts, so the truncation is visible rather than
// routine.
inline constexpr std::size_t kMaxReportSnapshotBytes = 4096;

} // namespace input_limits

// nullopt when `value` fits in `max_bytes`; otherwise the error to send (with
// status 400). `field` is the JSON key, echoed so a client can tell which of
// several fields was refused.
[[nodiscard]] inline std::optional<MatrixError> oversize_field(std::string_view field,
                                                               std::string_view value,
                                                               std::size_t max_bytes) {
    if (value.size() <= max_bytes) return std::nullopt;
    return MatrixError::invalid_param(std::string(field) + " is " + std::to_string(value.size()) +
                                      " bytes; the limit is " + std::to_string(max_bytes));
}

} // namespace bsfchat
