#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Short-lived signed media tickets.
//
// WHAT THIS REPLACES. The client used to put the viewer's 90-day access token
// in the media URL's query string, because QML's Image.source and
// MediaPlayer.source cannot set an Authorization header. That URL then reached
// the system browser (Qt.openUrlExternally on the file card), nginx's
// access_log, the user's browser history and their clipboard. The September
// 2026 media hardening cut the server-side links of the takeover chain — an
// attacker's page can no longer execute — but the credential was still in the
// URL. This is the piece that takes it out.
//
// WHAT A TICKET COMMITS TO, AND WHAT IT DOES NOT.
//
// A ticket is a signed statement of exactly one thing:
//
//     "at time T, <user_id> was allowed to download <media_id>, and this
//      statement stops being worth anything at <exp>"
//
// It is a POINTER TO AN AUTHORIZATION, NOT A REPLACEMENT FOR ONE. Presenting a
// valid ticket tells the download path who the caller is; it does not tell it
// that the caller may have the bytes. MediaHandler::handle_download re-runs
// may_download() on the decoded user id at fetch time, so a channel locked down
// (or a message redacted, or a room deleted) in the seconds between minting and
// fetching revokes the ticket's usefulness immediately. The ticket cannot widen
// access beyond what the bearer would get from their own session token.
//
// It is also NOT a bearer session credential. It names one media id and one
// user, it expires in minutes rather than months, it is minted only from an
// Authorization header (a ticket can never mint another ticket), and it grants
// nothing anywhere else in the API. A ticket leaked into an access log is worth
// one object to one already-authorized user for a few minutes, which is the
// whole point of the change.
//
// WHAT IS IN THE URL AFTERWARDS. `?mt=<b64url(user_id)>.<b64url(mac)>&exp=<ts>`.
// The user id is in there in the clear, because the fetch-time re-check needs
// to know who to re-check — the MAC covers it, so it cannot be swapped. That
// does put the caller's own mxid into nginx's access log. A user id is not a
// credential and the caller's own requests already identify them by IP and
// session; this is a deliberate trade for statelessness (no ticket table, no
// migration, no cross-restart state).
//
// MAC INPUT. Length-prefixed so the encoding is injective — plain
// concatenation would let (media "ab", user "c") and (media "a", user "bc")
// share a signature:
//
//     "bsfchat/media-ticket/v1" || u32be(len) media_id
//                               || u32be(len) user_id
//                               || u32be(len) server_name
//                               || u64be(exp)
//
// So a ticket for one object is not a ticket for another, a ticket for one user
// is not a ticket for another, and `exp` cannot be pushed out by editing the
// query string: it is signed, not merely carried.

namespace bsfchat::media_ticket {

// Ticket lifetime. Long enough that a channel's worth of images resolves under
// one mint each and a video keeps playing through it, short enough that a
// ticket recovered from a log or a proxy cache is stale before anyone reads it.
inline constexpr int64_t kDefaultTtlSeconds = 300;

// Clamp applied to the configured TTL. The ceiling matters more than the floor:
// the entire security argument for putting this in a URL is that it expires
// quickly, so an operator cannot turn it back into a long-lived bearer token.
inline constexpr int64_t kMinTtlSeconds = 30;
inline constexpr int64_t kMaxTtlSeconds = 3600;

// The key tickets are signed with, derived — never configured.
//
// HKDF-SHA256(ikm = instance_secret, salt = "bsfchat/media-ticket/v1",
//             info = server_name)
//
// The instance secret is a server-scoped random value the server generates for
// itself on first use and keeps in server_meta (see
// MediaHandler::ticket_key()). Derivation rather than direct use, and a
// domain-separating salt, so that when some later subsystem wants a signing key
// from the same secret it gets an unrelated one — exactly the arrangement
// VoiceHandler::livekit_room_key() uses for room keys.
//
// Throws std::runtime_error on an empty secret or an OpenSSL failure. An empty
// ikm would produce well-formed-looking bytes that every deployment with an
// empty secret would share, which is worse than not starting.
std::vector<unsigned char> derive_key(const std::string& instance_secret,
                                      const std::string& server_name);

// The `mt` query parameter value: "<b64url(user_id)>.<b64url(mac)>".
std::string mint(const std::vector<unsigned char>& key,
                 const std::string& server_name,
                 const std::string& media_id,
                 const std::string& user_id,
                 int64_t exp_unix_seconds);

// Verifies `mt` against `media_id` and `exp`, and returns the user id it names.
//
// nullopt for: a malformed ticket, a signature that does not match, an `exp`
// that has passed, or an `exp` implausibly far in the future (a signature is
// only as good as the clock it was issued under; a ticket claiming to be valid
// for a year was either signed by a server with a broken clock or is being
// replayed against one, and neither is worth honouring).
//
// Constant-time comparison: a byte-at-a-time memcmp on a MAC is forgeable given
// enough attempts, and media ids are enumerable targets.
std::optional<std::string> verify(const std::vector<unsigned char>& key,
                                  const std::string& server_name,
                                  const std::string& media_id,
                                  const std::string& mt,
                                  int64_t exp_unix_seconds,
                                  int64_t now_unix_seconds);

// Parses a decimal `exp` query parameter. Strict: digits only, no sign, no
// whitespace, must fit in an int64. nullopt otherwise.
std::optional<int64_t> parse_exp(const std::string& raw);

} // namespace bsfchat::media_ticket
