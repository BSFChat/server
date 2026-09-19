#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Opaque /sync tokens.
//
// WHAT THIS REPLACES, AND WHY. `next_batch` used to be "s" followed by the raw
// GLOBAL stream position — one counter shared by every room on the server. Any
// authenticated account could poll `GET /sync?timeout=0` once a second, read
// the integer, and subtract the events it was actually shown: the remainder is
// the exact number of events that happened everywhere else on the deployment,
// timestamped to the second. Over a day that reconstructs the activity profile
// of every private channel — when the exec channel is busy, when an incident
// starts, when an off-hours conversation happens — for rooms the caller cannot
// see and is not a member of. Recorded as finding 10 in
// docs/audit-data-2026-09.md.
//
// OPAQUE, NOT UNFORGEABLE. That is a deliberate choice, and it decides how
// strong this has to be.
//
// The oracle is the VALUE the server hands out, not the value the client hands
// back. A position the client sends in is not trusted with anything: it only
// says where in the stream to start scanning. SqliteStore::get_events_since
// joins room_members for the CALLER and filters addressed call signalling to
// the caller, and SyncEngine::build_incremental_sync then re-evaluates
// VIEW_CHANNEL per event through room_view() before anything reaches the
// response. So a caller who forged a position — or who simply passed `s0`,
// which is a supported request today and what every initial sync is — gets
// their own history and nobody else's, exactly as they would from /messages.
// Forgery buys nothing, so the property this needs is that the token REVEAL
// nothing, not that it be impossible to construct.
//
// Integrity comes along for free and is kept because it costs nothing: the
// plaintext block carries an 8-byte tag derived from the caller's user id, so
// a token minted for one account is rejected when presented by another, and a
// random 32-hex string clears the tag check with probability 2^-64. What the
// tag is NOT is load-bearing for access control; see above.
//
// WHY A KEYED PERMUTATION AND NOT AN ENCODING. Every order- or
// delta-preserving transform fails, including the two cheapest: `pos + k`
// preserves deltas exactly, and `pos XOR k` leaks them nearly as badly, since
// consecutive tokens give p1^p2 and the increments are small, so the low bits
// of the difference fall straight out. Hiding a delta needs a pseudorandom
// permutation. One AES-256 block over the position IS that permutation applied
// once, which is why the construction is a single block and not a mode.
//
// DETERMINISM IS LOAD-BEARING. The same (user, position) always mints the same
// string. The desktop client's SyncBackoff treats a fast reply whose next_batch
// did not move as a sign of an endpoint answering 200 unconditionally (a
// caching proxy, a misrouted reverse proxy) and answers with an escalating
// delay. A token with a nonce in it would change on every idle reply, which
// disables that guard — the mirror image of the bug the raw-counter token was
// introduced to fix, where a token pinned to the highest VISIBLE row never
// advanced and walked idle clients out to a 60 s poll interval. Both are
// regressions; determinism avoids both. It costs nothing here because a
// position is not a secret being encrypted, it is a value being hidden from
// arithmetic.
//
// COST. Minting is one HMAC-SHA256 over a short string plus one AES block, and
// reading is the same; each also allocates and tears down one EVP cipher
// context, because an EVP_CIPHER_CTX is not safe to share between the worker
// threads /sync runs on. That is a microsecond or so per response, against a
// handler that has already taken the store mutex and run a range scan over
// `events` — so caching the context (thread-local, or one per engine behind a
// lock) would be a real complication for no measurable return. The key itself
// IS cached: the HKDF runs once per process.
//
// WHAT IS NOT CHANGED. `prev_batch` and the `from=` parameter of
// /rooms/{id}/messages keep the "s<N>" form. That number is the stream position
// of an event in ONE room that the caller has already been shown, not the
// global head, so it is not this oracle — and /messages is a room-scoped read
// whose own permission check is unaffected by where the caller starts.

namespace bsfchat::sync_token {

// The key sync tokens are built with, derived — never configured.
//
//     HKDF-SHA256(ikm = instance_secret, salt = "bsfchat/sync-token/v1",
//                 info = server_name)
//
// A DISTINCT salt from media tickets (MediaTicket.h), which derive from the
// same instance secret. Reusing that key would make a media ticket's MAC and a
// sync token two uses of one key under two different constructions, which is
// the arrangement the domain separation exists to prevent.
//
// Throws std::runtime_error on an empty secret or an OpenSSL failure. An empty
// ikm produces well-formed-looking bytes that every deployment with an empty
// secret would share.
std::vector<unsigned char> derive_key(const std::string& instance_secret,
                                      const std::string& server_name);

// "t_" followed by 32 lowercase hex characters.
//
// Throws std::runtime_error on an OpenSSL failure, for the same reason
// generate_media_id() does: there is no safe degraded token.
std::string mint(const std::vector<unsigned char>& key,
                 const std::string& user_id,
                 int64_t position);

// Reads a token back to the stream position it names.
//
// Accepts BOTH forms:
//
//   * "t_<32 hex>" — this format. Decrypted, and the embedded tag must match
//     `user_id`.
//
//   * "s<digits>"  — THE LEGACY FORM, accepted on read only; nothing mints it
//     any more. Every client persists its sync token across restarts, so the
//     upgrade would otherwise force every client on every deployment into a
//     full initial sync at once, which is the one thing an opaque token must
//     not cost. A legacy token discloses the position its holder already had;
//     it cannot disclose anything new, and the holder cannot mint another.
//
//     WHEN THIS CAN BE DROPPED: one release after the release that introduces
//     the "t_" form. A client that has polled /sync even once against an
//     upgraded server is holding a "t_" token from then on, so the only holders
//     left after that are clients that have not run in a whole release cycle —
//     for whom a single full initial sync on next launch is the correct and
//     cheap outcome. Delete the kLegacy branch below and its tests together.
//
// nullopt for anything else. The caller decides what to do with that;
// SyncEngine treats it the way it has always treated a malformed token, as
// position 0 — a full replay of what the caller may see, never an error and
// never anyone else's events.
std::optional<int64_t> parse(const std::vector<unsigned char>& key,
                             const std::string& user_id,
                             const std::string& token);

} // namespace bsfchat::sync_token
