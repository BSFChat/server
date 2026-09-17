#pragma once

// Call signalling is NOT ordinary room content, and this header is the one
// place that says which events those are.
//
// ── The leak this exists to close ─────────────────────────────────────────
// Voice and video run as a WebRTC mesh: every pair of participants negotiates
// its own peer connection, and the negotiation — m.call.invite, m.call.answer,
// m.call.candidates, m.call.hangup and bsfchat.call.negotiate — rides the
// shared room timeline as ordinary events. ICE candidates ARE addresses: the
// host candidates carry the sender's LAN address, the server-reflexive ones
// carry their public IP, and both are in plain text inside `content`.
//
// The server used to deliver those events to EVERY member syncing the room and
// persist them forever alongside chat. So:
//
//   * a silent member of a busy voice channel could read the LAN and public IP
//     of every pair in it, without joining the call;
//   * anyone who joined the channel MONTHS LATER could page /messages back
//     through the history and harvest the same addresses at leisure.
//     (Production held 4,518 such events going back to April.)
//
// Neither is anything the participants consented to. A call between A and B
// exposes A's address to B — that is inherent to peer-to-peer — but it must
// not also broadcast it to C, D and to everyone who ever joins afterwards.
//
// ── The rule ─────────────────────────────────────────────────────────────
// A signalling event that names its addressee (`content.to`) is delivered to
// exactly two users — the sender and that addressee — and is retained only
// long enough to survive a client's gap between syncs. It never appears in
// /messages history, is never search-indexed and never counts as unread.
//
// An event with NO `to` is left alone, on every one of those paths. A client
// old enough not to address its signalling cannot be delivered to selectively
// (the server would have to parse SDP to guess the recipient, and guessing
// wrong silently breaks the call), so it keeps exactly today's behaviour and
// today's exposure. Every shipped client has addressed its signalling since
// the field was introduced; see voice/CallSignalCodec.h in the client.

#include <bsfchat/Constants.h>

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace bsfchat {

// The five event types that carry connection-establishment data.
//
// m.call.member is deliberately NOT here. It is the voice ROSTER — a state
// event saying "this user is in this call" — which every member of the channel
// is meant to see and which the UI cannot work without. It carries no address.
inline bool is_call_signalling_type(std::string_view event_type) {
    return event_type == event_type::kCallInvite ||
           event_type == event_type::kCallAnswer ||
           event_type == event_type::kCallCandidates ||
           event_type == event_type::kCallHangup ||
           event_type == event_type::kCallNegotiate;
}

// The addressee of a signalling event, read from its content.
//
// Returns nullopt for anything that is not addressed signalling — a different
// event type, unparseable content, a missing `to`, a `to` that is not a string,
// or an empty one. That nullopt is what "behave exactly as before" is keyed
// off everywhere downstream, so it has to be the answer for every doubtful
// case rather than only for the tidy ones.
//
// Parsed in C++ rather than with SQLite's json_extract() for the same reason
// `replaces` is (see Migrations.cpp): it keeps the rule identical between the
// insert path, the migration and the tests, with no dependency on which JSON
// functions a given SQLite build was compiled with.
inline std::optional<std::string> call_signal_addressee(std::string_view event_type,
                                                        const std::string& content_json) {
    if (!is_call_signalling_type(event_type)) return std::nullopt;
    auto j = nlohmann::json::parse(content_json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    auto it = j.find("to");
    if (it == j.end() || !it->is_string()) return std::nullopt;
    auto to = it->get<std::string>();
    if (to.empty()) return std::nullopt;
    return to;
}

namespace limits {

// How long an addressed signalling event is kept.
//
// It has to outlive the gap between one /sync returning and the next one being
// issued — a client that is briefly offline, or between long polls, must still
// receive the invite that was sent while it was not looking. Two minutes is
// far beyond that (a poll cycle is seconds) and far below anything that could
// be called a record: the 60 s `lifetime` on an invite has long since expired,
// the client's own stale-invite filter would discard it, and the call it
// belongs to is over either way.
//
// It deliberately does NOT survive a restart in any useful sense — the sweep
// runs at startup as well — because a call in progress across a server restart
// re-offers through the mesh reconciler within 5 s anyway.
inline constexpr int64_t kCallSignallingTtlMs = 120 * 1000;

} // namespace limits

} // namespace bsfchat
