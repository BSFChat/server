#pragma once

#include <string>
#include <vector>

namespace bsfchat {

class SqliteStore;
class PermissionsEngine;

// "Is this user a member of the room" and "may this user be told the room
// exists" are two different questions, and on this server they have different
// answers.
//
// A private channel is not a separate room: the client creates every channel
// public, force-joins everyone through auto-join, and then denies VIEW_CHANNEL
// to @everyone. backfill_auto_join re-adds every user to every such channel on
// each boot. "Joined but not permitted to view" is therefore the NORMAL steady
// state, not an edge case — which means a membership row carries no privacy
// meaning at all, and any response derived from one leaks the full list of the
// server's private channels.
//
// These two functions are the single definition of the rule. Anything that
// turns membership into something a user is shown should go through them rather
// than restate the check, because restating it is how the check gets forgotten:
// GET /_matrix/client/v3/joined_rooms returned raw membership for exactly that
// reason.
//
// Note the deliberate omission: neither function tests membership. They answer
// only the visibility half, so a caller that also needs "is a member" — a write
// path, say — states that separately and stays readable about which of the two
// it is relying on.

// Categories are exempt: the sidebar has to render the container node even when
// every channel inside it is hidden, so a category the user cannot "view" is
// still named to them. This matches SyncEngine, which has always done the same.
//
// That exemption makes this a rule about LISTING a room, not about acting
// inside one. Somewhere an endpoint lets a user DO something in a channel —
// join its call, publish a typing indicator, read its roster — the question is
// only kViewChannel, and it should be asked directly, as the voice and typing
// handlers do. Granting a category the benefit of the doubt in a sidebar is
// right; granting it to a request that acts is how an exemption becomes a hole.
// Is this room a category (a sidebar container) rather than a channel?
//
// Exposed rather than restated per call site: it was hand-rolled in three
// places before, and the conversion gate in handle_set_state, the parent check
// in handle_move_channel and the listing exemption below must agree about what
// a category is or the gate protects a different set than the exemption opens.
bool is_category_room(SqliteStore& store, const std::string& room_id);

bool can_view_room(SqliteStore& store, PermissionsEngine& perms,
                   const std::string& user_id, const std::string& room_id);

// The joined rooms this user may know about. `perms` is taken by reference and
// not constructed here so one instance — and therefore one cached read of the
// server roles and of this user's role assignment — spans the whole list.
// Constructing an engine per room turns this into an N+1 behind the store's
// global mutex, which is what it costs on a server with a few hundred channels.
std::vector<std::string> visible_joined_rooms(SqliteStore& store, PermissionsEngine& perms,
                                              const std::string& user_id);

// ── the channel directory ────────────────────────────────────────────────────
//
// One entry of the answer to "which channels exist on this server that I may be
// told about" — the question /joined_rooms deliberately cannot answer, because
// it starts from membership and a caller can only be a member of what somebody
// already put it in. A bot that has never been invited anywhere sees the same
// directory a human does.
//
// WHAT AN ENTRY CARRIES, and why it carries no more. A directory is read by
// anyone with a token, about channels they are not in, so each field is a field
// handed to every account on the server:
//
//   room_id, name   Needed. Without both, the directory cannot be rendered as a
//                   picker or acted on afterwards.
//   type            Needed to render one. A picker offering a voice channel as
//                   the destination for text alerts is a broken picker, and the
//                   value is already public to every account through the sync
//                   stub for categories and through /state for channels the
//                   caller can view.
//   category_id     The sidebar grouping. Set ONLY when the named parent is
//                   itself in this same response, so it can never be the one
//                   field that names a room the caller was not shown.
//   joined          The CALLER'S OWN membership row. Not a fact about the
//                   channel and not a fact about anybody else, so it discloses
//                   nothing the caller did not already have — and a bot
//                   deciding whether it must join before posting has no other
//                   way to ask across the whole list.
//
// Deliberately absent: topic, member count, last-activity, creator, and the raw
// sort_order integer. The first four are reconnaissance — a directory's job is
// "where may I post", not "tell me about this place I cannot enter". The fifth
// is subtler and is the reason it is called out here: sort_order is assigned
// per category with gaps, so publishing it would let a caller read the gaps
// and count the channels that were filtered out of their own response. Position
// is expressed by the ORDER OF THE ARRAY instead, which is dense by
// construction and therefore says nothing about what is missing from it.
struct ChannelDirectoryEntry {
    std::string room_id;
    std::string name;
    std::string type;        // room_type::kText / kVoice / kCategory, "" if unset
    std::string category_id; // empty when top-level or when the parent is not visible
    bool joined = false;     // the caller's own membership
};

// The directory for `user_id`: every non-direct room on the server that passes
// can_view_room(), in render order.
//
// The filter is can_view_room() and nothing else. This is a LISTING, which is
// precisely the case that helper's category exemption was written for — the
// same exemption /sync applies, so the directory and the sidebar name the same
// set of containers instead of disagreeing about them. It is NOT a licence to
// act: a caller that finds a category here still cannot read it, join its call
// or type in it, because those paths ask kViewChannel directly.
//
// The answer does not depend on whether the caller is a bot, and must not: a
// bot is an ordinary user account, and a special case inside a security filter
// is a second filter that only one class of caller ever exercises.
//
// Ordering is (parent, sort_order, room_id), flattened: each top-level entry,
// and immediately after a category its children. room_id breaks ties so the
// order is total and a client's list does not reshuffle between polls. Nesting
// is one level deep — a category is never filed under another category — which
// matches the client's sidebar model and makes a parent cycle unrepresentable.
//
// Cost is linear in the number of rooms: one sweep for the room rows, one for
// the caller's memberships, then one channel-override read per room inside
// compute(). `perms` is taken by reference for the reason given above — one
// engine for the whole list, or the role reads multiply by the room count.
std::vector<ChannelDirectoryEntry> visible_channel_directory(SqliteStore& store,
                                                             PermissionsEngine& perms,
                                                             const std::string& user_id);

} // namespace bsfchat
