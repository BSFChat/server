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
bool can_view_room(SqliteStore& store, PermissionsEngine& perms,
                   const std::string& user_id, const std::string& room_id);

// The joined rooms this user may know about. `perms` is taken by reference and
// not constructed here so one instance — and therefore one cached read of the
// server roles and of this user's role assignment — spans the whole list.
// Constructing an engine per room turns this into an N+1 behind the store's
// global mutex, which is what it costs on a server with a few hundred channels.
std::vector<std::string> visible_joined_rooms(SqliteStore& store, PermissionsEngine& perms,
                                              const std::string& user_id);

} // namespace bsfchat
