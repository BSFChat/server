#pragma once

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

// What a brand-new deployment hands its first user.
//
// THE PROBLEM. A freshly installed server came up with users = 0, rooms = 0,
// events = 0 and stayed that way. The first person to sign in landed in an
// empty shell: no channel to read, nothing to click, and — the part that made
// it a deadlock rather than a blank page — no way to make one.
//
// The deadlock is worth spelling out, because "the admin can just create a
// channel" is the obvious answer and it was false. Server-side the first
// account really does hold Admin: bootstrap_roles writes the role document to
// the `server_state` table and assigns `admin` to the oldest account, so
// POST /createRoom would have been allowed. But the CLIENT learns roles from
// ONE place — `bsfchat.server.roles` state events arriving in /sync — and
// write_server_scoped_state can only mirror those events into a room. With no
// rooms there is no mirror room, so the event is never delivered, the client
// computes its own permissions as zero, and every "+ create channel"
// affordance stays hidden. No rooms meant no way to learn you could make one,
// which meant no rooms.
//
// So the first channel cannot be the user's job. The server makes it.
//
// WHAT IT MUST NOT DO is invent channels on a server that already has some.
// Production is live and gets this build like any other. Two guards, and the
// second is the one that matters:
//
//   1. A `server_meta` marker, written on the FIRST boot of this build
//      whatever the outcome. A deployment that skipped creation because it
//      already had rooms is marked "skipped", so an operator who later deletes
//      every channel does not find them resurrected by the next restart. The
//      decision is taken once, against the server as it was when this code
//      first saw it, and never revisited.
//   2. `has_any_room()` — literally "is the rooms table empty". Not "no public
//      rooms" and not "no channels": a server whose only room is a category, or
//      a DM, or a channel everyone has left, has been used, and a used server
//      is not a new one.
//
// Ordered before backfill_auto_join in Server::start() so that the boot which
// creates the channels is also the boot that joins existing accounts to them.
// That is what carries an already-deployed-but-still-empty server (the UAT box
// had users = 1, rooms = 0) across the upgrade without anybody re-registering.
//
// Membership is not visibility (see auth/RoomVisibility.h), and nothing here
// bends that rule: the default channels are plain public channels with no
// permission overrides at all, so every user's VIEW_CHANNEL comes from
// @everyone exactly as it would for a channel an admin made by hand.
void bootstrap_default_channels(SqliteStore& store, SyncEngine& sync_engine,
                                const Config& config);

} // namespace bsfchat
