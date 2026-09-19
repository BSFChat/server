# Membership is not visibility

Audit accompanying the `/joined_rooms` disclosure fix (`fix/joined-rooms-leak`),
and a design recommendation on the thing that caused it.

Status: the fix is in this branch. **Nothing else here is fixed** — the findings
below are reported for triage, and the recommendation is not started.

## The shape of the bug

A private channel on this server is not a private room. The client creates every
channel with `visibility="public"` hardcoded (`client/src/net/MatrixClient.cpp`),
then writes an `@everyone DENY VIEW_CHANNEL` override; `ChannelSettings.qml`
defines `isPrivate` as exactly that deny bit. `SqliteStore::list_public_rooms()`
ignores overrides, so auto-join force-joins every user into every private
channel, and `backfill_auto_join` re-creates those rows on every boot.

So **"joined but not permitted to view" is the normal steady state**, and a
`room_members` row carries no privacy meaning whatsoever. Every response derived
from membership is therefore a candidate disclosure, and the question to ask each
one is: *does "joined" silently stand in for "allowed to know about"?*

`auth/RoomVisibility.h` is now the single place that answers it. Anything that
turns membership into something a user is shown should go through it.

## Audit

Every endpoint and response that derives from membership. "Correct" means the
membership test is either backed by a VIEW_CHANNEL check or is the right gate on
its own merits.

### Fixed in this branch

| Path | Was |
|---|---|
| `GET /joined_rooms` | Returned `get_joined_rooms()` verbatim — a complete index of every private channel on the server, to any authenticated user. |
| `GET /sync` (typing pass) | `SyncEngine` filters `rooms.join` by VIEW_CHANNEL; `SyncHandler` then walked the **raw** joined-room list and created a `rooms.join` entry for any room with a typist. One person typing in a private channel put its id in front of everyone it is hidden from. |

### Correct already

- **`GET /rooms/{id}/members`**, **`/state`**, **`/state/{type}`** — all three go
  through `can_read_room()`, which is membership **and** VIEW_CHANNEL. This is
  why the leak was ids only.
- **`GET /rooms/{id}/messages`** — checks `kViewChannel` explicitly.
- **`POST /search`** — filters joined rooms by VIEW_CHANNEL *before* the query
  and uses the result as the query's room restriction, so an inaccessible
  channel is never searched rather than searched-then-filtered. A
  client-supplied `filter.rooms` can only narrow that set. This is the pattern
  the rest of the codebase should look like. (It omits the category exemption,
  which is harmless — categories hold no messages.)
- **`m.direct` / DM derivation** — `get_direct_rooms()` requires `is_direct = 1`
  and the caller's own `membership = 'join'`. A DM is the one room kind where
  membership **is** the privacy boundary: nobody is force-joined into one,
  `list_public_rooms()` excludes `is_direct` rooms explicitly, and DMs carry no
  overrides. You only ever see your own. Correct, and deliberately unfiltered.
- **Mention fan-out** (`EventHandler::parse_mentions`) — tests `is_room_member`
  *and* `perms.can(target, room, kViewChannel)` per target, so a denied user is
  never badged for a channel they cannot see.
- **`GET /sync` presence pass** — aggregates member ids across joined rooms into
  a flat global map and emits no room ids, so it never disclosed one. Now
  derived from the filtered list anyway.
- **`POST /rooms/{id}/voice/livekit_token`**, **`/livekit_rekey`** — both check
  `kViewChannel` explicitly, with comments saying why.
- **Moderation writes** (`/kick`, `/ban`, `/unban`, `/invite`, `/category`,
  `/order`, `PUT /state/...`) — the `is_room_member` line is a cheap
  precondition, not the gate; each is followed by a real `PermissionsEngine`
  check at the right scope.
- **`POST /rooms/{id}/leave`** — membership is the correct and only gate;
  leaving is an act on your own membership row.
- **`list_public_rooms()`** — used only by auto-join. It is not reachable from
  any HTTP route; there is no public-rooms directory endpoint.

### Membership-only, not fixed — worth a decision before the RC ships

1. **`POST /rooms/{id}/voice/join` — no VIEW_CHANNEL check.** The gate is
   `is_room_member` plus "is the room voice-capable". Since everyone is a member
   of every channel, **a user denied VIEW_CHANNEL can join the mesh voice
   session of a private voice channel**, and `handle_voice_state` then accepts
   their state updates because it gates on "is an active call member", which
   they now are. This is not disclosure — it is participation. The LiveKit paths
   right next to it (`livekit_token`, `livekit_rekey`) both check `kViewChannel`
   and say so in comments, so the mesh path reads as an oversight rather than a
   decision. *Highest-severity finding here.*

2. **`GET /rooms/{id}/voice/members` — no VIEW_CHANNEL check.** Membership only,
   and it returns the live roster of a channel: user ids, mute/deafen state,
   screen-share and camera flags, device ids and session ids. A user denied
   VIEW_CHANNEL can watch who is talking in a private voice channel.

3. **`PUT /rooms/{id}/typing/{user}` — no VIEW_CHANNEL check.** A denied user
   can inject a typing indicator into a private channel. After the `/sync` fix
   other denied users no longer see it, but **users who can view the channel
   do** — so an outsider can make their name appear as "typing…" inside a
   channel they have no access to.

4. **`POST /rooms/{id}/read_marker` — no VIEW_CHANNEL check.** A denied user can
   write a read position into a channel they cannot read. Harmless in itself;
   listed because it is the same pattern and will be copied.

5. **`GET`/`PUT /bsfchat/rooms/{id}/notify_level` — no VIEW_CHANNEL check.**
   Returns only the caller's own setting, so nothing about the channel leaks,
   but it distinguishes "room exists and you are in it" from "not found". A
   room-id existence oracle. Negligible on its own — room ids are random and the
   index that made them guessable is what this branch closed — but it is only
   negligible *because* of that fix.

6. **`bsfchat.channel.permissions` is not in the DM structural-refusal list** in
   `handle_set_state`, so a DM participant holding MANAGE_ROLES can write a
   channel override onto their own DM. Only the two participants can reach it,
   so it is self-inflicted. Noted because denying VIEW_CHANNEL there now hides
   the DM from `/joined_rooms` and `/sync` while it still appears in `m.direct`
   — a pre-existing inconsistency this change makes symmetric rather than worse.

Items 1–3 all have the same character as the bug that was fixed: a check that
reads as an access check but, on this data model, is not one.

## Recommendation: stop modelling private channels as public-rooms-plus-override

**Do not start this in the RC.** It is a data-model change, and the fix above is
what the RC needs.

### The problem with the current model

- A `room_members` row means nothing. It is not evidence of access, and it never
  will be while auto-join creates one for every user in every channel.
- `backfill_auto_join` re-adds every user to every private channel on every
  boot, so the membership table cannot even be cleaned up — it regenerates.
- Privacy lives in one bit of one override event, read by a component
  (`PermissionsEngine`) that a caller has to remember to consult. The store's own
  `list_public_rooms()` does not consult it, which is what force-joins everyone
  in the first place.
- **Every one of the six findings above is the same mistake**, made
  independently by different people in different files, because the model makes
  the wrong thing the easy thing. `auth/RoomVisibility.h` makes the right thing
  easier, but it is a convention, not an invariant — the next endpoint can still
  call `get_joined_rooms()` directly. The bug class is not closed.

### What the alternative buys

Make a private channel actually private: `join_rule: "invite"`, excluded from
auto-join, membership granted when access is granted and revoked when it is
withdrawn. Then a membership row *means* access, `get_joined_rooms()` is a
correct answer to "what may this user see", and the VIEW_CHANNEL filter becomes
defence in depth rather than the only defence. Unaudited code fails closed.

### What it costs

- **A migration over live data**, and not a trivial one: it must decide, per
  channel and per user, which of today's meaningless membership rows should
  survive. The signal is the override set, so the migration is only as correct as
  the overrides are — and it runs against production rows where nobody has ever
  had to be precise about them.
- **Role changes stop being cheap.** Today, granting someone a role that allows
  VIEW_CHANNEL makes channels appear with no membership writes. Under the new
  model, every role assignment, role-permission edit and override change has to
  recompute memberships and emit join/leave events — a fan-out over
  (users x channels) that does not exist today, on every permission edit.
- **`m.room.member` events become permission-derived**, so `/sync` timelines
  churn on administrative changes, and clients will see joins and leaves that no
  human performed.
- **Two mechanisms during the transition.** Overrides cannot be removed — they
  are still how per-user exceptions work — so for at least one release both the
  membership model and the override model are live, and they can disagree.

### Recommended sequence

1. Ship this branch. It closes the disclosure.
2. Triage findings 1–3 as ordinary bugs against the current model — they are
   one-line VIEW_CHANNEL checks each, and none of them needs the redesign.
3. Make `get_joined_rooms()` hard to misuse: either move it behind
   `RoomVisibility`, or rename it to something that cannot be mistaken for an
   authorization answer.
4. Only then decide on the model change, with the migration written first and
   dry-run against a production snapshot.

Steps 1–3 remove the disclosure and most of the bug class; step 4 is what
actually closes it, and is a release of its own.
