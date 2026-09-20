# Membership is not visibility

Audit accompanying the `/joined_rooms` disclosure fix (`fix/joined-rooms-leak`),
and a design recommendation on the thing that caused it.

Status: findings 1–3 and the two `/joined_rooms` disclosures were fixed in
`fix/joined-rooms-leak`. Findings 4–6, reported for triage and deliberately
left at the time, are closed in `harden/ip-and-membership` (20 Sep 2026) — see
their section below. The design recommendation at the end is **still not
started**, and findings 4–6 are three more instances of the argument for it.

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
| `GET /sync` (typing pass, second half) | The same pass also walks `rooms.join` **as SyncEngine built it** and attaches a typing ephemeral to every entry with a typist, unchecked — on the assumption that everything in that map is something the caller may see. Categories break the assumption: they are deliberately exempt from VIEW_CHANNEL so the sidebar keeps its structure, so a denied category *is* in the map, and the pass narrated the activity inside it to the user it is hidden from. A category is meant to be a name and a position to that user; `"Alice is typing"` is neither. This matters more under `security/category-visibility`, which turns a denied category into an explicit name-and-ordering stub — attaching live activity to a stub contradicts the whole point of it. |
| `POST /rooms/{id}/voice/join` | Membership plus "is the room voice-capable", and nothing else — so a user denied VIEW_CHANNEL could join the **mesh** call. Participation, not disclosure. It also fed `handle_voice_state`, which authorises on "is an active call member"; this is the only endpoint that makes someone one, so gating it closes that path too. |
| `GET /rooms/{id}/voice/members` | Membership only, returning the live roster: who is connected, muted, deafened, screen-sharing, on what device and session. `/rooms/{id}/members` already refused a denied user; the louder of the two did not. |
| `PUT /rooms/{id}/typing/{user}` | Membership only. A typing indicator is a **write into** the channel and reaches exactly the people who can see it, so the `/sync` filter cannot contain it — an outsider could surface their name inside a channel they cannot open. |

All of these match `handle_livekit_token`: `PermissionsEngine::compute()` then
`has(flags, kViewChannel)`. They check `kViewChannel` directly rather than going
through `can_view_room()`, because that helper exempts categories — which is a
rule about *listing* a room in a sidebar, not about acting inside one. The
distinction is now recorded in `auth/RoomVisibility.h`.

Both directions are tested, and both were confirmed by mutation: removing the
gates fails the denial tests, and tightening them to demand `kManageChannels`
fails the permitted-user tests. The permitted user in each is an **ordinary
member holding only `kEveryoneDefault`** — asserting it with an admin proves
nothing, because ADMINISTRATOR short-circuits every flag. `e2e_voice`, which
drives two ordinary users through repeated real voice joins over HTTP against
the real binary, passes unchanged.

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
  any HTTP route, and the channel directory below deliberately does not use it:
  its "public" is the room's `visibility`, which is `public` on every channel on
  this server including the private ones, so it is precisely the wrong predicate
  for a listing.

- **`GET /bsfchat/channels`** (`feat/channel-directory`) — the channel
  directory, and the first endpoint here that enumerates rooms the caller is
  **not** a member of. It sweeps every non-direct room and filters each through
  `can_view_room()`; membership is never consulted, and appears in the response
  only as the caller's own `joined` flag, computed after the filter. Three
  things about it are worth keeping in mind before the next listing endpoint is
  written:

  * **DMs are excluded in SQL**, in `list_room_directory_rows()`, before any
    permission is evaluated. This is not tidiness. `compute()` clears channel
    overrides on a direct room (finding 6 above), so a DM that reached a
    VIEW_CHANNEL filter would **pass** it for every account on the server, and
    the directory would publish every private conversation on the instance. The
    invariant "a DM's privacy is its membership" has no expression in a
    server-wide room list, so a DM must never enter one.
  * **`category_id` is checked against the response**, not echoed from state.
    `handle_create_room` validates only that `parent_id` names an existing room
    — only `handle_move_channel` checks that it is a category — so a channel can
    genuinely carry a private channel as its parent, and echoing that id back
    would leak the room the filter had just removed.
  * **The sort order is not on the wire.** It is assigned per category with
    gaps, so publishing it would let a caller read the gaps and count what was
    filtered out of their own response. Position is carried by the array's own
    order, which is dense by construction. The general form of that rule — *a
    field derived from the unfiltered set is a disclosure even when every id in
    the response is permitted* — is the one most likely to be missed next time.

### Findings 4–6 — closed in `harden/ip-and-membership`, 20 Sep 2026

Numbering follows the original audit; 1–3 are in the table above. All three
were correctly deprioritised at the time: none of them discloses channel
content, and the surrounding work had not landed. They are closed now.

Each asks `kViewChannel` directly rather than going through `can_view_room()`.
These are **acting** paths, and that helper exempts categories — which is the
LISTING rule, for a sidebar that has to draw a container it cannot open. The
distinction is recorded in `auth/RoomVisibility.h` and above `can_read_room` in
`RoomHandler.cpp`; reinstating the exemption on a path that acts is how an
exemption becomes a hole.

4. **`POST /rooms/{id}/read_marker`** — membership **and** `kViewChannel`, in
   `EventHandler::handle_read_marker`. A denied user no longer writes a read
   position into a channel they cannot read, and the test asserts the row is
   absent rather than only that the request was refused. The refusal reuses the
   membership refusal's status and message verbatim; see 5 for why.

5. **`GET`/`PUT /bsfchat/rooms/{id}/notify_level`** — the gate is now one
   function, `notify_level_refused()`, shared by both handlers. The response
   body never leaked anything (it is the caller's own setting), so what is being
   closed is the **room-id existence oracle**: a 200 said "this room exists and
   you are in it" for a channel the caller is denied, while any other room id
   said 403.

   That makes the property to assert an unusual one. It is not "it refuses" —
   it is that **every** reason to stop answers identically: not a member, room
   does not exist, and member-but-denied all produce the same status and the
   same body, byte for byte. A distinguishable refusal is the oracle. The two
   checks live in one function specifically so they cannot drift apart later.
   Both tests compare a denied room against an invented room id rather than
   against a literal.

6. **`bsfchat.channel.permissions` on a DM** — fixed in **two** places, and the
   second one is the point.

   *The write.* The key is added to the structural-refusal list in
   `handle_set_state`, beside `bsfchat.room.category`, `bsfchat.room.type` and
   `m.room.join_rules`. A DM has no channel access control: its access control
   is that exactly two people are in it and nobody is ever force-joined into
   one, which is precisely why `m.direct` is derived straight from membership
   and deliberately left unfiltered.

   *Why a deny-list entry and not an allow-list for DMs.* This file argues the
   other way for `state_gate_for` — "allowing by default is what produced the
   hole" — and the obvious broader fix is to refuse every state type on a DM
   except a named few. It is wrong here, for a concrete reason: four of the
   types this route accepts are **not scoped to the room they are written in**
   (`bsfchat.server.info`, `.roles`, `.screenshare`, `bsfchat.member.roles`).
   `bsfchat.server.screenshare` in particular is a server-wide setting that the
   client writes into whichever room happens to be active
   (`ServerConnection::setScreenSharePolicy` takes `m_activeRoomId`), and that
   can be a DM. A default-refuse rule on DMs would break server administration
   from a DM window. What is wrong is specifically per-**channel** configuration
   on a room that is not a channel, and that is what is refused.

   *The read.* `PermissionsEngine::compute()` now clears channel overrides for a
   direct room. Refusing the write stops new ones; it does **not** repair a DM
   that already carries an override from a build without the refusal — and
   after the refusal nothing can, because clearing an override means writing an
   empty one through the route that now refuses. So the invariant this document
   already asserts ("DMs carry no overrides") is enforced where it is READ, and
   sync, listing, reading, voice and typing agree at once instead of each
   remembering the DM case. The lookup is ordered after `get_channel_overrides`
   and memoised per engine, so a room with no overrides pays nothing.

   This is the same lesson as the recommendation at the end of this document,
   one size down: `auth/RoomVisibility.h` "is a convention, not an invariant".
   For DMs specifically, it now is one.

**Tests.** Eleven in `tests/test_room_visibility.cpp`. Five were confirmed
failing first. Six are controls, and they are the half that would hurt: an
ordinary member holding only `kEveryoneDefault` must still mark a channel read
and set a notify level, a user-specific ALLOW override must still reinstate a
denied user, a real channel must still accept the override that is how a channel
is made private, and a DM must still answer `notify_level` (its default differs
from a channel's). Asserting any of these with an admin would prove nothing,
because ADMINISTRATOR short-circuits every flag.

### Deliberately left alone

- **`POST /rooms/{id}/voice/leave`** is membership-only and stays that way.
  Hanging up must never be refused — gating it would strand a user in a call
  they had just lost permission to be in.
- **`PUT /rooms/{id}/voice/state`** authorises on "is an active call member"
  rather than on a permission. It is now closed at the entrance, since
  `voice/join` is the only endpoint that makes someone an active member. One
  narrow window remains: a user whose VIEW_CHANNEL is revoked **while already in
  a call** keeps updating mute/deafen/screen-share until the heartbeat reaper
  expires them. Adding a check there is a one-liner, but it is a live-call path
  on the least-settled part of the codebase, and getting it wrong drops people
  mid-call — worth doing deliberately rather than alongside this fix.

## Update: kick is now enforced at `/join`

`fix/kick-enforceable` (audit-requests finding 6) closed the hole this document's
model made easy: a kicked user could rejoin any channel with one empty POST,
because every channel carries `join_rule: "public"` and nothing else was checked.
A kick now stamps `bsfchat.removed_by` on the member event it writes, and `/join`
refuses when the caller's current member event is a `leave` carrying that key
from somebody else. A voluntary leave stays rejoinable — under this model leaving
is how a user hides a channel, so it has to.

**It reinforces the recommendation below rather than replacing it.** The fix is a
check on one endpoint, and it needs a marker precisely because membership here
carries no meaning on its own: with `join_rule: "invite"` for private channels
there would be nothing for `/join` to refuse and no marker to write.

Note for operators until the client catches up: reversing a kick means inviting
the user back by mxid, since a removed user is no longer in the member list.

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

1. Ship this branch. It closes the disclosure. **Done.**
2. Triage findings 1–3 as ordinary bugs against the current model — they are
   one-line VIEW_CHANNEL checks each, and none of them needs the redesign.
   **Done**, and findings 4–6 with them (`harden/ip-and-membership`).
3. Make `get_joined_rooms()` hard to misuse: either move it behind
   `RoomVisibility`, or rename it to something that cannot be mistaken for an
   authorization answer.
4. Only then decide on the model change, with the migration written first and
   dry-run against a production snapshot.

Steps 1–3 remove the disclosure and most of the bug class; step 4 is what
actually closes it, and is a release of its own.
