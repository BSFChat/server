# Permissions audit, September 2026

Branch `audit/permissions-2026-09`, worktree `wt/server-permaudit`, from
`origin/main` at `7801693`. Protocol pinned at `3fd3f23`.

The question asked was: *"only users with permissions can actually do things"*.
This document answers it route by route. It is an audit and **nothing in the
server was changed** — see *Nothing was fixed* at the end for why, including for
the finding that is reachable by the least-privileged account on the server.

Every finding below is **PROVEN by a failing test**, not by reading. The tests
are in `tests/test_permission_audit_2026_09.cpp`, disabled by default so that
landing an audit does not redden CI, and run with:

```
./build/tests/server_tests --gtest_also_run_disabled_tests \
    --gtest_filter='PermissionAudit2026_09.*'
```

Each demonstrates a defect on `main` today and is written to pass once the
recommended fix lands. One test in that file is **enabled** and asserts correct
behaviour — see F4, which is a hypothesis that turned out to be wrong and is
recorded so nobody re-derives it.

The baseline for all of this is a green suite: 1124 unit tests pass on
`7801693`, and 1125 with the enabled control added.

---

## Summary

| | Finding | Severity | Reachable by | Proof |
|---|---|---|---|---|
| **F2** | Channel overrides have no containment rule and no rank check | **High** | `MANAGE_ROLES` in one channel | `F2a`, `F2b`, `F2c` |
| **F1** | `bsfchat.server.info` is gated at ROOM scope | **High** | a channel override granting `MANAGE_SERVER` | `F1` |
| **F6** | The bot rank check measures roles; a scoped bot holds none | **High** | delegated `MANAGE_BOTS` | `F6` |
| **F3** | `is_direct` is a caller-controlled bypass of the only check on `POST /createRoom`, and force-joins arbitrary accounts | **Medium-High** | **any authenticated account** | `F3`, `F3b` |
| **F5** | The media object → room binding is written by the caller | **Medium-High** | any member who knows a media id | `F5` |
| **F7** | `GET /bsfchat/roles` publishes the whole role document to any account | Medium | any authenticated account, incl. a scoped bot | reasoned |
| **F8** | Role delta endpoints are a read-modify-write with no lock spanning check and write | Medium | `MANAGE_ROLES`; and `self_roles` by any member | reasoned |
| **F9** | `POST .../voice/leave` is gated on `is_room_member` alone | Low | — (no escalation found) | reasoned |
| **F10** | Voice `room_admin` is granted with no rank check | Low-Medium | `MANAGE_CHANNELS` in one channel | reasoned |
| **F11** | Pre-permission refusals leak channel voice configuration | Low | any member | reasoned |
| **F12** | The audit log is not filtered by channel visibility | Low | `MANAGE_SERVER` | reasoned |

**F1, F2 and F6 compose.** F2 is the amplifier: it turns a grant of
`MANAGE_ROLES` in one channel into every channel-scoped flag in that channel,
and F1 turns one of those flags into a server-wide act. `F2b` proves the
two-request chain end to end.

---

## The model, restated, because the findings turn on it

Membership is not visibility. Every channel is a public Matrix room and every
account is force-joined into every one of them; a "private" channel is a public
room carrying an `@everyone DENY VIEW_CHANNEL` override. `is_room_member()` is
therefore not an access check. `docs/membership-vs-visibility.md` is the
authority on this and the rest of the server observes it well — see *What is
correct* below.

The second half of the model is scope. `perms.can(user, room_id, FLAG)` lets a
per-channel override contribute; `perms.can(user, "", FLAG)` does not. The
difference between those two arguments is the whole difference between "a
channel override can grant this" and "only a role can", which is why
`RoomHandler.cpp` gives the empty string a name (`kServerScope`) rather than
spelling it inline. **Findings F1 and F2 are both about that distinction**: F1
is a server-wide act evaluated at channel scope, and F2 is the absence of any
rule about what a channel override may say in the first place.

---

## F1 — `bsfchat.server.info` is gated at ROOM scope (High)

**What it is.** `RoomHandler::handle_set_state` maps `bsfchat.server.info` to
`MANAGE_SERVER` in `state_gate_for` (`src/api/RoomHandler.cpp:2043`), but the
type is in neither `is_server_scoped` nor `is_scope_only_server_act`, so
`perm_scope` resolves to the ROOM (`:2070`) and the check at `:2158` is
evaluated with channel overrides applied. A per-channel ALLOW override granting
`MANAGE_SERVER` in one unimportant channel is therefore sufficient to rewrite
the whole deployment's name and icon.

**Why it happens.** This is the third instance of one defect and the first two
were fixed *in this function, with comments explaining the rule*.
`bsfchat.room.type` was moved to server scope because "at room scope, an allow
override on a single channel — the natural way to give someone their own channel
— was enough to retype any channel as a category". `bsfchat.server.screenshare`
was moved for the same reason and its comment names the general form: the
setting "is not scoped to a channel", "the client writes it into whichever room
happens to be active", "every client applies whichever copy reaches it through
/sync, whatever room it arrived in". Every clause of that sentence is true of
`bsfchat.server.info` — `ServerConnection::updateServerName` writes it into
`m_activeRoomId` and falls back to the first room in the list
(`client/src/net/ServerConnection.cpp:3212`), and both sync-apply branches
(`:3615`, `:3705`) set `m_serverName` from whichever room it arrives in. It is
the same shape, by the same reasoning, and was left behind. The comment at
`RoomHandler.cpp:1891` even lists `bsfchat.server.info` among the four types
"NOT scoped to the room they are written in" — and then the scope expression
twelve lines later does not include it.

**How to reproduce.** `PermissionAudit2026_09.DISABLED_F1_ChannelOverride
GrantsServerWideRename`. An admin writes `user:@mallory ALLOW MANAGE_SERVER` on
`#general`; Mallory — an account holding only `@everyone` — then PUTs
`bsfchat.server.info` into `#general` and the server is renamed. The control in
the same test asserts that without the override the identical request is a 403,
so the override is what does it.

**What it lets an attacker do.** Rename the server and replace its icon for
every connected client, from a grant that said nothing about the server. Bounded
— it is not `MANAGE_SERVER` at server scope, so it does not unlock the audit log
(`AuditHandler.cpp:73` is correctly at server scope) — but the icon is an
`mxc://` the attacker controls and the name is arbitrary attacker text rendered
in every client's title bar, which is a serviceable phishing surface on a
self-hosted product whose identity is its name.

**Recommended fix.** Add `event_type::kServerInfo` to
`is_server_wide_media_setting`, or better, rename that flag to something like
`is_scope_only_server_setting` and list both types under it. The comment already
written above it needs no change — it describes `server.info` exactly. Do **not**
fold it into `is_server_scoped`: that flag also moves the authoritative copy into
`server_state` and routes the write through `write_server_scoped_state`, whose
rank checks parse the body as a role document. Nothing reads server identity out
of `server_state`, so that branch would write a row no read path consults. Scope
only, exactly as `server.screenshare` was done.

---

## F2 — channel overrides have no containment rule and no rank check (High)

This is the finding that was already reported and left open. It is worse than
"bounded to one channel", and F1 is why.

**What it is.** Writing `bsfchat.channel.permissions` is gated on
`MANAGE_ROLES` at ROOM scope (`RoomHandler.cpp:2040`, `:2158`) and on nothing
else. There is no rule that the actor may only grant bits it holds itself, and
no rank check on a `user:<target>` override. The content is stored verbatim:
`SqliteStore::get_channel_overrides` (`:3190`) parses `allow`/`deny` out of the
state event with no masking, and `PermissionsEngine::compute` applies them with
`base = (base & ~deny) | allow`.

The server has three ways to hand out permissions and they enforce different
rules:

| Route | "cannot grant what you do not hold" | rank check |
|---|---|---|
| `bsfchat.server.roles` (and the `/roles` delta endpoints) | yes — `may_edit_role_definitions` | yes |
| `bsfchat.member.roles` (and `/self_roles`) | yes — `may_assign_roles` / `may_self_assign_role` | yes |
| **`bsfchat.channel.permissions`** | **no** | **no** |

`PermissionsEngine.h` states the principle for the first two in as many words —
"MANAGE_ROLES is the permission an owner hands to a trusted-but-not-admin
'builder'; it must not be a one-request path to owning the server". The third
route is the one where that sentence is not enforced.

**How to reproduce.** Three tests.

* `DISABLED_F2a_ManageRolesGrantsItselfEveryChannelFlag` — a `builder` account
  holding `@everyone | MANAGE_ROLES` writes `user:@builder ALLOW kAllFlags` on a
  channel and comes out holding `MANAGE_CHANNELS`, `MANAGE_MESSAGES` and
  `MENTION_EVERYONE` there. The test asserts it held none of them beforehand.
* `DISABLED_F2b_ManageRolesInOneChannelRenamesTheServer` — the same builder, two
  requests, renames the server. F1 and F2 compose.
* `DISABLED_F2c_NoRankCheckOnAUserOverride` — the same builder writes a
  `SEND_MESSAGES` DENY override keyed on an account that outranks it, and is not
  refused.

**What it lets an attacker do.** Inside the one channel they were given,
everything: delete the channel (`handle_delete_room` is `MANAGE_CHANNELS` at room
scope, `:1626`), redact anyone's messages, rename and re-file it, ping
`@everyone`, and silence any member including one who outranks them. Outside it,
F1. The bound "one channel" is real for the direct effect and false for the
chain.

Two things that do *not* work, checked: an override granting `ADMINISTRATOR`
does not confer god mode, because `compute()` short-circuits the administrator
bit from the role base *before* overrides are applied and every `ADMINISTRATOR`
test on the server is at server scope; and an override cannot reach another
room, because `get_channel_overrides` is keyed on `room_id`.

**Why it happens.** The route grew out of "MANAGE_ROLES means you arrange who
sees what", which is true of the `role:` half. The `user:` half is a permission
grant to a named principal, which is the thing the other two routes have rules
about. Granting a bot a channel is now routine on this route, which is what
raises it from a latent defect to an operational one.

**Recommended fix.** Two rules, in `handle_set_state` beside the existing DM
refusal, or better in a `may_write_channel_override()` on `PermissionsEngine`
so that a future second writer cannot skip them:

1. **Containment.** The bits the write ADDS — `allow & ~previous.allow`, and
   symmetrically for `deny` — must be a subset of what the actor holds *in that
   room*. Scoped to what the edit adds, exactly as
   `may_edit_role_definitions` scopes its equivalent rule, so echoing back an
   existing override stays legal and removing a grant is never refused.
   `ADMINISTRATOR` should be excluded from `allow` outright: it means nothing at
   channel scope and its presence in an override is always either a mistake or
   an attempt.
2. **Rank.** A `user:<target>` override where `!outranks(actor, target)` is
   refused, the same test `may_assign_roles` and `handle_put_nickname` apply.
   A `role:<id>` override where the role's position is at or above the actor's
   should be refused for the same reason `may_edit_role_definitions` refuses to
   modify such a role.

Both bind administrators not at all (they short-circuit) and the synthetic
`@server` actor not at all, as everywhere else.

---

## F6 — the bot rank check measures roles, and a scoped bot holds none (High)

**What it is.** `BotHandler::authorize_bot_admin` gates token rotation,
deactivation and access-read on `perms.outranks(actor, bot_user_id)`
(`src/api/BotHandler.cpp:126`). `PermissionsEngine::highest_role_position`
(`src/auth/Permissions.cpp:162`) reads **only** the role assignment; channel
overrides are read inside `compute()` and only when a `room_id` is supplied, so
they contribute nothing to rank.

`BotHandler.h` prescribes the channel override as *the* way to scope a bot —
"Granting a bot a channel is writing `bsfchat.channel.permissions` with state_key
`user:<bot id>`", and "THERE IS NO WRITE SIBLING, deliberately" — and
`handle_create_bot` writes each new bot an explicitly **empty** role assignment
(`BotHandler.cpp:258`, `MemberRolesContent assignment;  // no roles`).

So a correctly-scoped bot holds zero roles, sits at position 0 permanently, and
**every** `MANAGE_BOTS` holder whose grant comes from a role at position ≥ 1
outranks it. The rank check is inert for exactly the configuration the feature
documents.

**How to reproduce.** `DISABLED_F6_BotRankIsBlindToChannelOverrides`. A `botmod`
role at position 10 holding `MANAGE_BOTS`; a `#leadership` channel with
`user:@botmod DENY VIEW_CHANNEL`; a bot with no roles and
`user:@bot_minutes ALLOW VIEW_CHANNEL|SEND_MESSAGES` on that channel. The test
asserts the preconditions (botmod cannot view it, the bot can) and then that
`outranks(botmod, bot)` is true.

**What it lets an attacker do.** `POST /bsfchat/bots/{id}/token` returns a
**non-expiring** bearer credential (`lifetime_ms == 0`, per
`SqliteStore::get_user_by_token`'s own comment) for an account that can read and
post in channels the caller is explicitly denied. `handle_list_bots` carries no
rank check by design, so every bot id is available to enumerate against; the
rotation works blind and needs no reconnaissance. The bot's owner learns nothing
until the integration breaks.

`BotHandler.h`'s own rationale describes the hole it is trying to close — "a
delegated MANAGE_BOTS holder at position 10 could rotate the token of a bot
holding Administrator" — and is correct about the *role* half of a bot's access.
It is blind to the channel half, which is the half the feature is built on.

**Recommended fix.** Rank is the wrong instrument here; the question is
containment, as in F2. Refuse rotation (and deactivation, and the access read)
unless the actor's access is a superset of the bot's: for every room in
`visible_channel_directory(actor)` ∪ the bot's bound rooms, `compute(bot, room) &
~compute(actor, room) == 0`, plus the existing role-rank test for the role half.
The cheap approximation — refuse when the bot holds `VIEW_CHANNEL` in any room
the actor does not — is most of the value for a fraction of the work and can be
computed from data `handle_get_bot_access` already assembles. Whichever is
chosen, `outranks()` alone must stop being the whole of the gate, because for a
scoped bot it is a comparison of 0 against 0.

---

## F3 — `is_direct` is a caller-controlled bypass of the only check on `POST /createRoom` (Medium-High)

**This is the only finding reachable by an account holding nothing but
`@everyone`, with no prior grant of any kind.**

**What it is.** `handle_create_room` reads `is_direct` straight from the request
body and skips its `MANAGE_CHANNELS` check when it is true
(`RoomHandler.cpp:685-693`). The invite loop then joins every invitee
**outright** rather than inviting them — `const auto state = (is_direct ||
invitee_is_bot) ? membership::kJoin : membership::kInvite` (`:833`) — and
nothing caps the length of `invite`. `CreateRoomRequest::invite` is an unbounded
`std::vector<std::string>` in the protocol and `from_json` imposes no limit.
There is also no rate limiter on this route: `SendLimiter` has buckets for send,
redact, media upload and profile, and `RoomHandler` holds no limiter at all.

The check it walks around is the one whose own comment says what it is for:
"This endpoint previously had NO authorization check at all, so any
authenticated user … could create channels; each public channel then
force-joined the entire user base … an amplification primitive."

**How to reproduce.** `DISABLED_F3_IsDirectBypassesCreateRoomPermission`. The
control asserts an ordinary member is refused a plain channel; the same request
with `"is_direct": true` and three invitees succeeds and force-joins all three.
`DISABLED_F3b_FakeDmHasNoModerationRemedy` shows an administrator being refused
`DELETE /rooms/{id}` on the result.

**What it lets an attacker do.** Three things, and the third is the one that
matters:

1. **Unconsented membership.** Arbitrary accounts are joined to a room they never
   asked for, which appears in their `m.direct` and their `/sync`. Dedup only
   fires for `invite.size() == 1`, so two invitees means unlimited rooms.
2. **Fan-out.** Each invitee costs a `set_membership` plus an
   `m.room.member` event plus a sync wake, unmetered.
3. **A room that is a DM to every predicate but is not one.** This is the
   invariant break, and it is load-bearing elsewhere:
   * `PermissionsEngine::compute` **clears channel overrides on a direct room**,
     so a `VIEW_CHANNEL` deny written onto it is silently discarded — the test
     asserts this directly. Nothing can hide the room from the people dragged
     into it.
   * `list_room_directory_rows()` excludes direct rooms in SQL, *before* any
     permission is evaluated, so it never appears in the channel directory. An
     administrator cannot find it.
   * `handle_delete_room` admits only participants of a direct room — the guard
     that protects a genuine two-person DM from a server admin protects this too.
     An administrator cannot delete it.
   * `handle_kick` refuses on a direct room. Nobody can be removed from it.

   So the only remedy is a server-wide ban on the creator, which is the
   sledgehammer the kick ladder exists to avoid.

`docs/membership-vs-visibility.md` rests three separate decisions on "a DM's
privacy is its membership" and "nobody is ever force-joined into one". Both
sentences are false while this holds.

**Why it happens.** `is_direct` was treated as a statement of intent by a
cooperating client rather than as a capability claim. The handler's comment —
"Direct messages are a per-user capability, not channel management: any
authenticated user may open a DM" — is right about a two-person DM and says
nothing about a fifty-person one, because nothing on this path knows the
difference.

**Recommended fix.** Make `is_direct` mean what the rest of the codebase assumes
it means:

1. Refuse `is_direct` with `invite.size() != 1`, or with the sole invitee being
   the caller. A DM is a conversation between exactly two people; that is the
   sentence every other DM guard is written against, and it should be enforced
   where the room is made rather than assumed by five readers.
2. Refuse `name`, `parent_id`, `is_category` and `voice` alongside `is_direct` —
   a DM is not server structure and `refuse_on_direct_room` already says so for
   every later edit.
3. Give the route a `SendLimiter` bucket. A DM is cheap; an unbounded supply of
   them is not.

Fix (1) alone closes the finding. It is also the one with a behavioural risk —
if any client opens a group DM today it would break — which is the reason it was
not applied here rather than tonight; see below.

---

## F5 — the media object → room binding is written by the caller (Medium-High)

**What it is.** `MediaHandler::may_download` (`src/api/MediaHandler.cpp:459`)
answers "may this user have these bytes" with, in order: the uploader; then
`VIEW_CHANNEL` in any room named in `media_refs` for this object; then, only
when `media_refs` is empty, `is_avatar_media()`. Rule 2 is correct and its
comment is right that neither half of `is_room_member && can(VIEW_CHANNEL)` is
redundant.

The table it consults is not. `SqliteStore::insert_event` indexes **every**
`mxc://` string at **every** depth of every event's content into `media_refs`
(`media_uris_in_content`, `SqliteStore.cpp:142`), with no check that the sender
uploaded the object or may currently read it, and no restriction on which field
it appears in. So the binding between an object and a room is a value the caller
writes.

`EventHandler`'s `ATTACH_FILES` gate does not stand in the way: `has_attachment`
is derived from `msgtype` (`EventHandler.cpp:602`), not from the presence of an
`mxc://`. A plain `m.text` message carrying the URI in any key creates the row.

**How to reproduce.** `DISABLED_F5_ASenderCanRebindMediaItMayNotRead`. Alice
posts an image in `#leadership`; Mallory is then denied `VIEW_CHANNEL` there —
the exact scenario `MediaAcl.LosingViewChannelRevokesTheAttachmentsToo` pins.
Mallory then sends an ordinary `m.text` message into `#general` through the real
`handle_send_event`, with the URI under an unrecognised key, and `#general`
appears in `get_media_rooms()` for that object.

**What it lets an attacker do.** It is a **revocation bypass**, not a blind
read: a media id is 128 bits of CSPRNG, so this is only available to someone who
already holds the id. What it defeats is every mechanism that is supposed to
take access away afterwards:

* **Channel lockdown.** The stated purpose of the rule-2 fix is that "locking a
  channel down did nothing for what was already posted in it (audit B3)". Anyone
  who noted the URI while permitted re-binds it and keeps the bytes.
* **Redaction.** `SqliteStore` deletes `media_refs` rows on redaction
  (`:2417`) precisely so a deleted attachment stops being fetchable. A re-bind
  reverses it.
* **The avatar fall-through, which is the worst variant.** Rule 3 is reached only
  when `media_refs` is empty — and redaction is exactly what empties it.
  `handle_put_avatar_url` stores whatever string the caller sends with no check
  that the `mxc://` is theirs or exists, so setting your own `avatar_url` to a
  redacted object makes `is_avatar_media()` true and the object readable by
  **every authenticated account on the server**. Redaction moves the object from
  channel-scoped to server-public.
* **Ticket minting.** `handle_ticket` gates on the same `may_download`, so a
  forged binding also yields a legitimately signed ticket.

**Recommended fix.** Index a media reference only when the sender may currently
read the object. The check already exists — it is `may_download` — but it lives
in `MediaHandler` and `insert_event` is in the store, so the predicate has to be
passed in or lifted. Concretely: have `EventHandler::handle_send_event` and
`RoomHandler::handle_set_state` compute the referenced URIs before the write and
refuse (or silently drop the reference for) any the sender cannot read, and have
`insert_event` take the vetted list rather than re-deriving it. Separately,
validate `avatar_url` on write: it must be an `mxc://` on this server naming an
object the caller uploaded. That second one is a one-line fix and closes the
server-public variant on its own.

---

## Medium and low findings

### F7 — `GET /bsfchat/roles` publishes the whole role document to any account

`handle_list_roles` (`src/api/RoleHandler.cpp:194`) requires authentication and
nothing else, and returns every role's `permissions` bitfield, `position`,
`self_assignable`, `hoist` and `mentionable`. The stated justification is that
"the role list already reaches every client on the server through the sync mirror
of the state event, so gating the read would hide nothing". That premise fails
for two classes of caller:

* **A scoped bot.** Bots are excluded from auto-join and the mirror is one pinned
  room, so a bot invited into one channel receives no role state through sync —
  `PermissionsHandler.h` says so explicitly. Its token buys it the complete
  escalation map: which role carries `ADMINISTRATOR`, which roles are
  self-assignable, and where each sits.
* **Any human denied `VIEW_CHANNEL` on the mirror room.** `SyncEngine` filters
  delivered rooms through `can_view_room`, so that member gets no role document
  through sync and the full one here.

Disclosure, not escalation, which is why it is Medium. **Fix:** narrow the
response for callers without `MANAGE_ROLES` at server scope to the presentation
fields the member list actually needs (id, name, colour, hoist, position),
omitting `permissions` and `self_assignable`; or gate the full document on
`MANAGE_ROLES` and let the client fall back to the sync mirror it already reads.

### F8 — the role delta endpoints are a read-modify-write with no lock spanning check and write

`RoleHandler.h` claims the delta endpoints perform the read-modify-write "under
the store's own lock, against the document as it stands at that moment". They do
not. `handle_update_role` reads the document at `:245`, applies the delta at
`:252`, and `commit_roles` then constructs a **fresh** `PermissionsEngine` whose
`may_edit_role_definitions` re-reads the document, so the proposal is built from
document A and authorised against document B; `set_server_state` performs no
compare-and-swap. `handle_create_role` and `handle_delete_role` have the same
shape.

The security consequence is not only a lost edit. Because `before` in the
"cannot grant what you do not hold" test is taken from the *fresh* document, a
concurrent **revocation can be silently reverted** by an unrelated rename: the
stale proposal still carries the revoked bit, `added` is non-empty, and the check
passes as long as the actor holds that bit themselves.

`change_self_role` has the identical shape (`:361` read, `:387` write) and is
callable by any ordinary member, retryable at line rate — which makes it the one
instance an attacker can drive rather than stumble into. **Fix:** a
compare-and-swap on `server_state` (store the superseded content's hash or a
version column and refuse the write if it moved), or hold the store lock across
read-check-write. The former is less invasive and `set_server_state` already
returns the superseded content, so the plumbing is half there.

### F9 — `POST /rooms/{id}/voice/leave` is gated on `is_room_member` alone

`handle_voice_leave` (`src/api/VoiceHandler.cpp:437`) stops at membership. Its
three siblings — `join` (`:297`), `members` (`:551`) and `state` (`:635`) — all
run `permission::has(perms.compute(user, room_id), kViewChannel)` after the same
membership test. This is the one write path in voice that bypasses the choke
point.

**I could not turn it into an escalation.** `leave` only ever touches
`state_key == *user_id` and short-circuits to a no-op when that row is not
active, and `join` — which is the only thing that creates an active row — is
gated. So its safety rests entirely on an invariant enforced in a different
handler, which is the reasoning `handle_voice_state`'s own comment rejects for
itself ("Authorization cached in a row is not authorization"). **Fix:** add the
same pair, for the same reason.

### F10 — voice `room_admin` is granted with no rank check

`handle_livekit_token` sets `grants.room_admin = permission::has(flags,
permission::kManageChannels)` (`VoiceHandler.cpp:972`), which gives LiveKit-side
server mute and participant removal. That is a moderation action against another
user, and it is the only one in the codebase with no `outranks()` test —
`RoomHandler.cpp:533`, `ProfileHandler.cpp:376` and `BotHandler.cpp:126` all
have one. A moderator with `MANAGE_CHANNELS` in one channel can SFU-mute or eject
the server owner in that channel's call, which the same server would refuse for a
kick, a ban or a rename. Combined with F2 it needs only `MANAGE_ROLES` in that
channel.

The awkwardness is that the grant is a JWT claim evaluated by the SFU, so a rank
rule cannot be expressed per-target inside it. **Fix:** either withhold
`room_admin` and route SFU moderation through a server endpoint that can apply
`outranks()`, or accept it and write down why — but it should not stay an
unremarked exception.

### F11 — pre-permission refusals leak channel voice configuration

`handle_voice_join` tests "is the room voice-capable" and "is voice enabled"
(`:262-275`) with two distinguishable 403 bodies *before* the `VIEW_CHANNEL`
check at `:296`. A user denied a private channel can therefore learn whether it
is a voice channel and whether its voice is on. The same ordering appears in
`handle_livekit_token` (`:888` before `:911`) and `handle_livekit_rekey`
(`:1078` before `:1098`). `PushHandler::notify_level_refused` is the pattern to
copy: one shared refusal, byte-identical whatever the reason. **Fix:** move the
`VIEW_CHANNEL` test above the capability tests.

### F12 — the audit log is not filtered by channel visibility

`handle_get_audit_log` gates correctly on `MANAGE_SERVER` at **server** scope
(`AuditHandler.cpp:73`, and the comment explains why the empty room id is the
point), then emits `target_room` and the full `before`/`after` payloads with no
visibility filter — which for `bsfchat.channel.permissions` records is the shape
of a private channel's overrides, and for rename records its name.

The codebase's own standard elsewhere is stricter: `handle_get_bot_access` runs
its channel list through `visible_channel_directory` so that "a delegated bot
administrator who cannot see #leadership would [not] learn that it exists, what
it is called and how its overrides are shaped". `MANAGE_SERVER` is a much heavier
flag than `MANAGE_BOTS`, so this is defensible — but it is delegable and does not
imply `VIEW_CHANNEL`, and the asymmetry between the two endpoints reads as
unconsidered rather than decided. **Fix:** decide it, one way or the other, in a
comment; and if filtering, note that `total` is a whole-table count and is itself
a small oracle.

---

## What is correct

A clean area is a result. Each line below was traced end to end, and the method
is named so the next auditor can skip it or disbelieve it deliberately.

**The engine.** `PermissionsEngine::compute` applies `@everyone`, then each role
in position order, then the user override, with the `ADMINISTRATOR`
short-circuit taken from the role base *before* overrides — which is what stops
an `ALLOW ADMINISTRATOR` override being god mode. `highest_role_position` excludes
self-assignable roles. `may_assign_roles` checks both directions (granting and
removing at-or-above your rank). `may_edit_role_definitions` checks the
*effective* position (`max(proposed, existing)`), which closes demotion-by-
repositioning, scopes the "cannot grant what you do not hold" rule to what the
edit adds, and refuses deletion of a role above you. `validate_role_document`
binds administrators too. `same_role` includes `mentionable` and
`self_assignable`. Verified by reading against the header's stated contract
clause by clause; the mismatch I looked hardest for — a field `same_role` omits
that confers power — is not there.

**Scope.** Every server-wide act I could find is evaluated at server scope:
membership moderation (`RoomHandler.cpp:528`, via `MembershipIntent::server_scope`
so the dedicated endpoints and the generic state route cannot disagree), the
server ban list (`:1476`), room creation (`:687`), `bsfchat.room.type` and
`bsfchat.server.screenshare` (`:2070`), nicknames (`ProfileHandler.cpp:357`,
`:365`), bots (`BotHandler.cpp:101`), roles (`RoleHandler.cpp:164`), the audit
log (`AuditHandler.cpp:73`), and the `ADMINISTRATOR` exemptions inside the
engine. **`bsfchat.server.info` is the single exception and it is F1.** Method: I
enumerated every `.can(`, `.compute(` and `kServerScope` call site in `src/` and
classified each by whether the act it gates is per-channel or server-wide.

**`is_room_member` is nowhere the authorization**, with one partial exception.
Every use I found is either a cheap precondition ahead of a real check
(`handle_set_state`, `/category`, `/order`, the moderation endpoints), correctly
paired (`can_read_room`, `notify_level_refused`, `may_download` rule 2), the
right gate on its own merits (`handle_leave`), or a response field rather than a
gate (`handle_get_bot_access`). The exception is `voice/leave` — F9 — where no
escalation was reachable.

**`POST /search`** builds its room restriction *before* the query from
`get_joined_rooms` filtered by `VIEW_CHANNEL`, passes it into
`search_messages` as the query's restriction rather than filtering output, and
intersects a caller-supplied `filter.rooms` against it — there is no branch where
the caller's list replaces or extends the permitted set. The cleanest endpoint in
the server.

**`/sync`.** `room_view()` returns three answers, not two; the category
exemption yields a name-and-ordering stub with no timeline, no members, no
`prev_batch` and no counts; `stubbed` keeps the counts pass off stub entries;
`attach_pending_invites` filters through `can_view_room`; a server-banned user
gets an empty response before anything else runs.

**Bot scoping.** `inherits_everyone_role` withholds the implicit default from
bots while leaving `@everyone` assignable by id; `bootstrap_roles` skips bots in
its assignment sweep so scoping survives a restart; `backfill_bot_everyone` keys
on "has no assignment document" rather than "has no roles", so it cannot
un-scope a deliberately empty bot; `may_self_assign_role` refuses bots first, in
both directions. `handle_create_bot` writes an empty assignment and the request
body cannot influence it. The rank check on the *role* half is right; F6 is the
channel half.

**`/self_roles`** enforces `may_self_assign_role` on both add and remove, with
the containment ceiling recomputed from the **current** role document rather than
trusted from write time, `@everyone` refused, and `self_assignable` re-checked on
removal so a mute role cannot be shed.

**The role delta endpoints carry no independent opinion.** All three build a
proposed document and route it through the same `may_edit_role_definitions` under
the same server-scope `MANAGE_ROLES` gate as the wholesale PUT. I looked
specifically for a field the delta path can change that the whole-document path
would refuse and did not find one — where they differ the delta path is the
*stricter* of the two (`apply_role_fields` masks undefined permission bits with
`& kAllFlags`; the wholesale `from_json` does not). F8 is a concurrency defect,
not an authority defect.

**`GET /bsfchat/permissions/{userId}`** takes nothing from the request but the
target id, computes at server scope, and answers "stranger", "invisible member"
and "no such account" identically. Two caveats worth recording rather than
filing: on a force-join server the *success* case is itself an existence
discriminator (200 ⇒ exists, 403 ⇒ does not), and the "you already share a
channel" rule is close to vacuous between humans for the same reason. Both are
consequences of force-join rather than defects in this endpoint, and the rule
genuinely binds for the case it was designed for — a bot.

**Media, apart from F5.** `handle_download` orders authentication, existence and
the ACL before touching storage, and answers "does not exist" and "not permitted"
with the identical 404. The ticket MAC is length-prefixed and injective,
compared with `CRYPTO_memcmp`, canonical-encoding enforced, expiry checked before
the MAC. `handle_ticket` runs the same `may_download` as the download path and
collapses existence and authorisation into one refusal. `normalise_content_type`
only ever downgrades, and SVG is excluded from both allowlists.

**Voice, apart from F9/F10/F11.** Join, roster read, state write and LiveKit
token mint all require `VIEW_CHANNEL` at channel scope before any side effect.
`handle_voice_state` hard-wires the state key to the authenticated caller at both
use sites — there is no body field, URL parameter or header that redirects it to
another user — and both refusals return before `record_heartbeat`, so a revoked
user cannot hold a roster slot. `handle_livekit_rekey` is the best-gated endpoint
in the server: `VIEW_CHANNEL` **and** `MANAGE_CHANNELS`, persisted before the
response claims success, audited, and the new key deliberately not returned.

**`m.room.power_levels` is inert.** `PowerLevelChecker` has no production caller
— it is referenced only by its own translation unit and by
`tests/test_permissions.cpp`. There is no second authority over permissions.
Writing the state event is gated on `MANAGE_CHANNELS` and nothing reads it.

**Server bans are enforced at the credential layer.** This is the property that
makes routes without an explicit ban check safe, and it is worth naming because
I set out to break it and could not. Placing a ban calls
`delete_all_tokens_for_user` (`RoomHandler.cpp:610`), and `handle_login`,
`handle_register` and `handle_refresh` each consult the ban list, so a banned
account cannot obtain a credential at all. Pinned by the one **enabled** test in
`test_permission_audit_2026_09.cpp`.

**The client mirror has not drifted.** `client/src/util/PermissionMath.cpp`
matches `compute()` structurally — same `@everyone`-first ordering, same
position sort, same administrator short-circuit before overrides, same
`inheritsEveryoneRole` rule — and its bit values match protocol's exactly. It
carries no rank maths at all, so it is not a second authority there. One
divergence: the server clears channel overrides on a direct room and the mirror
does not, so a legacy DM still carrying an override from a build before that fix
would render differently from how the server evaluates. Harmless in the deny
direction and cosmetic in the allow direction, but it is the one place the two
can disagree today.

**Already known and warned about, not re-reported as new.** With
`voice.turn_secret` unset, `GET /voip/turnServer` hands the deployment's static,
non-expiring TURN username and password to every authenticated caller. That is
real, but `Config.cpp:329-338` already emits a startup warning saying exactly
this, so it is a deployment decision with a visible tripwire rather than an
undiscovered hole.

---

## Nothing was fixed

The deliverable is the audit, and the instruction was to fix only something so
severe that leaving it overnight would be wrong. Nothing here meets that bar, and
the reasoning is worth writing down rather than asserting:

* **F1, F2, F6** each require a prior deliberate grant by somebody trusted —
  `MANAGE_ROLES` in a channel, or `MANAGE_BOTS`. They are escalations from a
  delegated role, not from nothing. They are also the three whose fixes need a
  containment rule designed once and applied in two places; doing that at speed
  is how the rule ends up in one of them.
* **F5** needs the attacker to already hold a 128-bit media id, which means they
  saw the object while permitted. It is a revocation bypass, not a read of
  arbitrary media.
* **F3** is the one reachable by anyone, and it is the one I came closest to
  fixing. It is abuse and unconsented membership rather than disclosure of
  anything that exists, and the fix — capping `invite` at one for a direct room —
  is a behavioural change that would break any client that opens a group DM
  today. That is a question for the owner and a morning, not for an auditor at
  night.

The audit changes two files and neither is server code: this document, and
`tests/test_permission_audit_2026_09.cpp` plus its line in
`tests/CMakeLists.txt`. The new tests are `DISABLED_` except the F4 control, so
CI is unchanged: 1125 tests, all green.

---

## What I did not reach

Named so the next auditor starts here rather than repeating me.

* **`AuthHandler.cpp`** (1364 lines) — login, registration, OIDC, refresh-token
  families, account linking. I traced only the authorization-relevant seams
  (`authenticate()`, the ban checks, token lifetime) and relied on
  `docs/auth-hardening-2026-09.md` for the rest. The refresh-family and
  account-link logic in particular is unaudited by me.
* **`e2e/` and the mutation harnesses.** I proved every finding with unit tests
  against the real handlers, but did not run `mutate*.py` against my new tests,
  so I have not confirmed they would survive a mutation of the fix. Given F1–F6
  are written to fail *before* the fix rather than after it, the usual mutation
  argument applies in reverse and is worth doing once each fix lands.
* **`SyncHandler.cpp`'s typing and presence passes.** `SyncEngine` I read in
  full; the handler's ephemeral passes I read only where the previous audit had
  already been.
* **`PushService::should_notify`** beyond confirming it runs a `VIEW_CHANNEL`
  check per notification.
* **The client as a gate.** I confirmed `PermissionMath` has not drifted and that
  no server check depends on it, but I did not sweep the QML for an affordance
  the client hides and the server serves. The shape to look for is a settings
  page whose gate is a flag the corresponding server route does not test.
* **`identity/`** — the separate OIDC service. Out of scope here entirely.
