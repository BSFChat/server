# Request-path disclosure and authorization audit — September 2026

Scope: every route registered in `src/core/Server.cpp` (lines 100–310) on `main`
at `c9a1e12`, plus `src/sync/SyncEngine.cpp`, `src/api/*Handler.cpp`, and the
read paths in `src/store/SqliteStore.cpp` they reach. Branch: `audit/request-path`.
Report only — nothing here is fixed.

## What this does NOT re-report

Two audits already cover parts of this surface and their findings are treated as
known:

* `docs/membership-vs-visibility.md` (`fix/joined-rooms-leak`) — the
  membership-is-not-visibility bug class. Its six open items (voice/join,
  voice/members, typing, read_marker, notify_level, DM channel-overrides) are
  **not** repeated here.
* `docs/auth-hardening-2026-09.md` (`harden/auth`) — 22 findings on
  registration, login, tokens, `/send` type gating, reactions, rate limits.

Where I disagree with either, it is called out explicitly under
[Corrections to the existing audits](#corrections-to-the-existing-audits).

---

## Summary

| # | Endpoint | Finding | Severity | Bucket |
|---|---|---|---|---|
| 1 | `GET /_matrix/media/v3/download/…` | Uploader-controlled `Content-Type` served `inline`, reached by a URL that carries the viewer's access token → one-click account takeover | **Critical** | Must fix |
| 2 | `GET /profile/{user}` ×4 | Entirely unauthenticated and unrate-limited: whole-user-base enumeration plus display names, avatars, nicknames | **High** | Must fix |
| 3 | `/sync`, `/rooms/{id}/state`, `/state/{type}`, `/members` | The category exemption is an unbounded VIEW_CHANNEL bypass, flippable by MANAGE_CHANNELS | **High** | Must fix |
| 4 | `POST /rooms/{id}/voice/livekit_rekey` | Key generation is in-memory only; a restart reverts the media key and re-admits every departed member | **High** | Must fix |
| 5 | `PUT /rooms/{id}/send/…` (edit path) | Global event-existence oracle: 404 / 400 / 403 distinguish "no such event" from "exists elsewhere" | Medium | **Fixed** |
| 6 | `POST /rooms/{id}/join` | Kick is unenforceable — the target rejoins any public-join_rule channel immediately | Medium | **Fixed** |
| 7 | `PUT /profile/{me}/displayname`, `/avatar_url`, `/nickname` | Unlimited (channels × 1) event amplification per request | Medium | **Fixed** |
| 8 | `PUT /rooms/{id}/send/…` | EMBED_LINKS is checked against `body` only; `formatted_body` bypasses it | Medium | **Fixed** |
| 9 | `GET /_matrix/client/versions` | Unauthenticated exact version **and git revision** — tells an attacker which hosts are unpatched | Medium | **Fixed** |
| 10 | `GET /voip/turnServer` | In static-credential mode, hands the shared config TURN password to every authenticated account | Medium | **Partly fixed — startup warning; the mode itself cannot be made safe** |
| 11 | `PUT /rooms/{id}/state/{type}` | Unknown state event types are accepted with MANAGE_CHANNELS as the fallback gate (allow-by-default) | Low | **Fixed** |
| 17 | `POST /pushers/set` | The rejected gateway URL is logged verbatim *after* the check that rejected it for containing control characters → server-log injection | Medium | **Already fixed on `main`; the sweep it asked for found a worse one — see 20** |
| 12 | `POST /bots/{id}/token` (`feat/bots`) | No rank and no owner check — a delegated MANAGE_BOTS role extracts a permanent token for an Administrator bot | **High** (unmerged) | Must fix before merge |
| 13 | `GET /bsfchat/bots` (`feat/bots`) | Returns every operator's bots: `owner_id`, `created_at`, `last_seen_at` | Low (unmerged) | Noted |
| 14 | `POST /pushers/set` | `append:false` deletes another account's pusher for a known pushkey | Low | Noted |
| 15 | `can_read_room()` | Timing distinguishes "room does not exist" from "room exists, you cannot view it" behind a uniform 403 | Low | Noted |
| 16 | `PUT /rooms/{id}/state/bsfchat.channel.permissions` | No rank check — a low-ranked MANAGE_ROLES holder can lock a higher-ranked non-admin moderator out of a channel | Low | Noted |
| 18 | `PUT /voice/state`, `/typing/{u}`, `/presence/{u}/status`, `/notify_level`, `/createRoom`, `/category` | Unguarded nlohmann type conversions → bare 500. No disclosure; robustness only | Low | Noted |
| 19 | client `bsfchat.log` | libdatachannel's own log stream is mirrored to disk, so ICE candidate lines put the user's LAN and public IP in a plaintext file | Low | Noted |
| 20 | `POST /_matrix/client/v3/login` | **Unauthenticated** server-log forgery: the lockout line logs the submitted login identifier verbatim | Medium | **Fixed** (found by 17's sweep) |

20 findings. Four must-fix before the RC (1–4), one must-fix before `feat/bots`
merges (12). Finding 20 was found by the sweep finding 17 asked for.

---

## Must fix before this RC

### 1. Media download is a one-click account takeover — CRITICAL

**Endpoint:** `GET /_matrix/media/v3/download/{server}/{mediaId}[/{fileName}]`
(`src/api/MediaHandler.cpp:238`), with `POST /_matrix/media/v3/upload`
(`MediaHandler.cpp:~130`) as the other half.

**What leaks:** the viewer's own access token, to whoever uploaded the file.

Three separately-defensible decisions compose into account takeover:

1. **Upload takes the `Content-Type` verbatim from the uploader's request
   header** and stores it (`MediaHandler.cpp`, `handle_upload`: `auto
   content_type = req.get_header_value("Content-Type");` — no allowlist, no
   sniffing, no rewrite to `application/octet-stream`).
2. **Download echoes it back with `Content-Disposition: inline`**
   (`MediaHandler.cpp:306-318`) and sets **no `X-Content-Type-Options: nosniff`,
   no CSP, no sandbox** — I grepped `server/src`, `deploy/` and `web/` for all
   three and found none.
3. **The client puts the access token in the URL query string.**
   `client/src/util/MediaUrl.h::buildMediaDownloadUrl` appends
   `?access_token=<token>`, and the server accepts it
   (`MediaHandler.cpp:223-236`, `authenticate_media`).

**Exploitation path** (one upload, one victim click, no other prerequisite than
being able to post a file in any channel the victim reads):

1. Attacker uploads a file whose body is HTML and whose request `Content-Type`
   header is `text/html`, with `?filename=Q3-budget.pdf`.
2. Attacker sends it as an ordinary `m.room.message` with `msgtype: m.file`.
3. Victim **left-clicks the file card**. `client/qml/components/MessageBubble.qml:1160`
   (`fileCardMouse.onClicked`) calls `Qt.openUrlExternally(bubble.mediaUrl)` —
   a plain single click, no confirmation. (Images have the same escape hatch on
   middle-click at `MessageBubble.qml:1047`.)
4. The victim's **system browser** opens
   `https://chat.host/_matrix/media/v3/download/host/<id>/Q3-budget.pdf?access_token=<VICTIM_TOKEN>`.
   The server returns `Content-Type: text/html`, `Content-Disposition: inline`.
5. The page executes on the chat origin. It reads its own
   `location.search` → the victim's access token, and `fetch()`es it out. It can
   also just use the token in-page: it is same-origin with the whole client API,
   and `Access-Control-Allow-Origin: *` is set on every response anyway
   (`Server.cpp:88-92`).

Tokens live 90 days and slide forward on use, so this is a durable session, not
a momentary one.

**Why this is not already covered.** The token-in-query part is *known and
accepted* — `MediaUrl.h` says so in its own comment ("a token in a query string
can be recorded by server access logs and any intervening proxy. The durable fix
is a short-lived signed media token"). That framing treats it as a log-hygiene
problem. It is not: combined with (1) and (2) it is credential theft. Note also
that `VoiceHandler::handle_livekit_token` refuses to put the media key in a URL
for exactly this reason and says so in a comment — the rule is understood in the
codebase and violated here.

**Secondary, same endpoint:** with nginx's default `access_log` on
(`deploy/nginx/bsfchat.conf.template` sets no `access_log off`), `$request`
includes the query string, so **every user's access token is written in
plaintext to `/var/log/nginx/access.log` on the production host** on every media
fetch, and retained by logrotate.

**Fix.**
- Serve media as `Content-Type: application/octet-stream` with
  `Content-Disposition: attachment` unless the stored type is on a short
  allowlist (`image/png|jpeg|gif|webp`, `video/mp4|webm`, `audio/*`,
  `application/pdf` if you want inline PDFs). Sniff the magic bytes rather than
  trusting the upload header.
- Always send `X-Content-Type-Options: nosniff`.
- Independently: replace `?access_token=` with a short-lived HMAC capability
  token scoped to one media id (`?mt=<sig>&exp=<ts>`), which is what
  `MediaUrl.h` already nominates as the durable fix. This also removes the
  nginx-log exposure.
- Serve media from a separate origin if you ever ship a browser client.

Any one of the three breaks the chain; the first two are hours of work and I
would do both.

---

### 2. All four profile reads are unauthenticated — HIGH

**Endpoints:**
- `GET /_matrix/client/v3/profile/{userId}` (`src/api/ProfileHandler.cpp:39`)
- `GET …/{userId}/displayname` (`ProfileHandler.cpp:69`)
- `GET …/{userId}/avatar_url` (`ProfileHandler.cpp:136`)
- `GET …/{userId}/nickname` (`ProfileHandler.cpp:201`)

**What leaks:** none of these four handlers calls `authenticate()`. Not once.
Every other read endpoint in the server does; these do not. Each answers
`404 "User not found"` for an unknown id and `200` for a known one.

**Exploitation path.** Anonymous, from anywhere on the internet:

```
for u in $(cat firstnames.txt); do
  curl -s -o /dev/null -w "%{http_code} $u\n" \
    https://chat.host/_matrix/client/v3/profile/@$u:chat.host
done
```

A `200` is a confirmed account. Then `GET /profile/@alice:chat.host` returns
`{"displayname":"Alice Fairbrother","avatar_url":"mxc://…","nickname":"al"}` —
the real name, because this is a small self-hosted server where people use their
real names.

**There is no rate limit on this.** On `main`, `RateLimiter` is constructed only
in `AuthHandler` (`src/api/AuthHandler.cpp:84-88`) and applied only to `/login`
and `/register`; I grepped for every `Limiter` use in `src/`. On `harden/auth`
the new `[limits]` block covers send, redact and upload — still not profile.
So the enumeration runs at whatever rate the socket allows.

The auth audit's finding 18 argues that `/register` answering `M_USER_IN_USE` is
an unavoidable leak bounded by the per-address attempt limiter. That reasoning is
right, and it is exactly what makes this worse: the careful bound on the front
door does not apply to the side door, which additionally hands over names and
avatars rather than just a yes/no.

**Severity.** High rather than critical because it is disclosure, not access.
But for a product whose pitch is self-hosting and not trusting someone else's
servers, "anyone on the internet can enumerate your entire member list and their
real names, unauthenticated" is a headline-grade defect.

**Fix.** Add the standard `authenticate()` preamble to all four handlers. Matrix
permits unauthenticated profile reads, and Synapse has
`require_auth_for_profile_requests` for precisely this; for BSFChat there is no
federation and no reason to allow it, so require auth unconditionally rather
than making it a config flag nobody sets. Keep the 404 for unknown users — once
the caller is authenticated, "is this a user on my own server" is not a secret.

---

### 3. The category exemption is an unbounded VIEW_CHANNEL bypass — HIGH

**Endpoints:** `GET /sync` (both `build_initial_sync` and
`build_incremental_sync`), `GET /rooms/{id}/state`, `GET /rooms/{id}/state/{type}`,
`GET /rooms/{id}/members`.

**Where:**
- `src/sync/SyncEngine.cpp:250` — `if (!is_category_room(store_, room_id) && !perms.can(user_id, room_id, kViewChannel)) continue;`
- `src/sync/SyncEngine.cpp:345` — the same, in `can_view`.
- `src/api/RoomHandler.cpp:76-84` — `can_read_room()`: `if (is_category_room(...)) return true;` **before** the VIEW_CHANNEL check.

**What leaks:** `is_category_room()` reads the latest `bsfchat.room.type` state
event and returns true if `type == "category"`. When it does, VIEW_CHANNEL is
never consulted — so for any room a user is a joined member of, being typed as a
category makes its **entire state, full member list and full timeline** readable
regardless of any deny override.

The justification in both comments is the sidebar: "so the sidebar can render the
container node even when its children are hidden". That needs the room's *name*.
It is implemented as a total bypass of the read gate.

**Exploitation path.** This is the part that makes it high rather than
cosmetic. Recall from `membership-vs-visibility.md` that every user is
force-joined into every non-category public room, and that a "private" channel
is a public room plus an `@everyone DENY VIEW_CHANNEL` override. So:

1. `#staff-only` is an ordinary text channel with `@everyone DENY VIEW_CHANNEL`.
   Every account on the server has a `room_members` row for it with
   `membership='join'` — that is the steady state, not an anomaly.
2. Mallory holds MANAGE_CHANNELS. Not admin — MANAGE_CHANNELS is the "builder"
   capability, and it is also grantable **per channel** by an allow override on
   that one channel, which is the natural way to give someone their own channel.
   `handle_set_state` evaluates it at **room scope** for `bsfchat.room.type`
   (`RoomHandler.cpp:1287-1292`: `required = kManageChannels`, `perm_scope = room_id`
   because `is_server_scoped` is false for this type).
3. `PUT /_matrix/client/v3/rooms/!staff/state/bsfchat.room.type` with
   `{"type":"category"}`. One request.
4. Mallory's **next `/sync`** now contains `!staff` with its full
   `state.events` and a 50-event timeline. So does every other user's. `GET
   /rooms/!staff/members` and `GET /rooms/!staff/state` also now answer 200.
   Retyping does not delete membership rows, so the whole user base is still
   joined.

There is no audit record for this: `handle_set_state` audits only
`bsfchat.channel.permissions` and the server-scoped role types
(`RoomHandler.cpp:1452-1459`). The visible symptom is that the channel's icon
changes in the sidebar.

**The accidental version is more likely than the malicious one.** An admin
reorganising the sidebar converts a channel into a category and silently
publishes its history to the entire server.

**Note the inconsistency it creates.** `POST /search` and `GET
/rooms/{id}/messages` both check VIEW_CHANNEL with no category exemption
(`SearchHandler.cpp:132`, `EventHandler.cpp:418`), so after step 3 `/messages`
still returns 403 for `!staff` while `/sync` hands over the same events. That
divergence is itself the tell that the exemption is not a considered policy.

**Fix.** Do not exempt the room. Exempt the *fields*: when the caller lacks
VIEW_CHANNEL on a category, return only `m.room.name`, `m.room.avatar`,
`bsfchat.room.type` and `bsfchat.room.category` — no timeline, no members, no
other state. That satisfies the sidebar requirement exactly. Concretely: in
`SyncEngine`, replace the `is_category_room(...) ||` short-circuit with a
`build_category_stub(room_id)` branch that emits state-only; in
`can_read_room()`, drop the exemption entirely and let `/state`, `/state/{type}`
and `/members` 403 (the sidebar does not call them for hidden nodes).

Secondarily, `bsfchat.room.type` should not be a room-scope MANAGE_CHANNELS
write on an existing room at all — changing a channel's kind is a structural act.
Gate the *transition* to/from `category` at server scope.

**Interaction with other branches.** `perf/sync-wakeups` keeps
`build_incremental_sync`'s filter unchanged (its §"Where the permission
evaluation happens" is explicit that there is deliberately no VIEW_CHANNEL
filter in the *wake* path and that the *build* filter is untouched), so this
survives that rewrite. `feat/sync-invites` routes its new invite section through
`can_view_room()`, which contains the same exemption
(`wt/server-invites` `SyncEngine.cpp`, `can_view_room`), so the invite section
inherits it.

---

### 4. LiveKit rekey does not survive a restart — HIGH

**Endpoint:** `POST /rooms/{id}/voice/livekit_rekey` (`src/api/VoiceHandler.cpp:929`).

**What leaks:** the channel's media encryption key, to everyone who ever held it.

`Server.cpp`'s route comment states the guarantee plainly: *"This is the only way
to stop a departed member decrypting."* The implementation does not provide it.

- The key is `HKDF(key_material, server_name ‖ room_id ‖ generation)` —
  deterministic in `generation` (`VoiceHandler.cpp:1004-1060`, `livekit_room_key`).
- `generation` lives in `key_generations_`, a plain
  `std::map<std::string, uint64_t>` guarded by `key_generation_mutex_`
  (`VoiceHandler.h`). It is **never persisted** — no store call, no state event,
  no config.
- `handle_livekit_token` reads it with `key_generations_.find(room_id)` and
  **defaults to 0 when absent** (`VoiceHandler.cpp:898-905`).

**Exploitation path.**

1. Bob is in `#leadership-voice`. He leaves the company; his VIEW_CHANNEL is
   revoked. Before leaving he keeps the base64 `encryption.key` his client was
   handed (it is in the `/voice/livekit_token` response body, and any client can
   log it).
2. A moderator does the right thing and `POST …/voice/livekit_rekey`.
   `generation` → 1. Bob's key is dead. The audit trail says the key was rotated.
3. The server restarts — a deploy, a crash, the nightly compose restart,
   anything.
4. `key_generations_` is empty. The next `/voice/livekit_token` for that room
   derives at `generation = 0`. **Bob's key is live again**, and nobody is told.

Bob no longer has API access, but he does not need it: LiveKit media is the
thing the key protects, and he can obtain a token any time he is re-added to a
channel, or simply pull the SFU stream if he retains any valid identity. More
importantly the *guarantee the endpoint advertises is false*, and a moderator
who rotated a key believes a departed member is locked out when they are not.

This is silent: the response still returns `{"key_generation": 1}`, so the
rotation looks successful every time, and every post-restart rotation returns 1
again.

**Fix.** Persist the generation. It is one integer per room — a
`bsfchat.voice.key_generation` server-scoped state row, or a column on `rooms`.
Load it on the first read for a room rather than defaulting to 0, and make the
in-memory map a cache over it. While there: a rekey should be audited
(`audit_channel_override_change` has the right shape) — today it is not, so
there is no record that the key was rotated at all.

---

## Should fix

### 5. The edit path is a global event-existence oracle — Medium

**Endpoint:** `PUT /rooms/{roomId}/send/m.room.message/{txnId}` with
`m.relates_to.rel_type = "m.replace"` (`src/api/EventHandler.cpp:250-302`).

`store_.get_event_by_id()` is a bare primary-key lookup with **no room scoping**
(`SqliteStore.cpp`, `WHERE e.event_id = ? LIMIT 1`). The handler then discloses
the result through four distinguishable answers, in this order:

| Condition | Response |
|---|---|
| no such event anywhere | `404 "Target message not found"` |
| exists, **different room** | `400 "Edit target is in a different room"` |
| exists here, someone else's | `403 "You can only edit your own messages"` |
| exists here, yours, not a message | `400 "Can only edit message events"` |
| exists here, yours, redacted | `404 "Target message has been deleted"` |

So any authenticated user can ask, for an arbitrary `$eventid`: does this exist
on the server, and is it in *this* room? Including events in channels they
cannot view and in other users' DMs.

The chain-resolution loop above it (`EventHandler.cpp:264-281`) makes it worse in
principle: it follows `m.relates_to` pointers through `get_event_by_id` across
room boundaries *before* the room check, so it will walk into a private room's
event to find its parent. It returns no content, so this is an oracle rather than
a read — but it is a read path that crosses a boundary it should not know about.

**Exploitation path.** Event ids are CSPRNG-random, so this is not blind
enumeration. It is *retained-knowledge* monitoring:

1. Alice is a member of `#staff` for six months and her client caches thousands
   of event ids.
2. Alice's VIEW_CHANNEL on `#staff` is revoked. `/sync`, `/messages`, `/search`
   and `/state` all correctly stop serving her.
3. Alice replays her cached ids against `PUT /rooms/!herOwnDM/send/…` with each
   as an edit target. `400 "different room"` = the event still exists;
   `404` = it has been redacted or the channel deleted.
4. She now has a live feed of moderation activity in a channel she was removed
   from — which messages get deleted, and when — plus confirmation that the
   channel still exists.

It also lets any member confirm whether a specific event id someone quoted to
them out of band is real, and in which room.

**Severity:** medium. It reveals metadata, not content, and needs prior
knowledge of event ids.

**Fix.** Collapse all three "not yours to edit" cases to the same `404`, exactly
as `harden/auth` finding 7 did for reactions — that table already says *"target
does not exist, is in another room, or is redacted → 404 (same answer for all
three — 'real, but elsewhere' is the confirmation being withheld)"*. The reasoning
is already written down and approved; it just was not applied here. Also move
the `target->room_id != room_id` check **before** the chain-resolution loop, and
constrain each hop to the same room.

`handle_redact` gets this right already (`EventHandler.cpp:513-520`: `if (!target
|| target->room_id != room_id)` → one shared 404) and is the model to copy.

**Resolved** (`harden/audit-request-path`, `EventHandler.cpp`).

Missing, elsewhere, and redacted now share one `404 "Target message not found"`,
produced by a single `not_here()` closure so the three cannot drift apart again.
The room check moved above the chain-resolution loop, and every hop is confined
to the room: a `m.relates_to` pointer that leaves it ends the chain instead of
being followed, so the loop no longer reads an event in a room the caller cannot
see. The redaction test moved up with it, above the sender and type checks —
answering "that is not a message" about a redacted event is still an answer.

The in-room refusals keep their own wording on purpose. Inside a channel the
caller can read, "you can only edit your own messages" (403) and "can only edit
message events" (400) disclose nothing they cannot already see in the timeline,
and collapsing them to 404 would make an ordinary client bug unexplainable. The
line is "may this caller see this room", not "is this refusal a refusal".

Four tests in `tests/test_request_hardening.cpp`. The one that bites asserts the
**equality** of the answers for a real event elsewhere and an id that exists
nowhere: a test that only asserted "cross-room edits are refused" passed against
the vulnerable code, because the refusal *was* the disclosure.

---

### 6. Kick is unenforceable — the target rejoins immediately — Medium

**Endpoint:** `POST /rooms/{roomId}/join` and `POST /join/{roomIdOrAlias}`
(`src/api/RoomHandler.cpp:559`).

`handle_join` checks: server ban, room exists, not a DM, and `join_rule`. It does
**not** check VIEW_CHANNEL, and it does not check whether the caller was recently
removed. Because the client hardcodes `visibility="public"`
(`client/src/net/MatrixClient.cpp:1349`), **every channel including every
"private" one has `join_rule: "public"`**, so the rule check always passes.

Meanwhile `kick_intent()` (`RoomHandler.cpp:130`) sets `membership='leave'` and
nothing else — no ban row, no token revocation, no join_rule change.

**Exploitation path.** A moderator kicks Mallory from `#general`. Mallory sends
`POST /_matrix/client/v3/rooms/!general/join` — one request, no body — and is
back, with a fresh `m.room.member` join event and a read marker. The moderator's
only remedies are a server-wide ban (which nukes every channel and every
session) or nothing.

This is not disclosure — Mallory could already read `#general` — but it means the
middle rung of the moderation ladder does not exist. It is in scope because it is
an authorization gap on a route in the table, and because `membership-vs-visibility.md`
does not cover it (it audits reads, and treats `/leave` as the only
membership-self-write).

**Fix.** Two options, and the second is better:
- Minimal: record the kick (a `kicked_until` row, or reuse the member event's
  timestamp) and refuse `/join` for a cooldown.
- Correct: a kick from a channel should write a per-room deny override for
  `user:@mallory` rather than only a membership row, so re-joining gains
  nothing. That fits the actual data model — in this design membership is not the
  boundary, VIEW_CHANNEL is — and it is the same insight
  `membership-vs-visibility.md` reaches from the read side.

Note this is one more argument for that document's §"Recommendation": under
`join_rule: "invite"` for private channels, `/join` would refuse and the problem
disappears for the channels where it matters.

**Resolved** (`fix/kick-enforceable`). `POST /join` refuses when the caller's
current `m.room.member` in that room is a removal somebody else performed.

**The finding was partly stale, and the next reader should not have to
rediscover it.** It says `kick_intent()` "sets `membership='leave'` and nothing
else — no ban row, no token revocation, no join_rule change", and infers a
data-model problem. The membership half has since been fixed elsewhere:
`AutoJoin::join_user_to_room` now returns early when *any* membership row
exists, with a comment saying exactly why ("a kick was silently undone by the
next restart or deploy"). So a kick already survived a restart, and `/join` was
the only remaining way back in. That narrowed this to one endpoint.

**Both options the finding offers were rejected.** A *cooldown* — its "minimal" —
is now strictly worse than doing nothing: with the auto-join fix in place a kick
is permanent until somebody acts, so a timer converts a permanent removal into a
delayed re-entry. A *per-user deny override* — its "correct" — is a channel ban
wearing a kick's name: it writes permission state from a moderation endpoint, so
the kicked user's id becomes permanent channel state readable by anyone who can
read the channel's overrides; it survives a later re-invite, so re-admitting
somebody silently fails until a second, different action is taken; and it leaves
kick and ban differing only in scope, which is the middle rung the finding set
out to create.

**What shipped instead.** A kick stamps `bsfchat.removed_by` (the actor's id)
onto the `m.room.member` event it already writes, from `MembershipIntent` so the
marker cannot disagree with which act was authorised; `/join` refuses when the
current member event is a `leave` carrying that key and sent by somebody else.
No schema change, no migration, no new table — it reads state that was already
being written.

**Why the sender alone is not the rule, which is the trap here.** "The member
event says `leave` and somebody else sent it" looks like a complete definition of
a kick. It is not. `unban_intent` projects `{"membership":"leave"}` with the
**moderator** as sender into every room where the target's row was `ban`
(`project_membership_everywhere`), deliberately, so that lifting a ban restores
the ability to return without deciding that they have — its own comment says so.
By sender alone that is a kick in every channel at once, so a sender-only rule
would have left every unbanned account permanently locked out of the whole
server: a worse bug than the one being fixed, and silent. A regression test
covers it, and reverting the rule to sender-only fails that test and nothing
else.

The marker goes on the **kick** rather than on the unban because rows written
before this change carry neither. Marking the kick leaves historical kicks
rejoinable — today's behaviour, so no regression — where marking the unban would
have re-locked everyone unbanned before the upgrade. When the evidence is
missing, fail open: this is a moderation control, not a confidentiality boundary
(the finding itself says "This is not disclosure"), so wrongly refusing a
legitimate member is the worse error.

**The un-kick path is `POST /rooms/{id}/invite`, and it is now the only one.**
Decided deliberately: a kick that does not kick is a moderation control that
lies, which is worse than an un-kick that needs a moderator to paste a user id.
The server capability exists and is tested; what is missing is a button, and a
missing button is a UI gap, not a security hole. The client side is filed
separately. Until it lands, reversing a kick means inviting the user by mxid —
worth a line in the release notes.

Eleven tests in `tests/test_kick_enforcement.cpp`: the kicked user refused; the
voluntary leaver still rejoins (which matters more here than elsewhere — with
auto-join putting everyone in everything, leaving is how a user hides a channel);
invite-after-kick re-admits; a re-admitted user can leave and rejoin again; a ban
is unaffected and still refused by the server-wide check ahead of this one; an
unbanned user can rejoin every channel; the refusal holds on a `join_rule:
"public"` channel, asserted explicitly so nobody "simplifies" the check into a
join-rule test that would do nothing on a real deployment; a kick in one channel
does not affect another; and the two last-writer cases — the dedicated `/kick`
endpoint refuses a target who already left, while the generic state route *can*
write `leave` over a self-leave (`classify_transition` clears
`require_target_in_room` there) and when it does, the moderator is the last
writer and the user is kicked. That last one was checked rather than assumed.

**This does not replace the model change.** `docs/membership-vs-visibility.md`
§Recommendation is still where this problem actually disappears: under
`join_rule: "invite"` for private channels there is nothing for `/join` to
refuse. This is the one-endpoint fix that makes kick work today, not an argument
against that.

---

### 7. Profile writes are an unmetered amplifier — Medium

**Endpoints:** `PUT /profile/{me}/displayname`, `PUT /profile/{me}/avatar_url`,
`PUT /profile/{userId}/nickname` — all three call
`ProfileHandler::broadcastMemberUpdate` (`src/api/ProfileHandler.cpp:355-382`).

Each request loops `store_.get_joined_rooms(user_id)` and does one
`insert_event` per room, then one `sync_engine_.notify_new_event()`. On a
50-channel server that is **50 event rows and a server-wide long-poll wake per
request**, and the wake is global — every parked `/sync` on the server re-scans.

There is no rate limit on any of the three, on `main` or on `harden/auth`
(`[limits]` buckets are send / redact / upload).

**Exploitation path.** `while true; do curl -X PUT …/displayname -d '{"displayname":"a"}'; done`
from one ordinary account. At a modest 200 req/s that is 10,000 event inserts
per second through the store's single global mutex, plus a wake storm, plus
unbounded growth of the `events` table. Every other client's sync latency
collapses. No moderation action stops it short of banning the account, and the
events are indistinguishable from legitimate profile churn.

**Fix.** Add a `profile` bucket to `SendLimiter` — the auth audit notes it takes
an identity string and an enum, so this is one enum entry and one config value.
Something like 10/minute is far above human use. Separately, consider coalescing:
`broadcastMemberUpdate` could debounce per user, since the member events are
idempotent rewrites.

**Resolved** (`harden/audit-request-path`).

A `kProfile` bucket on `SendLimiter`, `[limits] profile_limit = 10` per minute,
charged by all three endpoints. One bucket, not three: they are three doors onto
one amplifier, so separate budgets would only triple the ceiling. It is charged
against the account **being changed** rather than the caller, because the fan-out
is over that account's channels — otherwise a MANAGE_NICKNAMES holder spends one
budget while driving a different amplifier on every request.

Charged after validation and immediately before `broadcastMemberUpdate`, so a
malformed request that was never going to emit anything costs nothing.

The debounce the finding also suggested is **not** implemented. The rate limit
bounds the amplifier at its source; coalescing would add per-user timer state to
a handler that currently has none, to save work that is now capped at ten
requests a minute. Worth revisiting only if profile churn ever shows up in a
sync-latency profile.

---

### 8. EMBED_LINKS is checked against `body` only — Medium

**Endpoint:** `PUT /rooms/{roomId}/send/{eventType}/{txnId}`
(`src/api/EventHandler.cpp:222-230`).

```cpp
const std::string body = content.value("body", "");
...
if (!body.empty() && body_contains_url(body) &&
    !permission::has(user_perms, permission::kEmbedLinks)) { ... 403 ... }
```

`formatted_body` — the HTML the client actually renders for a formatted message —
is never examined.

**Exploitation path.** A role has EMBED_LINKS denied (the normal arrangement for
a new-member or untrusted role, to stop link spam and phishing). The user sends:

```json
{"msgtype":"m.text","body":"see attached",
 "format":"org.matrix.custom.html",
 "formatted_body":"<a href=\"https://phish.example/login\">chat.host login</a>"}
```

`body` contains no URL, so the gate passes. Every client renders the link, and
`LinkPreview.qml` will produce a preview card for it. The permission is
decorative.

The `@everyone` half of the same pattern (`body_mentions_everyone`, line 226) is
less serious, because the actual ping is gated separately and correctly on
`m.mentions.room` (`parse_mentions`, `EventHandler.cpp:101-113`) — a
`formatted_body` `@everyone` is a visual fake with no notification behind it.

**Fix.** Run `body_contains_url` over `formatted_body` too (and over
`m.new_content.body` / `m.new_content.formatted_body` for edits, which are not
checked either). Better: extract the set of text-bearing fields once and check
all of them, so a new field cannot be forgotten. The function's own comment
already says it is deliberately permissive; the problem is not the matcher, it is
what is fed to it.

**Resolved** (`harden/audit-request-path`, `EventHandler.cpp`).

`renderable_text(content)` collects every text-bearing field once — `body`,
`formatted_body`, `m.new_content.body`, `m.new_content.formatted_body` — and both
gates run over the collection. The finding's "better" option, because the matcher
was never the problem: the problem was that adding a field to the wire format did
not add it to the check.

MENTION_EVERYONE is extended the same way, even though the finding rates it lower.
It is the same line of code and the same list; leaving one of the two reading
`body` alone would have been re-creating the defect next to its fix.

---

### 9. `/versions` publishes the exact build and git revision — Medium

**Endpoint:** `GET /_matrix/client/versions` (`src/api/AuthHandler.cpp`,
`handle_versions`). Unauthenticated.

```json
{"versions":["…"],"unstable_features":{"bsfchat.server":true},
 "bsfchat.version":"…","bsfchat.revision":"<git sha>","bsfchat.channel":"…"}
```

The comment explains this is for operator support, which is a fair goal. The
consequence is that **anyone can fingerprint any BSFChat deployment down to the
commit.**

**Exploitation path.** This RC ships the fix for `harden/auth` finding 1 —
access tokens with 32 bits of entropy, enumerable in ~1.3 hours. After it lands,
`bsfchat.revision` tells an attacker, with one unauthenticated GET and no
guessing, exactly which self-hosted instances have not upgraded and are therefore
still spray-able. The same applies to every future fix. For self-hosted software
where upgrades are manual and staggered, that is a meaningful force multiplier.

**Fix.** Keep `versions` (clients need it). Move `bsfchat.version`,
`bsfchat.revision` and `bsfchat.channel` behind `authenticate()` — either onto
`/whoami`, or return them from `/versions` only when a valid token is presented.
An operator debugging their own server has a token; a scanner does not.

**Resolved** (`harden/audit-request-path`, `AuthHandler::handle_versions`) — and
this one is worth showing the working for, because the finding as written proposes
the wrong half.

`bsfchat.version`, `bsfchat.revision` and `bsfchat.channel` are now returned only
to a caller presenting a valid access token. `versions` and `unstable_features`
are unchanged and stay unauthenticated. An unauthenticated caller gets a 200 with
those keys simply absent — never a 401, because this endpoint is how a client
decides an address is a homeserver at all.

**Why not "authenticate the revision, keep the version".** That was the option
offered, and it does not survive contact with the threat model. The fix an
attacker is looking for ships in a release, so `bsfchat.version` alone answers
"has this host taken it" completely; the revision only adds precision *between*
releases. Publishing the version while hiding the revision is the theatre
version of this fix. It is both keys or neither.

**Why neither, rather than leaving it.** The support argument is real but it is
already satisfied twice over. `docs/release-channels.md` lists three ways to read
the build, and two of them — the startup log line and the OCI image labels — need
no HTTP at all and no token. An operator debugging their own server has a token
for the third. A scanner has none of the three. So the cost of moving these keys
is close to zero and the benefit is that fleet-wide "which hosts are unpatched"
stops being a single unauthenticated GET.

**What was checked before moving them.** The desktop client reads `/versions` in
exactly one place, `ServerDiscovery::looksLikeHomeserver`, and asks only whether
`versions` is an array — which is why that key could not move. Nothing in
`client/` or `web/` reads the three vendor keys. All four registered e2e scripts
use `/versions` purely as a liveness probe.

`docs/release-channels.md` is updated to show the curl with an `Authorization`
header and to point at the two offline routes.

---

### 10. `/voip/turnServer` hands out a shared static credential — Medium

**Endpoint:** `GET /_matrix/client/v3/voip/turnServer`
(`src/api/VoiceHandler.cpp:604`).

Authentication is the only gate — no VIEW_CHANNEL, no voice-capability check, no
rate limit, which is fine for the ephemeral path. In the
`turn_secret`-configured branch the server mints a per-user HMAC credential with
a TTL; that is correct.

In the **`else` branch** (`turn_secret` empty) it returns
`config_.voice.turn_username` and `config_.voice.turn_password` verbatim: the
deployment's long-lived shared coturn credential, to any authenticated account,
including one that just self-registered if registration is open. `ttl` is
documented in the code as "just a refresh hint" — the credential never expires
and cannot be revoked short of editing the config and restarting coturn.

**Exploitation path.** Register an account → `GET /voip/turnServer` → keep the
username and password → use the deployment's TURN relay as an open proxy
indefinitely, from outside, long after the account is banned (a ban revokes chat
tokens, not coturn credentials). Bandwidth is billed to the operator and the
relayed traffic appears to originate from their host. Per the production notes,
coturn is hand-rolled and systemd-managed there, so this depends on which mode
`server.toml` actually uses.

**Fix.** Refuse to start (or at least warn loudly, as `trusted_proxies` now does)
when `voice.enabled` is true and `turn_secret` is empty while
`turn_password` is set. The REST-API ephemeral mode is the only safe one for a
multi-user server; the static branch should be treated as a single-user
development affordance and say so.

**Partly resolved** (`harden/audit-request-path`), and the honest description is
that the handler cannot fix this.

A credential shared between every account is shared however carefully it is handed
over; there is no version of `handle_turn_server` that makes the static branch
safe, because the secret in the config is a single value with no per-user
component to bind to. So what landed is the recognition and the warning:
`turn_credentials_are_shared(const VoiceConfig&)` in `core/Config.h` names the
state — voice enabled, no `turn_secret`, a `turn_password` set — and
`Config::validate` warns loudly on every start, naming the consequence (no expiry,
no revocation, a banned account keeps a working relay credential, an open proxy on
the operator's bandwidth) and the fix (coturn `use-auth-secret` plus
`voice.turn_secret`). No secret is logged. `config/bsfchat-server.example.toml`
now marks the static pair single-user-development-only.

**Warned, not refused, deliberately.** The finding offers refusing to start.
`deploy/config/server.toml.template` ships `turn_secret`, so a deployment in the
static mode was hand-configured — but it is still somebody's working voice, and
turning a security warning into a failed start on upgrade is the worse outcome for
a self-hoster who pulls a patch release. If we would rather fail closed, it is one
line here; it needs a deliberate decision and a release note, not a quiet flip.

Four tests pin the predicate across the four mode combinations, so the condition
the warning is built on cannot drift away from the branch
`handle_turn_server` actually takes.

---

### 11. Unknown state event types are accepted by default — Low

**Endpoint:** `PUT /rooms/{roomId}/state/{eventType}[/{stateKey}]`
(`src/api/RoomHandler.cpp:1285-1292`).

```cpp
permission::Flags required = permission::kManageChannels;
if (is_server_scoped || evt_type == kChannelPermissions) required = kManageRoles;
else if (evt_type == kServerInfo) required = kManageServer;
```

Any event type not in that list — including types nobody has defined — is
accepted with MANAGE_CHANNELS, stored as room state, and delivered to every
member through `/sync`'s `state.events` with content taken verbatim from the
request body.

This is the state-route twin of `harden/auth` finding 4. That branch replaced
`/send`'s allow-by-default with a `send_gate_for` table and **refuses unknown
types**, reasoning that "allowing by default is what produced the hole; adding a
sendable type should be a deliberate edit". The auth doc then explicitly excludes
state events from its table on the grounds that `PUT /state/...` "has its own
per-type authorisation in RoomHandler". It does — but that authorisation is
allow-by-default, which is the thing the same document just finished arguing
against.

**Severity: low,** and deliberately so. It requires MANAGE_CHANNELS, which is
already a substantial capability, and the worst outcome is arbitrary
attacker-shaped JSON in the state of a channel you can already administer. There
is no ordinary-user path to it. Listed because it is the same bug class, one file
away, and because it will be copied.

**Fix.** Mirror `send_gate_for`: a `state_gate_for(type)` table, unknown types
refused with 403. Fold in the `bsfchat.room.type` scope change from finding 3
while you are there.

**Resolved** (`harden/audit-request-path`, `RoomHandler::handle_set_state`).

`state_gate_for(type)` is a closed table mirroring `send_gate_for`; an unlisted
type is refused with 403 and nothing is stored. Applied **before** the permission
test, because ADMINISTRATOR short-circuits every flag inside
`PermissionsEngine::compute` and a check ordered the other way round would leave
the hole open for exactly the account that can do the most with it.

Two absences are deliberate and commented as such. `m.room.member` never reaches
the table — self-membership and moderation of another member both return above it
— so listing it would be listing an unreachable case. `m.room.create` is refused:
it names the room's creator, the server writes it once at creation, and no
legitimate request rewrites it.

`bsfchat.server.screenshare` keeps MANAGE_CHANNELS at **room** scope, which is
what it has always had, so that this change is an allowlist and not a silent
re-gating hidden inside one. Writing it down made something visible that is worth
a look on its own: it is a server-wide setting (the maximum screen-share quality
for the deployment) reachable through a per-channel permission, which is the same
shape as the scope bug finding 3 fixed for `bsfchat.room.type`. Not changed here.
See [21](#21-bsfchatserverscreenshare-is-server-wide-on-a-per-channel-permission--low).

A regression test asserts that all thirteen types the shipped client PUTs through
this route are still accepted, so the allowlist cannot quietly shrink the surface.

---

### 17. The rejected push gateway URL is logged after the check that rejected it — Medium

**Endpoint:** `POST /_matrix/client/v3/pushers/set` (`src/api/PushHandler.cpp:244-249`).

```cpp
if (!gateway_url_allowed(url, config_.push, why)) {
    get_logger()->warn("Push: rejected pusher registration from {} for URL {} ({})",
                       *user_id, url, why);
```

`gateway_url_allowed` (`PushHandler.cpp:131-141`) refuses any URL containing a
character `< 0x21` or `0x7f` — which is the right check, and it explicitly names
control characters as "request-smuggling shapes". But the refusal path then
**logs the offending URL verbatim**, newlines and all. The one input the function
identified as dangerous is the one it writes to the log unescaped. There is also
no length bound on `data.url` at this point (`PushHandler.cpp:218` bounds
`pushkey` and `app_id`, not the URL).

**Exploitation path.** Any authenticated user:

```
POST /_matrix/client/v3/pushers/set
{"pushkey":"x","app_id":"y","kind":"http",
 "data":{"url":"https://a/\n[2026-09-19 03:11:00.000] [warning] Auth lockout engaged for ip:203.0.113.9\n"}}
```

The request is correctly rejected with a 400. The log now contains a fabricated
warning line, in the exact format spdlog emits
(`[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v`, `src/core/Logger.cpp:8-12`), with no
marker distinguishing it from a real one. Repeat at will, with any content.

This matters more here than it would elsewhere because `auth-hardening-2026-09.md`
finding 19 decides *not* to add auth events to `AuditLog` on the grounds that
"they are all recorded in the server log already" — registration, logins,
lockouts, password changes, refresh-family revocations. That makes the server log
the security-event record, and this endpoint lets any user write to it. An
attacker can bury a real lockout in a hundred fake ones, or manufacture evidence
against another account.

Note that `auth-hardening-2026-09.md` finding 9 fixed exactly this shape for
`device_id` ("arbitrary bytes — including the newlines that let a device id
forge extra lines in the server log"). Same bug, different field, not caught.

**Fix.** Escape or elide control characters before logging, and truncate to a
bound (128 chars is plenty for a diagnostic). Better: log the *reason* and the
URL's host only. Apply the same treatment at `src/push/PushService.cpp:192`,
which logs a stored pusher URL on the delivery path. Sweeping for other
user-controlled strings that reach the logger unescaped would be worth an hour —
`SearchHandler.cpp:197` and the `AuthHandler` lockout lines are the other
candidates.

---

**Already fixed on `main`** before this branch started, by `security/push`
(`7a0b7dc`). `PushHandler.cpp` wraps both the user id and the URL in `log_safe()`,
and `gateway_url_allowed` bounds the URL length before anything else, so the
"no length bound" half is closed too. `PushService.cpp`'s delivery-path log was
fixed in the same commit. Nothing to do here.

The finding's closing note — "sweeping for other user-controlled strings that
reach the logger unescaped would be worth an hour" — was the valuable part. It
found [20](#20-the-auth-lockout-line-is-an-unauthenticated-log-forgery--medium),
which is worse than the finding that prompted it.

---

### 20. The auth lockout line is an unauthenticated log forgery — Medium

**Endpoint:** `POST /_matrix/client/v3/login` (`src/api/AuthHandler.cpp`,
`record_failure`). Found by the sweep finding 17 asked for; not in the original
19.

```cpp
std::string user_failure_key(const std::string& user_id) {
    return "user:" + user_id.substr(0, 255);   // as SUBMITTED
}
...
get_logger()->warn("Auth lockout engaged for {}", key_a);
```

`user_failure_key` is keyed on the identifier **as submitted**, and correctly so
— keying on an account that exists would make the lockout an existence oracle.
The consequence is that it is arbitrary bytes from an unauthenticated request
body, and `record_failure` logged it verbatim.

**Exploitation path.** POST `/login` `max_failures` times with

```json
{"type":"m.login.password",
 "identifier":{"type":"m.id.user",
   "user":"victim\n[2026-09-19 03:11:00.000] [warning] Auth lockout engaged for ip:203.0.113.9"},
 "password":"wrong"}
```

and the server log gains a fabricated lockout against somebody else's address,
in the exact format `src/core/Logger.cpp` emits, with nothing distinguishing it
from a real record. No account required.

**Why this is worse than 17.** Finding 17 needed an account. This does not — it
is reachable by anyone who can reach the login endpoint. And the record it forges
is not an arbitrary line: it is *the auth lockout line itself*, which is the one
`auth-hardening-2026-09.md` finding 19 pointed at when it decided not to mirror
auth events into `AuditLog` ("they are all recorded in the server log already").
That decision makes the server log the security-event record for authentication,
and this was the unauthenticated write to it.

**Resolved** (`harden/audit-request-path`). `log_safe()` on both keys in
`record_failure`. Two more sites in the same sweep: the rejected OIDC subject in
`handle_login` (the string that just failed validation — same shape as 17) and
the SQLite exception text in `SearchHandler`, which can quote the caller's own
search terms back.

The test asserts the property rather than the escape: emit the forged identifier,
capture the logger through a ringbuffer sink, and require that **every captured
record contains exactly one newline**. Checking for a particular escape sequence
would pass for whichever characters somebody happened to think of; counting
records is the thing that has to be true. It fails against `main` with three
records from one log call.

---

### 21. `bsfchat.server.screenshare` is server-wide on a per-channel permission — Low

Noticed while writing the allowlist for finding 11, not fixed there.

`bsfchat.server.screenshare` sets the maximum screen-share quality **for the
deployment** — `ServerConnection::setMaxScreenShareQuality` writes it, nothing
scopes it to a room — but `handle_set_state` gates it on MANAGE_CHANNELS
evaluated at ROOM scope, so a per-channel override granting MANAGE_CHANNELS in
one unimportant channel lets that user change a server-wide media setting.

This is the same shape as finding 3's `bsfchat.room.type` scope bug and the same
sentence `may_edit_role_definitions` already writes down: a per-channel grant must
not be a lever on the server. The blast radius is much smaller — the worst outcome
is everyone's screen shares capped or uncapped, which is visible and trivially
reverted — which is why it is listed rather than folded into the finding-11 commit.
Changing it means moving it into `is_server_scoped` (which also moves where the
write lands) or giving it the `is_room_type_change` treatment (scope only), and
deciding which is a deliberate call, not a drive-by.

---

## `feat/bots` (unmerged)

### 12. Bot token rotation has no rank and no owner check — HIGH (blocks merge)

**Endpoints:** `POST /_matrix/client/v3/bsfchat/bots/{userId}/token`
(`wt/server-bots/src/api/BotHandler.cpp:229`) and
`DELETE /bsfchat/bots/{userId}` (`BotHandler.cpp:275`).

Both perform exactly one check — `perms.can(actor, kServerScope, kManageBots)` —
then take the target from the URL path. There is no `perms.outranks(actor,
user_id)` and no `bot->owner_id == *actor`. The rotate endpoint returns the new
plaintext token in the response body (`BotHandler.cpp:272`), and bot tokens are
created with `lifetime_ms = 0` — **they never expire**
(`wt/server-bots/src/store/SqliteStore.cpp:911`).

**Exploitation path.** MANAGE_BOTS is bit 13, is absent from `kEveryoneDefault`,
and is documented as a deliberately *delegable, non-admin* capability. A bot is
an ordinary user account and can hold any role.

1. The owner creates `@bot_deploy:host` and gives it the Admin role (position
   100) so it can manage channels.
2. Mallory holds a "Bot Wrangler" role at position 10 with MANAGE_BOTS and
   nothing else.
3. `POST /bsfchat/bots/@bot_deploy:host/token` → 200, `{"token": "…"}`.
4. Mallory now holds a non-expiring bearer token for an Administrator.

`DELETE` has the same shape: any MANAGE_BOTS holder can retire any other
operator's bot, forcing it out of every room.

This is precisely the escalation the rest of the codebase defends against —
`may_assign_roles` refuses to grant *or remove* a role at or above the actor's
position, `/kick`, `/ban` and `PUT /profile/{other}/nickname` all carry
`outranks()`. BotHandler carries neither, and no test covers cross-rank or
cross-owner rotation.

**Fix.** `if (!perms.outranks(*actor, user_id))` → 403, on both endpoints, and
decide whether `owner_id` restricts them too (see finding 13). Add the two tests.

### 13. `GET /bsfchat/bots` returns every operator's bots — Low (noted)

`store_.list_bots()` is an unfiltered select
(`wt/server-bots/src/store/SqliteStore.cpp:850`) and `bot_to_json`
(`BotHandler.cpp:64-82`) emits `owner_id`, `created_at`, `description`,
`deactivated_at` and `last_seen_at` for all rows. Any MANAGE_BOTS holder sees who
owns which integration and when each last authenticated — behavioural metadata
about someone else's automation.

Whether that is a leak or the intended admin model is a product call. What is not
defensible as-is: `owner_id` is stored and displayed but participates in **zero**
authorization decisions anywhere in `src/`. It makes a promise the code does not
keep. Either enforce it or drop it.

**Clean in `feat/bots`,** and worth recording: tokens are hashed (SHA-256 into
the existing `access_tokens.token_hash`, never stored plaintext); no token
material appears in list responses or the audit log; MANAGE_BOTS is genuinely
evaluated at server scope so a per-channel override cannot unlock it (with a test,
`tests/test_bots.cpp:939`); there is no bot-specific auth middleware and hence no
new timing shape; no IP or user-agent is recorded anywhere; `owner_id` and
`created_by` are taken from the token, never the body; the store re-enforces the
`bot_` namespace inside the transaction so a wrong handler cannot mint a
non-expiring credential for a human account.

---

## Noted

### 14. `/pushers/set` can delete another account's pusher — Low

`handle_set_pusher` (`src/api/PushHandler.cpp:293-299`): with `append` false
(the default), `delete_pushers_by_pushkey_except(pushkey, *user_id, app_id)`
removes every *other* account's pusher with that pushkey.

This is spec-mandated — a recycled device token must stop delivering the previous
owner's messages. But it means an attacker who learns a victim's pushkey (an APNs
or FCM device token) can register it to their own account and silently stop the
victim's push notifications, while receiving pushes for the attacker's own
messages on the victim's device. Requires the pushkey, which is not exposed by
any endpoint here (`pusher_to_json` returns only the caller's own, and correctly
omits the stored `device_id`). Low, and not obviously fixable without breaking
the spec behaviour. Noted so it is a known trade rather than a surprise.

### 15. `can_read_room()` leaks room existence by timing — Low

The uniform `403 "No access to this channel"` on `/state`, `/state/{type}` and
`/members` is deliberate and correct. The path behind it is not uniform
(`RoomHandler.cpp:76-84`):

- room does not exist → `is_room_member` misses on an index → return, **one query**
- room exists, no VIEW_CHANNEL → `is_room_member` hit, `is_category_room` state
  lookup, then `PermissionsEngine` does `get_server_roles` +
  `get_member_role_ids` + `get_channel_overrides` → **four-plus queries**

Same status, same body, measurably different latency.

This is the shape `harden/auth` finding 2 found at `/login`, and I looked for it
specifically. It is far weaker: the ratio there was ~1000× (PBKDF2 vs nothing);
here it is perhaps 5–20× on sub-millisecond operations, all behind the store's
single global mutex, so contention noise swamps it at low sample counts. And room
ids are CSPRNG-random, so there is nothing useful to enumerate — the value is
confined to confirming a specific id learned out of band.

**Ranked low and I would not fix it for this RC.** If you want it gone, the cheap
version is to call `store_.room_exists(room_id)` first and 403 on that too, which
makes both paths do at least one room lookup — but that does not equalise the
tail, and doing it properly means a constant-time dummy permission evaluation,
which is not worth the complexity here. Recording it so the search is on the
record rather than repeated.

I checked the other "expensive work skipped on not-found" candidates and found
nothing: `/refresh` and all token validation look up by SHA-256 digest (constant
work either way, no secret-dependent comparison); `/account/password` is
authenticated so PBKDF2 timing reveals nothing new; `/register` does tell you a
name is taken but says so explicitly already; media download's `authenticate_media`
is a digest lookup. **This category is otherwise clean.**

### 16. Channel overrides have no rank check — Low

`PUT /rooms/{id}/state/bsfchat.channel.permissions` requires MANAGE_ROLES at
**room scope** (`RoomHandler.cpp:1287`, `perm_scope = room_id`). The rank checks
`may_assign_roles` / `may_edit_role_definitions` are invoked only for the
server-scoped types (`RoomHandler.cpp:1393-1424`), so nothing constrains *whose*
access an override may modify.

Consequences, both bounded:
- A MANAGE_ROLES holder can write `allow: kAllFlags` for `user:@self` on a
  channel, granting themselves every room-scope permission there — including
  MANAGE_CHANNELS, hence delete. Note that `compute()` applies the ADMINISTRATOR
  short-circuit **before** overrides (`Permissions.cpp:80`), so this cannot
  escalate to server scope. Bounded to one channel, which is arguably what
  per-channel MANAGE_ROLES means.
- The reverse: a low-ranked MANAGE_ROLES "builder" can write
  `deny: kViewChannel` for `user:@moderator` and lock a **higher-ranked
  non-admin** out of a channel. Administrators are immune (same short-circuit),
  so this only reaches moderators whose role lacks the ADMINISTRATOR bit.

At least it is audited — `audit_channel_override_change` captures before and
after (`RoomHandler.cpp:1443-1459`), which is why this is low rather than medium.

**Fix if you want it:** apply an `outranks()` check to any override whose key is
`user:<id>` or `role:<id>` naming a role at or above the actor's position.

### 18. Unguarded JSON type conversions return a bare 500 — Low

Several handlers check `contains()` but not the type, or call `.value()` on a
body that may not be an object. nlohmann throws `type_error.302` / `.306`, the
exception escapes the handler, and — because there is **no `set_exception_handler`
anywhere in the repo** — httplib 0.47.0 answers `500` with an **empty body**
(`httplib.h:12417-12435`). So there is no disclosure; this is robustness, and it
is in the report only because the brief asked whether error bodies carry
anything. They do not.

Sites:

| File:line | Trigger |
|---|---|
| `VoiceHandler.cpp:590-593` | `PUT …/voice/state` `{"muted":"yes"}` (×4 fields) |
| `TypingHandler.cpp:64`, `:72` | `PUT …/typing/{u}` with a non-object body, or `{"typing":"yes"}` |
| `PresenceHandler.cpp:57` | `PUT /presence/{u}/status` with a non-object body |
| `PushHandler.cpp:359` | `PUT …/notify_level` with a non-object body |
| `RoomHandler.cpp:510` | `POST /createRoom` `{"parent_id": 5}` |
| `RoomHandler.cpp:1532` | `PUT …/category` with a non-string, non-null `parent_id` |

`PushHandler.cpp:207-209` already does the `is_object()` check on the *other*
entry point in the same file, so the pattern exists and was simply not applied.
The `VoiceHandler` one throws while holding `voice_state_mutex_` — the
`lock_guard` unwinds correctly so there is no deadlock, but the read-modify-write
is abandoned halfway.

**Fix.** `is_object()` on every parsed body, `is_boolean()`/`is_string()` beside
every `contains()`. Every `std::stoi`/`stoll` in the handlers is already guarded,
so this is the last family.

**Standing hazard, worth writing down:** `SqliteStore.cpp:28` appends the entire
SQL statement to its exception message, and `:146` appends the database path.
Those strings are currently only ever logged. The day somebody adds a generic
`set_exception_handler` that echoes `e.what()` — the obvious thing to do to fix
the silent 500s above — every one of them becomes response-body disclosure at
once. Fix the type checks; do not fix them by adding an echoing handler.

### 19. The client mirrors libdatachannel's ICE logs to disk — Low

`client/src/util/FileLogger.cpp:98-104` installs a `qInstallMessageHandler` that
mirrors **every** level — not only `qWarning` — to
`~/Library/Logs/<app>/bsfchat.log` (macOS) or `<AppDataLocation>/logs/bsfchat.log`,
5 MB × 3 generations, at the default umask.

`client/src/voice/PeerConnectionManager.cpp:507-509` pipes libdatachannel's own
log stream into that handler at Warning and Info level, so ICE candidate lines —
which are the user's LAN address and their public reflexive address in plain text
— land in that file.

This is the user's own address, not anyone else's, so it is low. It is worth
recording for coherence: `store/CallSignalling.h` is an entire subsystem built on
the premise that ICE candidates are addresses and must reach exactly two people,
and the client then writes its own to a world-readable-by-default file. If that
log is ever attached to a bug report — and `ClientSettings.qml:1262` gives users a
button that opens the log directory, which is precisely an invitation to attach
it — the address goes with it.

The rest of the client logging surface is **clean**: no `qWarning`/`qCDebug`
anywhere in `client/src` interpolates an access token, a password, a `Bearer`
header or a request URL. `MatrixClient.cpp` has two log calls in 1500 lines and
neither carries a URL; `HttpFetch.cpp`, `IdentityApiClient.cpp`, `Updater.cpp`,
`ServerDiscovery.cpp`, `NotificationManager.cpp` and `App.cpp` log nothing at
all. Two minor items: `IdentityClient.cpp:234-240` writes the first 200 bytes of
a failed OAuth token-exchange **response body** to the log and into the UI error
string (it is an error body, so no issued token is in it), and
`SyncLoop.cpp:191` logs the opaque `/sync` cursor at warn level.

---

## Checked and found CORRECT

This is the coverage map. Everything below I read end to end and believe is right;
where the reasoning is subtle I have said why so a future reader does not have to
redo it.

**Permission scoping (the server-vs-room-scope bug class).** Every site was
checked against `PermissionsEngine::compute`'s `if (room_id.empty()) return base;`
(`Permissions.cpp:85`), which is what makes an empty room id immune to channel
overrides.

- `GET /audit` — `kManageServer` at `""` (`AuditHandler.cpp:73`). Correct, with a
  comment saying why.
- `GET /server_bans` — `kBanMembers` at `kServerScope` (`RoomHandler.cpp:1073`).
- `/kick`, `/ban`, `/unban` — `server_scope = true` in the intent structs, so
  `scope = kServerScope` (`RoomHandler.cpp:265-276`).
- `PUT /profile/{u}/nickname` — both `kChangeNickname` and `kManageNicknames` at
  `kServerScope` (`ProfileHandler.cpp:270`, `:278`), with `outranks()` for the
  cross-user case and correctly *not* for self.
- `POST /createRoom` — `kManageChannels` at `""` (`RoomHandler.cpp:403`).
- `bsfchat.server.roles` / `bsfchat.member.roles` — `perm_scope = kServerScope`
  plus `may_assign_roles` / `may_edit_role_definitions`
  (`RoomHandler.cpp:1382-1424`). The rank logic itself
  (`Permissions.cpp:141-215`) is thorough: it blocks granting a role at or above
  your own, **and removing one**, and creating or deleting one, and
  non-administrators granting ADMINISTRATOR. Self-assignment is allowed but only
  downward, which is the right call and correctly reasoned in the header.

**Membership moderation.** `apply_membership_moderation`
(`RoomHandler.cpp:243-367`) is the single implementation behind `/kick`, `/ban`,
`/unban` and the generic state route, and `classify_transition` derives the act
from `(before, after, banned)` rather than from the URL. This is the right
architecture and it closes four divergences the duplicated code had. The
orderings are load-bearing and correct: ban row before token revocation (no
re-login window), ban row before projection (fail closed), permission and rank
checks **before** the `require_target_in_room` / `require_target_banned`
preconditions (so a refusal tells an unauthorised caller nothing about the
target's state). `MembershipAction::kInfer` is used only by the generic route,
which is what stops `POST /kick` against a banned user being read as an unban.

**DM isolation.** `refuse_on_direct_room` guards `/invite`, `/category`,
`/order` and the three structural state types on the generic route
(`RoomHandler.cpp:1246`, `:1487`, `:1577`, `:1240-1248`). `handle_delete_room`
requires participation for a DM regardless of MANAGE_CHANNELS
(`RoomHandler.cpp:663-670`) — and the comment is right that without it the audit
record would have captured the member list on the way out. `handle_join` refuses
a DM whatever a stale `join_rule` says (`RoomHandler.cpp:597-603`).
`list_public_rooms()` excludes `is_direct` rooms in SQL. `get_direct_rooms`
requires the caller's own `membership='join'`. The DM boundary is genuinely
membership, and it holds.

**`POST /search`.** The best-behaved endpoint in the codebase. The searchable
room set is computed from the caller's joined rooms filtered by VIEW_CHANNEL
*before* the query and used as the query's restriction
(`SearchHandler.cpp:127-133`), so an inaccessible channel is never searched
rather than searched-then-filtered. A client `filter.rooms` intersects, never
substitutes (`SearchHandler.cpp:146-158`). `filter.senders` is capped at 32.
`count` is computed over the same restricted set, so it cannot leak a hit count
from a hidden channel. It omits the category exemption, which — given finding 3 —
makes it *stricter* than `/sync`, in the right direction.

**Call-signalling privacy.** `get_events_since` carries a genuine **per-event**
filter (`SqliteStore.cpp`: `AND (e.signal_to IS NULL OR e.signal_to = ?1 OR
e.sender = ?1)`), and `/messages` passes no viewer so addressed signalling is
absent from history entirely. This is the one place the sync filter is finer than
per-room, and `store/CallSignalling.h` documents the rule precisely. The residual
— an event with no `to` is broadcast as before — is a deliberate,
documented compatibility choice, and it can only expose the sender's own address,
so there is nothing an attacker can do with it that they cannot do to themselves.

**Cross-user writes.** Every user-id-from-path write I could find compares
against the token:
- `PUT /profile/{u}/displayname`, `/avatar_url` — `*user_id != target_user_id`
  → 403 (`ProfileHandler.cpp:111`, `:178`).
- `PUT /presence/{u}/status` — same (`PresenceHandler.cpp:34`).
- `PUT /rooms/{r}/typing/{u}` — same (`TypingHandler.cpp:39`).
- `PUT /rooms/{r}/state/m.room.member/{u}` — self path requires
  `state_key == *user_id`, refuses anything but join/leave, and **builds the
  profile fields server-side via `member_event_content` rather than echoing the
  body**, which is what stops display-name forgery (`RoomHandler.cpp:1309-1340`).
- `PUT /profile/{u}/nickname` — the one that deliberately accepts another target,
  and it is correctly gated (see above).
- `/read_marker`, `/notify_level` (both), `/pushers` — key on `*user_id`, never
  on anything from the request.
- `GET /whoami` returns `{user_id}` and nothing else. No device id, no session
  id, no token.
- `POST /logout` deletes only the presented token; `/logout/all` resolves the
  user from the token first.

**Push.** `PushService.cpp:94` filters notification targets by
`perms.can(user_id, n.room_id, kViewChannel)`, so a denied user is not notified
about a channel they cannot see. `GET /pushers` returns only the caller's own
rows, and `pusher_to_json` deliberately omits the stored `device_id`. The SSRF
gate on `data.url` (`PushHandler.cpp:118-165`) is thorough — scheme allowlist,
no userinfo, no control characters, prefix allowlist when configured, and an
internal-address backstop covering loopback, RFC1918, CGNAT, link-local/metadata,
multicast, IPv6 ULA and `::ffff:` mapped forms, and bare dotless names. I tried
to find a bypass and did not.

**Mentions.** `parse_mentions` (`EventHandler.cpp:88-155`) is non-forgeable by
construction: the mentioner is always the authenticated sender, targets must be
joined **and** hold VIEW_CHANNEL, `@room` is gated on MENTION_EVERYONE, the
sentinel is unspellable, self-mentions are dropped, the list is capped and
deduped. Invalid targets are dropped silently rather than rejected, so it is also
not a membership probe. Mentions are deliberately not recorded for edits, which
closes the "edit an old message to ping people" hole — the comment explaining why
removal-on-edit is *also* not implemented is correct.

**`handle_redact`.** Gets the event-oracle question right where the edit path
(finding 5) gets it wrong: `if (!target || target->room_id != room_id)` → one
shared 404 (`EventHandler.cpp:513-520`). It also actually strips the content
rather than only appending a redaction event.

**Sync mechanics.** `next_batch` is derived from the position the scan *covered*,
never from a separately-read head, in both the initial and incremental paths —
which is a correctness property, not a security one, but it is the thing that
would otherwise silently drop events. The long-poll re-check loop terminates
(`checked_pos` advances, with a fallback to the head when a scan is cut short by
its limit). A server-banned user gets an immediate empty response rather than a
held thread. Malformed `since`, `timeout`, `limit` and `from` parameters are all
guarded — the unguarded `std::stoi` sites that used to throw out of handlers are
gone.

**`feat/sync-invites`.** `get_invite_state` is a **whitelist** of seven room-level
types plus the invitee's own member event, enforced inside the SQL subquery so a
row outside it is never read. An invitee learns the room's name, topic, avatar,
join rules and type — and nothing else. No timeline, no other members' events, no
overrides. `attach_pending_invites` gates on `can_view_room`, which is right in
principle (it inherits finding 3's exemption, but that is finding 3's problem,
not this branch's). Correct.

**CORS.** `Access-Control-Allow-Origin: *` with `Allow-Headers: Authorization`
(`Server.cpp:88-99`) is the standard Matrix posture and is safe here: auth is a
bearer token, not a cookie, so a wildcard origin grants a third-party page
nothing it does not already have. It is only load-bearing in finding 1, where the
attacker's page is same-origin anyway.

**Error bodies carry nothing.** I checked all 17 `.what()` call sites in `src/`:
every one goes to the logger or into a re-thrown `runtime_error`, and **not one
reaches `res.set_content`**. The handlers most likely to slip — media upload,
LiveKit token and key signing, search, password change — all log the exception
and answer with a fixed `MatrixError`, and two of them carry an explicit "never
echo `e.what()`" comment. No response header leaks version or build info either;
the complete set the server sets is the three CORS headers, `Content-Disposition`,
`Accept-Ranges`, `Content-Range` and `Retry-After`, and httplib 0.47.0 emits no
`Server:` header of its own. The build-info disclosure is in a *body*, on
`/versions` — finding 9.

**Server logs carry no credentials.** Across 128 logging call sites: no access
token, no refresh token, no LiveKit token, no password, no password hash, no
`Authorization` header, no pushkey, no message content, no client request body.
`Config.cpp:218-223` deliberately logs the LiveKit `api_secret` as the literal
`"set"`/`"missing"`. The lines that mention "token" carry only a JWKS `kid` or an
OIDC subject. What *is* in the log and should be known rather than discovered:
client IP addresses at `AuthHandler.cpp:103-108` and `:141` (the lockout warning
keys on `"ip:" + addr`), the database and config paths in the startup banner, an
absolute media path via `MediaHandler.cpp:216`, and raw S3 error XML at
`S3Client.cpp:223`/`:269`. All are operator-visible only. The one that is not
merely operator-visible is finding 17.

**Audit log.** `record_to_json` (`AuditHandler.cpp:37-54`) returns only
moderation facts. `limit`, `from` and the four filters are validated, and an
empty filter value is a 400 rather than a silently-ignored filter — which is the
right call on an audit log for exactly the reason the comment gives. Retention is
unbounded and `total` is reported whole-table so an operator can see it.

---

## Corrections to the existing audits

**`membership-vs-visibility.md` — one addition, no disagreements.** Its item 2
flags `GET /rooms/{id}/voice/members` for returning the roster (with device and
session ids) without a VIEW_CHANNEL check. `POST /rooms/{id}/voice/join`
**returns the same roster, with the same fields** (`VoiceHandler.cpp:343-360`),
so fixing item 2 alone would leave the disclosure intact through item 1's
endpoint. Both need the check. Otherwise its six findings are accurate, its
"Correct already" list matches what I found, and its §Recommendation is the right
read — findings 3 and 6 in this document are two more instances of the same root
cause.

**`auth-hardening-2026-09.md` — one gap, no disagreements.** Finding 7's
resolution table for reactions states the correct answer to the
event-oracle question and applies it to `m.reaction` only. The **edit** path in
the same file has the identical shape and did not get it (finding 5 above).
Separately, its decision to exclude state events from the `send_gate_for` table
on the grounds that `PUT /state/...` "has its own per-type authorisation" is
technically true but understates it: that authorisation is allow-by-default
(finding 11). Neither is an error in what the document says — both are places
where a conclusion it reached was not carried one file across.

---

## What I did not cover

- The registration, login, token and rate-limit paths — `harden/auth` owns them
  and I did not re-derive its work.
- `identity/` (the OIDC service) — a separate process on a separate port.
- The store's write paths and migrations, except where a read path reaches them.
- I did not build or run the server. Every finding here is derived from reading
  `main` at `c9a1e12` plus the named branch worktrees. Findings 1, 2 and 3 are
  the ones I would most want confirmed by an actual request before the fix is
  designed; all three are unambiguous in the source (an absent `authenticate()`
  call, an unconditional `return true`, and a verbatim header echo), which is why
  I have ranked them without doing so.
