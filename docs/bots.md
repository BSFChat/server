# Writing bots for BSFChat

This is the guide for writing a program that talks to a BSFChat server as a bot
account. It describes what the server **actually does**, verified against the
source, not what the Matrix specification says it ought to do.

Start with [`examples/python-bot/`](../examples/python-bot/) — a runnable
reference bot in ~400 lines of Python with no dependencies beyond the standard
library. This document explains what that code is doing and why.

---

## 0. Read this first: do not use a Matrix SDK

The server answers `GET /_matrix/client/versions` with `{"versions": ["v1.12"]}`.
That is a claim about the *shape* of the endpoints we implement, not a claim of
completeness. BSFChat implements a **subset** of the Matrix client-server API,
and the subset is chosen for what a Discord/Teamspeak-style chat product needs.

Off-the-shelf Matrix SDKs — `matrix-nio`, `mautrix-python`, `matrix-bot-sdk` —
will connect, will log in, will even receive some messages, and will then break
in ways that are hard to diagnose, because they negotiate features off that
version string and then call endpoints that return 404 or silently behave
differently. Specifically, none of the following exist:

| Matrix feature | Status here |
| --- | --- |
| User-Interactive Auth (UIA) on `/register` | **Not implemented.** `/register` takes `{username, password}` and returns a token directly. SDKs that expect a UIA flow stall on the first request. |
| Sync filters (`/user/{id}/filter`, `?filter=`) | **Not implemented.** The `filter` query param is ignored entirely. You get every event in every room you can see. |
| `GET /rooms/{id}/event/{id}` | **No route.** There is no way to fetch a single event by id. Page `/messages` or keep your own cache. |
| Account data (`/user/{id}/account_data/{type}`) | **No route.** `m.direct` appears in `/sync` (synthesised by the server from room flags), but you cannot read or write account data. |
| E2EE, device keys, `/keys/*`, cross-signing | **Not implemented.** No route, no device list, no to-device messaging. |
| Application Service API (`/_matrix/app/*`) | **Not implemented.** There are no appservices, no namespaces, no transaction pushes. |
| Room versions, federation, `/directory`, spaces | **Not implemented.** |
| `/relations` endpoints | **No route.** Relations are plain content fields; you aggregate them yourself. |
| Presence `/presence/{id}/status` GET | **PUT only.** Presence is read out of `/sync`. |

Use a thin HTTP client instead. The entire surface a bot needs is seven
endpoints, and you can hold all of them in your head. The reference bot uses
`urllib` from the standard library; `httpx` or `requests` are equally fine.

---

## 1. Getting a bot account and a token

Bots are **ordinary user accounts** with three differences: their localpart is
reserved to the `bot_*` namespace, they have no password and cannot use
`/login`, and they are excluded from channel auto-join.

Bot accounts are created by an administrator, not by the bot. The endpoints are
BSFChat extensions, namespaced `bsfchat/` because they have no Matrix
equivalent. They require the `MANAGE_BOTS` permission (or `ADMINISTRATOR`).

### Create

```http
POST /_matrix/client/v3/bsfchat/bots
Authorization: Bearer <an admin's access token>
Content-Type: application/json

{"localpart": "bot_weather", "display_name": "Weather", "description": "Forecasts on demand"}
```

```json
201 {"user_id": "@bot_weather:chat.example.com",
     "display_name": "Weather",
     "token": "syt_...long-random-string..."}
```

**The token is shown once** — it appears in this response and nowhere else,
ever. Only its hash is stored, so it cannot be recovered from the database or
the audit log. If you lose it, rotate.

The localpart must start with `bot_`, must be more than the prefix alone, and is
otherwise the ordinary username grammar (`a-z`, `0-9`, `.`, `_`, `-`, max 64
chars). A localpart outside the namespace is `400 M_INVALID_PARAM`; one already
taken is `400 M_USER_IN_USE`.

### List

```http
GET /_matrix/client/v3/bsfchat/bots
```
```json
200 {"bots": [{"user_id": "@bot_weather:chat.example.com",
               "display_name": "Weather",
               "description": "Forecasts on demand",
               "owner_id": "@alice:chat.example.com",
               "created_at": 1758000000000,
               "deactivated": false,
               "last_seen_at": 1758003600000}]}
```

Listing never returns tokens — no branch of it can, because the plaintext was
never stored.

| Field | Notes |
| --- | --- |
| `owner_id` | Who is currently responsible for the bot. A current fact, not a historical one. |
| `created_at` | Always present, ms since epoch. |
| `deactivated` | **Always present**, so "not deactivated" and "server too old to say" are not the same value. |
| `deactivated_at` | Present **only when deactivated** — you never get a `0` that reads as "deactivated at the epoch". |
| `last_seen_at` | Present **only once the bot has authenticated**. Coarse: it is throttled to one write per minute so a busy bot does not put a store write on every request. It answers "has anyone decommissioned this integration?" |

### Rotate the token

```http
POST /_matrix/client/v3/bsfchat/bots/@bot_weather:chat.example.com/token
```
```json
200 {"token": "syt_...a-new-one..."}
```

Rotation **invalidates every prior token immediately**. A bot holding the old
one gets `401 M_UNKNOWN_TOKEN` on its very next request, including on a `/sync`
long poll that is already parked — treat a 401 as "stop and reload credentials",
not as something to retry. See §9. Room membership survives a rotation: it is a
credential change, not a new account.

### Deactivate

```http
DELETE /_matrix/client/v3/bsfchat/bots/@bot_weather:chat.example.com
```

This is a **deactivation, not a hard delete**, and the distinction matters:

- Every token is revoked; the bot can no longer sync, send or authenticate.
- The bot is made to **leave its rooms**, so it does not linger as an
  apparently-live member.
- The record **stays in the list**, flagged `"deactivated": true` with a
  `deactivated_at`. The localpart therefore **stays reserved** — you cannot
  recreate `bot_weather`, and a future bot cannot inherit a previous one's name.
- It is a **one-way door.** Rotating the token of a deactivated bot is refused
  (`400 M_INVALID_PARAM`); there is no revive. Create a new bot instead, so
  there is a creation record for it.
- Calling it twice is idempotent and returns `200`.

All four management endpoints evaluate `MANAGE_BOTS` at **server scope**, so a
per-channel permission override cannot unlock them.

### Telling a bot from a human

`GET /_matrix/client/v3/profile/{userId}` gains a `"bsfchat.bot": true` key for
bot accounts:

```json
200 {"displayname": "Weather", "bsfchat.bot": true}
```

**The key is emitted only when it is true.** For a human it is *absent*, not
`false` — the same convention as an unset `displayname`. Read it as
`profile.get("bsfchat.bot", False)` and never test for the key's presence
expecting a boolean either way.

**Profile reads require authentication.** `GET /profile/{userId}` and its
`/displayname`, `/avatar_url` and `/nickname` variants all need a bearer token —
including when your bot reads *its own* profile. Without one you get
`401 M_MISSING_TOKEN`.

These four were previously the only unauthenticated read endpoints in the
server, which made them a user-existence oracle (404 vs 200) over the whole
account namespace, plus every account's display name and avatar, at line rate.
They now gate on being signed in — nothing more, since reading another user's
profile is perfectly legitimate and is what a member list does.

The response is always a JSON object.

`GET /_matrix/client/v3/account/whoami` carries the same key, for the **caller**:

```json
200 {"user_id": "@bot_weather:chat.example.com", "bsfchat.bot": true}
```

Since you should be calling `whoami` at startup anyway (§2), that is a free way
for shared code to discover it is running as a bot — and skip the password and
session-expiry affordances that mean nothing for one.

---

## 2. The auth model

There is exactly one rule: put the token in an `Authorization` header on every
request.

```
Authorization: Bearer syt_...
```

That is the same header every human client uses, and the bot token authenticates
against **every existing endpoint** unchanged. There is no separate bot API
surface: once you hold a token, `/sync`, `/rooms/.../send/...`, `/media/upload`,
`/rooms/.../kick` and the rest work exactly as they do for a person, subject to
the same permission checks.

Things that do **not** apply to bots:

- `POST /login` — a bot account has no password hash, so password login is
  refused. There is no bot login flow. Your token *is* your session.
- `POST /refresh` — bot tokens are not part of the refresh-token scheme.
- `POST /logout` / `/logout/all` — rotation is the revocation mechanism.

**A bot token never expires.** Human access tokens have a 90-day sliding
lifetime, on the assumption that there is a person who can log in again when a
session lapses; a bot has nobody. An expiring bot token would be an integration
that stops working on a date nobody wrote down, with a `401` as its only
explanation. A bot credential ends only by rotation or deactivation, and both
are explicit operator actions. Do not write refresh logic; you will never need
it.

Two failure codes you will see, and they mean different things:

| Response | Meaning |
| --- | --- |
| `401 M_MISSING_TOKEN` | No `Authorization` header, or it was not `Bearer <x>`. Your client is broken. |
| `401 M_UNKNOWN_TOKEN` | Header present, token not recognised. Rotated, deleted, or typo'd. Do not retry. |

Verify a token with `GET /_matrix/client/v3/account/whoami`, which returns
`{"user_id": "..."}`. **Call this at startup and keep the answer** — you need
your own user id to avoid replying to yourself (§5).

> TLS is not implemented in the server process. `[tls] enabled = true` makes the
> server refuse to start rather than serve plaintext on a port an admin believes
> is HTTPS. In production, BSFChat sits behind nginx. Point your bot at the
> `https://` front door, not at the origin port, or your token crosses the
> network in the clear.

---

## 3. Getting into a room

Normal users are **force-joined to every public channel** on registration, and
to every new public channel as it is created. **Bots are excluded from this.**
That is deliberate: a server with forty channels should not have every bot
sitting in all forty, holding membership rows and receiving every message.

There are two ways in, and the first is the one to reach for.

### Being invited (the normal gesture)

An operator invites the bot the same way they would invite anyone:

```http
POST /_matrix/client/v3/rooms/{roomId}/invite
{"user_id": "@bot_weather:chat.example.com"}
```

**Inviting a bot joins it immediately, server-side.** There is no pending
invitation to accept and nothing for the bot to do: the server writes a real
`m.room.member` join event, and your bot simply observes itself joined on its
next `/sync`, in the ordinary timeline, like any other membership change.

From the bot author's side that means: **you write no invite-handling code at
all.** If your bot needs to react to being added to a channel — post a greeting,
register the room in its own state — watch for an `m.room.member` event whose
`state_key` is your own user id and whose `content.membership` is `join`:

```python
if event["type"] == "m.room.member" \
        and event.get("state_key") == self.user_id \
        and event["content"].get("membership") == "join":
    # we were just added to event["room_id"]
```

The gesture is idempotent — inviting a bot already in the channel changes
nothing and does not error. It is refused for a **deactivated** bot and for a
**banned** one.

This is bot-specific behaviour. **Inviting a human still creates an ordinary
pending invite** that the person accepts in their client; nothing about human
invite semantics changed.

### Joining by room id (public channels)

A bot can also let itself into any public channel using its own token, which is
useful when the bot is configured with a list of channels rather than being
invited to them. Both spellings work:

```http
POST /_matrix/client/v3/rooms/{roomId}/join
POST /_matrix/client/v3/join/{roomId}
```
```json
200 {"room_id": "!abc:chat.example.com"}
```

For a channel whose `m.room.join_rules` is `public` this succeeds for any
non-banned account. For `invite` it requires a pending invite — so for a
private channel, have an operator invite the bot instead, which joins it
outright. A direct message room always fails with `403`: DMs are never joinable
by request.

Joining a room the bot is already in is harmless, so a bot can simply attempt
its configured rooms at every startup.

### Knowing where you are

`GET /_matrix/client/v3/joined_rooms` returns `{"joined_rooms": [...]}`, which is
how a bot rediscovers itself across restarts — including channels it was invited
into while it was down.

---

## 4. The sync loop

`GET /_matrix/client/v3/sync` is the only way to receive anything. It is a
**long poll**, and it is **event-driven on the server side** — this is the single
most misunderstood thing about the API, so be precise about it.

When you park a `/sync`, the handler scans for events newer than your `since`
token. If it finds none, it blocks on a condition variable. Any commit anywhere
on the server calls `notify_new_event()`, which wakes every parked sync; each one
re-scans, and the ones with something visible to their user return immediately.
The wake-up path is a condition-variable signal, so delivery is **microseconds**
after the write commits, not milliseconds and certainly not seconds.

**`timeout` is the idle ceiling, not a polling interval.** It is the longest the
server will hold a request that has nothing to say. It has no effect whatsoever
on how quickly a message reaches you. A bot polling with `timeout=1000` is not
faster than one polling with `timeout=300000`; it is 300× more requests for
identical latency.

```
GET /_matrix/client/v3/sync?since=s4711&timeout=300000
```

- Default `timeout`: **30000** ms. Maximum: **300000** ms (5 minutes); larger
  values are clamped, not rejected.
- A malformed `timeout` (`?timeout=abc`) is silently replaced with the default.
- `timeout=0` returns immediately with whatever is pending.

### Why you should use a long timeout

The server is cpp-httplib, which is **thread-per-connection**: one pool worker is
occupied for the whole keep-alive session of a connection, not per request. A
parked `/sync` therefore *holds a worker thread for its entire duration*.

The default pool is `workers = 64`, sized at roughly four connections per
connected client (a client holds its sync, plus voice polling, plus media, plus
identity fetches). **A bot costs about what a client costs.** Ten bots on a small
server is a real fraction of the pool.

The implication for you is the opposite of the usual advice: a long `timeout` is
*cheaper* for the server than a short one, because a short one adds connection
churn on top of the same held worker. Use **60–300 s** and let the condition
variable do its job. A tight loop of `timeout=1000` polls is the one pattern
that will actually hurt a server, and it buys nothing.

### Handling `since` correctly

The token is **opaque**: store it and echo it back, and do not parse, compare or
do arithmetic on it. The current format is `t_` followed by 32 hex characters,
e.g. `t_9f3c1a...`; servers before September 2026 emitted `s<integer>` instead,
and an upgraded server still accepts that older spelling from a token you
persisted (for one release — after that it will read as "from the beginning").
Neither spelling means anything you can use. In particular the number in the old
form was the server's global stream position, and a bot that subtracted two of
them was counting activity in rooms it could not see; that is why it is gone.

```
1. First ever sync:   GET /sync?timeout=0            (no `since`)
                      -> full room state + last 20 messages per room + next_batch
2. Save next_batch. DISCARD the timeline. (see below)
3. Thereafter:        GET /sync?since=<saved>&timeout=300000
                      -> process timeline, save the new next_batch, repeat
```

Four things that will bite you:

- **The initial sync replays history.** With no `since`, you get the last 20
  events in every room you are in. A naive bot processes all of them as if they
  just arrived and answers twenty-minute-old commands on every restart. Take the
  `next_batch` from the initial sync and throw the events away, unless you are
  deliberately implementing catch-up.
- **A malformed `since` silently means "from the beginning".** An unparseable
  token is coerced to position 0, which replays *everything your bot is allowed
  to see* into it. Persist the token exactly as the server sent it — byte for
  byte, no trimming, no case folding, no re-encoding — and if you want a sanity
  check before use, check it is non-empty and matches `^(t_[0-9a-f]{32}|s\d+)$`
  rather than assuming either shape.
- **A token is bound to the account it was issued to.** Do not share one between
  two bot identities; the second will be treated as having no token at all.
- **`next_batch` can come back unchanged** on an idle timeout. That is normal and
  means "nothing happened". It is not an error and must not trigger backoff.

### The response shape

```json
{
  "next_batch": "s4712",
  "rooms": {
    "join": {
      "!abc:chat.example.com": {
        "timeline": {"events": [ ... ], "limited": false, "prev_batch": "s4690"},
        "state":    {"events": [ ... ]},
        "ephemeral": {"events": [{"type": "m.typing", "content": {"user_ids": []}}]},
        "unread_notifications": {"notification_count": 3, "highlight_count": 1}
      }
    }
  },
  "presence": {"events": [{"type": "m.presence", "sender": "@josh:...", "content": {...}}]},
  "account_data": {"events": [{"type": "m.direct", "content": {...}}]}
}
```

Each timeline event is:

```json
{"event_id": "$xyz:chat.example.com",
 "room_id": "!abc:chat.example.com",
 "sender": "@josh:chat.example.com",
 "type": "m.room.message",
 "origin_server_ts": 1758000000000,
 "content": {"msgtype": "m.text", "body": "hello"},
 "state_key": "...",        // present only on state events
 "unsigned": { ... }}       // edit bundling, see §6
```

State events appear in **both** `state.events` and `timeline.events` in an
incremental sync. Do not count them twice.

`m.direct` is restated on essentially every delivered sync. It is a full
replacement of the DM map, never a delta, and is safe to ignore unless your bot
cares about DMs.

---

## 5. Dispatching on messages — the two footguns

### Footgun 1: your bot sees its own messages

`/sync` returns everything in the room, **including events your bot just sent**.
A bot that replies to every `m.room.message` will reply to its own reply, and
then to that, forever, at the speed of a condition variable. This is the single
most common way to take a server down with a bot.

```python
if event["sender"] == self.user_id:
    continue
```

Put that check first, before anything else. This is why §2 says to call
`/whoami` at startup.

It is also worth ignoring other bots by default (`@bot_` prefix, or a profile
lookup for `bsfchat.bot`), so that two bots cannot get into a loop with each
other.

### Footgun 2: edits arrive as new messages

An edit is a **new** `m.room.message` event carrying
`content["m.relates_to"]["rel_type"] == "m.replace"`. Its top-level `body` is the
new text prefixed with `"* "` by convention. If you dispatch naively, editing
`!ping` into `!pong` makes your bot answer `!ping` a second time — and somebody
who edits an old message can make your bot act on it at any time.

```python
rel = event["content"].get("m.relates_to") or {}
if rel.get("rel_type") in ("m.replace", "m.annotation"):
    continue
```

Skip `m.annotation` too unless you specifically want to react to reactions.

### A sane dispatch order

1. `event["type"] != "m.room.message"` → skip (unless you want state/reactions).
2. `event["sender"] == self.user_id` → skip.
3. `m.relates_to.rel_type` in `{m.replace, m.annotation}` → skip.
4. `event["content"].get("msgtype") != "m.text"` → skip (unless handling media).
5. Match `body` against your command prefix.

The reference bot does exactly this in `_dispatch()`.

---

## 6. Sending

```http
PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
Authorization: Bearer <token>
Content-Type: application/json
```
```json
200 {"event_id": "$xyz:chat.example.com"}
```

Note `PUT`, not `POST`, and note that the response is `200` with only an
`event_id`.

### Which event types you may send

The send endpoint is **deny-by-default**. Only these types are accepted:

| Type | Extra permission |
| --- | --- |
| `m.room.message` | `SEND_MESSAGES` |
| `m.reaction` | `ADD_REACTIONS` |
| `m.call.invite`, `m.call.answer`, `m.call.candidates`, `m.call.hangup`, `m.call.member`, `bsfchat.call.negotiate` | none beyond `VIEW_CHANNEL` |

Anything else is `403 M_FORBIDDEN` — *"Events of type 'x' cannot be sent to a
room"*. **If your bot stores custom event types in the timeline, it is now
broken.** There is no opt-in and no config switch; adding a sendable type is a
deliberate edit to the server's table. Keep bot-specific data in your own
storage, or express it as an `m.room.message` your bot can recognise.

State events are not on this endpoint at all. They go to
`PUT /rooms/{id}/state/{type}/{key}`, which has its own per-type authorisation.

### Transaction ids and idempotency

The server keys the transaction record on
**`(user_id, device_id, room_id, txn_id)`**. A `device_id` is bound to the
access token, so for a bot it is stable for the life of a token and changes when
the token is rotated.

- **Retrying a send with the same `txnId` is safe.** You get `200` with the
  original `event_id` and no duplicate. That is exactly what you want on a
  timeout or a dropped connection: retry with the *same* id, do not invent a new
  one.
- **The same `txnId` in a different room is a different request**, and posts
  normally. The room is part of the key.
- **A counter that resets on restart is still a bug.** A restarting bot reuses
  its token, so it keeps the same `device_id`; starting again at `txn-1` in the
  same room means its first sends after every restart are answered with old
  event ids and never posted. Use a timestamp-plus-counter
  (`f"{time.time_ns()}-{n}"`) or a UUID.
- **Redaction is idempotent too**, in its own separate namespace keyed on
  `(user, device, room, target_event, txn)`. Retrying a redaction returns the
  original redaction event rather than appending a second one. The target is
  part of that key, so reusing an id for a *different* target in the same room
  still deletes what you asked it to.

### Message shapes

All of these are `PUT .../send/m.room.message/{txn}` with different content.

**Plain text**
```json
{"msgtype": "m.text", "body": "pong"}
```

**Rich text.** `formatted_body` is rendered by the desktop client as Qt RichText
— an HTML subset, not a browser. Tags the client itself emits and reliably
renders: `<b>`, `<i>`, `<code>`, `<pre>`, `<a href>`, `<br>`, and inline
`style=` attributes. `body` must always be present as the plain-text fallback,
and it is what search and push notifications use.
```json
{"msgtype": "m.text",
 "format": "org.matrix.custom.html",
 "body": "Build 42: PASSED in 3m12s",
 "formatted_body": "Build <b>42</b>: <code>PASSED</code> in 3m12s"}
```

**Notice.** `m.notice` is the conventional msgtype for automated output; some
clients render it dimmer. It is otherwise identical to `m.text`.
```json
{"msgtype": "m.notice", "body": "Deploy finished."}
```

**Emote** (`/me`): `{"msgtype": "m.emote", "body": "shrugs"}`.

**Reply.** Purely a content convention — the server does not validate the target
exists, is in the room, or is visible to you. The client renders the quoted
context.
```json
{"msgtype": "m.text", "body": "pong",
 "m.relates_to": {"m.in_reply_to": {"event_id": "$target"}}}
```

**Thread.** Same deal, also unvalidated.
```json
{"msgtype": "m.text", "body": "in thread",
 "m.relates_to": {"rel_type": "m.thread", "event_id": "$threadRoot"}}
```

**Edit.** This one the server *does* understand and enforce.
```json
{"msgtype": "m.text", "body": "* corrected text",
 "m.new_content": {"msgtype": "m.text", "body": "corrected text"},
 "m.relates_to": {"rel_type": "m.replace", "event_id": "$original"}}
```
Rules the server applies, which differ from plain Matrix:
- You can only edit **your own** messages (`403`). `MANAGE_MESSAGES` does not
  grant editing others' text — it grants deletion, matching Discord.
- Editing a redacted message is `404`.
- Editing across rooms is `400`.
- An edit aimed at another edit **resolves back to the original** (up to 10 hops).
- The server reconciles the edit into the original server-side, so a fresh
  `/sync` or `/messages` returns the new content with an `unsigned.m.relations`
  bundle and `unsigned["bsfchat.original_content"]`. You do not have to apply
  edits yourself when loading history.
- **Edits fire no mention badges and no push notifications.** You cannot get
  someone's attention by editing a message to mention them. Deliberate.

**Reaction.** A separate event type, not a message.
```json
PUT .../send/m.reaction/{txn}
{"m.relates_to": {"rel_type": "m.annotation", "event_id": "$target", "key": "👍"}}
```
There is no `body`. Requires the `ADD_REACTIONS` permission (§8), and the
content is validated:

- `m.relates_to` must be present with `rel_type` exactly `m.annotation`, else
  `400`.
- `event_id` and `key` must both be non-empty, else `400`.
- `key` is capped at **64 bytes** — generous for a ZWJ sequence with modifiers,
  but it is a storage bound, not an emoji validator.
- The target must **exist and be in the same room**, else `404`. A target in
  another room gets the same "does not exist" answer on purpose, so the endpoint
  cannot be used to probe for event ids elsewhere.
- A **redacted** target cannot acquire new reactions (`404`).

**Reacting twice with the same `(sender, target, key)` is idempotent**: you get
`200` with the existing reaction's `event_id`, not an error and not a second
event. Remove a reaction by redacting the reaction event; a redacted reaction no
longer counts as a duplicate, so react → unreact → react works.

**Redaction** (deleting a message):
```http
PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}
{"reason": "spam"}
```
This genuinely strips the target's content in the database — it is a real
delete, not a client-side hint. You may always redact your own events; redacting
anyone else's needs `MANAGE_MESSAGES`.

### Mentions

Mentions are **only** read from a structured block. Nothing is scraped from the
body.

```json
{"msgtype": "m.text", "body": "@josh your build is done",
 "m.mentions": {"user_ids": ["@josh:chat.example.com"]}}
```

- The server validates each target: it must be a valid user id, a **joined
  member** of the room, and hold `VIEW_CHANNEL` there. Targets that fail are
  **silently dropped**, not rejected — your message still sends.
- Self-mentions are dropped.
- Maximum **50** entries; over that the whole send is rejected `400`.
- `{"m.mentions": {"room": true}}` is a room-wide ping and requires
  `MENTION_EVERYONE`; without it the send fails `403` (it is not silently
  dropped).

---

## 7. Media

**Upload** takes a raw binary body — *not* multipart, *not* base64:

```http
POST /_matrix/media/v3/upload?filename=chart.png
Authorization: Bearer <token>
Content-Type: image/png

<raw bytes>
```
```json
200 {"content_uri": "mxc://chat.example.com/AbCdEf0123456789"}
```

Then post a message referencing it. Note this needs the `ATTACH_FILES`
permission — **any msgtype other than `m.text`, `m.emote` or `m.notice` counts as
an attachment**, whether or not there is actually a file involved.

```json
{"msgtype": "m.image", "body": "chart.png",
 "url": "mxc://chat.example.com/AbCdEf0123456789",
 "info": {"mimetype": "image/png", "size": 20481, "w": 800, "h": 600}}
```

**Download** translates `mxc://<server>/<id>` to:

```http
GET /_matrix/media/v3/download/<server>/<id>
```

Downloads are authenticated by default (`[media] require_auth = true`), so send
your `Authorization` header. The desktop client instead appends
`?access_token=...` because Qt's image loader cannot set headers — you can do the
same, but prefer the header; query strings leak into logs. Range requests are
supported (at most 4 ranges, else `416`).

Limits: `max_upload_size_mb` defaults to **50**; exceeding it is `413
M_TOO_LARGE`. An empty body is `400 M_INVALID_PARAM`. Media from another
server's `mxc://` is `404` — there is no federation and nothing is proxied.

---

## 8. Permissions — grant a bot only what it needs

Permissions are a Discord-shaped 64-bit bitfield, serialised on the wire as a
lowercase hex string (`"0x0f"`) because JSON cannot hold 64-bit integers safely.

| Bit | Flag | Grants |
| --- | --- | --- |
| 0 | `VIEW_CHANNEL` | See the channel at all. Prerequisite for everything. |
| 1 | `SEND_MESSAGES` | Post `m.room.message`. |
| 2 | `ATTACH_FILES` | Post any msgtype other than text/emote/notice. |
| 3 | `EMBED_LINKS` | Post a body containing an `http(s)://` URL. |
| 4 | `MANAGE_MESSAGES` | Delete others' messages; bypass slowmode. |
| 5 | `MANAGE_CHANNELS` | Create/modify/delete channels. |
| 6 | `MANAGE_ROLES` | Edit roles and per-channel overrides. |
| 7 | `KICK_MEMBERS` | `POST /rooms/{id}/kick`. |
| 8 | `BAN_MEMBERS` | `POST /rooms/{id}/ban`, `/unban`. |
| 9 | `MENTION_EVERYONE` | `m.mentions.room`, and literal `@everyone`/`@here` in a body. |
| 10 | `MANAGE_SERVER` | Server settings, audit log, ban list. |
| 11 | `CHANGE_NICKNAME` | Own per-server nickname. |
| 12 | `MANAGE_NICKNAMES` | Others' nicknames. |
| 13 | `MANAGE_BOTS` | Create/list/rotate/deactivate bot accounts. |
| 14 | `ADD_REACTIONS` | Send `m.reaction`. In the default `@everyone` set. |
| 15 | `ADMINISTRATOR` | Everything, bypassing all overrides. |

Effective permissions are computed as: OR of the user's roles → short-circuit to
everything if `ADMINISTRATOR` → then per-channel overrides applied in order
(`@everyone` override, then each role's override by ascending position, then the
user-specific override), each as `(perms & ~deny) | allow`.

### Three gates that will surprise you

These fire on `m.room.message` sends and reject with `403`:

1. **`EMBED_LINKS` is checked against the message body by regex.** Any
   `http(s)://` token anywhere in `body` — including inside a code block, and
   including one your bot is merely quoting back — requires `EMBED_LINKS`. A bot
   that posts links needs this flag.
2. **`MENTION_EVERYONE` is checked against the literal strings `@everyone` and
   `@here` in `body`**, independently of the structured `m.mentions` block. An
   echo bot repeating a user's text containing `@everyone` gets `403` and drops
   the message. Either hold the permission, or strip those tokens before echoing.
3. **`ATTACH_FILES` is checked on msgtype, not on content.** See §7.

Note that **reactions have their own permission**, `ADD_REACTIONS`, rather than
riding on `SEND_MESSAGES`. That is what makes "everyone may react, only a few may
post" expressible — an ordinary read-mostly announcement channel. The practical
consequence for you: denying a bot `SEND_MESSAGES` no longer makes it silent,
because it can still react. Deny both if that is what you mean.

`ADD_REACTIONS` is in the default `@everyone` set and was backfilled onto every
role that already had `SEND_MESSAGES`, so nothing changed on upgrade. But a bot
given a deliberately narrow allow-mask needs the bit set explicitly.

### Granting permission to a bot

Grant a bot the minimum, per channel, with a **user-specific channel override**.
This is a state event, so it needs `MANAGE_ROLES`:

```http
PUT /_matrix/client/v3/rooms/{roomId}/state/bsfchat.channel.permissions/user:@bot_weather:chat.example.com
{"allow": "0x03", "deny": "0x00"}
```

That grants exactly `VIEW_CHANNEL | SEND_MESSAGES` in that one channel. Add
`0x4000` for `ADD_REACTIONS`, `0x08` for `EMBED_LINKS`, `0x04` for
`ATTACH_FILES`. Prefer this to putting a bot in the `mod` or `admin` role: a
channel override is scoped and auditable, a role is not.

To assign a server-wide role instead (`MANAGE_ROLES` also required):

```http
PUT /_matrix/client/v3/rooms/{roomId}/state/bsfchat.member.roles/@bot_weather:chat.example.com
{"role_ids": ["mod"]}
```

A bot that only reads and replies in one channel does **not** need a role.

---

## 9. Rate limits, backoff, and error handling

### What is rate-limited

**The write endpoints are limited, per account.** The limiter keys on your
identity, not on the connection or the address — so opening ten connections does
not buy ten budgets, and you are never sharing a bucket with whoever else is
behind your NAT. Three independent buckets, so exhausting one does not starve
the others:

| Bucket | Endpoint | Default |
| --- | --- | --- |
| send | `PUT /rooms/{id}/send/{type}/{txn}` | 120 / 60 s |
| redact | `PUT /rooms/{id}/redact/{event}/{txn}` | 60 / 60 s |
| media | `POST /_matrix/media/v3/upload` | 30 / 60 s |

These are set to stop a loop, not to pace a conversation — 120 events a minute
is two a second sustained, which nothing reaches by typing. If your bot trips
one, that is a bug or a runaway, and the right response is to back off and fix
it, not to raise the limit.

Exceeding a bucket is `429 M_LIMIT_EXCEEDED` with **both** a `Retry-After`
header (whole seconds) and `retry_after_ms` in the body. Honour whichever you
read; they describe the same wait.

The **credential endpoints** — `/login`, `/register`, `/refresh`,
`/account/password` — have their own separate limiter, keyed on client address
(30 attempts / 60 s by default, plus a failure lockout). A bot touches none of
these.

`/sync` is not rate-limited. The constraint there is the worker pool (§4), not a
counter.

The other 429 is **slowmode**, which is per-channel and per-user rather than
per-account:

```json
429 {"errcode": "M_LIMIT_EXCEEDED",
     "error": "Slowmode is enabled in this channel",
     "retry_after_ms": 4200}
```

Honour `retry_after_ms` exactly — it is the real remaining window, not an
estimate. `MANAGE_MESSAGES` bypasses slowmode; it does not bypass the rate
limiter above.

### The error envelope

Every error is `{"errcode": "M_...", "error": "human text"}`. The codes you will
meet: `M_FORBIDDEN`, `M_UNKNOWN_TOKEN`, `M_MISSING_TOKEN`, `M_NOT_FOUND`,
`M_BAD_JSON`, `M_INVALID_PARAM`, `M_LIMIT_EXCEEDED`, `M_TOO_LARGE`, `M_UNKNOWN`.

### How to back off

| Situation | What to do |
| --- | --- |
| `429` | Sleep for `Retry-After` (seconds) or `retry_after_ms`, then retry once. If you are hitting it repeatedly, you have a loop — fix the bot, do not tighten the sleep. |
| `5xx`, connection refused, DNS failure | Exponential backoff with jitter: 1, 2, 4, 8 … capped at 60 s. Reset the delay after any success. |
| Read timeout on `/sync` | **Not an error.** Your client's socket timeout must exceed `timeout` + margin (e.g. `timeout=300000` → socket timeout 330 s). Reconnect immediately with the *same* `since`. |
| `401 M_UNKNOWN_TOKEN` | **Stop.** Do not retry, do not back off. The token was rotated or the bot deleted. Exit non-zero and let your supervisor restart you with fresh credentials. |
| `403` on a send | A permission problem or a content gate (§8). Log it and drop the message; retrying will fail identically. |
| `400 M_BAD_JSON` | Your bug. Log the payload. |

Never retry a `4xx` other than `429`. Nothing about the request will have changed.

### Token rotation and revocation, operationally

When an admin rotates a bot's token, the old one dies instantly. A parked
`/sync` returns `401` as soon as it next evaluates. A robust bot:

1. reads its token from the environment or a file, never a literal in source;
2. exits non-zero on `401 M_UNKNOWN_TOKEN` rather than hot-looping;
3. is run under something that restarts it (systemd, a container restart
   policy), so re-issuing the secret and bouncing the unit is the whole
   rotation procedure.

---

## 10. Voice is not available to bots

**You cannot write a music bot, a recording bot, or a soundboard bot.** Please
read this before starting one.

The voice REST endpoints — `POST /rooms/{id}/voice/join`, `/voice/leave`,
`GET /voice/members`, `PUT /voice/state` — manage **roster state only**. They
record who is nominally in a voice channel, and whether they are muted or
deafened, so the sidebar can draw it. They carry **no media whatsoever**.

Actual audio and video are a **WebRTC mesh negotiated peer-to-peer between C++
desktop clients**, with signalling passed as `m.call.*` timeline events and media
flowing directly between peers (or via coturn when a peer is behind a
restrictive NAT). There is no SFU on the mesh path, no server-side mixing, and
no server-side audio at all. The server never sees a single RTP packet.

For a bot to participate in voice it would have to implement a full WebRTC
endpoint — ICE, DTLS-SRTP, Opus, and the `m.call.*` negotiation including the
`bsfchat.call.negotiate` extension — and then mesh with every other participant
individually. That is not a documented or supported integration path.

(A LiveKit SFU path exists behind `POST /rooms/{id}/voice/livekit_token`, but it
404s unless `[voice.livekit]` is configured, is not the shipped default, and is
not a bot API either.)

A bot *can* usefully read voice roster state — `GET /rooms/{id}/voice/members`,
or the `m.call.member` state events in `/sync` — to post "Josh joined General"
notices. That is the extent of it.

---

## 11. Known gaps

Honest list, as of this writing:

- **You cannot send custom event types** (§6). The send endpoint is
  deny-by-default and the allowlist is short. Bot-specific data goes in your own
  storage, not in the room timeline.
- **There is no hard delete for a bot account.** `DELETE` deactivates (§1). That
  is the right default, but it means a typo'd localpart is burned permanently.
- **No way to fetch one event by id.** If you hold an `event_id` from a relation
  and want its content, you must page `/messages` backwards until you find it.
- **No `/relations`.** Aggregating reactions, threads and replies is your job.
- **`/sync` has no `rooms.leave` section.** Being kicked or leaving is not
  reported as such; the room simply stops appearing.
- **`formatted_body` is passed through verbatim** and rendered by the desktop
  client as Qt RichText. Emit only the tag subset in §6.
- **No structured command framework.** No slash-command registration, no
  autocomplete, no interaction model. A command is a message body your bot
  chooses to match on.

Closed since earlier drafts of this guide, noted because you may have read
around them: `/sync` now has a real `rooms.invite` section (irrelevant to bots —
inviting a bot still joins it outright, so you still write no invite-handling
code, see §3); reactions are validated and permissioned (§6, §8); `/redact` is
idempotent (§6); profile reads return an object and require auth (§1).

---

## 12. Cheat sheet

```
GET    /_matrix/client/versions                              server version, no auth
GET    /_matrix/client/v3/account/whoami                     who am I
GET    /_matrix/client/v3/joined_rooms                       where am I
POST   /_matrix/client/v3/rooms/{room}/join                  get in
POST   /_matrix/client/v3/rooms/{room}/leave                 get out
GET    /_matrix/client/v3/sync?since=&timeout=               receive (long poll)
PUT    /_matrix/client/v3/rooms/{room}/send/{type}/{txn}     send
PUT    /_matrix/client/v3/rooms/{room}/redact/{ev}/{txn}     delete
GET    /_matrix/client/v3/rooms/{room}/messages?dir=b&from=  history
GET    /_matrix/client/v3/rooms/{room}/members               who is here
GET    /_matrix/client/v3/rooms/{room}/state                 channel state
POST   /_matrix/media/v3/upload?filename=                    upload (raw body)
GET    /_matrix/media/v3/download/{server}/{id}              download
GET    /_matrix/client/v3/profile/{user}                     profile
POST   /_matrix/client/v3/rooms/{room}/kick|ban|unban        moderation
POST   /_matrix/client/v3/bsfchat/bots                       create a bot (admin)
GET    /_matrix/client/v3/bsfchat/bots                       list bots (admin)
POST   /_matrix/client/v3/bsfchat/bots/{user}/token          rotate (admin)
DELETE /_matrix/client/v3/bsfchat/bots/{user}                deactivate (admin)
```

Now go read [`examples/python-bot/`](../examples/python-bot/).

---

*The bot account lifecycle described in §1 is exercised end to end by
[`tests/e2e/e2e_bots.sh`](../tests/e2e/e2e_bots.sh) against a real server
binary. Everything else here was verified by reading the handlers; where the
server's behaviour differs from what the Matrix spec would lead you to expect,
this document describes the server.*
