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
               "deactivated": false}]}
```

Listing never returns tokens. `owner_id` is who is currently responsible for the
bot. Deactivated bots are **included and flagged**, not hidden (see below), and
carry a `deactivated_at` timestamp.

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

This endpoint is **unauthenticated** — it takes no token and checks none. Handy,
but do not treat a profile lookup as proof of anything privileged.

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

A bot joins a room explicitly:

```http
POST /_matrix/client/v3/rooms/{roomId}/join
```
```json
200 {"room_id": "!abc:chat.example.com"}
```

For a channel whose `m.room.join_rules` is `public` this succeeds for any
non-banned account. For `invite` it requires a pending invite, and for a direct
message room it always fails with `403` — DMs are never joinable by request.

`GET /_matrix/client/v3/joined_rooms` returns `{"joined_rooms": [...]}`, which is
how a bot discovers what it is already in across restarts.

> ### Gotcha: a bot cannot see that it has been invited
>
> `/sync` only ever returns a `rooms.join` block. There is **no `rooms.invite`
> and no `rooms.leave` section**, and the event query that feeds sync joins
> against `room_members` with `membership = 'join'` — so an invite creates no
> event your bot can ever observe.
>
> In practice this means the "invite the bot to a channel" flow does not work
> end to end today. Configure your bot with the room ids it should be in (or
> have it join every public channel it is told about) and call
> `POST /rooms/{id}/join` at startup. See §11.

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

The token format is `s<integer>`, e.g. `s4711`. Treat it as opaque; just store
and echo it.

```
1. First ever sync:   GET /sync?timeout=0            (no `since`)
                      -> full room state + last 20 messages per room + next_batch
2. Save next_batch. DISCARD the timeline. (see below)
3. Thereafter:        GET /sync?since=<saved>&timeout=300000
                      -> process timeline, save the new next_batch, repeat
```

Three things that will bite you:

- **The initial sync replays history.** With no `since`, you get the last 20
  events in every room you are in. A naive bot processes all of them as if they
  just arrived and answers twenty-minute-old commands on every restart. Take the
  `next_batch` from the initial sync and throw the events away, unless you are
  deliberately implementing catch-up.
- **A malformed `since` silently means "from the beginning".** An unparseable
  token is coerced to position 0, which replays *the entire server history* into
  your bot. If you persist your token, validate it matches `^s\d+$` before use.
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

### Transaction ids and idempotency — read carefully

Idempotency **is** implemented, and its scope is narrower than you would guess.
The server keys the transaction record on **`(sender_user_id, txn_id)` only** —
*not* on the room, and *not* on the event type.

Consequences:

- **Retrying a send with the same `txnId` is safe.** You get `200` with the
  original `event_id` and no duplicate message. This is the behaviour you want
  on a timeout or a dropped connection: retry with the *same* id.
- **Reusing a `txnId` across rooms silently drops the second send.** If you send
  `txnId=1` to `!a` and then `txnId=1` to `!b`, the second call returns `200`
  with the *first* message's `event_id` and **nothing is posted to `!b`**. It
  looks like success. Your `txnId` must be globally unique per bot, not per room.
- **A counter that resets on restart is a bug.** If your bot restarts and starts
  again at `txn-1`, its first few sends after every restart vanish into the
  idempotency table. Use a timestamp-plus-counter (`f"{time.time_ns()}-{n}"`) or
  a UUID.
- **Redaction is not idempotent.** `PUT /rooms/{id}/redact/{eventId}/{txnId}`
  parses the `txnId` out of the path and then never uses it. Retrying a redact
  creates a second `m.room.redaction` event. It is harmless (the target is
  already stripped) but it is noise in the timeline.

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
There is no `body`. No server-side validation of any kind: the target is not
checked for existence, room membership or visibility, and duplicates are not
deduplicated. Remove a reaction by redacting the reaction event.

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
| 13 | `MANAGE_BOTS` | Create/list/rotate/delete bot accounts. *(new — see §11)* |
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

Also note: the per-type gates in the send handler apply **only to
`m.room.message`**. An `m.reaction` send is gated on `VIEW_CHANNEL` alone — a bot
denied `SEND_MESSAGES` can still react. Do not rely on denying `SEND_MESSAGES` to
make a bot silent.

### Granting permission to a bot

Grant a bot the minimum, per channel, with a **user-specific channel override**.
This is a state event, so it needs `MANAGE_ROLES`:

```http
PUT /_matrix/client/v3/rooms/{roomId}/state/bsfchat.channel.permissions/user:@bot_weather:chat.example.com
{"allow": "0x03", "deny": "0x00"}
```

That grants exactly `VIEW_CHANNEL | SEND_MESSAGES` in that one channel. Add
`0x08` if it posts links. Prefer this to putting a bot in the `mod` or `admin`
role: a channel override is scoped and auditable, a role is not.

To assign a server-wide role instead (`MANAGE_ROLES` also required):

```http
PUT /_matrix/client/v3/rooms/{roomId}/state/bsfchat.member.roles/@bot_weather:chat.example.com
{"role_ids": ["mod"]}
```

A bot that only reads and replies in one channel does **not** need a role.

---

## 9. Rate limits, backoff, and error handling

### What is actually rate-limited

Only the **credential endpoints** — `/login`, `/register`, `/refresh`,
`/account/password` — carry a rate limiter (30 attempts per address per 60 s by
default, plus a failure lockout). **A bot touches none of these.**

There is **no general request rate limit.** `/sync`, `/send`, `/messages`,
`/upload` are ungated. That is a reason to be well-behaved, not a licence: the
limit you will hit is the thread pool, not a 429.

The one 429 a bot will genuinely see is **slowmode**:

```json
429 {"errcode": "M_LIMIT_EXCEEDED",
     "error": "Slowmode is enabled in this channel",
     "retry_after_ms": 4200}
```

Slowmode is per-channel and per-user. Honour `retry_after_ms` exactly — it is the
real remaining window, not an estimate. `MANAGE_MESSAGES` bypasses slowmode.

### The error envelope

Every error is `{"errcode": "M_...", "error": "human text"}`. The codes you will
meet: `M_FORBIDDEN`, `M_UNKNOWN_TOKEN`, `M_MISSING_TOKEN`, `M_NOT_FOUND`,
`M_BAD_JSON`, `M_INVALID_PARAM`, `M_LIMIT_EXCEEDED`, `M_TOO_LARGE`, `M_UNKNOWN`.

### How to back off

| Situation | What to do |
| --- | --- |
| `429` | Sleep `retry_after_ms`, then retry once. |
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

- **`MANAGE_BOTS` (bit 13) is new**, added alongside the bot account endpoints.
  On a server predating it, only `ADMINISTRATOR` can manage bots.
- **There is no hard delete for a bot account.** `DELETE` deactivates (§1). That
  is the right default, but it means a typo'd localpart is burned permanently.
- **Invites are invisible to bots** (§3). `/sync` has no `rooms.invite` section
  and the sync query filters to `membership = 'join'`, so a bot cannot detect
  that it was invited. Until that is fixed, configure room ids explicitly.
- **No way to fetch one event by id.** If you hold an `event_id` from a relation
  and want its content, you must page `/messages` backwards until you find it.
- **No `/relations`.** Aggregating reactions, threads and replies is your job.
- **Reactions are unvalidated and ungated** beyond `VIEW_CHANNEL` (§8).
- **`formatted_body` is passed through verbatim** and rendered by the desktop
  client as Qt RichText. Emit only the tag subset in §6.
- **No structured command framework.** No slash-command registration, no
  autocomplete, no interaction model. A command is a message body your bot
  chooses to match on.

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
GET    /_matrix/client/v3/profile/{user}                     profile (no auth)
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
