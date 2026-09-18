# Auth, registration and abuse-control audit — September 2026

Scope: the registration and authentication path (`api/AuthHandler`, `auth/LocalAuth`,
`auth/OidcAuth`, `http/Middleware`, `http/ClientAddress`, the `access_tokens` schema and its
v7 hashed/expiring migration, and the `[auth]` limits block), plus the abuse surface past
authentication (`api/EventHandler`, `api/MediaHandler`).

Branch: `harden/auth` in both `server/` and `protocol/`. Tests went 621 → 654 (unit), and the
e2e scripts pass.

**The two repositories must land together.** See [Production notes](#production-notes).

---

## Summary

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Access and refresh tokens had 32 bits of entropy, not 256 | **Critical** | Fixed (protocol) |
| 2 | `/login` timing enumerates accounts | **High** | Fixed |
| 3 | No refresh-token reuse detection | **High** | Fixed (schema v19) |
| 4 | `/send` applied no permission gate to any type but `m.room.message` | **High** | Fixed |
| 5 | No rate limit on send, redact or media upload | **Medium** | Fixed (`[limits]`) |
| 6 | Transaction ids scoped too widely: cross-room and cross-device collisions | **Medium** | Fixed (schema v20) |
| 7 | Reaction targets unvalidated | **Medium** | Fixed — *shape decision pending, see below* |
| 8 | Password policy was a length floor only | **Medium** | Fixed |
| 9 | `device_id` unvalidated and unbounded | **Medium** | Fixed |
| 10 | A password change could be a no-op that still revoked every session | **Low** | Fixed |
| 11 | `trusted_proxies` accepts a public network silently | **Low** | Fixed (startup warning) |
| 12 | Three profile endpoints return JSON `null` for a fresh account | **Medium** | Fixed elsewhere |
| 13 | `sanitize_localpart` collisions / impersonation | — | **Not a real issue** |
| 14 | Reserved-name list incomplete or unenforced on the OIDC path | — | **Not a real issue** |
| 15 | Token and password comparisons not constant-time | — | **Not a real issue** |
| 16 | Session invalidation gaps (password change, logout-all, ban) | — | **Not a real issue** |
| 17 | `X-Forwarded-For` spoofing when `trusted_proxies` is unset | — | **Not a real issue** |
| 18 | Account enumeration through `/register` | — | Partly unavoidable, **not fixed** |
| 19 | Auth events absent from `AuditLog` | — | **Not fixed, by design** |
| 20 | Localpart homoglyph impersonation (`l`/`1`, `0`/`o`) | Low | **Not fixed — needs a decision** |
| 21 | Reactions have no dedup | Low | **Not fixed — needs a decision** |
| 22 | `/redact` parses a txn id and ignores it | Low | **Not fixed** |

---

## Fixed

### 1. Access and refresh tokens had 32 bits of entropy — CRITICAL

`protocol/src/Identifiers.cpp::random_base64()` was:

```cpp
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<int> dist(0, 63);
```

An `mt19937` seeded from a single 32-bit value produces output that is a pure function of
those 32 bits. The length of the string is irrelevant: `generate_access_token()` returned 43
base64 characters and `auth/LocalAuth.h` documented it as "~256 bits", but the token could
only ever be one of 2³² values.

This was measured rather than assumed. Recovering the seed from the first **8 characters** of
a token runs at ~930,000 candidates/second on one core of this machine, so the entire keyspace
of every token the server can ever issue enumerates in **about 1.3 hours**. Against a live
deployment that is session hijacking by spraying: an attacker needs to hit any one live token,
not a specific one, so the expected work scales down with the number of signed-in users.

It applied to refresh tokens too — the credential specifically designed to outlive a password
change — and to event, room and device ids. (`MediaHandler` already generated its own media
ids from `RAND_bytes`, so media was not affected; `generate_media_id()` in the protocol library
has no caller.)

Fixed in `protocol/` by drawing from `RAND_bytes`, the OpenSSL CSPRNG already linked there for
JWT verification. `& 0x3F` folds 256 byte values onto the 64-character alphabet exactly, so
there is no modulo bias. A `RAND_bytes` failure throws; nothing falls back.

The existing generator tests could not see this — two consecutive tokens still differed and the
length was always right. The new test uses the birthday bound: 500,000 draws from a 2³² space
collide ~29 times on average (33 when actually run against the old code) and cannot collide at
all in a real 256-bit space.

`BSFCHAT_PROTOCOL_CSPRNG_IDENTIFIERS` is defined by the fixed protocol header, and
`auth/LocalAuth.cpp` `#error`s without it. That guard is not decoration: `cmake/Dependencies.cmake`
falls back to fetching protocol `main` from GitHub when no local checkout sits beside the server,
so a green build is *not* evidence of which protocol version went in.

### 2. `/login` timing enumerates accounts — HIGH

The 403 body is deliberately identical for "no such user" and "wrong password", with a comment
explaining why. The code was not:

```cpp
auto hash = store_.get_password_hash(user_id);
if (!hash || !verify_password(login_req.password, *hash)) {
```

`!hash` short-circuits, so a login for an account that does not exist skipped PBKDF2 entirely
and returned in microseconds, while one for an account that does spent ~0.5s at the shipped
cost of 19. That is a difference you can read off a stopwatch, from an unauthenticated
endpoint, before any rate limit has been tripped — the lockout ordering that was carefully
designed not to be an oracle was sitting next to one.

An account with an empty stored hash (OIDC-backed) failed just as quickly, which additionally
advertised which accounts sign in through the identity provider.

Both paths now verify against something: `dummy_password_hash(cost)` is a cached PBKDF2 hash of
32 CSPRNG bytes at the configured cost, and the result is discarded. Tested by ratio rather
than by an absolute bound, since both measurements share whatever else the machine is doing;
before the fix the ratio was ~0.001.

### 3. No refresh-token reuse detection — HIGH

Rotation was already correct: `consume_refresh_token` deletes the row, so the old access and
refresh pair both die. What rotation alone cannot do is notice theft, and it leaves theft
profitable. If the thief redeems first, the honest client's next refresh fails, the user signs
in again — and the thief keeps a live, self-renewing session that no longer shares a secret with
anyone. Nobody is alerted; to the user it looks like an ordinary session expiry.

The standard response (OAuth 2.0 Security BCP §4.14.2) is to remember which refresh tokens have
been spent and treat a second redemption as proof the chain was copied. Schema v19 adds
`access_tokens.family_id` and a `consumed_refresh_tokens` table; a replay revokes every session
descended from that login, because at that point the two branches are indistinguishable.

Details worth knowing:

* Pre-v19 sessions each become a family of one — the rotation history that would have grouped
  them was never recorded.
* An empty `family_id` is never treated as a wildcard. It would match every row a migration
  missed and log the entire server out.
* Spent-token records are pruned after one access-token lifetime: a family that has not rotated
  in that long has no live sessions left to revoke.
* The response is the same 401 either way. A caller whose family was just revoked has by
  construction presented an invalid token, and saying more would tell an attacker probing old
  tokens which of them were once real.

### 4. `/send` applied no permission gate to any type but `m.room.message` — HIGH

Reported by the coordinator, confirmed here. The `SEND_MESSAGES`, `ATTACH_FILES` and
`EMBED_LINKS` checks all sat inside `if (evt_type == "m.room.message")`. The only authorisation
applied to anything else was `VIEW_CHANNEL`.

The consequence is larger than reactions. A member with `SEND_MESSAGES` explicitly **denied**
could post an event of **any type at all**, with arbitrary content, into the room timeline,
where it is stored and delivered to every member through `/sync` — including a type nobody has
ever defined. The comment claiming non-message types "use separate permission semantics not
worth spelling out here" is what stopped anyone looking; for reactions there were none.

Replaced with a table (`send_gate_for`), and **an unrecognised type is refused**. Allowing by
default is what produced the hole; adding a sendable type should be a deliberate edit.

| Type | Gate |
|---|---|
| `m.room.message` | `SEND_MESSAGES` (+ the existing content gates: attach / embed / mention-everyone, and slowmode) |
| `m.reaction` | `SEND_MESSAGES` |
| `m.call.invite` / `answer` / `candidates` / `hangup`, `bsfchat.call.negotiate`, `m.call.member` | `VIEW_CHANNEL` only — the same gate `VoiceHandler::handle_voice_join` applies |
| anything else | refused, 403 |

Reactions gate on `SEND_MESSAGES` because this server has no `ADD_REACTIONS` bit. Adding one is
a permissions-model change (and `Permissions.h` is being edited on `feat/bots`), not a fix for
this defect. `SEND_MESSAGES` is the conservative reading: nobody who can post text is newly
blocked, and everyone who was muted now actually is.

State events are absent from the table because they belong on `PUT /rooms/{id}/state/...`, which
has its own per-type authorisation in `RoomHandler`.

### 5. No rate limit on send, redact or media upload — MEDIUM

The brief's Part 2, and a real gap. See the new `[limits]` block in
`config/bsfchat-server.example.toml` and `core/SendLimiter.h` for the reasoning; the short
version:

* Keyed on the **account**, so ten connections do not buy ten budgets, and so one household NAT
  is not one message budget.
* Defaults far above human use — 120 sends, 60 redactions, 30 uploads per minute. This stops a
  loop; it does not pace a conversation.
* Separate counters per bucket, so exhausting one does not block the other.
* 429 `M_LIMIT_EXCEEDED` with `Retry-After` (rounded up) and `retry_after_ms`, identical in shape
  to the auth limiter's refusal — now shared in `http/RateLimitResponse.h`.
* The send check sits **after** the txn-id short-circuit (a retry of an already-accepted request
  is what we ask clients to do, and a flood is made of distinct transactions) and **before** the
  permission computation (the work worth refusing).
* Upload bounds how *many* uploads an account makes. The size of any one is
  `[media] max_upload_size_mb`, enforced while streaming by `set_payload_max_length`.

`SendLimiter` takes the identity as a string and selects a bucket by enum, so the tighter
per-bot bucket that `feat/bots` will want is one enum entry and one configured size, with no
call-site changes.

### 6. Transaction ids scoped too widely — MEDIUM

Reported by the coordinator, confirmed. `get_transaction_event(user_id, txn_id)` keyed on the
sender alone. Two silent failures:

* Reusing a txn id in a **different room** returned 200 with the *first* message's event id and
  posted nothing to the second room — indistinguishable from success to the caller.
* Two clients signed in as the same user both start their counters at 1, so the second client's
  early messages vanished into the first client's records.

Schema v20 rekeys on `(user_id, device_id, room_id, txn_id)`. Matrix scopes a txn id per access
token, which is the device; the room is ours and makes the key match the request being retried.
Pre-v20 rows are dropped rather than migrated — `device_id` was never recorded for them, so any
backfill is a guess that matches either nothing or everything. The entire cost is that a retry
in flight across the upgrade could post twice, on a server that has just restarted.

The retry-dedup property migration v6 was written for is now covered by a test, alongside the
per-room and per-device cases.

### 7. Reaction targets unvalidated — MEDIUM (shape decision pending)

A reaction names the event it annotates and that was taken entirely on trust: any string was
accepted, including the id of an event in a room the sender cannot see. The reaction was then
stored in *this* room referring to an event that is not in it.

**What is now accepted, unchanged from what the client sends:**

```json
{"m.relates_to": {"rel_type": "m.annotation", "event_id": "$...", "key": "👍"}}
```

**What is now refused:**

| Condition | Response |
|---|---|
| `m.relates_to` missing, not an object, or `rel_type` != `m.annotation` | 400 `M_BAD_JSON` |
| `event_id` empty or missing | 400 `M_BAD_JSON` |
| target event does not exist | 404 |
| target event exists but is in another room | 404 — deliberately the same answer, since "real, but elsewhere" is the confirmation being withheld |
| target event is redacted | 404 (matches how edits already treat a redacted target) |
| sender lacks `SEND_MESSAGES` | 403 |

`key` is **not** validated at all: any value, including absent or empty, is still accepted.
That was deliberate — narrowing it is a wire-shape decision.

> **This landed on the branch before the request to propose it first arrived.** It is confined
> to one block in `EventHandler::handle_send_event` in commit `e35cbf7` and can be dropped
> without touching the permission gate in finding 4. The client's `sendReaction` always sends
> all three fields and always targets an event in the room being viewed, so no existing flow is
> refused. The two behaviour changes worth weighing are that reacting to a *redacted* event now
> fails (a client would show an error toast), and that reacting to an event the server does not
> have — an optimistic local id, say — now 404s instead of silently storing a dangling reaction.

### 8. Password policy was a length floor only — MEDIUM

Eight characters and nothing else. The two rules added are the ones that pay for themselves
against how this server is actually attacked, because both defeat the *existing* lockout:

* **A password built from the username.** The attacker needs one guess, not thousands, so the
  per-account failure counter never fills.
* **A common password sprayed across many accounts.** No single account accumulates enough
  failures to trip anything.

`password_policy_error()` refuses the username (case-insensitively), any password containing a
username of 4+ characters, ~40 common passwords that survive an 8-character minimum, and the
service's own name. Deliberately not a breach corpus: that means a multi-megabyte data file to
ship and keep current, or a network dependency on HIBP. Past the first few hundred guesses, the
lockout and rate limits are the control that matters.

Applied at `/account/password` as well as `/register` — a rule that only guards the front door
is not a rule, since "register with something acceptable, then change it" is two requests.

### 9. `device_id` unvalidated and unbounded — MEDIUM

`login_req.device_id.value_or(generate_device_id())` went straight to storage. Unbounded length
on a row kept for the token's 90-day life, and arbitrary bytes — including the newlines that let
a device id forge extra lines in the server log, where it is printed next to a user id.

Bounded to 255 and refused for control characters only. Deliberately **not** a charset
allowlist: a client that has already persisted a device id containing a non-ASCII character
would otherwise be unable to log in at all.

### 10. A no-op password change still revoked every session — LOW

`new_password == current_password` is now refused, checked **after** the current password has
been proved so this does not become a password checker for whoever holds a token. Previously
such a change logged every other device out while leaving the credential the user was trying to
replace in place — the opposite of what they asked for.

### 11. `trusted_proxies` accepts a public network silently — LOW

Parsing was validated (a bad entry throws at startup) but the *meaning* was not. Trusting a
network means believing its `X-Forwarded-For`, so an entry reaching into public address space —
or something as wide as `0.0.0.0/0` — is not a loose limit but an off switch: anything inside it
picks its own rate-limit identity once per request. The symptom (limits never firing for the
attacker who matters) looks exactly like limits working.

Startup now warns, naming the entry. Warned rather than refused: an operator may genuinely run a
proxy on a public address, and failing startup over a configuration that was working would be
its own outage. Containment is the test, not overlap — `10.0.0.0/4` covers private space but is
mostly public.

### 12. Profile endpoints return JSON `null` — MEDIUM — fixed elsewhere

`handle_get_profile`, `handle_get_displayname` and `handle_get_avatar_url` build their response
with `json resp;`, which default-constructs a JSON **null**, and every assignment into it is
conditional. A user who trips no branch gets the four bytes `null` under a 200. Every freshly
registered account is in exactly that state until its owner sets a display name, so this is the
*default* response for a new user, and it breaks even defensive client code (`r.json().get(...)`
raises `TypeError` in Python, because `.json()` is `None`).

Confirmed as the complete set: the `json resp;` sites in `SyncHandler`, `EventHandler`,
`RoomHandler` and `AuthHandler` all pass through a `to_json` that populates an object
unconditionally, and `VoiceHandler::handle_turn_server` assigns a whole object on both branches.

**Fixed on another branch at the coordinator's direction; deliberately untouched here** so two
branches do not edit the same three lines.

---

## Not a real issue

### 13. `sanitize_localpart` collisions and impersonation — REFUTED

The escaping is injective, so two distinct OIDC subjects cannot produce the same localpart.
Lowercase alphanumerics and `. - /` pass through; `A-Z` becomes `_` + the lowercase letter;
*everything else*, including a literal `_`, becomes `=hh`. Because `_` and `=` are only ever
emitted as escape prefixes, the output parses back unambiguously.

The other sub-questions:

* **Case folding** — registration already restricts usernames to lowercase, so there is no case
  to fold. SQLite's default `BINARY` collation is correct here for the same reason.
* **Empty after sanitize** — registration refuses an empty username; the OIDC path refuses a
  subject that sanitizes to nothing (`localpart == "oidc_"`) and validates the assembled id with
  `UserId::is_valid`.
* **Cross-namespace collision** — sanitized output can contain `=` and `/`, which registration's
  charset excludes, and local usernames can contain `_`, which sanitization always escapes. The
  namespaces cannot meet.
* **Leading/trailing separators** — a username of `.` or `-` is accepted and is a valid
  localpart. It is ugly, not a security boundary; see finding 20 for the part that is arguable.

### 14. Reserved names — REFUTED as stated

The list (`server`, `oidc_*`) is complete for the code as it stands. `@server:<server_name>` is
the only synthetic actor `PermissionsEngine` grants `ADMINISTRATOR` to unconditionally, and the
`@room` mention sentinel cannot be registered because every real user id contains a colon.

The enforcement question resolves too, though the reasoning is worth writing down because it is
load-bearing and implicit: the OIDC auto-create path does **not** check the reserved list, and
does not need to, because everything it creates is prefixed `oidc_` and local registration
refuses that prefix. If that prefix is ever removed or made configurable, the reserved check
must move to a shared helper both paths call.

### 15. Token and password comparisons — already correct

`verify_password` compares with `CRYPTO_memcmp` after a length check, with a comment explaining
why. Tokens are never compared in application code at all: they are looked up by SHA-256 digest
as a primary key, so there is no secret-dependent comparison to leak. (The single unsalted
SHA-256 is the right choice here and `auth/LocalAuth.h` argues it correctly — *provided* the
tokens are high-entropy, which is finding 1.)

### 16. Session invalidation — already correct

* A password change revokes every other session (`delete_other_tokens_for_user`), keeping the
  one that just re-authenticated. Opt out with `"logout_devices": false`.
* `logout_all` kills refresh tokens too, necessarily: a refresh token is the `refresh_hash`
  *column* of the row its access token lives on, so there is no way to revoke one and leave the
  other.
* A server-wide ban calls `delete_all_tokens_for_user` immediately (`RoomHandler.cpp:331`), and
  `/login` re-checks the ban after password verification so the account cannot simply get a
  fresh token. `/sync` checks it as well.
* There is no account deactivation feature to have a gap.

### 17. `X-Forwarded-For` spoofing — REFUTED

`ClientAddressResolver` is carefully built. The header is read **only** when the socket peer is
in `trusted_proxies`, hops are walked right-to-left, multiple header *lines* are treated as
unknowable (because httplib's multimap does not promise order), and an unresolvable client
returns `nullopt`, which callers treat as "skip per-address limits" rather than as a shared
bucket.

With `trusted_proxies` unset behind nginx the failure mode is *degraded but safe*: the header is
ignored, every client shares the proxy's bucket, and the server warns (at most once a minute)
naming the address and the fix. The header is never trusted from an untrusted peer. Finding 11
covers the one direction that was silent — trusting too much rather than too little.

---

## Not fixed

### 18. Account enumeration through `/register`

`/register` answers `M_USER_IN_USE` for a taken username. That is unavoidable: a registration
form has to tell you the name is taken. The per-address attempt limiter (30/60s) is what bounds
it, and it deliberately counts *every* attempt, including the cheap "taken" answer, so the
tighter creation limit is not burned by someone working through a list.

One smaller leak is left in place: a banned username returns a distinct 403 "This user is banned
from this server", so an anonymous caller can learn that a given username is banned. It is
deliberate — the person it is really addressed to is the ban target trying to re-register, and
telling them why is better than a confusing "taken". Flagged rather than changed because it is a
product call.

### 19. Auth events are absent from `AuditLog` — by design

`audit/AuditLog.h` is a **moderation** log: every action it records is an act of authority by
one user over another (kick, ban, role change, channel deletion, permission override), it is
readable through `GET /audit` by anyone with the permission, and the action names are documented
as an append-only vocabulary.

Registration, password change, logout-all and lockout trips are self-service events. Putting
them in a moderator-readable log changes what that endpoint exposes — "when did Alice last
change her password" is not a moderation fact — and expands a schema whose scope is deliberately
narrow.

They are all recorded in the server log already: registration and login at info, lockouts at
warn ("Auth lockout engaged for …"), password changes with the count of sessions revoked, and
now refresh-token family revocations at warn.

**If you want a security-events log, it should be a separate sink** with its own retention and
its own access rule, not a new vocabulary inside the moderation log. That is a design decision,
not a defect, so it is not made here.

### 20. Localpart homoglyph impersonation — needs a decision

Usernames allow `[a-z0-9._-]`, which contains the classic confusable pairs: `l`/`1`, `0`/`o`,
`rn`/`m`, and three interchangeable-looking separators. `@josh` and `@j0sh` are different
accounts that look alike in a member list.

Not fixed, for three reasons. The display layer already handles the sharper version of this
problem — `identity/Nickname.cpp` validates UTF-8 strictly and rejects bidi overrides,
zero-width characters, tag characters and C0/C1 controls, and nicknames are what clients render
where they show people. A confusable-skeleton uniqueness check is a real feature (it needs a
normalisation table, a decision about what to do with the accounts that already exist, and an
answer for what a user sees when their chosen name is refused for resembling someone else's),
not a hardening pass. And it is squarely in the "speculative defence-in-depth that makes the
auth path harder to reason about" category the brief asks to avoid.

**Decision needed** if you want it: it is a registration-policy feature, sized in days not hours.

### 21. Reactions have no dedup — needs a decision

One user can react with the same key to the same event repeatedly, producing N reaction events.
The client's `MessageModel` dedups by *reaction event id*, so each one renders as a separate
reaction from the same person.

Not fixed because the correct behaviour is a product decision that reaches the client: a repeat
could be refused (409), silently ignored (200 with the existing event id), or toggle the
reaction off, which is what Discord does and what users will expect. Toggling in particular
needs the client to stop sending a redaction for un-reacting, or to keep doing so. The new send
limiter does bound the abuse in the meantime.

### 22. `/redact` parses a txn id and ignores it

`handle_redact` matches `{txnId}` out of the path and never uses it, so redaction is not
idempotent: a client retry produces a second `m.room.redaction` event for an already-redacted
target. Noted by the coordinator.

Left alone deliberately. The end state is correct either way (the target stays redacted) and the
fix is not the one-liner it looks like — it needs the same `(user, device, room, txn)` record
`/send` uses, which means deciding whether a redaction and a message may share a txn-id
namespace. Worth doing; not worth widening this branch for. The redact limiter now bounds the
duplicate events a loop can produce.

---

## Production notes

**PRODUCTION CONFIG CHANGE REQUIRED — `auth.trusted_proxies`.**
This is the one that has bitten this project before, and it is *not* introduced by this branch;
it is pre-existing and this branch only makes it louder. Production runs nginx in front of the
server, so the socket peer is the Docker bridge, not loopback. With the shipped default
(`["127.0.0.0/8", "::1"]`) the `X-Forwarded-For` nginx sets is ignored and **every client on the
server shares one rate-limit bucket** — so one abusive client can lock everyone out of `/login`.
Before deploying, `/root/bsfchat/deploy` `server.toml` needs:

```toml
trusted_proxies = ["127.0.0.0/8", "::1", "172.16.0.0/12"]
```

Confirm it by watching the log for `carries X-Forwarded-For, but that address is not in
auth.trusted_proxies` after the restart. Its absence is the signal that this is set correctly.

**Two migrations run on first start: v18 → v19 → v20.** Both are additive DDL inside the normal
transactional runner. v20 drops the `event_transactions` rows (see finding 6); nothing else is
discarded. There is no down migration — the server refuses to start against a database newer
than it understands, so **take the usual backup before upgrading and roll back by restoring it**,
not by downgrading the binary against the migrated file.

**No configuration is required for the new `[limits]` block.** Omitting it entirely gives the
documented defaults. Set `limits.enabled = false` only if something upstream enforces its own
ceiling; the server warns at startup when it is off.

**Nobody is logged out by any of this.** Existing tokens keep working and keep sliding their
expiry. They were minted by the old generator, though, so they carry the old 32 bits — see the
recommendation below.

## Recommended follow-ups

1. **Consider a one-time revocation of all access tokens after deploying finding 1.** Every token
   issued before the CSPRNG fix has 32 bits of entropy and stays valid for up to 90 days,
   sliding forward on use. The fix stops *new* weak tokens; it does not retire the existing
   ones. `DELETE FROM access_tokens;` logs everyone out once and they sign in again. Whether a
   self-hosted instance with a known user list warrants that is Josh's call — it is disruptive,
   and the attack needs sustained online spraying that would be visible in the logs.
2. **Decide on findings 20, 21 and 22**, all of which are product calls rather than defects.
3. **The `m.reaction` shape in finding 7** needs sign-off, per the note there.
4. A dedicated `ADD_REACTIONS` permission bit, if reactions should be mutable separately from
   messages. Touches `Permissions.h`, which `feat/bots` is also editing — worth sequencing after
   that branch.
