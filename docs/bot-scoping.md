# Scoping a bot

What "decide what this bot can reach when you create its token" turned out to
be, once the existing permission model was read carefully: **one grant that was
being handed out for free**, and a read endpoint so a UI can author the rest
without reimplementing the permission algorithm.

Status: the server side is done on `feat/bot-scoping` (protocol and server).
The Bots tab is not built — §7 is the contract it needs. §8 is the list of
things this deliberately does not do, and why each one is not an oversight.

---

## 1. The question

> "when we create a bot token, we can decide whether to give it a list of server
> members, channels, categories they can/can't access, etc? [...] it should
> update the existing permissions model which should be expanded for it. Don't
> increase complexity with the system, just build on what we have."

The binding constraint is the last sentence, so the first job was to establish
what the existing model can already express. Three of the four axes turned out
to have very different answers.

---

## 2. What the model could already say

### 2.1 Channels: already expressible, and already enforced

A per-channel override is a `bsfchat.channel.permissions` state event whose
`state_key` is `role:<id>` **or `user:<mxid>`** (`protocol/MatrixTypes.h`), and
`PermissionsEngine::compute()` applies the user-specific one last, after the
role overrides, as `(perms & ~deny) | allow`. A bot is an ordinary user account
with a reserved localpart, so `user:@bot_weather:…` has always been a legal
override target. `docs/bots.md` §8 has recommended exactly this since bots
landed.

Enforcement was already there too, and not in one place — every path that
matters asks `PermissionsEngine` at room scope:

| Path | Asks |
| --- | --- |
| `/rooms/{id}/messages`, `/state`, `/state/{type}`, `/members` | `kViewChannel` (via `can_read_room`) |
| `/rooms/{id}/send/...` | `kViewChannel`, then `kSendMessages` |
| `/sync` | `SyncEngine` filters `rooms.join` by `kViewChannel` |
| `/joined_rooms` | `visible_joined_rooms()` |
| `/bsfchat/channels` | `can_view_room()` per entry |
| voice join / roster / token / rekey | `kViewChannel` |
| `/typing`, `/read_marker`, `/notify_level` | `kViewChannel` |
| media download | a room the caller may view that carries the media |

So the answer to "is what is missing enforcement, or only a UI?" is: **neither,
quite.** What was missing was the *default*. See §2.4.

### 2.2 Categories: not expressible, and the gap is real but small

Categories are rooms (`bsfchat.room.type = "category"`), so they can carry
overrides — and those overrides do nothing useful, because **nothing
propagates**. `compute()` reads `get_channel_overrides(room_id)` for exactly the
room it was asked about; there is no parent lookup anywhere in the engine. A
deny on a category hides the category node from a sidebar and leaves every
channel inside it untouched.

That is a genuine gap in the model, and it is deliberately **not** closed here.
See §8.2: under default-deny it stops being a security question and becomes a
convenience one, and the safe version of the convenience belongs in the write
the tab performs, not in the engine.

### 2.3 Members: NOT an axis that falls out of channel visibility

The tempting reading is "a bot that cannot see a channel cannot see its
members, so member scoping is channel scoping". The first half is true —
`/rooms/{id}/members` goes through `can_read_room()`, which is membership
**and** `kViewChannel`. The second half is false, for a reason specific to this
server:

```cpp
// SqliteStore::get_room_members
"SELECT user_id, membership FROM room_members WHERE room_id = ?"
```

No predicate. And `docs/membership-vs-visibility.md` is about why that matters:
every channel here is created `visibility="public"`, auto-join force-joins every
human into every one of them, and `backfill_auto_join` re-creates those rows at
every boot. So **the member list of any channel is the member list of the whole
server**, and letting a bot into one channel discloses every account on the
instance.

There are three more routes to the same information, none of them channel-shaped:

* `GET /profile/{userId}` and its variants need a bearer token and nothing else.
  Any account that can guess or learn an id gets a display name and an avatar.
* `GET /bsfchat/permissions/{userId}` is gated on a *shared channel the caller
  may view*, or `MANAGE_ROLES` — so it is closed to a default-deny bot, but it
  opens for any channel the bot is granted, and that channel's roster is
  everybody.
* `/sync`'s presence pass aggregates member ids across the caller's visible
  rooms into a flat global map.

So "a list of members this bot may access" is a **new axis**, not a projection
of the channel one, and it is the one thing asked for that this change does not
build. §8.1 says why building it would have been worse than not.

### 2.4 The default was the whole problem

`bootstrap_roles` assigns `["everyone"]` to any account without an assignment,
and `handle_create_bot` called it. So a bot arrived holding `kEveryoneDefault` —
`VIEW_CHANNEL | SEND_MESSAGES | ATTACH_FILES | EMBED_LINKS | CHANGE_NICKNAME |
ADD_REACTIONS` — on every channel on the server. Bots are excluded from
auto-join, which limits what arrives in their `/sync`, but not what they may
reach: every channel carries `join_rule: "public"` including the private ones,
so a bot could let itself into any of them with one POST and then read and post,
because it held the permissions to.

And **nothing an operator wrote could take that back**, short of a deny override
on every channel individually, re-applied by hand to every channel created
afterwards. A role only ever ADDS bits; there is no assignment, on any account,
that subtracts something `@everyone` already grants. That is why "this bot may
see these three channels and nothing else" was not a sentence the permission
model could say — not because the channel machinery was missing, but because
the floor was above the ceiling.

A default-deny bot with explicit grants is therefore very nearly the whole
feature, which is the conclusion this document was willing to reach.

---

## 3. The change

**A bot does not inherit the implicit `@everyone` role.**

`permission::inherits_everyone_role(user_id)` in the protocol; consumed in
`resolve_user_roles()` and in `compute()`'s un-bootstrapped fallback. That is
the rule. Everything else follows from it or protects it:

* **`@everyone` becomes an ordinary role for a bot** — still assignable, by id,
  like any other. "Let this bot behave like a member" remains available; it just
  has to be said on purpose. This is also why the upgrade is invisible: every
  bot on a running server already holds `["everyone"]` explicitly, written by
  `bootstrap_roles` when it was created.
* **A bot's scope is then the two things the model already has.** Roles for
  server-wide permissions, `user:<bot id>` channel overrides for channels. No
  new concept, no new table, no second evaluation path. `PermissionsEngine`
  remains the one authority and is unchanged apart from the rule above.
* **Creation writes an explicit empty assignment** through
  `write_server_scoped_state`, so the scope is audited from the first moment,
  mirrored to clients, and shaped exactly like a human's.
* **`bootstrap_roles` no longer assigns to bots.** It runs at every boot; without
  the exclusion it would undo an operator's scoping overnight — the same shape
  as `backfill_auto_join` re-joining bots to every channel.
* **A one-time backfill** (`migration.bot_explicit_everyone`) writes
  `["everyone"]` for any existing bot with no assignment *document*, so a
  deployment upgrading across this change sees no behaviour change at all. Keyed
  on the document's existence rather than on the role list, because
  `get_member_role_ids()` returns an empty vector both for a bot that predates
  scoping and for one created since, whose assignment is legitimately empty —
  confusing the two would un-scope every new bot at the next restart.
* **A bot cannot self-assign a role.** §6.1.

Deliberately keyed on the user id rather than on `users.kind`: the `bot_`
namespace is closed on every account-creation path (registration refuses the
prefix, OIDC auto-create mints `oidc_`, bot creation requires it), so a real bot
always classifies as one — which is the direction that matters. The failure this
must not have is a bot quietly keeping the default.

---

## 4. What a scoped bot can and cannot do

With an empty assignment and no overrides, a bot holds `0x0` everywhere. It can
still authenticate, call `/whoami`, read its own permissions, and `POST /join`
on a public channel — joining is not refused, because membership is not a
permission on this server. It gains nothing by it: every read, write, voice and
media path asks `PermissionsEngine`, so the join produces a membership row and
an empty `/sync`.

**That shape was a silent dead end and is now a loud one.** See §10: the design
is unchanged, but nothing between "bot created" and "403 about a channel" used
to state it, so the first operator to run the obvious sequence lost an hour to
it. The join still succeeds and must.

Grant it a channel:

```http
PUT /rooms/{roomId}/state/bsfchat.channel.permissions/user:@bot_weather:chat.example.com
{"allow": "0x4003", "deny": "0x0"}
```

`VIEW_CHANNEL | SEND_MESSAGES | ADD_REACTIONS` in that one channel, and nothing
anywhere else. Grant it a server-wide capability the ordinary way, with a role:

```http
PUT /rooms/{roomId}/state/bsfchat.member.roles/@bot_weather:chat.example.com
{"role_ids": ["moderation"]}
```

---

## 5. What was rejected

### 5.1 A role minted per bot

The obvious design, and the one this work started from: create a role with each
bot, positioned below its creator, holding nothing, and let the Bots tab edit
it. It adds no new concepts — roles and overrides — and inherits rank, audit and
the client mirror for free.

It was rejected because **it does not solve the problem.** A per-bot role can
only add permissions, and `@everyone` is OR'd in regardless, so a bot whose own
role holds nothing still has `VIEW_CHANNEL` and `SEND_MESSAGES` everywhere.
Something has to subtract `@everyone`, and no role can. Once `@everyone` is
withheld, the per-bot role has no work left to do that an ordinary role
assignment does not already do.

It also costs more than it looks:

* **Roles are a shared, ranked, server-wide vocabulary.** One per bot makes the
  list grow without bound, and every surface that renders roles — the member
  sidebar's hoisting, the role picker, mention targets, the roles page — has to
  learn to hide a class of them.
* **`limits::kMaxRoles` is a hard cap shared with human roles.** Bots would eat
  an operator's budget.
* **Lifecycle.** Deactivation would have to delete the role, and
  `handle_delete_role` sweeps every account on the server to strip the dead id.
  That is real machinery to maintain in exchange for nothing.

### 5.2 A bot-scoping table

A `bot_channel_access` table, checked by the bot endpoints. Rejected on sight:
it is the second authorization system the request explicitly ruled out, it would
be consulted only by the paths that remembered to, and `membership-vs-visibility`
is four pages on what happens when a second source of truth about access exists
beside the permission engine.

### 5.3 A write endpoint for grants

`PUT /bsfchat/bots/{id}/access/{roomId}` would be convenient and is not built.
The state routes already do it, already audit it
(`audit_channel_override_change`, `write_server_scoped_state`), and already
carry the rank and containment rules. A second way to author the same state is
the one that ends up missing a rule.

The consequence is worth stating plainly rather than treating as a gap:
**`MANAGE_BOTS` alone cannot grant a bot access to anything.** Letting a bot
into a channel takes `MANAGE_ROLES` in that channel, which is the same authority
it takes to let a person in. An operator who may mint credentials but may not
hand out channel access is a coherent and probably desirable split.

---

## 6. Adversarial review

This project has shipped privilege escalations before — a permission put on a
role the actor did not hold, a demotion performed by repositioning — and a
scoping system that can be escaped is worse than none, because it will be
trusted. Every way out that was found:

### 6.1 Self-assignable roles — closed

`POST /bsfchat/self_roles/{roleId}` is the one path that grants a role with no
rank check and no `MANAGE_ROLES`. It pays for that bypass with the containment
rule: a self-assignable role's permissions must be a subset of `@everyone`'s.
For a person that is the right trade. For a bot it was **the entire scoping
boundary**, because `@everyone`'s permissions are precisely the set a scoped bot
was denied — one request against any opt-in role and a scoped bot is back to
member-level access on every channel, using nothing but the token it already
holds.

`may_self_assign_role()` now refuses bot actors first, in both directions
(removal too: a role can carry channel DENY overrides, so "muted" is a role).
Refused by account kind rather than by making opt-in roles bot-proof, because
the roles are not the problem — there is no human behind the token to click one.

### 6.2 The un-bootstrapped fallback — closed

`compute()` returns `kEveryoneDefault` when the server has no roles and the
account has no assignment, so a fresh deployment is usable before bootstrap
runs. That is the one place the default grant is handed out with no document to
read it from, which makes it the most dangerous corner of the rule rather than
an exception to it. It now returns `0` for a bot.

### 6.3 The boot sweep — closed

`bootstrap_roles` grants `@everyone` to any account without an assignment, at
every boot. Left alone, the server would have quietly undone every operator's
scoping at the next restart.

### 6.4 The `@everyone` channel override still applies to a bot — accepted

`compute()` applies the `role:everyone` override unconditionally, to everyone,
whether or not they hold the role. It is a statement about a **channel** ("this
one is open to everybody"), not about who holds which role, so the behaviour is
kept. The consequence: a channel carrying an explicit `role:everyone` ALLOW of
`VIEW_CHANNEL` is visible to a scoped bot.

Accepted, because it is not an escalation: writing that override takes
`MANAGE_ROLES` in that channel, and anyone holding it could equally write
`user:<bot>` ALLOW. Nothing on this server writes such an override by default —
`handle_create_room` emits no channel permissions at all, and making a channel
private writes a DENY — so a default-deny bot really is denied everywhere on a
normal deployment. It is documented because the assumption "default-deny means
absolutely deny" would otherwise be made by the next reader.

### 6.5 ADMINISTRATOR still means everything — deliberate

A bot assigned a role carrying `ADMINISTRATOR` short-circuits to `kAllFlags`,
before overrides, exactly as a person does. Pinned by a test that denies the bot
`kAllFlags` by name in a channel and asserts it gets in anyway. Making
`ADMINISTRATOR` weaker for bots would be a bot-flavoured special case inside the
evaluation, which is the thing this design is trying not to have.

### 6.6 Channel overrides have no containment rule — pre-existing, reported

Writing `bsfchat.channel.permissions` requires `MANAGE_ROLES` **at room scope**
and nothing else. There is no "you cannot grant an override a permission you do
not hold yourself" — the rule `may_edit_role_definitions` enforces for role
documents — and no rank check against the override's target. So a delegated
`MANAGE_ROLES` holder in one channel can write themselves, or a bot, an ALLOW of
any bit in that channel.

This predates bot scoping and applies to humans identically. It is bounded:
server-scoped acts were already moved out of room scope (`is_server_scoped`,
`is_room_type_change`, `is_server_wide_media_setting`), so the blast radius is
the one channel the actor already administers. It is **not** an escape from bot
scoping, because the person writing the grant holds the authority that channel
requires. Recording it here because "grant a bot a channel" is now a routine
gesture on that route, which makes it worth hardening on its own branch:
containment plus a rank check against `user:<target>` overrides.

### 6.7 Client-side drift — a client follow-up, not closed here

`client/src/util/PermissionMath.cpp` mirrors the evaluation, and
`ServerConnection::permissionsFor(sender, roomId)` calls it for **other**
accounts — the mention path asks whether a sender holds `MENTION_EVERYONE`. That
mirror does not know this rule, so it computes too-high permissions for a bot
sender. The failure is cosmetic (the client would render a bot's `@everyone` as
a live ping that the server had already refused to deliver), but it is drift in
the direction that has bitten before. The mirror carries its own copy of every
constant by design, so the fix is a two-line rule in `PermissionMath` beside the
others, with `permission::inherits_everyone_role` cited as the authority.

---

## 7. What the Bots tab needs from the API

Everything below already exists on this branch. No further server work is
required to build the UI.

### Read — one call per bot

```http
GET /_matrix/client/v3/bsfchat/bots/{userId}/access
```
```json
200 {
  "user_id": "@bot_weather:chat.example.com",
  "deactivated": false,
  "role_ids": ["moderation"],
  "server_permissions": "0x0080",
  "can_view_any_listed_channel": true,
  "channels": [
    {"room_id": "!cat:…", "name": "Team", "type": "category",
     "joined": false, "permissions": "0x0"},
    {"room_id": "!rel:…", "name": "releases", "type": "text",
     "category_id": "!cat:…", "joined": true, "permissions": "0x4003",
     "override": {"allow": "0x4003", "deny": "0x0"}},
    {"room_id": "!gen:…", "name": "general", "type": "text",
     "category_id": "!cat:…", "joined": false, "permissions": "0x0"}
  ]
}
```

| Field | Notes |
| --- | --- |
| `role_ids` | The assignment as stored — the editable document. Does not include `@everyone` unless it was granted explicitly, which for a bot is now meaningful. |
| `server_permissions` | What that amounts to at server scope, `ADMINISTRATOR` already short-circuited into `kAllFlags`. Render "this bot is an administrator" from this, not from the role list. |
| `can_view_any_listed_channel` | The headline. True when the bot holds `VIEW_CHANNEL` in at least one channel below. `false` is "this bot has been minted and never granted anything", which is the state the tab has to make impossible to miss — everything else on the page is a detail of it. Computed over the listed channels, so it inherits the caller-visibility caveat. |
| `channels[].permissions` | The bot's **effective** mask in that channel, from `PermissionsEngine`. The number to render the row from. |
| `channels[].override` | Present **only** when a `user:<bot>` override exists. Absent is a third state, distinct from `allow=0 deny=0`, and is where "revoke this grant" should land. |
| `channels[].joined` | The **bot's** membership, not the caller's. A bot must be in a channel to post in it, so a tab that has just granted `VIEW_CHANNEL` still has to say it is not in there yet. |
| ordering | Render order, as `/bsfchat/channels`: top-level entries in the operator's arrangement, each category immediately followed by its own channels. Do not sort it. |

Gated on `MANAGE_BOTS` at server scope **plus the rank rule** — the same
`authorize_bot_admin` that rotation and deactivation use, so a bot ranking at or
above the caller is refused and a non-bot id is a 404 identical to a bot that
does not exist. The channel list is filtered by the **caller's** own
visibility, so the answer can legitimately be partial; do not present it as "the
channels on this server".

### Write — the routes that already exist

Grant or revoke a channel (`MANAGE_ROLES` **in that channel**):

```http
PUT /_matrix/client/v3/rooms/{roomId}/state/bsfchat.channel.permissions/user:{botUserId}
{"allow": "0x4003", "deny": "0x0"}
```

Change server-wide roles (`MANAGE_ROLES`, rank-checked):

```http
PUT /_matrix/client/v3/rooms/{roomId}/state/bsfchat.member.roles/{botUserId}
{"role_ids": ["moderation"]}
```

Two things for the UI to get right:

1. **`MANAGE_BOTS` does not imply either of these.** A caller who can see the
   Bots tab may not be able to edit any grant on it. Gate the controls on the
   same permissions the server will, per channel — the tab already re-evaluates
   on `permissionsGeneration`.
2. **Revoking a grant means clearing the override, not writing `allow: 0`.** The
   route has no DELETE; writing `{"allow":"0x0","deny":"0x0"}` is the closest
   available and leaves an inert event behind, which is why `override` is
   reported as present-or-absent rather than as a pair of numbers.

A "give this bot member-level access" affordance is `role_ids: ["everyone"]`.
Worth offering explicitly, because it is the shape every bot created before this
change already has.

---

## 8. Not built, on purpose

### 8.1 A member allowlist

Asked for, and deliberately absent. It cannot be expressed in the existing model
— it is a per-principal ACL over user ids, which is neither a role nor an
override — so building it means building the second authorization system the
request ruled out. And it would not work:

* Every channel's member list is the whole server (§2.3), so the union a bot can
  reach is all-or-nothing whatever the list said.
* `/profile/{userId}` needs only a token. A bot filtered out of a member list
  still resolves any id it has ever seen in a message, a mention or an audit
  record.
* `/sync` presence, mention fan-out, and `/bsfchat/permissions/{userId}` each
  reach members by a different route, none of which consults such a list.

A filter that catches one of four routes is worse than no filter, because the
operator who configured it believes the other three are closed.

**The honest fix is the one `membership-vs-visibility.md` already recommends**
and defers: stop modelling private channels as public-rooms-plus-override, so
that a `room_members` row means access. Then a channel's member list is the
people who may actually be in it, and "which members may this bot see" becomes a
consequence of channel scoping rather than a separate axis. Until then, the
truthful statement for the UI is: *a bot can see every account on this server;
channel scoping controls what it can read and where it can act, not who it knows
about.* Do not offer a control that implies otherwise.

### 8.2 Category inheritance

Overrides do not propagate from a category to its channels (§2.2), and this
change does not make them. Adding inheritance to `compute()` would change the
meaning of every existing category override on every deployment, for every
account, to fix a convenience — and the engine is the one component that must
stay small.

Under default-deny the convenience is safe to do at **write** time instead: "let
this bot into this category" is a fan-out that writes a `user:<bot>` override on
each channel currently in it. A channel added to the category later is simply
not covered, which under default-deny means the bot cannot see it — the failure
is closed, and visible in the very table the tab renders. That is a tab feature,
not a server one, and it is why the access report carries `category_id`.

The same fan-out under the old default would have failed **open**, which is why
this ordering matters.

### 8.3 Making an invite grant access

`docs/bots.md` calls inviting a bot "the normal gesture", and inviting one joins
it outright. Under default-deny that gesture no longer produces a working bot on
its own: membership is not access here, so the invite has to be accompanied by a
channel grant, and the grant should come **first** — a bot with no `VIEW_CHANNEL`
cannot see the channel in `/sync` and so does not even observe its own join.

Making `/invite` write the `user:<bot>` override was considered and rejected.
Writing an override is `MANAGE_ROLES` in that channel; inviting is not. Folding
the grant into the invite would be a second path that authors channel
permissions without the authority channel permissions require, which is the
exact shape of the escalations this codebase has already shipped twice. The Bots
tab can perform both in one click — that is a UI affordance, not a server rule.

`tests/e2e/e2e_bots.sh` asserts both halves in order, against the real binary:
granted-but-not-joined cannot post, and invited-after-granting can.

### 8.4 Cleanup on deactivation

Deactivation revokes every token and makes the bot leave its rooms. It does not
strip the bot's role assignment or its channel overrides, and should not: the
account can never authenticate again, and its localpart is reserved forever, so
the grants are inert. Leaving them means the access report still explains what a
deactivated bot used to be allowed to do, which is what an operator reading an
audit trail wants. Rotation changes credentials, not identity, so scope survives
it — as it must, or every rotation would silently break an integration.

---

## 9. Tests

`tests/test_bot_scoping.cpp`, eighteen tests. Nine of the thirteen scoping tests
were confirmed failing before the change; the four that passed are the controls,
and they are the half that would hurt — an ordinary member is unchanged
(including one whose assignment does not *name* `@everyone`, which is what makes
it implicit), an explicit `@everyone` reproduces today's behaviour exactly, a
role still grants server-wide, and `ADMINISTRATOR` still short-circuits for a
bot. Two assertions in `tests/test_bots.cpp` moved with the behaviour and say so
in place.

`tests/e2e/mutate_botscope.py` puts the old behaviour back one guard at a time —
sixteen mutations, including **both** directions of the `@everyone` rule, since
"the bot has no permissions" passes just as well on a server where the
permission system is broken for everybody. 16/16 detected.

§8 of `tests/test_bot_scoping.cpp` was added later and tests the SEQUENCE rather
than the rule: create, token, join, post, through the real handlers, which
nothing covered. See §10. Its controls are the two directions of the wrong
explanation — a human denied in one channel, and a scoped bot denied in one
channel, must both keep the channel-shaped refusal. `tests/e2e/e2e_bots.sh` runs
the same sequence against the real binary, including the join warning and the
refusal's classification.

Expectations are derived from protocol constants throughout, never from what
`auth/Permissions.cpp` computes.

---

## 10. The dead end this left behind (2026-09-24)

Scoping was right. The onboarding was not, and the two are easy to confuse, so
this section is the record of the difference.

### What happened

An operator ran the obvious sequence against `test.bsfchat.com`, current `main`:

| # | Request | Answer |
| --- | --- | --- |
| 1 | `POST /bsfchat/bots` | `201` — bot created |
| 2 | `POST /bsfchat/bots/{id}/token` | `200` — token issued |
| 3 | `POST /rooms/{room}/join` as the bot | `200` — **joined** |
| 4 | `PUT /rooms/{room}/send/m.room.message/{txn}` | `403 M_FORBIDDEN "No access to this channel"` |

Every step reported success until the last one, and the last one named the
**channel**. The channel was fine. The cause was `bsfchat.member.roles` being
`{"role_ids": []}` — §3, working exactly as designed.

### What was NOT the fix

Giving a new bot `@everyone` at creation. That is the behaviour §2.4 removed and
§5.1 explains cannot be un-removed selectively: a role only ever ADDS, so a bot
that inherits `@everyone` cannot be scoped down afterwards without a deny
override on every channel, re-applied by hand to every channel created later.
The whole feature is that the floor is below the ceiling. Nor was it the docs:
`docs/bots.md` §8 already said "Do not read a successful join as access", in
those words, before any of this.

What was missing was that **the server never said it at the moment it mattered**.
Four requests reported success and meant three, and the one refusal pointed at
the wrong noun.

### What changed

Nothing in the permission model. Four statements, on paths that already existed:

* **`POST /bots` declares the scope it just wrote** — `role_ids` (read back out
  of the assignment, not hardcoded) and a `bsfchat.warning` sentence. §1 of
  `docs/bots.md`.
* **The join warns on its own 200.** `bsfchat.warning` again, and the server log
  line changes with it, because "User X joined room Y" was the other thing that
  read as success. The join is not refused — §4 depends on it succeeding.
* **The refusal names the account.** `no_channel_access()` in
  `src/api/ChannelAccessRefusal.h` builds the body for all eight handlers that
  answer "you are in this room and may not see it", and where the cause is a bot
  holding nothing it says so and carries `BSFCHAT.BOT_NOT_SCOPED`. The ordinary
  case keeps its sentence and gains `BSFCHAT.NO_VIEW_CHANNEL`.
* **The access report answers the question in one field** —
  `can_view_any_listed_channel`. It could always be derived from the body; now
  it does not have to be.

The predicate is `!inherits_everyone_role(id) && assignment is empty`, and the
conjunction is load-bearing: a **human** with an empty assignment document still
holds `@everyone` implicitly (§3), so "this account has no roles" would be a
false explanation and would send them to the wrong page. `test_bot_scoping.cpp`
§8 pins both directions.

### What is still open, and it is a client change

`GET /bots/{id}/access` is not called by anything. The Bots pane in Server
Settings (`client/qml/components/BotManagerPane.qml`) creates, lists, rotates and
deactivates, and says nothing about access — so the tab §7 was written for is
still not built, and an operator standing in front of the pane that made the bot
has no indication that it needs a grant or where to perform one. A grant is
reachable today only indirectly: add the bot to a channel, then assign it a role
from the member-list context menu. The finest-grained grant the server
supports — a `user:<mxid>` channel override — has no UI at all, although
`MatrixClient::setChannelOverride` already accepts the key.

Also client-side: `bsfchat.errcode` is parsed nowhere
(`client/src/net/MatrixFailure.h` drops every field but `errcode`, `error` and
`retry_after_ms`), and the QML toasts that render a failed state write replace
the server's sentence with "you don't have permission" on any 403. Until that
changes, the prose is the only part of this that reaches a person through the
client, which is why the prose carries the explanation and not only the code.
