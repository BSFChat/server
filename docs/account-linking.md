# Account linking, and the three accounts on production

## The problem

An `m.login.token` sign-in derives a user id from the identity provider's `sub`
claim — `@oidc_<sanitised sub>:server` — and creates that account if it is
missing. Nothing relates it to the local account the same person already had.

On the production deployment one human owns three accounts:

| user id | how it signs in | display name | roles |
| --- | --- | --- | --- |
| `@josh:chat.bsfchat.com` | password | josh | `@everyone`, `admin` |
| `@oidc_a5cdbefe-…:chat.bsfchat.com` | BSFChat ID | josh | `@everyone` |
| `@oidc_76ea6af7-…:chat.bsfchat.com` | BSFChat ID | joshb | `@everyone` |

Nothing in the client says they are the same person, and nothing in the server
says they are different people either — they are simply three unrelated
accounts. Roles, DMs and history do not follow the human between them, which is
how the owner of the server ended up signed in with no permissions and no way
to reach Server Settings. (The lockout itself is the other half of this work;
see `src/cli/AdminCli.h` on the `feat/admin-recovery` branch.)

## What was built

A `linked_identities` table (schema v28) keyed on `(issuer, subject)`, and one
endpoint that writes to it:

```
POST /_matrix/client/v3/bsfchat/account/link_identity
Authorization: Bearer <token for the account that will survive>
{ "type": "m.login.token", "token": "<id_token for the identity>" }
```

The request is authenticated **twice over**, and that is the whole security
argument: the bearer token proves control of the surviving account, the
id_token proves control of the identity. Neither alone attaches anything, so
merely *asserting* an identity — naming a subject, presenting a token this
server cannot verify — can never claim somebody else's account. Both halves are
credentials that already sign their own side in, so holding both is exactly the
claim being recorded: one person, two logins.

After a link, `m.login.token` for that identity resolves to the linked account
before any `oidc_*` id is derived. Unlinked identities behave exactly as before.

`GET /_matrix/client/v3/bsfchat/account/linked_identities` returns the caller's
own links — issuer and date only. The subject never leaves the database, and
there is no way to ask about another account: "which identity-provider account
is @josh?" is not a question one member gets to ask about another.

### What happens to the abandoned account

Nothing is deleted, ever.

* **Its user id stays taken.** The `users` row is untouched, so the id can
  never be recycled to anybody else. This matters more than it looks: the id
  embeds the provider subject, so a recycled one would let a later account
  inherit the appearance of this person's history.
* **Its messages stay where they are**, under its own sender id. They are
  deliberately *not* rewritten to the surviving account. A rewrite would forge
  history — it would make the surviving account appear to have said things it
  never said, in rooms it may never have been in — and it would have to touch
  every event, redaction, read marker, mention and push record naming the old
  sender. Old messages keep showing the old name. That is honest, and it is
  what comparable products do.
* **Its live sessions are revoked.** After the link the person has one account;
  a still-valid token for the other one is a session they did not ask to keep,
  and on a shared or lost device it is one nobody would think to end.
* **It stops being a way to sign in.** The identity now resolves through the
  link table, and the account has an empty password hash, so no
  `m.login.password` will ever authenticate it either.
* **It is not re-pointable.** A link is an insert, never an update. Moving an
  identity onto a different account would take the sign-in route away from an
  account whose owner may no longer be in the room to object, so there is no
  code path that does it.

### Nothing is backfilled

The v28 migration creates the table and stops. An existing `@oidc_<sub>` account
*could* be matched to its subject by reversing the localpart sanitiser, and
linked automatically — but choosing which local account to link it to would be a
guess, and the only available evidence is the display name. That evidence is
worthless here: on production "josh" and "joshb" are the same person, while on a
server of any size two accounts sharing a display name usually are not. A wrong
guess merges two people's histories, roles and DMs, and there is no undo.

So linking is always an act by the account owner, proving both sides.

## Migrating the three production accounts

**Nothing here has been run. Do not run it against production without reading
the whole section first.** The server upgrade itself is the normal procedure in
`reference_prod_host`; this is only what to do afterwards.

### Decide which account survives

`@josh:chat.bsfchat.com`. It holds `admin`, it is the id people recognise, and
it is the one with a password — so it stays reachable if the identity provider
is ever down, which the `oidc_*` accounts are not.

### Link the identity that is actually used

The owner, **signed in as `@josh` with a password**, obtains an id_token from
BSFChat ID for the identity behind `@oidc_a5cdbefe-…` (the one displaying
"josh"), and POSTs it to `/account/link_identity`. From then on, signing in
with BSFChat ID lands in `@josh`, with admin.

There is no client UI for this yet (see *Deferred* below), so today this is one
`curl` by the owner with their own two credentials — not an operator action, and
specifically not a database edit. The whole point of this work is that the
recovery for a broken account is no longer "hand-write rows over SSH".

### The second identity

`@oidc_76ea6af7-…` ("joshb") is a *different* identity at the provider — a
second BSFChat ID account, not a second session of the first. Two options, and
the owner picks:

1. **Link it too.** The table allows several identities per account, so both
   BSFChat IDs would sign in as `@josh`. Do this if both provider accounts are
   genuinely theirs and both will keep being used.
2. **Leave it.** It keeps its messages and its user id and simply stops being
   signed into. Do this if the second provider account was a mistake.

Either way its history stays put and its id stays taken.

### Verifying afterwards

* `GET /account/linked_identities` as `@josh` lists one entry per link.
* Signing in with BSFChat ID returns `user_id: @josh:chat.bsfchat.com`.
* The audit log has one `account.link` record per link, naming the issuer and
  the superseded account. It does **not** record the subject as a claim of its
  own; see `audit_action::kAccountLink` for why the superseded user id is
  recorded even though the subject is legible from it.
* The old accounts still appear in old messages. That is correct, not a bug.

### If it goes wrong

There is no unlink endpoint yet (see below). Until there is, the recovery is a
deliberate, visible `DELETE FROM linked_identities WHERE …` by the operator,
with the server stopped — the identity then mints or reuses its `oidc_*` account
exactly as it did before, because nothing about that account was destroyed. That
is the reason nothing is destroyed.

## Deferred, and why

* **Unlinking.** Needs a decision this work did not want to make blind: an
  unlink is how a stolen session detaches the real owner's identity from their
  own account, so it needs re-authentication and probably a notification, and a
  notification path does not exist. Until then the operator does it by hand,
  which is rare, visible and reversible.
* **Linking in the other direction** — keeping the `oidc_*` account and
  attaching a *local* account to it. The abandoned id would then be the nice one
  (`@josh`), which is the opposite of what anyone wants, and it also means
  deciding what "the password for this account" now means. Out of scope until
  somebody actually asks for it.
* **Client UI.** The endpoints are done; the settings screen that calls them is
  not. This is the largest remaining gap for an ordinary user, who cannot be
  expected to `curl`.
* **Merging content.** Deliberately never: see "its messages stay where they
  are" above.
