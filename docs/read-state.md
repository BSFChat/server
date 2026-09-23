# Read state across devices

Read a channel on the phone; the dot stays lit on the desktop. The unread
*count* clears, because the server derives it from the read marker, but the dot
does not, because the client computes it from a timestamp it keeps in local
settings and nothing ever corrected that timestamp.

It was never a bug in the sense of something that used to work. `/sync` carried
no account data of any kind, so nothing a user stores about themselves — their
read markers, their block list — ever left the device that wrote it. This
document is what was added and why it is shaped the way it is.

## What is on the wire

Two sections, both of them Matrix's own:

* Top-level `account_data.events` — the account's stored documents. Today that
  is `m.ignored_user_list` (the block list) and anything else a client chooses
  to PUT. `m.direct` also travels here, as it always has.
* Per-room `rooms.join.{roomId}.account_data.events` — `m.fully_read`, the
  reader's own "read up to here" for that room.

`m.fully_read`'s content is the spec's `event_id` plus one extension:

```json
{"event_id": "$abc:server", "bsfchat.origin_server_ts": 1700000000000}
```

The timestamp is there because of what the client does with it. The unread dot
is arithmetic on `origin_server_ts` (`client/src/core/ReadState.h`), and the
event a marker names is very often one the receiving device has never loaded —
the phone read the room, the desktop has a sidebar row for it and no timeline.
Resolving the id would mean a `/messages` request per room per marker, on the
one endpoint a client polls continuously, to recover a number the server had in
its hand when it wrote the row. A client that only knows the spec reads
`event_id` and ignores the rest.

## Why there is no second stream position

The obvious objection to putting account data in `/sync` is that account data
is not on the event stream, so an incremental sync has nothing to compare a
token against. The usual answer is a second position in the token — a
`next_batch` of the form `events:account_data:receipts` — and that is what this
server deliberately does not do.

Stream positions here do not come from the events table. They come from a
single persisted counter, `server_meta.next_stream_position`, claimed under the
store mutex by `SqliteStore::claim_stream_position_locked()`. An event row is
simply the commonest thing that claims one. So an account-data write claims one
too, stores it in `updated_pos`, and is thereby ordered against messages and
against other account-data writes by *the number the client's existing token
already carries*.

That buys:

* no token format change, and no migration for every token in the field;
* one ordering to keep consistent instead of two;
* the delta bounded by exactly the position `next_batch` is built from, so a
  document written after the scan is picked up by the next poll rather than
  delivered under a token that does not cover it.

The cost is that a rare, small write consumes a position out of a 64-bit
counter. That is the whole of it.

## Delta, not restatement

`m.direct` and the pending-invite list are *restated* on every delivered
response. Both are derived, small, and idempotent, and restating them is what
lets a client learn about a DM that predates its token.

Account data is not like that. It is a store the client writes into, of
unbounded size, and restating it on every poll would put the block list on the
wire every 30 seconds forever — and leave a client unable to tell a change from
an echo. So it is a delta keyed on `updated_pos`, and an empty section means
"nothing changed", not "you have no account data". A client that needs a
document it has never been told about reads it from
`GET /_matrix/client/v3/user/{userId}/account_data/{type}`; an initial sync
carries the complete set.

The one-time backfill in migration v30 exists for the same reason: rows written
before the upgrade would otherwise sit below every token forever. They are
stamped with one freshly claimed position, so each established client is told
its stored state exactly once and never again.

## Membership is not visibility

Account data is per-user, which makes it look exempt from the visibility rules.
It is not, because a read marker names a **room**.

Every account on this server is force-joined into every channel, private ones
included (`docs/membership-vs-visibility.md`), and permissions change: a user
can hold a read marker for a channel they may no longer view. Delivering that
marker would name the channel to somebody the rest of `/sync` has just decided
must not be told it exists — a per-user section turned into a channel oracle.

So room account data is gated on `room_view() == kFull`, the reading rule, not
on `!= kNone`, the listing rule that lets a category render in the sidebar. A
category stub gets a name and a sort order; a read position inside it is
contents. `SyncEngine` drops the marker rather than the room, in both the
initial and the incremental path, and `test_read_state_sync.cpp` pins both.

Global account data needs no such gate: every document in it is one the caller
PUT themselves.

## Waking

A read marker and an account-data write both use `notify_ephemeral()`, the
counter typing and presence already use, and not `notify_new_event()`.

Since these writes now claim a stream position, `notify_new_event()` would in
fact work — the head does move. It is not used because that would be two
mechanisms for one kind of change, and a reader of the wait loop would have to
check both. The rule stays as PR #4 left it: `notify_ephemeral()` is "something
changed that is not a timeline event".

The wake is *when*, not *whether*. A client that misses it — its poll was
already returning, the phone was asleep — still finds the change on its next
poll, because the delta is keyed on a stored position and not on having been
listening at the right moment. That is the difference between this and typing,
and it is why this section is worth having at all.

## Read receipts are not implemented

Matrix has two read-state shapes. `m.fully_read` is the reader's own marker,
private to them. `m.read` receipts are a *broadcast*: they tell everybody else
in the room how far you have read.

Only the first is here, and the second is deliberately out of scope rather than
pending:

* Nothing in this client consumes a receipt. The unread dot needs a per-room
  "read up to here" for **the reader**, which is exactly `m.fully_read`.
* A receipt is a per-recipient disclosure in a product whose pitch is that it
  does not do surveillance. "Everyone can see when you read their message" is a
  feature with an opinion in it, and it needs the owner's decision and a
  privacy setting, not a protocol change made in passing.
* On this server it would also need a fan-out with a visibility gate per
  recipient, because membership is not visibility: receipts in a channel go to
  the members who may view it, which is not the membership list.

Building it badly alongside this would have meant a broadcast nobody reads,
gated by rules nobody had decided. It is its own piece of work.
