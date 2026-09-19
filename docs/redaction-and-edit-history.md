# Redaction and edit history

What "delete" and "edit" mean on this server, and why they mean those things.
Written for the next person who has to change either one, because changing one
without the other is how the RC-blocking defects B1, B9 and B12 happened.

## The two operations

**Editing is revision.** An edit is a new `m.room.message` carrying
`m.relates_to: { rel_type: "m.replace" }`. The original event keeps its identity
— same event id, same sender, same `origin_server_ts` — and gains a pointer
(`events.edited_by`) to the replacement that currently wins. Every read path
resolves through that pointer, so the API serves the current text; the pre-edit
text stays on the original's row and is served alongside it as
`unsigned.bsfchat.original_content`, and each intermediate version stays in the
timeline as its own event.

**Redaction is removal.** It is the only removal. The row survives as a
tombstone (id, type, sender, timestamp) and the content is gone.

## The invariant

> After a redaction returns, no surface of the server still holds the text of
> the redacted message or of any edit of it: not the `events` rows, not the FTS
> index, not the bundled edit history, not the mention rows, and not the
> undispatched push queue.

"The message" is not a row. It is the original event plus every `m.replace` of
it, transitively. That is the whole content of the invariant: a message that has
been edited is several rows, and a redaction that strips one of them is not a
redaction.

`SqliteStore::redact_event` is the single place this is enforced, in one
transaction, and the enforcement is unconditional — re-redacting a message that
an older build redacted badly finishes the job. Migration v20 does the same
sweep once at upgrade for the messages nobody will think to redact twice.

## Decision: edit history is kept, and it is public to the room

We keep it. Matrix keeps it; so does every system where "what did that say
before?" is a moderation question. The prior versions of an edited message are
readable by the members of the channel, in two forms: the replacement events
themselves, and `unsigned.bsfchat.original_content` on the original.

This is defensible for one reason only — **redaction reaches all of it.** An
edit does not remove what it replaced, and it was never able to; before the B1
fix, neither did a redaction, so there was no way for a user to un-say anything.
Now there is exactly one way, and it works. If a future change makes redaction
stop reaching edit history, this decision has to be revisited in the same
commit, not afterwards.

Two things follow that are **not** done here and should be picked up by whoever
owns the client and the product copy:

- The edit box must not read as a way to remove text. A user who pasted the
  wrong buffer and edits it away has published it and then revised it; the UI
  should say so, and should point at delete.
- "Show edit history" is a one-click read of every prior version for every
  reader. It follows from the decision above, but it deserves to be a decision
  someone made on purpose rather than a menu item that appeared.

Sender-gating the bundle (serving `bsfchat.original_content` only to the sender
and to `MANAGE_MESSAGES` holders) was considered and not done. It does not
change what a reader can see — every intermediate version is an ordinary
timeline event either way — so it would cost a new viewer parameter on three
read paths and a client-side regression in mention rendering, in exchange for
hiding one version out of N. If edit history is ever made private, it has to be
done at the level of which events a reader is served, not by trimming
`unsigned`.

## The push queue is a race, not a filter

Notification payloads are snapshotted at enqueue time and delivered out of band,
with retries for up to an hour. Three guards, because the queue straddles the
redaction:

1. **Enqueue** skips any push whose event is already redacted. The event is
   visible to `/sync` before the send path enqueues, so a fast redaction can
   land in the gap and find no rows to delete.
2. **Redaction** deletes the queued rows for the message and every edit of it.
   This is the one that matters in practice.
3. **Dispatch** re-checks at claim time and drops the row instead of delivering
   it. The worker POSTs outside the store lock, so this is the last point at
   which the answer is still knowable.

A push already handed to a gateway cannot be recalled. That window — claimed,
in flight, then redacted — is the residual risk and is accepted: it is bounded
by one HTTP request rather than by the retry schedule.

Unregistering a pusher also deletes its queued rows. Otherwise removing a device
leaves notifications that keep POSTing message text to a gateway URL for a
device that is gone.

## The search index

`event_search` is external-content FTS5. A replacement is never indexed as
itself — the original's row is re-indexed with the resolved (post-edit) text, so
an edited message stays one hit whose text is current. Consequently a redaction
that clears the original's index row clears both versions, and there is nothing
extra to do for the edits. That is a property of the current indexing rule, not
a coincidence, so it is pinned by a test
(`RedactionResidue.SearchForgetsBothVersionsOfARedactedMessage`): if
replacements are ever indexed separately, that test fails and this section is
wrong.
