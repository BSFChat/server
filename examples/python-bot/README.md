# BSFChat reference bot (Python)

A complete, runnable bot in two files and no dependencies. Copy this directory
and start editing.

- `bsfchat_bot.py` — the client. Auth, the long-poll sync loop, sending,
  reactions, redaction, media upload, backoff. Standard library only.
- `bot.py` — three example commands (`!ping`, `!echo`, `!status`).

Requires Python 3.9+. There is deliberately no Matrix SDK — see
[`../../docs/bots.md` §0](../../docs/bots.md) for why using one will waste your
afternoon.

## Setup

**1. Get a bot account.** An administrator (someone with `MANAGE_BOTS` or
`ADMINISTRATOR`) creates it:

```bash
curl -X POST "$HOMESERVER/_matrix/client/v3/bsfchat/bots" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"localpart":"bot_example","display_name":"Example","description":"Reference bot"}'
```

```json
{"user_id":"@bot_example:chat.example.com","display_name":"Example","token":"syt_..."}
```

**The token is shown once.** The server stores only a hash. Lose it and you
rotate; there is no recovery.

The localpart must start with `bot_`. Deleting a bot **deactivates** it rather
than removing it, and the localpart stays reserved for good — so pick the name
deliberately.

**2. Give it somewhere to talk.** Bots are excluded from the auto-join that puts
human accounts in every public channel, so getting in is deliberate.

The normal gesture is to **invite the bot**, exactly as you would a person:

```bash
curl -X POST "$HOMESERVER/_matrix/client/v3/rooms/$ROOM/invite" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"@bot_example:chat.example.com"}'
```

Inviting a bot **joins it immediately** — there is no pending invitation to
accept, and the bot needs no invite-handling code. It just sees itself joined on
its next sync; the `@bot.on_joined` handler in `bot.py` shows how to react.

Alternatively, for public channels, set `BSFCHAT_ROOMS` and the bot lets itself
in by room id at startup.

Either way the bot needs permission to speak. The minimum grant, scoped to one
channel:

```bash
curl -X PUT "$HOMESERVER/_matrix/client/v3/rooms/$ROOM/state/bsfchat.channel.permissions/user:@bot_example:chat.example.com" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"allow":"0x03","deny":"0x00"}'   # VIEW_CHANNEL | SEND_MESSAGES
```

Add `0x08` (`EMBED_LINKS`) if it posts URLs, `0x04` (`ATTACH_FILES`) if it posts
images or files. Prefer a per-channel override to a server role.

**3. Run it.**

```bash
export BSFCHAT_HOMESERVER=https://chat.example.com
export BSFCHAT_TOKEN=syt_...
export BSFCHAT_ROOMS='!abc123:chat.example.com'
python3 bot.py
```

Then type `!ping` in that channel.

`BSFCHAT_LOG_LEVEL=DEBUG` turns up the logging.

### Production

Run it under something that restarts it — systemd, or a container restart
policy. The bot exits **non-zero** on `401 M_UNKNOWN_TOKEN`, which is what you
get after a token rotation. That makes rotation a two-step operation: issue the
new token, update the secret, bounce the unit.

Keep the token in the environment or a file mode 0600, never in source or in a
URL query string.

## Writing your own commands

A command is a decorated function. The handler receives the raw event and a
small context dict:

```python
@bot.command("roll")
def roll(event, ctx):
    # ctx = {"room_id", "event_id", "sender", "args"}
    import random
    sides = int(ctx["args"] or 6)
    bot.send_text(ctx["room_id"], f"🎲 {random.randint(1, sides)}", notice=True)
```

`bot.command("roll")` matches `!roll` (the prefix is set when you construct
`BSFChatBot`). Everything after the command word arrives as `ctx["args"]`.

Handlers run **inline on the sync loop**. A handler that blocks for ten seconds
blocks message delivery for ten seconds. Anything slow — an HTTP call to a
third-party API, a database query — belongs on a thread or a queue, with the
handler just enqueueing the work.

The methods you have:

| Call | What it does |
| --- | --- |
| `send_text(room, body, notice=False)` | Plain message. `notice=True` is the convention for bot output. |
| `send_html(room, body, formatted_body, reply_to=None, notice=False)` | Rich text, optionally as a reply. |
| `react(room, event_id, "👍")` | Emoji reaction. |
| `redact(room, event_id, reason=None)` | Delete a message. Own always; others' need `MANAGE_MESSAGES`. |
| `upload(data, filename, mimetype)` | Returns an `mxc://` URI to reference from an `m.image`/`m.file` message. |
| `send_event(room, type, content)` | The escape hatch — any event type, any content. |
| `join(room_id)` / `joined_rooms()` | Membership. |

`@bot.on_joined` registers a callback for "this bot was added to a channel",
called as `fn(room_id, event)`. That is how you react to being invited.

To handle anything else — every message, other state changes, voice roster
events — pass `on_sync=` to `bot.run()` and read the raw response, or subclass
and override `_dispatch()`.

## Four things that will bite you

These are in the code with long comments, but worth stating plainly:

1. **Your bot sees its own messages.** `/sync` returns everything in the room,
   including what you just sent. A bot that replies to every message replies to
   its own reply, forever. `_dispatch()` checks `sender == self.user_id` first.
   If you bypass the dispatcher, do this check yourself.

2. **Edits arrive as new messages.** An edit is a fresh `m.room.message` with
   `m.relates_to.rel_type == "m.replace"` and a body prefixed `"* "`. Without
   filtering, editing a typo re-runs the command — and anyone can re-trigger
   your bot by editing an old message.

3. **Transaction ids must be globally unique per bot**, not per room and not per
   process. The server keys idempotency on `(sender, txn_id)` only, so reusing
   an id in a different room returns `200` with the *first* message's event id
   and posts nothing. It looks like success. The client here uses
   `nanosecond-epoch + counter`; do not replace it with a bare counter.

4. **Use a long sync timeout.** `timeout` is the idle ceiling, not a polling
   interval — the server wakes a parked `/sync` within microseconds of a commit
   via a condition variable. Short timeouts do not reduce latency, and each
   parked sync holds a server worker thread. The default here is the 300 s
   maximum, and that is the right value.

## What you cannot do

**No voice.** The voice REST endpoints manage roster state only; audio and video
are a WebRTC mesh between C++ desktop clients and the server never touches a
media packet. A music bot is not possible. You can read the voice roster and
post about it.

**No invite *acceptance* flow** — and you do not need one. Inviting a bot joins
it outright, so it arrives as a normal join event (`@bot.on_joined`). `/sync`
still has no `rooms.invite` section, which matters only for human accounts.

**No single-event fetch, no `/relations`, no filters, no account data, no
E2EE.** See [`../../docs/bots.md` §0 and §11](../../docs/bots.md).
