#!/usr/bin/env python3
"""Reference BSFChat bot — start here.

Three commands that between them show every shape you need:

    !ping           plain text, and a reaction on the triggering message
    !echo <text>    echoing UNTRUSTED user input safely
    !status         rich text with formatted_body, sent as a reply

Run it:

    export BSFCHAT_HOMESERVER=http://127.0.0.1:8448
    export BSFCHAT_TOKEN=syt_...            # from POST /bsfchat/bots
    export BSFCHAT_ROOMS='!abc:host,!def:host'
    python3 bot.py

See README.md for setup and ../../docs/bots.md for the full API guide.
"""

from __future__ import annotations

import logging
import os
import sys
import time

from bsfchat_bot import (
    BSFChatBot,
    BotError,
    TokenRevoked,
    defang_pings,
    html_escape,
)

STARTED_AT = time.time()


def build_bot() -> BSFChatBot:
    homeserver = os.environ.get("BSFCHAT_HOMESERVER")
    token = os.environ.get("BSFCHAT_TOKEN")
    if not homeserver or not token:
        sys.exit(
            "Set BSFCHAT_HOMESERVER and BSFCHAT_TOKEN.\n"
            "  BSFCHAT_HOMESERVER=https://chat.example.com\n"
            "  BSFCHAT_TOKEN=<the token shown once by POST /bsfchat/bots>"
        )

    bot = BSFChatBot(homeserver, token, command_prefix="!")

    # ── !ping ───────────────────────────────────────────────────────────
    @bot.command("ping")
    def ping(event, ctx):
        bot.send_text(ctx["room_id"], "pong", notice=True)
        # A reaction is a separate event type with no `body`. Worth knowing:
        # reactions are gated on VIEW_CHANNEL only, not SEND_MESSAGES.
        bot.react(ctx["room_id"], ctx["event_id"], "\N{TABLE TENNIS PADDLE AND BALL}")

    # ── !echo ───────────────────────────────────────────────────────────
    @bot.command("echo")
    def echo(event, ctx):
        """Echo user input — the canonical place to get security wrong.

        Two server-side content gates fire on the BODY of an m.room.message,
        regardless of what the sender intended:

          * a literal "@everyone"/"@here" anywhere in the body needs
            MENTION_EVERYONE, else the send is 403'd and the message is lost;
          * any http(s):// URL in the body needs EMBED_LINKS.

        So a bot echoing arbitrary text either holds both permissions or
        defangs the input. Defanging is the right default for an echo bot:
        it should not be a privilege-laundering machine that lets anyone
        ping the whole server through it.
        """
        text = ctx["args"]
        if not text:
            bot.send_text(ctx["room_id"], "Usage: !echo <text>", notice=True)
            return
        bot.send_text(ctx["room_id"], defang_pings(text), notice=True)

    # ── !status ─────────────────────────────────────────────────────────
    @bot.command("status")
    def status(event, ctx):
        """Rich reply: formatted_body plus an m.in_reply_to relation.

        `body` is the plain-text fallback and is mandatory — it is what search
        indexes and what push notifications display. `formatted_body` is
        rendered by the desktop client as Qt RichText: <b> <i> <code> <pre>
        <a href> <br> and inline style= are safe; a browser-grade HTML subset
        is NOT available.

        Note html_escape() on the sender: a display name or user id is
        attacker-controlled text and must never be interpolated into markup raw.
        """
        uptime = int(time.time() - STARTED_AT)
        hours, rem = divmod(uptime, 3600)
        minutes, seconds = divmod(rem, 60)
        pretty = f"{hours}h {minutes}m {seconds}s"
        rooms = len(bot.joined_rooms())
        sender = html_escape(ctx["sender"] or "")

        bot.send_html(
            ctx["room_id"],
            body=f"Up {pretty}, in {rooms} room(s). Asked by {ctx['sender']}.",
            formatted_body=(
                "<b>Reference bot</b><br>"
                f"Uptime: <code>{pretty}</code><br>"
                f"Rooms: <code>{rooms}</code><br>"
                f"<i>asked by {sender}</i>"
            ),
            reply_to=ctx["event_id"],
            notice=True,
        )

    return bot


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("BSFCHAT_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    bot = build_bot()
    bot.connect()  # verifies the token and learns our own user id

    # Bots are EXCLUDED from the auto-join that force-joins human accounts to
    # every public channel, and a bot cannot observe an invite (/sync has no
    # rooms.invite section). So the rooms come from configuration and we join
    # explicitly. Joining a room we are already in is harmless.
    wanted = [r.strip() for r in os.environ.get("BSFCHAT_ROOMS", "").split(",") if r.strip()]
    for room_id in wanted:
        try:
            bot.join(room_id)
            logging.info("joined %s", room_id)
        except BotError as exc:
            logging.error("could not join %s: %s", room_id, exc)

    joined = bot.joined_rooms()
    if not joined:
        logging.warning(
            "not in any room — set BSFCHAT_ROOMS, or have an admin grant the "
            "bot VIEW_CHANNEL and join it to a channel"
        )
    else:
        logging.info("listening in %d room(s): %s", len(joined), ", ".join(joined))

    try:
        bot.run()
    except KeyboardInterrupt:
        logging.info("stopping")
        return 0
    except TokenRevoked as exc:
        # Deliberately fatal. The token was rotated or the bot deleted; no
        # amount of retrying changes that. Exit non-zero so the supervisor
        # restarts us once the secret has been re-issued.
        logging.error("token is no longer valid (%s) — exiting", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
