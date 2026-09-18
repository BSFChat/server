#!/usr/bin/env python3
"""A minimal, complete BSFChat bot client.

Standard library only — no Matrix SDK, and deliberately so. BSFChat implements
a SUBSET of the Matrix client-server API (no UIA, no filters, no account data,
no E2EE, no appservices), so an off-the-shelf SDK negotiates features off the
advertised "v1.12" and then breaks in confusing ways. See ../../docs/bots.md §0.

The whole surface a bot needs is about seven endpoints, and they are all here.

If you prefer `httpx`, swap out `_request()` — nothing else in this file knows
how the HTTP happens.
"""

from __future__ import annotations

import json
import itertools
import logging
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable

log = logging.getLogger("bsfchat.bot")

# The server clamps ?timeout= to 300000 ms. Use the maximum.
#
# This is the opposite of the usual polling advice, and it matters. /sync is a
# long poll that is EVENT-DRIVEN server side: a condition variable wakes it
# within microseconds of a commit. `timeout` is the idle ceiling — how long the
# server holds a request that has nothing to say — not a polling interval. A
# short timeout does NOT reduce latency; it only multiplies connections.
#
# And each parked /sync holds a server worker thread for its whole duration
# (cpp-httplib is thread-per-connection, pool default 64). A tight loop of
# 1-second polls is strictly worse for the server than one 5-minute poll, for
# identical delivery latency.
SYNC_TIMEOUT_MS = 300_000

# Must exceed SYNC_TIMEOUT_MS plus network margin, or we'd abort our own long
# polls every single time and hammer the server with reconnects.
SYNC_SOCKET_TIMEOUT_S = (SYNC_TIMEOUT_MS / 1000) + 30

# Sync tokens are "s<integer>". A malformed `since` is coerced to position 0
# server side, which replays the ENTIRE server history into the bot — so a
# corrupt persisted token is not a small problem. Validate before use.
SYNC_TOKEN_RE = re.compile(r"^s\d+$")

# Relations we must not treat as fresh user input.
#   m.replace    — an edit. Arrives as a NEW m.room.message whose body is the
#                  new text prefixed "* ". Dispatching on it makes the bot
#                  answer a command a second time when somebody fixes a typo,
#                  and lets anyone re-trigger the bot by editing an old message.
#   m.annotation — a reaction.
#   m.thread     — a threaded reply; handle it if you want, but it is not a
#                  top-level message.
IGNORED_RELATIONS = {"m.replace", "m.annotation"}


class BotError(Exception):
    """A request failed in a way the caller should know about."""

    def __init__(self, status: int, errcode: str, message: str):
        super().__init__(f"{status} {errcode}: {message}")
        self.status = status
        self.errcode = errcode
        self.message = message


class TokenRevoked(BotError):
    """401 M_UNKNOWN_TOKEN — the token was rotated or the bot was deleted.

    This is fatal on purpose. It is not retryable: nothing about the request
    will change on a second attempt, and a bot that hot-loops on it just burns
    a server thread. Exit non-zero and let systemd (or your container restart
    policy) bring the bot back with the re-issued secret.
    """


class BSFChatBot:
    """Long-polls /sync and dispatches m.room.message events to handlers."""

    def __init__(self, homeserver: str, token: str, *, command_prefix: str = "!"):
        # Tolerate a trailing slash so "https://chat.example.com/" works.
        self.homeserver = homeserver.rstrip("/")
        self.token = token
        self.command_prefix = command_prefix

        # Filled in by connect(). We MUST know our own user id before
        # dispatching anything — see _dispatch().
        self.user_id: str | None = None

        self.since: str | None = None
        self._handlers: list[tuple[str, Callable[[dict, dict], None]]] = []

        # Transaction ids must be globally unique per bot, for the lifetime of
        # the account — NOT just per room and NOT just per process.
        #
        # The server keys idempotency on (sender, txn_id) alone: not the room,
        # not the event type. So reusing an id in a different room returns 200
        # with the FIRST message's event_id and posts nothing to the second
        # room. It looks exactly like success. A counter that restarts at 1 on
        # every process start has the same failure: the first few sends after
        # each restart silently vanish.
        #
        # Nanosecond timestamp + process-lifetime counter gets both properties.
        self._txn_counter = itertools.count()
        self._txn_epoch = time.time_ns()

    # ── HTTP ────────────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        raw_body: bytes | None = None,
        content_type: str = "application/json",
        timeout: float = 30.0,
    ) -> Any:
        """One HTTP request. Returns parsed JSON, or raises BotError.

        `body` is JSON-encoded; `raw_body` is sent verbatim (media upload).
        """
        url = self.homeserver + path
        data = raw_body
        if data is None and body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)
        # Every endpoint takes the same bearer token. There is no separate bot
        # API: the token authenticates against the normal client-server API.
        req.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("Content-Type", content_type)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read()
                return json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                err = json.loads(payload)
                errcode = err.get("errcode", "M_UNKNOWN")
                message = err.get("error", "")
                retry_after = err.get("retry_after_ms")
            except (ValueError, AttributeError):
                errcode, message, retry_after = "M_UNKNOWN", payload[:200].decode(
                    "utf-8", "replace"
                ), None

            if exc.code == 401 and errcode == "M_UNKNOWN_TOKEN":
                raise TokenRevoked(exc.code, errcode, message) from exc

            if exc.code == 429:
                # Slowmode is the one 429 a bot realistically meets. The value
                # is the real remaining window, not an estimate, so sleeping it
                # exactly and retrying once is correct.
                delay = (retry_after or 1000) / 1000
                log.warning("rate limited, sleeping %.1fs (%s)", delay, message)
                time.sleep(delay)
                raise BotError(exc.code, errcode, message) from exc

            raise BotError(exc.code, errcode, message) from exc

    # ── lifecycle ───────────────────────────────────────────────────────

    def connect(self) -> str:
        """Verify the token and learn our own user id. Call before run()."""
        who = self._request("GET", "/_matrix/client/v3/account/whoami")
        self.user_id = who["user_id"]
        log.info("connected as %s", self.user_id)
        return self.user_id

    def joined_rooms(self) -> list[str]:
        """Rooms we are already in — how a bot rediscovers itself on restart."""
        return self._request("GET", "/_matrix/client/v3/joined_rooms").get(
            "joined_rooms", []
        )

    def join(self, room_id: str) -> str:
        """Join a room.

        Bots are EXCLUDED from the auto-join that force-joins human accounts to
        every public channel, so this is always explicit. Note also that a bot
        cannot see that it has been invited — /sync has no rooms.invite section
        — so room ids have to come from configuration. See docs/bots.md §3.
        """
        path = f"/_matrix/client/v3/rooms/{urllib.parse.quote(room_id)}/join"
        return self._request("POST", path)["room_id"]

    # ── sending ─────────────────────────────────────────────────────────

    def _next_txn(self) -> str:
        return f"{self._txn_epoch}-{next(self._txn_counter)}"

    def send_event(self, room_id: str, event_type: str, content: dict) -> str:
        """PUT an event. Returns its event_id."""
        path = (
            f"/_matrix/client/v3/rooms/{urllib.parse.quote(room_id)}"
            f"/send/{urllib.parse.quote(event_type)}/{self._next_txn()}"
        )
        return self._request("PUT", path, body=content)["event_id"]

    def send_text(self, room_id: str, body: str, *, notice: bool = False) -> str:
        """Plain text. `notice` uses m.notice, the convention for bot output."""
        return self.send_event(
            room_id,
            "m.room.message",
            {"msgtype": "m.notice" if notice else "m.text", "body": body},
        )

    def send_html(
        self,
        room_id: str,
        body: str,
        formatted_body: str,
        *,
        reply_to: str | None = None,
        notice: bool = False,
    ) -> str:
        """Rich text, optionally as a reply.

        `body` is the plain-text fallback and is NOT optional: it is what search
        indexes and what push notifications show.

        `formatted_body` is rendered by the desktop client as Qt RichText — an
        HTML subset, not a browser. Stick to <b> <i> <code> <pre> <a href> <br>
        and inline style=. Anything else may render as literal text.

        A reply is purely a content convention; the server does not check that
        the target exists or is in this room.
        """
        content: dict[str, Any] = {
            "msgtype": "m.notice" if notice else "m.text",
            "body": body,
            "format": "org.matrix.custom.html",
            "formatted_body": formatted_body,
        }
        if reply_to:
            content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}
        return self.send_event(room_id, "m.room.message", content)

    def react(self, room_id: str, event_id: str, key: str) -> str:
        """Add an emoji reaction. Note: no `body` field, and a distinct type."""
        return self.send_event(
            room_id,
            "m.reaction",
            {"m.relates_to": {"rel_type": "m.annotation",
                              "event_id": event_id, "key": key}},
        )

    def redact(self, room_id: str, event_id: str, reason: str | None = None) -> str:
        """Delete an event. Own events always; others' need MANAGE_MESSAGES.

        NOT idempotent: the server parses the txnId out of the path and never
        uses it, so a retry appends a second redaction event. Harmless, but do
        not retry casually.
        """
        path = (
            f"/_matrix/client/v3/rooms/{urllib.parse.quote(room_id)}"
            f"/redact/{urllib.parse.quote(event_id)}/{self._next_txn()}"
        )
        return self._request("PUT", path, body={"reason": reason} if reason else {})[
            "event_id"
        ]

    def upload(self, data: bytes, filename: str, mimetype: str) -> str:
        """Upload media, returning an mxc:// URI.

        RAW binary body — not multipart, not base64. Posting the result as
        anything but m.text/m.emote/m.notice requires the ATTACH_FILES
        permission.
        """
        path = "/_matrix/media/v3/upload?" + urllib.parse.urlencode(
            {"filename": filename}
        )
        return self._request(
            "POST", path, raw_body=data, content_type=mimetype, timeout=120
        )["content_uri"]

    # ── handlers ────────────────────────────────────────────────────────

    def command(self, name: str) -> Callable:
        """Decorator registering a handler for `<prefix><name>`.

        The handler is called as handler(event, ctx) where `ctx` carries
        room_id, event_id, sender and args (everything after the command word).
        """

        def decorate(fn: Callable[[dict, dict], None]) -> Callable:
            self._handlers.append((name, fn))
            return fn

        return decorate

    def _dispatch(self, room_id: str, event: dict) -> None:
        # ── the two footguns, in the order they must be checked ──────────

        if event.get("type") != "m.room.message":
            return

        # 1. OUR OWN MESSAGES COME BACK THROUGH /sync.
        #    A bot that replies to every message replies to its own reply, then
        #    to that, forever, at condition-variable speed. This one check is
        #    the difference between a bot and an outage.
        if event.get("sender") == self.user_id:
            return

        # Ignore other bots too, so two bots cannot loop off each other.
        # (Cheap heuristic: the reserved bot_* localpart. A profile lookup for
        # "bsfchat.bot": true is the authoritative answer if you need it.)
        if str(event.get("sender", "")).startswith("@bot_"):
            return

        content = event.get("content") or {}

        # 2. EDITS ARRIVE AS NEW MESSAGES.
        #    An m.replace is a fresh m.room.message whose body is "* <new text>".
        #    Without this, editing "!ping" into "!pong" runs !ping again, and
        #    anyone can re-trigger the bot by editing an ancient message.
        relation = content.get("m.relates_to") or {}
        if relation.get("rel_type") in IGNORED_RELATIONS:
            return

        if content.get("msgtype") != "m.text":
            return

        body = (content.get("body") or "").strip()
        if not body.startswith(self.command_prefix):
            return

        word, _, args = body[len(self.command_prefix):].partition(" ")
        ctx = {
            "room_id": room_id,
            "event_id": event.get("event_id"),
            "sender": event.get("sender"),
            "args": args.strip(),
        }
        for name, handler in self._handlers:
            if name == word:
                try:
                    handler(event, ctx)
                except BotError as exc:
                    # A 403 here is usually a permission or content gate (a URL
                    # in the body needs EMBED_LINKS, "@everyone" needs
                    # MENTION_EVERYONE). Retrying fails identically.
                    log.error("handler %r failed: %s", name, exc)
                except Exception:
                    log.exception("handler %r raised", name)
                return

    # ── the sync loop ───────────────────────────────────────────────────

    def _initial_sync(self) -> None:
        """Establish a starting position WITHOUT replaying history.

        With no `since`, /sync returns the last 20 events in every joined room.
        A naive bot processes those as if they just arrived and answers
        twenty-minute-old commands on every restart. So: take next_batch, throw
        the events away. timeout=0 returns immediately.
        """
        resp = self._request(
            "GET", "/_matrix/client/v3/sync?timeout=0", timeout=60
        )
        self.since = resp["next_batch"]
        log.info("initial sync complete, starting from %s", self.since)

    def run(self, *, on_sync: Callable[[dict], None] | None = None) -> None:
        """Long-poll forever. Blocks. Raises TokenRevoked if the token dies."""
        if self.user_id is None:
            self.connect()

        # Guard against a corrupt persisted token: an unparseable `since` means
        # "from position 0" server side, i.e. the entire server history.
        if self.since is not None and not SYNC_TOKEN_RE.match(self.since):
            log.warning("discarding malformed sync token %r", self.since)
            self.since = None
        if self.since is None:
            self._initial_sync()

        backoff = 1.0
        while True:
            params = {"timeout": str(SYNC_TIMEOUT_MS), "since": self.since}
            url = "/_matrix/client/v3/sync?" + urllib.parse.urlencode(params)
            try:
                resp = self._request("GET", url, timeout=SYNC_SOCKET_TIMEOUT_S)
                backoff = 1.0  # reset only on an actual success
            except TokenRevoked:
                # Fatal by design — see the class docstring.
                raise
            except (BotError, urllib.error.URLError, OSError, TimeoutError) as exc:
                # A read timeout is not an error: reconnect at once with the
                # SAME `since`, so nothing is skipped. Anything else backs off
                # exponentially with jitter, capped at a minute.
                if isinstance(exc, (TimeoutError, urllib.error.URLError)) and (
                    "timed out" in str(exc).lower()
                ):
                    log.debug("sync timed out, reconnecting")
                    continue
                delay = min(backoff, 60.0) * (0.5 + random.random())
                log.warning("sync failed (%s), retrying in %.1fs", exc, delay)
                time.sleep(delay)
                backoff = min(backoff * 2, 60.0)
                continue

            # next_batch may be UNCHANGED on an idle timeout. That means
            # "nothing happened" — it is normal, not a failure, and must not
            # trigger backoff.
            self.since = resp.get("next_batch", self.since)

            for room_id, room in (resp.get("rooms", {}).get("join", {}) or {}).items():
                for event in (room.get("timeline", {}) or {}).get("events", []) or []:
                    self._dispatch(room_id, event)

            if on_sync:
                on_sync(resp)


def html_escape(text: str) -> str:
    """Escape text for safe inclusion in a formatted_body.

    formatted_body is passed through the server verbatim and rendered by the
    desktop client as Qt RichText, so never interpolate user-supplied text into
    markup without escaping it.
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# The server rejects a send whose body contains a literal @everyone or @here
# unless the sender holds MENTION_EVERYONE — independently of the structured
# m.mentions block. An echo bot repeating a user's text would get a 403 and
# drop the message, so defang the tokens instead.
_PING_TOKENS = re.compile(r"@(everyone|here)\b", re.IGNORECASE)


def defang_pings(text: str) -> str:
    """Make @everyone / @here safe to echo back."""
    return _PING_TOKENS.sub(lambda m: "@​" + m.group(1), text)
