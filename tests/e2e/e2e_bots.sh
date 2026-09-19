#!/bin/bash
# End-to-end check of the bot account lifecycle against the REAL bsfchat-server
# binary over HTTP.
#
# The whole flow a bot author follows, in order:
#
#   admin creates a bot   -> 201 with a one-time token
#   bot authenticates     -> whoami, with the SAME bearer header as a human
#   bot is NOT auto-joined-> the exclusion that distinguishes a bot account
#   bot joins a channel   -> explicit, because nothing joins it for us
#   a human sends         -> the bot's PARKED long poll returns it
#   bot replies           -> the human sees it
#   token rotated         -> new token works, OLD token is dead
#   bot deleted           -> token dead, account gone from the list
#
# Safety: everything lives under a throwaway directory. The real dev database is
# checksummed before and after and the script HARD-FAILS if a single byte
# changed, and hard-fails if the server did not create its database at the
# configured path (which is how a misparsed TOML would show up).
#
# Nothing here hard-codes an absolute path; locations come from lib.sh.
#
# Exit codes: 0 pass, 1 check failures, 77 bot endpoints not implemented
# (skipped), 90 fatal, 91 the real dev data was touched.
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1
WORK=$(mktemp -d /tmp/bsfchat-bots-e2e-XXXXXX)
REALDATA=$(e2e_real_data_dir || echo /nonexistent)
PORT=${PORT:-8901}
ROOT="http://127.0.0.1:${PORT}"
BASE="${ROOT}/_matrix/client/v3"
FAILURES=0
CHECKS=0
SRV_PID=""

cleanup() {
  if [[ -n "${SRV_PID:-}" ]]; then kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; fi
  pkill -P $$ curl 2>/dev/null
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 90; }

# ── guard: snapshot the real dev database ────────────────────────────────
snapshot() { find "$REALDATA" -type f -exec shasum {} \; 2>/dev/null | sort; }
snapshot > "$WORK/real-before.txt"
[[ -s "$WORK/real-before.txt" ]] || die "could not checksum $REALDATA; refusing to run blind"

cat > "$WORK/server.toml" <<EOF
[server]
name = "e2e"
bind_address = "127.0.0.1"
port = ${PORT}
# Deliberately small. A bot parks a long poll on a worker for its whole
# duration (cpp-httplib is thread-per-connection), and this script parks one
# while doing other work — so a pool this size proves the parked sync is not
# starving the rest.
workers = 8

[database]
path = "${WORK}/e2e.db"

[media]
path = "${WORK}/media/"
max_upload_size_mb = 5
require_auth = true

[auth]
registration_enabled = true
password_hash_cost = 4
access_token_lifetime_days = 1

[storage]
type = "local"

[voice]
enabled = false

[push]
enabled = false

[tls]
enabled = false
EOF

start_server() {
  # A stranger on our port would answer /versions and make us believe OUR server
  # came up — which is how a port collision masquerades as a TOML misparse.
  if lsof -nP -iTCP:${PORT} -sTCP:LISTEN >/dev/null 2>&1; then
    die "port ${PORT} is already in use (another server is listening); refusing to run"
  fi
  ( cd "$WORK" && exec "$BIN" --config "$WORK/server.toml" > "$WORK/server-$1.log" 2>&1 ) &
  SRV_PID=$!
  for _ in $(seq 1 100); do
    if curl -sf "${ROOT}/_matrix/client/versions" > /dev/null 2>&1; then return 0; fi
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
      echo "--- server log ---"; cat "$WORK/server-$1.log"; die "server exited during startup"
    fi
    sleep 0.2
  done
  cat "$WORK/server-$1.log"; die "server never became ready"
}
stop_server() {
  kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
  for _ in $(seq 1 50); do
    lsof -nP -iTCP:${PORT} -sTCP:LISTEN >/dev/null 2>&1 || return 0
    sleep 0.2
  done
  die "server did not release port ${PORT}"
}

req() { # req METHOD PATH TOKEN BODY -> prints HTTP status, body in last-body.json
  local m=$1 p=$2 t=${3:-} b=${4:-}
  local args=(-s -o "$WORK/last-body.json" -w '%{http_code}' -X "$m" "${BASE}${p}")
  [[ -n "$t" ]] && args+=(-H "Authorization: Bearer $t")
  [[ -n "$b" ]] && args+=(-H 'Content-Type: application/json' -d "$b")
  curl "${args[@]}"
}

check() { # check LABEL EXPECTED ACTUAL
  CHECKS=$((CHECKS+1))
  if [[ "$2" == "$3" ]]; then
    printf 'ok   %-58s %s\n' "$1" "$3"
  else
    printf 'FAIL %-58s expected %s got %s  body=%s\n' "$1" "$2" "$3" "$(cat "$WORK/last-body.json" 2>/dev/null)"
    FAILURES=$((FAILURES+1))
  fi
}

note() { printf 'ok   %-58s %s\n' "$1" "${2:-}"; CHECKS=$((CHECKS+1)); }
fail() { printf 'FAIL %-58s %s\n' "$1" "${2:-}"; CHECKS=$((CHECKS+1)); FAILURES=$((FAILURES+1)); }

jfield() { python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2],""))
except Exception: print("")' "$WORK/last-body.json" "$1"; }

jfield_of() { python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2],""))
except Exception: print("")' "$1" "$2"; }

# One literal for every account, as the sibling e2e scripts do. It must not
# contain the username, must not be on the common-password denylist, and must
# not contain the product name — password_policy_error() refuses all three, so a
# per-user password built from $1 is rejected at registration.
E2E_PW="e2e-correct-horse-7"

register() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"${E2E_PW}\"}" >/dev/null
  jfield access_token
}
login() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/login" -H 'Content-Type: application/json' \
    -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"$1\"},\"password\":\"${E2E_PW}\"}" >/dev/null
  jfield access_token
}

# ── phase 0: an admin, and a channel to talk in ──────────────────────────
start_server first
[[ -f "$WORK/e2e.db" ]] || die "server did not create its database at the CONFIGURED path ($WORK/e2e.db) — TOML likely misparsed"

T_ADMIN=$(register alice)
[[ -n "$T_ADMIN" ]] || { cat "$WORK/server-first.log"; die "registration failed"; }
stop_server

# Restart so bootstrap_roles grants the admin role to the OLDEST account —
# the real ownership path, not a fixture poke.
start_server second
T_ADMIN=$(login alice)
[[ -n "$T_ADMIN" ]] || die "login failed after restart"
ADMIN="@alice:e2e"

curl -s -o "$WORK/last-body.json" -X POST "${BASE}/createRoom" -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' -d '{"name":"general","visibility":"public"}' >/dev/null
ROOM=$(jfield room_id)
[[ -n "$ROOM" ]] || { cat "$WORK/last-body.json"; die "admin could not create a channel"; }
echo "     admin = $ADMIN   room = $ROOM"

# ── phase 1: create the bot ──────────────────────────────────────────────
echo
echo "── T1: bot creation ─────────────────────────────────────────────────"

STATUS=$(req POST "/bsfchat/bots" "$T_ADMIN" \
  '{"localpart":"bot_e2e","display_name":"E2E Bot","description":"exercised by e2e_bots.sh"}')

# Written ahead of the server side landing. If the route does not exist yet,
# say so plainly and skip rather than reporting a wall of failures that all
# mean the same thing.
if [[ "$STATUS" == "404" || "$STATUS" == "405" ]]; then
  echo
  echo "SKIP: this server does not implement POST /_matrix/client/v3/bsfchat/bots"
  echo "      (got HTTP $STATUS: $(cat "$WORK/last-body.json"))"
  echo "      The bot account endpoints are not in this build. Nothing was validated."
  stop_server
  snapshot > "$WORK/real-after.txt"
  diff -q "$WORK/real-before.txt" "$WORK/real-after.txt" >/dev/null || { echo "FATAL: $REALDATA CHANGED"; exit 91; }
  rm -rf "$WORK"
  exit 77
fi

check "admin creates a bot"                     201 "$STATUS"
BOT_ID=$(jfield user_id)
BOT_TOKEN=$(jfield token)
BOT_NAME=$(jfield display_name)
[[ -n "$BOT_TOKEN" ]] || die "create returned no token: $(cat "$WORK/last-body.json")"
echo "     bot = $BOT_ID"

check "bot id is in the bot_* namespace"        "@bot_e2e:e2e" "$BOT_ID"
check "display_name echoed back"                "E2E Bot" "$BOT_NAME"

# A non-admin must not be able to mint accounts.
T_BOB=$(register bob)
[[ -n "$T_BOB" ]] || die "could not register a plain user"
check "plain user cannot create a bot"          403 "$(req POST "/bsfchat/bots" "$T_BOB" \
  '{"localpart":"bot_sneaky","display_name":"Sneaky","description":""}')"

check "reserved namespace enforced"             400 "$(req POST "/bsfchat/bots" "$T_ADMIN" \
  '{"localpart":"notabot","display_name":"Nope","description":""}')"

# Listing must never hand back credentials.
check "admin lists bots"                        200 "$(req GET "/bsfchat/bots" "$T_ADMIN")"
if grep -q "$BOT_TOKEN" "$WORK/last-body.json"; then
  fail "listing does not leak the token"
else
  note "listing does not leak the token"
fi

# The listing contract: owner_id and deactivated are ALWAYS present; the
# timestamps are present only when they mean something, so a reader is never
# handed a 0 that looks like "deactivated at the epoch".
if python3 - "$WORK/last-body.json" "$BOT_ID" "$ADMIN" <<'PY'
import json, sys
bots = json.load(open(sys.argv[1])).get("bots", [])
row = next((b for b in bots if b.get("user_id") == sys.argv[2]), None)
if row is None:
    sys.exit(1)
ok = (row.get("owner_id") == sys.argv[3]
      and row.get("deactivated") is False
      and "created_at" in row
      and "deactivated_at" not in row)      # absent while live
sys.exit(0 if ok else 1)
PY
then
  note "listing shape: owner_id, deactivated, no deactivated_at"
else
  fail "listing shape: owner_id, deactivated, no deactivated_at" "body=$(cat "$WORK/last-body.json")"
fi

# ── phase 2: the bot authenticates ───────────────────────────────────────
echo
echo "── T2: bot auth ─────────────────────────────────────────────────────"

check "bot token authenticates (whoami)"        200 "$(req GET "/account/whoami" "$BOT_TOKEN")"
check "whoami returns the bot's id"             "$BOT_ID" "$(jfield user_id)"

# The credential is the token. There is no password to guess.
BOT_LOGIN_BODY=$(python3 -c 'import json,sys
print(json.dumps({"type":"m.login.password",
                  "identifier":{"type":"m.id.user","user":"bot_e2e"},
                  "password":sys.argv[1]}))' "$E2E_PW")
check "bot cannot password-login"               403 "$(req POST "/login" "" "$BOT_LOGIN_BODY")"

# Profile reads are AUTHENTICATED now — they were the last unauthenticated read
# endpoints and made a user-enumeration oracle. A bot must present its token to
# read any profile, including its own.
check "unauthenticated profile read is 401"     401 "$(req GET "/profile/${BOT_ID}" "")"
check "  with M_MISSING_TOKEN"                  "M_MISSING_TOKEN" "$(jfield errcode)"

check "profile marks it as a bot"               200 "$(req GET "/profile/${BOT_ID}" "$BOT_TOKEN")"
check "  bsfchat.bot is true"                   "True" "$(python3 -c 'import json,sys
print(json.load(open(sys.argv[1])).get("bsfchat.bot"))' "$WORK/last-body.json")"

# whoami carries the same flag, for the CALLER — so shared client code can
# discover it is running as a bot on the request it already makes at startup.
req GET "/account/whoami" "$BOT_TOKEN" >/dev/null
check "  whoami carries bsfchat.bot"            "True" "$(python3 -c 'import json,sys
print(json.load(open(sys.argv[1])).get("bsfchat.bot"))' "$WORK/last-body.json")"

# For a human the key is ABSENT, not false. The response must also be an OBJECT:
# this handler used to serialise as the literal `null` for an account with no
# displayname, avatar or nickname, which broke the idiomatic
# .get("bsfchat.bot", False) with a TypeError.
req GET "/profile/@alice:e2e" "$BOT_TOKEN" >/dev/null
if python3 - "$WORK/last-body.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if not isinstance(doc, dict):
    print("not an object:", repr(doc), file=sys.stderr)
    sys.exit(1)
sys.exit(0 if doc.get("bsfchat.bot") is None else 1)
PY
then
  note "human profile: object, key omitted" "$(cat "$WORK/last-body.json")"
else
  fail "human profile: object, key omitted" "body=$(cat "$WORK/last-body.json")"
fi

# ── phase 3: auto-join exclusion ─────────────────────────────────────────
echo
echo "── T3: bots are excluded from auto-join ─────────────────────────────"

# A human registering now is force-joined to every public channel. The bot,
# created before this same channel existed, must NOT be.
check "a human IS auto-joined"                  200 "$(req GET "/joined_rooms" "$T_BOB")"
if grep -q "$ROOM" "$WORK/last-body.json"; then
  note "  human sees the public channel" "$ROOM"
else
  fail "  human sees the public channel" "body=$(cat "$WORK/last-body.json")"
fi

check "bot starts in no rooms"                  200 "$(req GET "/joined_rooms" "$BOT_TOKEN")"
if grep -q "$ROOM" "$WORK/last-body.json"; then
  fail "  bot was NOT auto-joined" "bot is in $ROOM but should not be: $(cat "$WORK/last-body.json")"
else
  note "  bot was NOT auto-joined" "$(cat "$WORK/last-body.json")"
fi

# Before joining, the bot cannot post there.
check "bot cannot send before joining"          403 "$(req PUT "/rooms/${ROOM}/send/m.room.message/pre1" "$BOT_TOKEN" \
  '{"msgtype":"m.text","body":"should not appear"}')"

check "bot joins explicitly"                    200 "$(req POST "/rooms/${ROOM}/join" "$BOT_TOKEN")"
check "  join returns the room id"              "$ROOM" "$(jfield room_id)"
# The other spelling of the same thing, and joining twice must be harmless.
check "  /join/{roomId} works too"              200 "$(req POST "/join/${ROOM}" "$BOT_TOKEN")"

# ── phase 4: receive via sync, then reply ────────────────────────────────
echo
echo "── T4: sync delivery and reply ──────────────────────────────────────"

# Starting position. timeout=0 returns at once; a real bot takes next_batch
# from this and DISCARDS the events, so a restart does not replay history.
curl -s -o "$WORK/bot-initial.json" "${BASE}/sync?timeout=0" -H "Authorization: Bearer $BOT_TOKEN"
SINCE=$(jfield_of "$WORK/bot-initial.json" next_batch)
[[ -n "$SINCE" ]] || die "bot initial sync returned no next_batch"
case "$SINCE" in
  s*) note "initial sync token is s<n>" "$SINCE" ;;
  *)  fail "initial sync token is s<n>" "got $SINCE" ;;
esac

# Park the bot's long poll BEFORE the send, which is what a real bot is doing
# at all times. A 60s timeout with an event-driven wake-up: this returns in
# milliseconds, not in 60 seconds, and that is the point of the assertion.
( curl -s -o "$WORK/bot-sync.json" \
    "${BASE}/sync?timeout=60000&since=${SINCE}" \
    -H "Authorization: Bearer $BOT_TOKEN"
  python3 -c 'import time;print(time.time())' > "$WORK/bot-sync.done" ) &
SYNC_PID=$!
sleep 0.7   # the poll is now blocked inside the server's condition variable

T0=$(python3 -c 'import time;print(time.time())')
check "human sends a command"                   200 "$(req PUT "/rooms/${ROOM}/send/m.room.message/cmd1" "$T_ADMIN" \
  '{"msgtype":"m.text","body":"!ping"}')"
CMD_EVENT=$(jfield event_id)

wait $SYNC_PID 2>/dev/null
T1=$(cat "$WORK/bot-sync.done" 2>/dev/null || echo "$T0")
DELIV_MS=$(python3 -c "print(f'{($T1-$T0)*1000:.0f}')")

if python3 - "$WORK/bot-sync.json" "$ROOM" '!ping' <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
room = doc.get("rooms", {}).get("join", {}).get(sys.argv[2], {})
bodies = [e.get("content", {}).get("body")
          for e in room.get("timeline", {}).get("events", [])]
sys.exit(0 if sys.argv[3] in bodies else 1)
PY
then
  note "parked sync delivered the message" "${DELIV_MS} ms"
else
  fail "parked sync delivered the message" "body=$(head -c 400 "$WORK/bot-sync.json")"
fi

# The wake-up is a condition-variable signal, not a poll. On loopback there is
# no legitimate reason for this to be slow; a second here would mean the
# delivery path has regressed to polling.
if [[ "$DELIV_MS" -lt 1000 ]]; then
  note "delivery was event-driven (< 1000 ms)" "${DELIV_MS} ms"
else
  fail "delivery was event-driven (< 1000 ms)" "${DELIV_MS} ms — /sync is not waking on commit"
fi

SINCE=$(jfield_of "$WORK/bot-sync.json" next_batch)
if [[ -n "$SINCE" && "$SINCE" == s* ]]; then
  note "sync token advanced" "$SINCE"
else
  fail "sync token advanced" "got '$SINCE'"
fi

# The bot replies: formatted_body plus an m.in_reply_to relation, which is the
# shape the reference bot's !status command sends.
REPLY_BODY=$(python3 -c 'import json,sys
print(json.dumps({
  "msgtype":"m.notice",
  "body":"pong",
  "format":"org.matrix.custom.html",
  "formatted_body":"<b>pong</b>",
  "m.relates_to":{"m.in_reply_to":{"event_id":sys.argv[1]}}}))' "$CMD_EVENT")
check "bot replies with formatted_body"         200 "$(req PUT "/rooms/${ROOM}/send/m.room.message/reply1" "$BOT_TOKEN" "$REPLY_BODY")"
REPLY_EVENT=$(jfield event_id)
[[ -n "$REPLY_EVENT" ]] || fail "reply returned an event_id"

# Transaction idempotency: the SAME txnId must return the SAME event id and
# must not post a second message. This is what makes retrying a timed-out send
# safe, and it is keyed on (sender, txn_id) only — see docs/bots.md §6.
check "retrying the same txnId is accepted"     200 "$(req PUT "/rooms/${ROOM}/send/m.room.message/reply1" "$BOT_TOKEN" "$REPLY_BODY")"
check "  and returns the original event_id"     "$REPLY_EVENT" "$(jfield event_id)"

# The human sees the reply exactly once.
curl -s -o "$WORK/admin-msgs.json" "${BASE}/rooms/${ROOM}/messages?dir=b&limit=20" \
  -H "Authorization: Bearer $T_ADMIN"
PONGS=$(python3 -c 'import json,sys
doc=json.load(open(sys.argv[1]))
print(sum(1 for e in doc.get("chunk",[])
          if e.get("content",{}).get("body")=="pong"))' "$WORK/admin-msgs.json")
check "human sees the reply exactly once"       1 "$PONGS"

# A reaction is a distinct event type with NO body field. Built with python so
# the emoji is real UTF-8 — bash does not expand \x escapes inside "..." and the
# literal backslashes make the payload invalid JSON.
RX_BODY=$(python3 -c 'import json,sys
print(json.dumps({"m.relates_to":{"rel_type":"m.annotation",
                                  "event_id":sys.argv[1],"key":"\U0001F44D"}}))' "$CMD_EVENT")
check "bot can react"                           200 "$(req PUT "/rooms/${ROOM}/send/m.reaction/rx1" "$BOT_TOKEN" "$RX_BODY")"
RX_EVENT=$(jfield event_id)

# Reacting again with the same (sender, target, key) is IDEMPOTENT — the same
# event id back, not an error and not a second event. A fresh txnId, so this
# exercises the reaction dedup rather than the transaction replay.
check "duplicate reaction is idempotent"        200 "$(req PUT "/rooms/${ROOM}/send/m.reaction/rx2" "$BOT_TOKEN" "$RX_BODY")"
check "  returns the original reaction id"      "$RX_EVENT" "$(jfield event_id)"

# Reaction content is validated now.
check "reaction needs m.annotation rel_type"    400 "$(req PUT "/rooms/${ROOM}/send/m.reaction/rx3" "$BOT_TOKEN" \
  "{\"m.relates_to\":{\"rel_type\":\"m.replace\",\"event_id\":\"${CMD_EVENT}\",\"key\":\"x\"}}")"
check "reaction needs a key"                    400 "$(req PUT "/rooms/${ROOM}/send/m.reaction/rx4" "$BOT_TOKEN" \
  "{\"m.relates_to\":{\"rel_type\":\"m.annotation\",\"event_id\":\"${CMD_EVENT}\"}}")"
check "reaction key is length-bounded"          400 "$(req PUT "/rooms/${ROOM}/send/m.reaction/rx5" "$BOT_TOKEN" \
  "$(python3 -c 'import json,sys
print(json.dumps({"m.relates_to":{"rel_type":"m.annotation",
                                  "event_id":sys.argv[1],"key":"x"*200}}))' "$CMD_EVENT")")"
check "reaction target must exist"              404 "$(req PUT "/rooms/${ROOM}/send/m.reaction/rx6" "$BOT_TOKEN" \
  '{"m.relates_to":{"rel_type":"m.annotation","event_id":"$nope:e2e","key":"x"}}')"

# The send endpoint is deny-by-default: an unrecognised type is refused rather
# than stored. This is the check that catches a regression back to the old
# allow-everything shape, which let a muted member write arbitrary events.
check "custom event types are REFUSED"          403 "$(req PUT "/rooms/${ROOM}/send/com.example.botstate/cs1" "$BOT_TOKEN" \
  '{"hello":"world"}')"

# /redact is idempotent on its txn id, in a namespace separate from sends.
REDACT_ME=$(req PUT "/rooms/${ROOM}/send/m.room.message/tmp1" "$BOT_TOKEN" \
  '{"msgtype":"m.notice","body":"delete me"}' >/dev/null; jfield event_id)
check "bot redacts its own message"             200 "$(req PUT "/rooms/${ROOM}/redact/${REDACT_ME}/rd1" "$BOT_TOKEN" '{"reason":"e2e"}')"
REDACTION_EVENT=$(jfield event_id)
check "retrying the redaction is idempotent"    200 "$(req PUT "/rooms/${ROOM}/redact/${REDACT_ME}/rd1" "$BOT_TOKEN" '{"reason":"e2e"}')"
check "  returns the original redaction id"     "$REDACTION_EVENT" "$(jfield event_id)"

# ── phase 5: invite auto-joins a bot ─────────────────────────────────────
echo
echo "── T5: inviting a bot joins it outright ─────────────────────────────"

# A SECOND channel, which the bot is not in — bots are excluded from auto-join,
# so a channel created now leaves the bot outside it.
curl -s -o "$WORK/last-body.json" -X POST "${BASE}/createRoom" -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' -d '{"name":"ops","visibility":"public"}' >/dev/null
ROOM2=$(jfield room_id)
[[ -n "$ROOM2" ]] || die "admin could not create the second channel"
echo "     room2 = $ROOM2"

req GET "/joined_rooms" "$BOT_TOKEN" >/dev/null
if grep -q "$ROOM2" "$WORK/last-body.json"; then
  fail "bot is outside the new channel" "already in $ROOM2"
else
  note "bot is outside the new channel"
fi

# Park the bot's poll FIRST. The whole point of the design is that the bot does
# nothing: no invite to accept, no join call. It must simply observe itself
# joined, as an ordinary m.room.member event in the timeline.
#
# Drain first with timeout=0. The bot's own reply and reaction from T4 are still
# unconsumed, and a poll started from a token behind them returns instantly with
# those instead of waiting for the invite — which is exactly the "initial sync
# replays history" trap the docs warn bot authors about.
curl -s -o "$WORK/bot-drain.json" "${BASE}/sync?timeout=0&since=$(jfield_of "$WORK/bot-sync.json" next_batch)" \
  -H "Authorization: Bearer $BOT_TOKEN"
SINCE2=$(jfield_of "$WORK/bot-drain.json" next_batch)
[[ -n "$SINCE2" ]] || die "could not establish a drained sync position for the invite test"
( curl -s -o "$WORK/bot-invite-sync.json" \
    "${BASE}/sync?timeout=60000&since=${SINCE2}" \
    -H "Authorization: Bearer $BOT_TOKEN" ) &
SYNC_PID=$!
sleep 0.7

check "admin invites the bot"                   200 "$(req POST "/rooms/${ROOM2}/invite" "$T_ADMIN" \
  "{\"user_id\":\"${BOT_ID}\"}")"

wait $SYNC_PID 2>/dev/null

# The assertion that matters: a JOIN membership for the bot itself, in the new
# room, delivered without the bot ever calling /join.
if python3 - "$WORK/bot-invite-sync.json" "$ROOM2" "$BOT_ID" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
room = doc.get("rooms", {}).get("join", {}).get(sys.argv[2], {})
for e in room.get("timeline", {}).get("events", []):
    if (e.get("type") == "m.room.member"
            and e.get("state_key") == sys.argv[3]
            and e.get("content", {}).get("membership") == "join"):
        sys.exit(0)
sys.exit(1)
PY
then
  note "bot observed itself JOINED via sync" "no join call made"
else
  fail "bot observed itself JOINED via sync" "body=$(head -c 500 "$WORK/bot-invite-sync.json")"
fi

# Membership is real, not cosmetic: it can act there.
check "invited bot can post in that channel"    200 "$(req PUT "/rooms/${ROOM2}/send/m.room.message/inv1" "$BOT_TOKEN" \
  '{"msgtype":"m.notice","body":"invited, and here"}')"

req GET "/joined_rooms" "$BOT_TOKEN" >/dev/null
if grep -q "$ROOM2" "$WORK/last-body.json"; then
  note "joined_rooms now lists the channel"
else
  fail "joined_rooms now lists the channel" "body=$(cat "$WORK/last-body.json")"
fi

# Re-inviting a bot that is already in must be a no-op, not an error.
check "re-inviting is idempotent"               200 "$(req POST "/rooms/${ROOM2}/invite" "$T_ADMIN" \
  "{\"user_id\":\"${BOT_ID}\"}")"

# Human invite semantics must be UNCHANGED — a human is not force-joined by an
# invite. Bob is auto-joined to public channels, so use a private room to tell
# an invite apart from auto-join.
curl -s -o "$WORK/last-body.json" -X POST "${BASE}/createRoom" -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' -d '{"name":"private-room","visibility":"private"}' >/dev/null
ROOM3=$(jfield room_id)
if [[ -n "$ROOM3" ]]; then
  check "admin invites a HUMAN"                 200 "$(req POST "/rooms/${ROOM3}/invite" "$T_ADMIN" '{"user_id":"@bob:e2e"}')"
  req GET "/joined_rooms" "$T_BOB" >/dev/null
  if grep -q "$ROOM3" "$WORK/last-body.json"; then
    fail "  human is NOT force-joined" "bob was auto-joined to $ROOM3 by an invite"
  else
    note "  human is NOT force-joined" "invite semantics unchanged for people"
  fi
else
  fail "could not create a private room for the human-invite check"
fi

# ── phase 6: token rotation ──────────────────────────────────────────────
echo
echo "── T6: token rotation revokes the old credential ────────────────────"

OLD_TOKEN="$BOT_TOKEN"
check "admin rotates the bot token"             200 "$(req POST "/bsfchat/bots/${BOT_ID}/token" "$T_ADMIN")"
NEW_TOKEN=$(jfield token)
[[ -n "$NEW_TOKEN" ]] || die "rotation returned no token"

if [[ "$NEW_TOKEN" == "$OLD_TOKEN" ]]; then
  fail "rotation issued a different token"
else
  note "rotation issued a different token"
fi

check "OLD token is rejected"                   401 "$(req GET "/account/whoami" "$OLD_TOKEN")"
check "  with M_UNKNOWN_TOKEN"                  "M_UNKNOWN_TOKEN" "$(jfield errcode)"
check "OLD token cannot send"                   401 "$(req PUT "/rooms/${ROOM}/send/m.room.message/dead1" "$OLD_TOKEN" \
  '{"msgtype":"m.text","body":"should be rejected"}')"
check "OLD token cannot sync"                   401 "$(req GET "/sync?timeout=0" "$OLD_TOKEN")"

check "NEW token authenticates"                 200 "$(req GET "/account/whoami" "$NEW_TOKEN")"
check "  as the same bot"                       "$BOT_ID" "$(jfield user_id)"
# Rotation is a credential change, not a new account: membership survives.
check "NEW token is still in the room"          200 "$(req PUT "/rooms/${ROOM}/send/m.room.message/post-rot1" "$NEW_TOKEN" \
  '{"msgtype":"m.notice","body":"rotated and still here"}')"

check "plain user cannot rotate"                403 "$(req POST "/bsfchat/bots/${BOT_ID}/token" "$T_BOB")"

# ── phase 7: deactivation ────────────────────────────────────────────────
echo
echo "── T7: deactivation ─────────────────────────────────────────────────"

# DELETE is a DEACTIVATION, not a hard delete, and deliberately so: the row
# stays so the localpart remains reserved (a recreated "bot_deploy" would
# otherwise inherit a previous bot's name) and so there is a record. What must
# be true is that the credential dies and the account cannot act or be revived.
check "plain user cannot deactivate"            403 "$(req DELETE "/bsfchat/bots/${BOT_ID}" "$T_BOB")"
check "admin deactivates the bot"               200 "$(req DELETE "/bsfchat/bots/${BOT_ID}" "$T_ADMIN")"
check "deactivated bot's token is dead"         401 "$(req GET "/account/whoami" "$NEW_TOKEN")"
check "  and it cannot sync"                    401 "$(req GET "/sync?timeout=0" "$NEW_TOKEN")"
check "  and it cannot send"                    401 "$(req PUT "/rooms/${ROOM}/send/m.room.message/zombie1" "$NEW_TOKEN" \
  '{"msgtype":"m.text","body":"should be rejected"}')"

# Deactivation must be a one-way door. If rotating could mint a fresh token,
# "deactivated" would only mean "until somebody rotates it".
check "deactivated bot cannot be revived"       400 "$(req POST "/bsfchat/bots/${BOT_ID}/token" "$T_ADMIN")"

# Nor talked back into a channel by inviting it. If an invite could re-join a
# deactivated bot, "deactivated" would only hold until somebody invited it.
INV_STATUS=$(req POST "/rooms/${ROOM2}/invite" "$T_ADMIN" "{\"user_id\":\"${BOT_ID}\"}")
if [[ "$INV_STATUS" == "400" || "$INV_STATUS" == "403" ]]; then
  note "inviting a deactivated bot is refused" "$INV_STATUS"
else
  fail "inviting a deactivated bot is refused" "got $INV_STATUS body=$(cat "$WORK/last-body.json")"
fi

# Deactivating twice must not error or double-log.
check "deactivation is idempotent"              200 "$(req DELETE "/bsfchat/bots/${BOT_ID}" "$T_ADMIN")"

req GET "/bsfchat/bots" "$T_ADMIN" >/dev/null
if python3 - "$WORK/last-body.json" "$BOT_ID" <<'PY'
import json, sys
bots = json.load(open(sys.argv[1])).get("bots", [])
row = next((b for b in bots if b.get("user_id") == sys.argv[2]), None)
sys.exit(0 if row is not None and row.get("deactivated") is True else 1)
PY
then
  note "still listed, flagged deactivated"
else
  fail "still listed, flagged deactivated" "body=$(cat "$WORK/last-body.json")"
fi

# The localpart stays taken, which is the point of keeping the row.
check "localpart stays reserved"                400 "$(req POST "/bsfchat/bots" "$T_ADMIN" \
  '{"localpart":"bot_e2e","display_name":"Impostor","description":""}')"
check "  with M_USER_IN_USE"                    "M_USER_IN_USE" "$(jfield errcode)"

stop_server

# ── guard: the real dev database must be byte-identical ──────────────────
snapshot > "$WORK/real-after.txt"
if ! diff -q "$WORK/real-before.txt" "$WORK/real-after.txt" > /dev/null; then
  echo; echo "FATAL: $REALDATA CHANGED during the E2E run:"
  diff "$WORK/real-before.txt" "$WORK/real-after.txt"
  exit 91
fi
echo
echo "guard: $REALDATA byte-identical before and after (verified, $(wc -l < "$WORK/real-before.txt") files)"
echo "guard: server used $WORK/e2e.db ($(wc -c < "$WORK/e2e.db") bytes)"
echo
echo "checks=$CHECKS failures=$FAILURES"
rm -rf "$WORK"
exit $(( FAILURES > 0 ? 1 : 0 ))
