#!/bin/bash
# End-to-end check that a human account can see, accept and refuse an invite,
# against the REAL bsfchat-server binary over HTTP.
#
# The unit tests call SyncEngine and RoomHandler directly. What they cannot
# cover is the wire: whether rooms.invite survives serialization, what an
# invitee's /sync actually contains, and — the part that matters most here —
# what it does NOT contain for a room they have not joined. A leak check is
# worth little if it only ever looks at a C++ struct.
#
# Safety: everything lives under a throwaway directory. The real dev database
# is checksummed before and after and the script HARD-FAILS if a single byte
# changed, and hard-fails if the server did not create its database at the
# configured path (which is how a misparsed TOML would show up).
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1
WORK=$(mktemp -d /tmp/bsfchat-invites-e2e-XXXXXX)
REALDATA=$(e2e_real_data_dir || echo /nonexistent)
PORT=${PORT:-8903}
BASE="http://127.0.0.1:${PORT}/_matrix/client/v3"
FAILURES=0
CHECKS=0
SRV_PID=""

cleanup() {
  if [[ -n "${SRV_PID:-}" ]]; then kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; fi
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 90; }

# Conditional, the way e2e_voice.sh does it: this script is registered with
# ctest and so runs in CI, where there is no sibling dev data directory to
# protect and an unconditional checksum would abort the run. Where there IS one,
# failing to read it aborts rather than running blind.
snapshot() { find "$REALDATA" -type f -exec shasum {} \; 2>/dev/null | sort; }
if [[ -d "$REALDATA" ]]; then
  snapshot > "$WORK/real-before.txt"
  [[ -s "$WORK/real-before.txt" ]] || die "could not checksum $REALDATA; refusing to run blind"
else
  echo "no live dev data directory alongside this checkout; nothing to guard"
fi

# TOML TABLES, not flat keys. A flat `database_path = ...` parses to nothing and
# the server silently falls back to its default path — which is how a previous
# run migrated the owner's real database.
cat > "$WORK/server.toml" <<EOF
[server]
name = "e2e"
bind_address = "127.0.0.1"
port = ${PORT}
workers = 4

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
  if lsof -nP -iTCP:${PORT} -sTCP:LISTEN >/dev/null 2>&1; then
    die "port ${PORT} is already in use (another server is listening); refusing to run"
  fi
  ( cd "$WORK" && exec "$BIN" --config "$WORK/server.toml" > "$WORK/server-$1.log" 2>&1 ) &
  SRV_PID=$!
  for _ in $(seq 1 100); do
    if curl -sf "http://127.0.0.1:${PORT}/_matrix/client/versions" > /dev/null 2>&1; then return 0; fi
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

req() { # req METHOD PATH TOKEN BODY -> prints HTTP status
  local m=$1 p=$2 t=${3:-} b=${4:-}
  local args=(-s -o "$WORK/last-body.json" -w '%{http_code}' -X "$m" "${BASE}${p}")
  [[ -n "$t" ]] && args+=(-H "Authorization: Bearer $t")
  [[ -n "$b" ]] && args+=(-H 'Content-Type: application/json' -d "$b")
  curl "${args[@]}"
}

check() { # check LABEL EXPECTED ACTUAL
  CHECKS=$((CHECKS+1))
  if [[ "$2" == "$3" ]]; then
    printf 'ok   %-62s %s\n' "$1" "$3"
  else
    printf 'FAIL %-62s expected %s got %s  body=%s\n' "$1" "$2" "$3" "$(head -c 400 "$WORK/last-body.json" 2>/dev/null)"
    FAILURES=$((FAILURES+1))
  fi
}

jfield() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$WORK/last-body.json" "$1"; }

register() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"e2e-invites-pw-7Kq2\",\"auth\":{\"type\":\"m.login.dummy\"}}" >/dev/null
  jfield access_token
}
login() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/login" -H 'Content-Type: application/json' \
    -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"$1\"},\"password\":\"e2e-invites-pw-7Kq2\"}" >/dev/null
  jfield access_token
}
create_private_room() { # create_private_room TOKEN NAME -> room id
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/createRoom" -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$2\",\"visibility\":\"private\",\"topic\":\"the $2 channel\"}" >/dev/null
  jfield room_id
}
send() { # send TOKEN ROOM BODY
  curl -s -o /dev/null -X PUT \
    "${BASE}/rooms/$2/send/m.room.message/$(date +%s%N)" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d "{\"msgtype\":\"m.text\",\"body\":\"$3\"}"
}

# /sync into a named file, so each assertion reads a snapshot rather than
# racing a fresh request.
sync_to() { # sync_to TOKEN SINCE FILE [TIMEOUT]
  local q="?timeout=${4:-0}"
  [[ -n "$2" ]] && q="${q}&since=$2"
  curl -s -o "$3" -X GET "${BASE}/sync${q}" -H "Authorization: Bearer $1"
}

# The invite assertions all reduce to questions about one /sync body, so they go
# through one python helper rather than a pile of greps: "grep -q invite" would
# pass on the word appearing anywhere, including in a join_rule.
#
# Prints a line per query. Usage: probe FILE ROOM QUERY...
#   invited          -> yes/no   room is in rooms.invite
#   joined           -> yes/no   room is in rooms.join
#   state_types      -> sorted "type/state_key" list from invite_state
#   invite_keys      -> the JSON keys of the rooms.invite entry
#   leaked           -> any m.room.message body reachable anywhere in the body
probe() {
  python3 - "$1" "$2" "${@:3}" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
room = sys.argv[2]
rooms = body.get("rooms", {})
inv = rooms.get("invite", {}).get(room)
for q in sys.argv[3:]:
    if q == "invited":
        print("yes" if inv is not None else "no")
    elif q == "joined":
        print("yes" if room in rooms.get("join", {}) else "no")
    elif q == "state_types":
        evs = (inv or {}).get("invite_state", {}).get("events", [])
        print(",".join(sorted(f"{e.get('type')}/{e.get('state_key','')}" for e in evs)))
    elif q == "invite_keys":
        print(",".join(sorted((inv or {}).keys())))
    elif q == "leaked":
        # Every message body anywhere in the response, whatever section it
        # arrived in. This is the check that a struct-level test cannot make.
        found = []
        def walk(node):
            if isinstance(node, dict):
                if node.get("type") == "m.room.message":
                    found.append(node.get("content", {}).get("body", "?"))
                for v in node.values(): walk(v)
            elif isinstance(node, list):
                for v in node: walk(v)
        walk(body)
        print(";".join(found) if found else "none")
    else:
        print("?" + q)
PY
}

# ── accounts ─────────────────────────────────────────────────────────────
start_server first
[[ -f "$WORK/e2e.db" ]] || die "server did not create its database at the CONFIGURED path ($WORK/e2e.db) — TOML likely misparsed"

T_ALICE=$(register alice); T_BOB=$(register bob); T_CAROL=$(register carol)
[[ -n "$T_ALICE" && -n "$T_BOB" && -n "$T_CAROL" ]] || { cat "$WORK/server-first.log"; die "registration failed"; }
stop_server

# Restart so bootstrap_roles grants the admin role to the OLDEST account (alice).
start_server second
T_ALICE=$(login alice); T_BOB=$(login bob); T_CAROL=$(login carol)
[[ -n "$T_ALICE" && -n "$T_BOB" && -n "$T_CAROL" ]] || die "login failed after restart"
B="@bob:e2e"; C="@carol:e2e"

echo
echo "── T1: an invite arrives, and as an invite ──────────────────────────"

ROOM=$(create_private_room "$T_ALICE" planning)
[[ -n "$ROOM" ]] || die "room creation failed"
echo "     room=$ROOM"

# Carol joins and the room gets some history, so there is something to leak.
check "carol is invited to the private room" 200 \
  "$(req POST "/rooms/$ROOM/invite" "$T_ALICE" "{\"user_id\":\"$C\"}")"
check "carol accepts" 200 "$(req POST "/rooms/$ROOM/join" "$T_CAROL")"
send "$T_ALICE" "$ROOM" "the merger closes friday"
send "$T_CAROL" "$ROOM" "does legal know"

# Bob's token BEFORE he is invited, so the next poll is a genuine delta.
sync_to "$T_BOB" "" "$WORK/bob-0.json"
SINCE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["next_batch"])' "$WORK/bob-0.json")
check "bob sees no invite before there is one" "no" "$(probe "$WORK/bob-0.json" "$ROOM" invited)"

check "alice invites bob" 200 \
  "$(req POST "/rooms/$ROOM/invite" "$T_ALICE" "{\"user_id\":\"$B\"}")"

sync_to "$T_BOB" "$SINCE" "$WORK/bob-1.json"
check "the invite reaches bob's /sync" "yes" "$(probe "$WORK/bob-1.json" "$ROOM" invited)"
check "...and not as a joined room"     "no"  "$(probe "$WORK/bob-1.json" "$ROOM" joined)"
check "...under invite_state, Matrix's shape" "invite_state" \
  "$(probe "$WORK/bob-1.json" "$ROOM" invite_keys)"

echo
echo "── T2: stripped state — what bob may and may not read ──────────────"

TYPES=$(probe "$WORK/bob-1.json" "$ROOM" state_types)
echo "     invite_state: $TYPES"
for want in "m.room.name/" "m.room.create/" "m.room.join_rules/" "m.room.member/$B" "m.room.member/@alice:e2e"; do
  CHECKS=$((CHECKS+1))
  if [[ ",$TYPES," == *",$want,"* ]]; then
    printf 'ok   %-62s\n' "invite_state carries $want"
  else
    printf 'FAIL %-62s got %s\n' "invite_state is missing $want" "$TYPES"
    FAILURES=$((FAILURES+1))
  fi
done
for unwanted in "m.room.power_levels/" "m.room.member/$C"; do
  CHECKS=$((CHECKS+1))
  if [[ ",$TYPES," == *",$unwanted,"* ]]; then
    printf 'FAIL %-62s got %s\n' "invite_state must NOT carry $unwanted" "$TYPES"
    FAILURES=$((FAILURES+1))
  else
    printf 'ok   %-62s\n' "invite_state withholds $unwanted"
  fi
done

# Each state event exactly once. Finding the inviter means reading bob's own
# member event and asking the room again, and asking again used to re-select
# the room's own state with it — every name, topic and join rule arrived twice.
CHECKS=$((CHECKS+1))
DUPES=$(printf '%s' "$TYPES" | tr ',' '\n' | sort | uniq -d | paste -sd' ' -)
if [[ -z "$DUPES" ]]; then
  printf 'ok   %-62s\n' "invite_state carries each state event once"
else
  printf 'FAIL %-62s dupes: %s\n' "invite_state has duplicate state events" "$DUPES"
  FAILURES=$((FAILURES+1))
fi

# The one that matters: no message from a room bob has not joined, in ANY
# section of the response.
check "no message from the room reaches the invitee" "none" \
  "$(probe "$WORK/bob-1.json" "$ROOM" leaked)"

# Still true once the room goes on living underneath him.
send "$T_ALICE" "$ROOM" "and the price is 4.2bn"
sync_to "$T_BOB" "$SINCE" "$WORK/bob-2.json"
check "...still none after more traffic" "none" \
  "$(probe "$WORK/bob-2.json" "$ROOM" leaked)"
check "...and the invite is still stated" "yes" \
  "$(probe "$WORK/bob-2.json" "$ROOM" invited)"

# /messages is the other way into a room's history.
check "GET /messages is refused for a room he has not joined" 403 \
  "$(req GET "/rooms/$ROOM/messages?limit=10" "$T_BOB")"

echo
echo "── T3: an invite older than the client's token ──────────────────────"

# Bob's client walks its token to the head WITHOUT being shown the invite —
# the state every account on an upgraded server starts in.
sync_to "$T_BOB" "" "$WORK/bob-head.json"
HEAD=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["next_batch"])' "$WORK/bob-head.json")
sync_to "$T_BOB" "$HEAD" "$WORK/bob-3.json"
check "a pending invite is restated past its own position" "yes" \
  "$(probe "$WORK/bob-3.json" "$ROOM" invited)"

echo
echo "── T4: a restated invite must not turn the long poll into a spin ───"

# An invite counted as payload would return instantly, forever, for as long as
# it stayed unanswered. This poll must block for its timeout instead.
sync_to "$T_BOB" "$HEAD" "$WORK/bob-head2.json"
HEAD2=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["next_batch"])' "$WORK/bob-head2.json")
START=$(python3 -c 'import time;print(int(time.time()*1000))')
sync_to "$T_BOB" "$HEAD2" "$WORK/bob-4.json" 1500
ELAPSED=$(python3 -c "import time;print(int(time.time()*1000)-$START)")
CHECKS=$((CHECKS+1))
if [[ "$ELAPSED" -ge 1200 ]]; then
  printf 'ok   %-62s %sms\n' "the poll parked rather than returning on the invite" "$ELAPSED"
else
  printf 'FAIL %-62s returned after %sms\n' "the poll span on a restated invite" "$ELAPSED"
  FAILURES=$((FAILURES+1))
fi
check "...and the idle reply still carries the invite" "yes" \
  "$(probe "$WORK/bob-4.json" "$ROOM" invited)"

echo
echo "── T5: a parked poll is woken by the invite, not by its timeout ────"

ROOM2=$(create_private_room "$T_ALICE" strategy)
[[ -n "$ROOM2" ]] || die "second room creation failed"
sync_to "$T_BOB" "" "$WORK/bob-5a.json"
SINCE2=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["next_batch"])' "$WORK/bob-5a.json")

START=$(python3 -c 'import time;print(int(time.time()*1000))')
sync_to "$T_BOB" "$SINCE2" "$WORK/bob-5.json" 20000 &
POLL=$!
sleep 1
req POST "/rooms/$ROOM2/invite" "$T_ALICE" "{\"user_id\":\"$B\"}" > /dev/null
wait $POLL
ELAPSED=$(python3 -c "import time;print(int(time.time()*1000)-$START)")
check "the parked poll came back with the invite" "yes" \
  "$(probe "$WORK/bob-5.json" "$ROOM2" invited)"
CHECKS=$((CHECKS+1))
if [[ "$ELAPSED" -lt 6000 ]]; then
  printf 'ok   %-62s %sms\n' "...promptly, not at the poll timeout" "$ELAPSED"
else
  printf 'FAIL %-62s took %sms (poll timeout was 20000)\n' "the invite waited out the poll" "$ELAPSED"
  FAILURES=$((FAILURES+1))
fi

echo
echo "── T6: accepting, off the back of the invite ───────────────────────"

# The room is invite-only, so this 200 is itself the proof that the invite is
# what admitted him.
check "bob joins the room he was invited to" 200 "$(req POST "/rooms/$ROOM/join" "$T_BOB")"
sync_to "$T_BOB" "$SINCE" "$WORK/bob-6.json"
check "the room is now joined" "yes" "$(probe "$WORK/bob-6.json" "$ROOM" joined)"
check "...and no longer an invite" "no" "$(probe "$WORK/bob-6.json" "$ROOM" invited)"
check "...and the history he may now read is there" 200 \
  "$(req GET "/rooms/$ROOM/messages?limit=10" "$T_BOB")"
CHECKS=$((CHECKS+1))
if grep -q "the merger closes friday" "$WORK/last-body.json"; then
  printf 'ok   %-62s\n' "a joined member reads the backlog"
else
  printf 'FAIL %-62s body=%s\n' "a joined member should read the backlog" "$(head -c 200 "$WORK/last-body.json")"
  FAILURES=$((FAILURES+1))
fi

echo
echo "── T7: declining ───────────────────────────────────────────────────"

# ROOM2's invite is still outstanding. /leave is the decline; it used to be
# join-only, so an invitee could accept and not refuse.
check "bob declines the other invite" 200 "$(req POST "/rooms/$ROOM2/leave" "$T_BOB")"
sync_to "$T_BOB" "$SINCE2" "$WORK/bob-7.json"
check "the declined invite is gone from /sync" "no" \
  "$(probe "$WORK/bob-7.json" "$ROOM2" invited)"
check "...and it did not become a joined room" "no" \
  "$(probe "$WORK/bob-7.json" "$ROOM2" joined)"
check "declining twice is refused" 403 "$(req POST "/rooms/$ROOM2/leave" "$T_BOB")"
check "a declined invite does not admit him" 403 "$(req POST "/rooms/$ROOM2/join" "$T_BOB")"

stop_server

# ── guard: the real dev database must be byte-identical ──────────────────
if [[ -f "$WORK/real-before.txt" ]]; then
  snapshot > "$WORK/real-after.txt"
  if ! diff -q "$WORK/real-before.txt" "$WORK/real-after.txt" > /dev/null; then
    echo "FATAL: the real dev database at $REALDATA CHANGED during this run:"
    diff "$WORK/real-before.txt" "$WORK/real-after.txt"
    exit 91
  fi
  echo
  echo "real dev database unchanged (verified byte-for-byte)"
fi

echo
echo "══ $((CHECKS - FAILURES))/${CHECKS} checks passed ══"
[[ $FAILURES -eq 0 ]] || exit 1
