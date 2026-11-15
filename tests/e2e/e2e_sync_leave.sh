#!/bin/bash
# End-to-end check of /sync's rooms.leave section (audit 2026-11-15, R-1),
# against the REAL bsfchat-server binary over HTTP.
#
# The section is not in the protocol's SyncResponse yet: SyncHandler writes it
# into the JSON after to_json (sync/SyncEngine.h, attach_leave_section). So the
# unit tests, which read SyncResult, cannot see whether it actually reaches the
# wire. This does:
#   L1  your own leave arrives as rooms.leave, reason "leave", with the event
#   L2  a deleted channel arrives as rooms.leave, reason "deleted"
#   L3  a deletion wakes a PARKED poll promptly instead of at timeout
#   L4  /joined_rooms agrees: neither room is listed any more
#
# Safety: identical to e2e_invites.sh — throwaway directory, the real dev
# database is checksummed before and after, and the configured database path
# must be the one the server created.
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1
WORK=$(mktemp -d /tmp/bsfchat-leave-e2e-XXXXXX)
REALDATA=$(e2e_real_data_dir || echo /nonexistent)
PORT=${PORT:-8913}
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
    -d "{\"username\":\"$1\",\"password\":\"e2e-leave-pw-3Rv8\",\"auth\":{\"type\":\"m.login.dummy\"}}" >/dev/null
  jfield access_token
}
login() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/login" -H 'Content-Type: application/json' \
    -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"$1\"},\"password\":\"e2e-leave-pw-3Rv8\"}" >/dev/null
  jfield access_token
}
# /sync into a named file, so each assertion reads a snapshot rather than
# racing a fresh request.
sync_to() { # sync_to TOKEN SINCE FILE [TIMEOUT]
  local q="?timeout=${4:-0}"
  [[ -n "$2" ]] && q="${q}&since=$2"
  curl -s -o "$3" -X GET "${BASE}/sync${q}" -H "Authorization: Bearer $1"
}

# Same request, but the poll TIMES ITSELF and the span lands in $SPAN_MS.
#
# T4 and T5 below both turn on how long a poll blocked, and they used to get
# that by shelling out to `python3 -c 'import time'` on either side of the
# call. Two interpreter starts inside the measured interval is tens of
# milliseconds on an idle box and can be hundreds on a busy one, which is
# noise the server did not produce. curl's %{time_total} is measured inside
# the process that made the request, so what comes back is the poll and
# nothing else. The one python3 call left converts the result afterwards,
# outside the interval.
SPAN_MS=0
sync_to_timed() { # sync_to_timed TOKEN SINCE FILE TIMEOUT -> sets SPAN_MS
  local q="?timeout=${4}"
  [[ -n "$2" ]] && q="${q}&since=$2"
  curl -s -o "$3" -w '%{time_total}' -X GET "${BASE}/sync${q}" \
    -H "Authorization: Bearer $1" > "$3.t"
  SPAN_MS=$(python3 -c "print(int(float(open('$3.t').read().strip())*1000))" 2>/dev/null || echo 0)
}


create_public_room() { # create_public_room TOKEN NAME -> room id
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/createRoom" -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$2\",\"visibility\":\"public\"}" >/dev/null
  jfield room_id
}
next_batch() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["next_batch"])' "$1"; }

# Usage: leave_probe FILE ROOM QUERY...
#   listed     -> yes/no  room is a key of rooms.leave
#   reason     -> its bsfchat.reason
#   events     -> "type/state_key/membership" for each timeline event
#   joined     -> yes/no  room is in rooms.join
leave_probe() {
  python3 - "$1" "$2" "${@:3}" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
room = sys.argv[2]
rooms = body.get("rooms", {})
left = rooms.get("leave", {}).get(room)
for q in sys.argv[3:]:
    if q == "listed":
        print("yes" if left is not None else "no")
    elif q == "reason":
        print((left or {}).get("bsfchat.reason", ""))
    elif q == "events":
        evs = (left or {}).get("timeline", {}).get("events", [])
        print(",".join(f"{e.get('type')}/{e.get('state_key','')}/{e.get('content',{}).get('membership','')}" for e in evs))
    elif q == "joined":
        print("yes" if room in rooms.get("join", {}) else "no")
    else:
        print("?" + q)
PY
}
in_joined_rooms() { # in_joined_rooms TOKEN ROOM -> yes/no
  curl -s -o "$WORK/jr.json" -X GET "${BASE}/joined_rooms" -H "Authorization: Bearer $1"
  python3 -c 'import json,sys;print("yes" if sys.argv[2] in json.load(open(sys.argv[1])).get("joined_rooms",[]) else "no")' "$WORK/jr.json" "$2"
}

# ── accounts ─────────────────────────────────────────────────────────────
start_server first
[[ -f "$WORK/e2e.db" ]] || die "server did not create its database at the CONFIGURED path ($WORK/e2e.db) — TOML likely misparsed"
T_ALICE=$(register alice); T_BOB=$(register bob)
[[ -n "$T_ALICE" && -n "$T_BOB" ]] || { cat "$WORK/server-first.log"; die "registration failed"; }
stop_server
# Restart so bootstrap_roles grants the admin role to the OLDEST account (alice).
start_server second
T_ALICE=$(login alice); T_BOB=$(login bob)
[[ -n "$T_ALICE" && -n "$T_BOB" ]] || die "login failed after restart"
B="@bob:e2e"

echo
echo "── L1: your own leave ──────────────────────────────────────────────"
ROOM=$(create_public_room "$T_ALICE" general)
[[ -n "$ROOM" ]] || die "room creation failed"
sync_to "$T_BOB" "" "$WORK/bob-0.json"
check "bob was auto-joined to the public channel" "yes" "$(leave_probe "$WORK/bob-0.json" "$ROOM" joined)"
SINCE=$(next_batch "$WORK/bob-0.json")
check "bob leaves (from another device)" 200 "$(req POST "/rooms/$ROOM/leave" "$T_BOB")"
sync_to "$T_BOB" "$SINCE" "$WORK/bob-1.json"
check "the room is in rooms.leave"          "yes"   "$(leave_probe "$WORK/bob-1.json" "$ROOM" listed)"
check "...with bsfchat.reason = leave"      "leave" "$(leave_probe "$WORK/bob-1.json" "$ROOM" reason)"
check "...carrying bob's own leave event"   "m.room.member/$B/leave" \
  "$(leave_probe "$WORK/bob-1.json" "$ROOM" events)"
check "...and not in rooms.join"            "no"    "$(leave_probe "$WORK/bob-1.json" "$ROOM" joined)"
sync_to "$T_BOB" "$(next_batch "$WORK/bob-1.json")" "$WORK/bob-1b.json"
check "it is not repeated on the next poll" "no"    "$(leave_probe "$WORK/bob-1b.json" "$ROOM" listed)"

echo
echo "── L2: a deleted channel ───────────────────────────────────────────"
DOOMED=$(create_public_room "$T_ALICE" doomed)
[[ -n "$DOOMED" ]] || die "room creation failed"
sync_to "$T_BOB" "" "$WORK/bob-2a.json"
SINCE2=$(next_batch "$WORK/bob-2a.json")
check "alice deletes the channel" 200 "$(req DELETE "/rooms/$DOOMED" "$T_ALICE")"
sync_to "$T_BOB" "$SINCE2" "$WORK/bob-2.json"
check "bob is told to drop it"          "yes"     "$(leave_probe "$WORK/bob-2.json" "$DOOMED" listed)"
check "...with bsfchat.reason = deleted" "deleted" "$(leave_probe "$WORK/bob-2.json" "$DOOMED" reason)"
check "...and an empty timeline"         ""        "$(leave_probe "$WORK/bob-2.json" "$DOOMED" events)"

echo
echo "── L3: deletion wakes a parked poll ────────────────────────────────"
DOOMED2=$(create_public_room "$T_ALICE" doomed-too)
[[ -n "$DOOMED2" ]] || die "room creation failed"
sync_to "$T_BOB" "" "$WORK/bob-3a.json"
SINCE3=$(next_batch "$WORK/bob-3a.json")
( sleep 0.5; curl -s -o /dev/null -X DELETE "${BASE}/rooms/$DOOMED2" -H "Authorization: Bearer $T_ALICE" ) &
DELETER=$!
sync_to_timed "$T_BOB" "$SINCE3" "$WORK/bob-3.json" 20000
wait "$DELETER"
check "the parked poll carried the deletion" "deleted" "$(leave_probe "$WORK/bob-3.json" "$DOOMED2" reason)"
CHECKS=$((CHECKS+1))
if (( SPAN_MS < 10000 )); then
  printf 'ok   %-62s %s ms\n' "...and returned well before its 20 s timeout" "$SPAN_MS"
else
  printf 'FAIL %-62s %s ms\n' "...and returned well before its 20 s timeout" "$SPAN_MS"
  FAILURES=$((FAILURES+1))
fi

echo
echo "── L4: /joined_rooms agrees ────────────────────────────────────────"
check "the room bob left is not in /joined_rooms" "no" "$(in_joined_rooms "$T_BOB" "$ROOM")"
check "the deleted room is not in /joined_rooms"  "no" "$(in_joined_rooms "$T_BOB" "$DOOMED")"

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
