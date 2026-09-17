#!/bin/bash
# Measures end-to-end text-message delivery latency: the wall-clock gap between
# Alice's PUT /send returning and Bob's already-pending /sync long poll coming
# back with that message.
#
# This exists because "messages take ages to arrive" is unfalsifiable from the
# code alone. The interesting number is not how fast a single idle server
# answers — that has always been quick — but what happens once the httplib
# worker pool is saturated by long polls, which is the normal steady state of
# this product: every connected client parks a 30s /sync on a worker and holds
# it there.
#
# WORKERS is deliberately a parameter so the same script produces the
# before/after numbers for a pool-sizing change.
#
#   WORKERS=4 ./e2e_sync_latency.sh     # what production shipped
#   WORKERS=32 ./e2e_sync_latency.sh
#
# HOLDERS simulates the *other* connections a real client keeps open besides
# its sync (the 5s voice poll, identity-key fetches, media). Each is a separate
# TCP connection, and httplib dispatches one pool task per CONNECTION for the
# whole keep-alive session, so each one pins a worker.
set -u
SCRATCH="$(cd "$(dirname "$0")" && pwd)"
source "$SCRATCH/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1

WORKERS=${WORKERS:-4}
HOLDERS=${HOLDERS:-2}
ROUNDS=${ROUNDS:-3}
PORT=${PORT:-18471}
BASE="http://127.0.0.1:$PORT"
RUN="$SCRATCH/e2e-run-latency"

rm -rf "$RUN"; mkdir -p "$RUN/data" "$RUN/media"
cat > "$RUN/server.toml" <<EOF
[server]
name = "latency.test"
bind_address = "127.0.0.1"
port = $PORT
workers = $WORKERS

[database]
path = "$RUN/data/bsfchat.db"

[media]
path = "$RUN/media/"

[auth]
registration_enabled = true
password_hash_cost = 12

[voice]
enabled = false

[push]
enabled = false
EOF

( cd "$RUN" && exec "$BIN" --config "$RUN/server.toml" ) > "$RUN/server.log" 2>&1 &
SV_PID=$!
cleanup(){ kill $SV_PID 2>/dev/null; pkill -P $$ curl 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

for _ in $(seq 1 80); do
  curl -sf "$BASE/_matrix/client/versions" >/dev/null 2>&1 && break
  sleep 0.25
done
grep -q "Server name: latency.test" "$RUN/server.log" || {
  echo "FATAL: config not honoured"; tail -20 "$RUN/server.log"; exit 1; }

jqf(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
reg(){ curl -s -X POST "$BASE/_matrix/client/v3/register" -H 'Content-Type: application/json' \
       -d "{\"username\":\"$1\",\"password\":\"password123\"}"; }

A=$(reg alice); B=$(reg bob)
AT=$(printf '%s' "$A" | jqf "['access_token']")
BT=$(printf '%s' "$B" | jqf "['access_token']")
[ -n "$AT" ] && [ -n "$BT" ] || { echo "registration failed: $A / $B"; exit 1; }

ROOM=$(curl -s -X POST "$BASE/_matrix/client/v3/createRoom" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"name":"latency","visibility":"public"}' \
  | jqf "['room_id']")
[ -n "$ROOM" ] || { echo "createRoom failed"; exit 1; }
curl -s -o /dev/null -X POST "$BASE/_matrix/client/v3/rooms/$ROOM/join" -H "Authorization: Bearer $BT"

# Bob's starting position. Also warms the connection pool.
SINCE=$(curl -s "$BASE/_matrix/client/v3/sync?timeout=0" -H "Authorization: Bearer $BT" | jqf "['next_batch']")

echo "== workers=$WORKERS holders=$HOLDERS rounds=$ROUNDS =="

# Saturate the pool the way real clients do: each holder is its OWN connection
# parked on a long poll, exactly like a second/third signed-in desktop client.
HOLDER_PIDS=()
for i in $(seq 1 "$HOLDERS"); do
  curl -s -o /dev/null \
    "$BASE/_matrix/client/v3/sync?timeout=30000&since=$SINCE" \
    -H "Authorization: Bearer $AT" &
  HOLDER_PIDS+=($!)
done
sleep 1.0   # let every holder actually reach the server and claim a worker

TOTAL=0
for r in $(seq 1 "$ROUNDS"); do
  # Bob's pending long poll, on its own connection, timestamped the instant it
  # returns. --no-keepalive so each round is a fresh connection, which is what
  # a client that just consumed a sync and immediately re-polls looks like.
  ( curl -s -o "$RUN/bob.$r.json" \
      "$BASE/_matrix/client/v3/sync?timeout=30000&since=$SINCE" \
      -H "Authorization: Bearer $BT"
    python3 -c "import time;print(time.time())" > "$RUN/bob.$r.done" ) &
  BOB_PID=$!
  sleep 0.6   # Bob is now blocked inside the server's condition variable

  T0=$(python3 -c "import time;print(time.time())")
  SENT=$(curl -s -X PUT \
    "$BASE/_matrix/client/v3/rooms/$ROOM/send/m.room.message/lat$r" \
    -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
    -d "{\"msgtype\":\"m.text\",\"body\":\"round $r\"}")
  T1=$(python3 -c "import time;print(time.time())")

  wait $BOB_PID 2>/dev/null
  T2=$(cat "$RUN/bob.$r.done" 2>/dev/null || echo "$T1")

  GOT=$(python3 -c "
import json,sys
d=json.load(open('$RUN/bob.$r.json'))
n=sum(len(v.get('timeline',{}).get('events',[])) for v in d.get('rooms',{}).get('join',{}).values())
print(n)" 2>/dev/null || echo 0)

  read -r SEND_MS DELIV_MS <<<"$(python3 -c "print(f'{($T1-$T0)*1000:.0f} {($T2-$T0)*1000:.0f}')")"
  printf "  round %d: send(PUT) %6s ms   delivery(send->sync returns) %6s ms   events=%s\n" \
    "$r" "$SEND_MS" "$DELIV_MS" "$GOT"
  printf '%s' "$SENT" | grep -q event_id || echo "        WARN: send did not return an event_id: $SENT"
  TOTAL=$(python3 -c "print($TOTAL + $DELIV_MS)")

  SINCE=$(python3 -c "
import json;print(json.load(open('$RUN/bob.$r.json'))['next_batch'])" 2>/dev/null || echo "$SINCE")
done

for p in "${HOLDER_PIDS[@]}"; do kill "$p" 2>/dev/null; done

AVG=$(python3 -c "print(f'{$TOTAL/$ROUNDS:.0f}')")
echo "  mean delivery: ${AVG} ms"
# Under 200ms is the bar: on loopback with an event-driven wake-up there is no
# legitimate reason for a pending sync to lag a send by more than that.
if [ "$AVG" -lt 200 ]; then echo "  RESULT: PASS (< 200 ms)"; exit 0
else echo "  RESULT: FAIL (>= 200 ms)"; exit 1; fi
