#!/bin/bash
# Proves that a parked /sync WAKES ON A COMMIT rather than sitting out its
# timeout — and keeps doing so when the httplib worker pool is saturated by
# other long polls, which is this product's normal steady state: every
# connected client parks a 30s /sync on a worker and holds it there.
#
# WHAT THIS DEFENDS, AND WHAT IT DELIBERATELY DOES NOT
#
# The regression that matters is binary, not gradual. SyncEngine::handle_sync
# parks on new_event_cv_ and notify_new_event() has to reach it; every way
# that has broken (a notify published outside wait_mutex_, a head dragged
# backwards by out-of-order commits, checked_pos sampled from the head instead
# of the scan) produces the SAME symptom: the poll sits out its whole timeout
# holding a message that was committed and readable the entire time. That is a
# difference between milliseconds and SECONDS. It is not a difference between
# 150 ms and 250 ms.
#
# This script used to assert a mean under 200 ms. That budget did not measure
# the server; it measured how much spare capacity the box had. On an idle
# machine the real wake is single-digit milliseconds and the reported 60-110 ms
# was almost entirely harness overhead — four python3 interpreter starts per
# round, just to read a clock, each of which can exceed the whole budget on a
# loaded box. It flaked under concurrent load and passed alone, so it reported
# the state of the machine, not the state of the code.
#
# Two changes fix that without giving up the property:
#
#   1. The poll times ITSELF, in-process, with curl's %{time_total}. No
#      interpreter start sits inside the measured interval any more.
#
#   2. The gate is RELATIVE. Every run first measures an UNWOKEN poll — the
#      same request with nothing sent to it, which must block for its full
#      timeout — and then requires the woken polls to come back in less than
#      HALF of that, on the same machine, in the same run, under the same
#      load. A box that is twice as slow inflates both numbers and the ratio
#      survives. There is also a flat 2 s ceiling on the derived delivery, so
#      a wake that degrades to "eventually" rather than "immediately" is still
#      caught even if the timeout were ever raised.
#
# A regression that breaks the wake shows up as a poll that blocks for
# POLL_TIMEOUT_MS: ~10x over the relative gate and ~3x over the flat ceiling.
# There is no plausible amount of machine load that hides that, and no
# plausible regression that lands between 200 ms and 2 s — the code either
# signals the condition variable or it does not.
#
# Fine-grained wake correctness is separately and deterministically covered by
# SyncTest.LongPollWakeUp (tests/test_sync.cpp), which asserts on the CONTENT
# of the woken response and has no timing budget at all. What this script adds
# on top is the part a unit test structurally cannot reach: the real binary,
# real sockets, and a worker pool already pinned by other connections.
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
# Short enough that the unwoken control round does not dominate the runtime,
# long enough that a woken poll and a timed-out one are never confusable.
POLL_TIMEOUT_MS=${POLL_TIMEOUT_MS:-6000}
# The holders must stay parked for the whole run, control round included.
HOLD_MS=${HOLD_MS:-60000}
# How long Bob's poll is already blocked before the send lands. This is
# subtracted back out to derive the delivery figure.
PARK_S=${PARK_S:-0.6}
# Flat ceiling on the derived delivery. An order of magnitude looser than the
# 200 ms it replaces, and still an order of magnitude tighter than the symptom
# of every wake regression this test has ever been pointed at.
CEILING_MS=${CEILING_MS:-2000}
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
# Reap hard rather than politely: anything still holding this script's stdout
# keeps ctest blocked on the pipe long after the script itself is done.
cleanup(){
  kill $SV_PID 2>/dev/null
  pkill -P $$ curl 2>/dev/null
  sleep 0.2
  pkill -9 -P $$ curl 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

for _ in $(seq 1 80); do
  curl -sf "$BASE/_matrix/client/versions" >/dev/null 2>&1 && break
  sleep 0.25
done
grep -q "Server name: latency.test" "$RUN/server.log" || {
  echo "FATAL: config not honoured"; tail -20 "$RUN/server.log"; exit 1; }

jqf(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
reg(){ curl -s -X POST "$BASE/_matrix/client/v3/register" -H 'Content-Type: application/json' \
       -d "{\"username\":\"$1\",\"password\":\"e2e-correct-horse-7\"}"; }
# Seconds (curl's %{time_total}, e.g. "0.612345") -> whole milliseconds. Every
# call to this is OUTSIDE a measured interval, which is the whole point.
ms(){ python3 -c "print(int(float(open('$1').read().strip())*1000))" 2>/dev/null || echo 0; }

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

echo "== workers=$WORKERS holders=$HOLDERS rounds=$ROUNDS poll_timeout=${POLL_TIMEOUT_MS}ms =="

# Saturate the pool the way real clients do: each holder is its OWN connection
# parked on a long poll, exactly like a second/third signed-in desktop client.
# --max-time on every poll below, and stdio pointed away from the harness.
# Both matter for the same reason: a curl with no ceiling that never gets an
# answer blocks forever, and ctest does not read EOF on a test's output until
# every process holding that pipe is gone — so one stuck background curl turns
# a 10-second script into a 300-second ctest TIMEOUT with no diagnostic at
# all. Seen once in a full -j2 sweep while a second build was running. A
# ceiling converts that into a clean, legible failure.
MAX_POLL_S=$(python3 -c "print(int($POLL_TIMEOUT_MS/1000) + 20)")
MAX_HOLD_S=$(python3 -c "print(int($HOLD_MS/1000) + 10)")

HOLDER_PIDS=()
for i in $(seq 1 "$HOLDERS"); do
  curl -s -o /dev/null --max-time "$MAX_HOLD_S" \
    "$BASE/_matrix/client/v3/sync?timeout=$HOLD_MS&since=$SINCE" \
    -H "Authorization: Bearer $AT" > /dev/null 2>&1 &
  HOLDER_PIDS+=($!)
done
sleep 1.0   # let every holder actually reach the server and claim a worker

# --- the control -------------------------------------------------------------
# The same poll, on the same box, with the same pool pressure, and NOTHING
# sent to it. This is what "did not wake" looks like, measured rather than
# assumed, and it is the yardstick every woken round below is judged against.
#
# It doubles as a lower-bound check on the timeout path itself: a poll that
# comes back early with no payload is the spin regression e2e_invites T4
# guards from the other side, and it would quietly make the ratio test
# meaningless. A lower bound cannot be broken by a slow machine.
curl -s -o "$RUN/idle.json" -w '%{time_total}' --max-time "$MAX_POLL_S" \
  "$BASE/_matrix/client/v3/sync?timeout=$POLL_TIMEOUT_MS&since=$SINCE" \
  -H "Authorization: Bearer $BT" > "$RUN/idle.t" 2>/dev/null
IDLE_MS=$(ms "$RUN/idle.t")
printf "  control: an UNWOKEN poll blocked %6s ms (server timeout %s ms)\n" \
  "$IDLE_MS" "$POLL_TIMEOUT_MS"
FLOOR_MS=$(python3 -c "print(int($POLL_TIMEOUT_MS*0.8))")
if [ "$IDLE_MS" -lt "$FLOOR_MS" ]; then
  echo "  FAIL: an idle poll with nothing to deliver returned after ${IDLE_MS} ms"
  echo "        — it must block until its timeout. Either the poll is spinning,"
  echo "        or something delivered payload the control was not expecting;"
  echo "        the woken/unwoken comparison below cannot mean anything until"
  echo "        this holds."
  exit 1
fi

TOTAL=0
for r in $(seq 1 "$ROUNDS"); do
  # Bob's pending long poll, on its own connection, TIMING ITSELF. curl's
  # %{time_total} is measured inside the process that made the request, so no
  # interpreter start, fork or scheduler hiccup lands inside the interval.
  # --no-buffer is irrelevant here; what matters is that the only thing
  # between "send committed" and "this number stops counting" is the server.
  ( curl -s -o "$RUN/bob.$r.json" -w '%{time_total}' --max-time "$MAX_POLL_S" \
      "$BASE/_matrix/client/v3/sync?timeout=$POLL_TIMEOUT_MS&since=$SINCE" \
      -H "Authorization: Bearer $BT" > "$RUN/bob.$r.t" 2>/dev/null ) &
  BOB_PID=$!
  sleep "$PARK_S"   # Bob is now blocked inside the server's condition variable

  SENT=$(curl -s -X PUT \
    "$BASE/_matrix/client/v3/rooms/$ROOM/send/m.room.message/lat$r" \
    -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
    -d "{\"msgtype\":\"m.text\",\"body\":\"round $r\"}")

  wait $BOB_PID 2>/dev/null
  WOKE_MS=$(ms "$RUN/bob.$r.t")
  if [ "$WOKE_MS" -ge $(( MAX_POLL_S * 1000 - 500 )) ]; then
    echo "  FAIL: round $r's poll hit curl's ${MAX_POLL_S}s ceiling — the"
    echo "        request never came back at all, which is not a latency"
    echo "        result. Check $RUN/server.log."
    exit 1
  fi

  GOT=$(python3 -c "
import json,sys
d=json.load(open('$RUN/bob.$r.json'))
n=sum(len(v.get('timeline',{}).get('events',[])) for v in d.get('rooms',{}).get('join',{}).values())
print(n)" 2>/dev/null || echo 0)

  # The poll had already been parked for PARK_S when the send went out, so
  # what is left over that is the send->delivery gap. curl starts counting a
  # few ms after the shell backgrounds it, so this slightly UNDER-states the
  # true gap; the gate that decides pass/fail is the raw poll span, which
  # needs no such correction.
  DELIV_MS=$(python3 -c "print(max(0, $WOKE_MS - int($PARK_S*1000)))")
  printf "  round %d: poll span %6s ms   delivery(send->sync returns) ~%5s ms   events=%s\n" \
    "$r" "$WOKE_MS" "$DELIV_MS" "$GOT"
  [ "$GOT" = "1" ] || echo "        WARN: expected exactly 1 timeline event, saw $GOT"
  printf '%s' "$SENT" | grep -q event_id || echo "        WARN: send did not return an event_id: $SENT"
  TOTAL=$(python3 -c "print($TOTAL + $DELIV_MS)")

  SINCE=$(python3 -c "
import json;print(json.load(open('$RUN/bob.$r.json'))['next_batch'])" 2>/dev/null || echo "$SINCE")
done

for p in "${HOLDER_PIDS[@]}"; do kill "$p" 2>/dev/null; done

AVG=$(python3 -c "print(int($TOTAL/$ROUNDS))")
AVG_POLL=$(python3 -c "print(int($AVG + $PARK_S*1000))")
HALF_IDLE=$(python3 -c "print(int($IDLE_MS/2))")
echo "  mean delivery: ${AVG} ms   (mean poll span ${AVG_POLL} ms vs unwoken ${IDLE_MS} ms)"

# A slowdown that is real but not a wake failure still deserves to be seen.
# It does not fail the build, because the only thing separating 200 ms from
# 700 ms on this box is what else is running on it.
if [ "$AVG" -ge 200 ]; then
  echo "  NOTE: mean delivery ${AVG} ms is above the 200 ms this used to gate on."
  echo "        Expected when the machine is busy; worth a look if it shows up"
  echo "        on an idle box or moves after a change to the sync path."
fi

FAIL=0
if [ "$AVG_POLL" -ge "$HALF_IDLE" ]; then
  echo "  FAIL: a woken poll (${AVG_POLL} ms) is not markedly faster than an"
  echo "        unwoken one (${IDLE_MS} ms) on this same machine in this same"
  echo "        run. The parked /sync is being answered by its timeout rather"
  echo "        than by the commit."
  FAIL=1
fi
if [ "$AVG" -ge "$CEILING_MS" ]; then
  echo "  FAIL: mean delivery ${AVG} ms exceeds the ${CEILING_MS} ms ceiling."
  FAIL=1
fi
if [ "$FAIL" = 0 ]; then
  echo "  RESULT: PASS (woken ${AVG_POLL} ms < half of unwoken ${IDLE_MS} ms; delivery ${AVG} ms < ${CEILING_MS} ms)"
  exit 0
fi
echo "  RESULT: FAIL"; exit 1
