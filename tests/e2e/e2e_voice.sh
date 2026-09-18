#!/bin/bash
# Two-client voice end-to-end check against the REAL bsfchat-server binary.
#
# Why this exists: every voice fix since April has been compile-and-unit-test
# only. Unit tests call VoiceHandler's methods directly, so they never exercise
# routing, auth middleware, JSON on the wire, or what /sync actually shows the
# other participant. This drives two registered users through the full
# join -> state -> poll -> leave lifecycle over HTTP and asserts BOTH sources
# of truth at every step: the roster (GET .../voice/members) and the
# m.call.member events each client sees in /sync.
#
# It needs no TURN server and no coturn container. The roster and the state
# events are pure server state; media never flows here. allow_peer_to_peer is
# on and no relay is configured, so the script is self-contained.
#
# Safety: everything lives under a throwaway temp directory and the server runs
# with its cwd inside it, so even a relative-path fallback lands there. The
# live dev data directory is fingerprinted before and after and the script
# hard-fails if a byte changed.
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1

WORK=$(mktemp -d /tmp/bsfchat-voice-e2e.XXXXXX)
CONF="$WORK/server.toml"
LOG="$WORK/server.log"
REALDATA=$(e2e_real_data_dir || echo /nonexistent)

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n        expected: %s\n        got:      %s\n' "$1" "$2" "$3"; }
check(){ # name expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "$2" "$3"; fi
}
die() { echo "FATAL: $*" >&2; exit 1; }

# An ephemeral port, claimed by the kernel and released immediately. Six of
# these scripts can be running at once on one machine (one per workstream), so
# a fixed port number is a collision waiting to happen.
PORT=$(python3 -c "
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")
[ -n "$PORT" ] || die "could not claim an ephemeral port"
BASE="http://127.0.0.1:$PORT"
V3="$BASE/_matrix/client/v3"

REAL_BEFORE=""
if [ -d "$REALDATA" ]; then
    REAL_BEFORE=$(find "$REALDATA" -type f -exec shasum {} \; 2>/dev/null | sort)
    [ -n "$REAL_BEFORE" ] || die "could not checksum $REALDATA; refusing to run blind"
fi

SRV_PID=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
}
trap cleanup EXIT

mkdir -p "$WORK/data" "$WORK/media"
cat > "$CONF" <<EOF
[server]
name = "voice.e2e"
bind_address = "127.0.0.1"
port = $PORT

[database]
path = "$WORK/data/bsfchat.db"

[media]
path = "$WORK/media/"

[auth]
registration_enabled = true
password_hash_cost = 4

[voice]
enabled = true
# No TURN and no relay: this script asserts server-side roster state only,
# so peer-to-peer is all it needs and coturn is not a dependency.
allow_peer_to_peer = true
EOF

( cd "$WORK" && exec "$BIN" --config "$CONF" ) > "$LOG" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 80); do
    curl -sf "$BASE/_matrix/client/versions" >/dev/null 2>&1 && break
    kill -0 "$SRV_PID" 2>/dev/null || { cat "$LOG"; die "server exited during startup"; }
    sleep 0.25
done
curl -sf "$BASE/_matrix/client/versions" >/dev/null 2>&1 || { cat "$LOG"; die "server never came up on $PORT"; }

# The config-honoured guard: if the TOML was misparsed the server falls back to
# ./data/bsfchat.db and everything after this would be testing the wrong
# database. Both must hold before a single assertion runs.
grep -q "Server name: voice.e2e" "$LOG" || { tail -20 "$LOG"; die "config server name not honoured"; }
[ -f "$WORK/data/bsfchat.db" ] || { tail -20 "$LOG"; die "server did not create its database at the configured path"; }

echo "server: $BIN"
echo "port:   $PORT"
echo "work:   $WORK"
echo

# --- helpers -----------------------------------------------------------------

# python3 rather than jq: jq is not installed everywhere and the other scripts
# in this directory already take this route.
jget() { # <json> <python expression over d>
    printf '%s' "$1" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print('<unparseable>'); sys.exit(0)
try:
    v = eval(sys.argv[1])
except Exception as e:
    print('<missing:%s>' % e); sys.exit(0)
print(v if isinstance(v, str) else json.dumps(v))" "$2"
}

reg() { curl -s -X POST "$V3/register" -H 'Content-Type: application/json' \
        -d "{\"username\":\"$1\",\"password\":\"e2e-correct-horse-7\"}"; }

# The voice roster as the server reports it, flattened to a stable, comparable
# string: "user=active/muted" per member, sorted.
roster() { # <token> <room>
    curl -s "$V3/rooms/$2/voice/members" -H "Authorization: Bearer $1" | python3 -c "
import sys, json
d = json.load(sys.stdin)
rows = sorted('%s:muted=%s' % (m['user_id'].split(':')[0].lstrip('@'),
                               str(m.get('muted', False)).lower())
              for m in d.get('members', []))
print(','.join(rows) if rows else '<empty>')"
}

# The m.call.member transitions for <user> that <token> has been told about
# since <since>, oldest first, joined with '>'. Prints "<flags>|<next_batch>".
#
# Incremental rather than initial sync on purpose. This is how a real client
# learns about a peer joining or leaving, and it scopes each assertion to the
# step that produced it instead of re-reading a whole timeline that the
# server's timeline limit would eventually truncate.
sync_delta() { # <token> <since> <room> <user_id>
    curl -s "$V3/sync?timeout=0&since=$2" -H "Authorization: Bearer $1" | python3 -c "
import sys, json
d = json.load(sys.stdin)
room = d.get('rooms', {}).get('join', {}).get(sys.argv[1], {})
out = []
for ev in room.get('timeline', {}).get('events', []):
    if ev.get('type') != 'm.call.member' or ev.get('state_key') != sys.argv[2]:
        continue
    out.append('active' if ev.get('content', {}).get('active') else 'inactive')
print('%s|%s' % ('>'.join(out) if out else '<none>', d.get('next_batch', '')))" "$3" "$4"
}

# Bash 3.2 (the system bash on macOS) has no associative arrays and no
# namerefs, so the since-token bookkeeping is explicit. Each user tracks their
# own stream position.
A_SINCE=""; B_SINCE=""

# Reads alice's view of bob's transitions since her last read, advancing her
# token. The DELTA variable holds the result.
DELTA=""
alice_saw() { # <user_id>
    local out; out=$(sync_delta "$AT" "$A_SINCE" "$ROOM" "$1")
    DELTA="${out%|*}"; A_SINCE="${out##*|}"
}
bob_saw() { # <user_id>
    local out; out=$(sync_delta "$BT" "$B_SINCE" "$ROOM" "$1")
    DELTA="${out%|*}"; B_SINCE="${out##*|}"
}

# --- setup -------------------------------------------------------------------

echo "== register two users and create a voice channel =="
A=$(reg alice); B=$(reg bob)
AT=$(jget "$A" "d['access_token']"); AU=$(jget "$A" "d['user_id']")
BT=$(jget "$B" "d['access_token']"); BU=$(jget "$B" "d['user_id']")
[ -n "$AT" ] && [ -n "$BT" ] || die "registration failed: $A / $B"
ok "registered $AU and $BU"

ROOM=$(jget "$(curl -s -X POST "$V3/createRoom" -H "Authorization: Bearer $AT" \
    -H 'Content-Type: application/json' \
    -d '{"name":"General Voice","visibility":"public","preset":"public_chat"}')" "d['room_id']")
case "$ROOM" in !*) ok "created room $ROOM";; *) die "createRoom failed: $ROOM";; esac

curl -s -X POST "$V3/rooms/$ROOM/join" -H "Authorization: Bearer $BT" >/dev/null
VS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    "$V3/rooms/$ROOM/state/m.room.voice/" -H "Authorization: Bearer $AT" \
    -H 'Content-Type: application/json' -d '{"enabled":true,"max_participants":0}')
check "marked the room voice-capable (PUT m.room.voice)" "200" "$VS"

# Baseline both clients' stream positions. Every transition asserted below is
# a delta from here, so each step is checked against what it alone produced.
alice_saw "$BU"; bob_saw "$AU"

# Everything below routes through the real HTTP stack, so a 404 here would mean
# the voice routes are not registered at all — which unit tests cannot detect.
echo

# --- step 1: alice joins -----------------------------------------------------

echo "== step 1: alice joins voice =="
AJOIN=$(curl -s -X POST "$V3/rooms/$ROOM/voice/join" -H "Authorization: Bearer $AT" \
        -H 'Content-Type: application/json' -d '{"device_id":"ALICEDEV"}')
A_SESSION=$(jget "$AJOIN" "d['session_id']")
A_JOINED_AT=$(jget "$AJOIN" "d['joined_at']")
case "$A_SESSION" in
    "<missing"*|"") bad "join returns a session token" "32 hex chars" "$AJOIN";;
    *) [ "${#A_SESSION}" -eq 32 ] && ok "join returned session $A_SESSION" \
           || bad "session token length" "32" "${#A_SESSION}";;
esac
check "join reports joined_at" "true" "$([ "$A_JOINED_AT" -gt 0 ] 2>/dev/null && echo true || echo false)"
check "roster shows alice alone, unmuted" "alice:muted=false" "$(roster "$AT" "$ROOM")"
bob_saw "$AU"; check "bob's sync is told alice went active" "active" "$DELTA"

# --- step 2: bob joins -------------------------------------------------------

echo
echo "== step 2: bob joins =="
BJOIN=$(curl -s -X POST "$V3/rooms/$ROOM/voice/join" -H "Authorization: Bearer $BT" \
        -H 'Content-Type: application/json' -d '{"device_id":"BOBDEV"}')
B_SESSION=$(jget "$BJOIN" "d['session_id']")
check "bob's join lists alice as an existing member" "1" \
      "$(jget "$BJOIN" "len([m for m in d['members'] if m['user_id']=='$AU'])")"
check "roster shows both, unmuted" "alice:muted=false,bob:muted=false" "$(roster "$AT" "$ROOM")"
alice_saw "$BU"; check "alice's sync is told bob went active" "active" "$DELTA"
check "two different sessions" "false" "$([ "$A_SESSION" = "$B_SESSION" ] && echo true || echo false)"

# --- step 3: bob mutes -------------------------------------------------------

echo
echo "== step 3: bob mutes (PUT voice/state) =="
MS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$V3/rooms/$ROOM/voice/state" \
     -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' \
     -d "{\"muted\":true,\"session_id\":\"$B_SESSION\"}")
check "voice/state accepted with the current session" "200" "$MS"
check "roster shows bob muted, alice unchanged" "alice:muted=false,bob:muted=true" "$(roster "$AT" "$ROOM")"
alice_saw "$BU"; check "the mute reaches alice as a still-active member event" "active" "$DELTA"

echo "== step 3b: a state PUT from a superseded session is refused =="
STALE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$V3/rooms/$ROOM/voice/state" \
        -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' \
        -d '{"muted":false,"session_id":"00000000000000000000000000000000"}')
check "stale-session state PUT rejected" "403" "$STALE"
check "bob is still muted" "alice:muted=false,bob:muted=true" "$(roster "$AT" "$ROOM")"
alice_saw "$BU"; check "the refused PUT emitted no event at all" "<none>" "$DELTA"

# --- step 4: the out-of-order leave (V-H1) -----------------------------------

echo
echo "== step 4: leave/rejoin raced — an old session's leave must not win =="
# The client sent leave and then join on two connections; the server saw the
# join first. This is what used to leave a live participant marked inactive:
# audible to peers, missing from the roster, never heartbeating.
ALEAVE1=$(curl -s -X POST "$V3/rooms/$ROOM/voice/leave" -H "Authorization: Bearer $AT" \
          -H 'Content-Type: application/json' -d "{\"session_id\":\"$A_SESSION\"}")
check "alice's first leave took effect" "true" "$(jget "$ALEAVE1" "d['changed']")"
check "roster shows bob alone" "bob:muted=true" "$(roster "$BT" "$ROOM")"
bob_saw "$AU"; check "bob is told alice went inactive" "inactive" "$DELTA"

AJOIN2=$(curl -s -X POST "$V3/rooms/$ROOM/voice/join" -H "Authorization: Bearer $AT" \
         -H 'Content-Type: application/json' -d '{"device_id":"ALICEDEV"}')
A_SESSION2=$(jget "$AJOIN2" "d['session_id']")
check "rejoin minted a new session" "false" "$([ "$A_SESSION" = "$A_SESSION2" ] && echo true || echo false)"
bob_saw "$AU"; check "bob is told alice is back" "active" "$DELTA"

# The delayed leave from the FIRST session finally arrives.
LATE=$(curl -s -X POST "$V3/rooms/$ROOM/voice/leave" -H "Authorization: Bearer $AT" \
       -H 'Content-Type: application/json' -d "{\"session_id\":\"$A_SESSION\"}")
check "late leave from the old session is a no-op" "false" "$(jget "$LATE" "d['changed']")"
check "and says why" "stale_session" "$(jget "$LATE" "d['reason']")"
check "alice is STILL in the roster" "alice:muted=false,bob:muted=true" "$(roster "$BT" "$ROOM")"
bob_saw "$AU"
check "and bob was never told otherwise" "<none>" "$DELTA"

echo "== step 4b: a duplicate leave on an inactive row is a no-op, not an event =="
DUP=$(curl -s -X POST "$V3/rooms/$ROOM/voice/leave" -H "Authorization: Bearer $BT" \
      -H 'Content-Type: application/json' -d "{\"session_id\":\"$B_SESSION\"}")
check "bob's leave took effect" "true" "$(jget "$DUP" "d['changed']")"
DUP2=$(curl -s -X POST "$V3/rooms/$ROOM/voice/leave" -H "Authorization: Bearer $BT" \
       -H 'Content-Type: application/json' -d "{\"session_id\":\"$B_SESSION\"}")
check "the second leave changes nothing" "false" "$(jget "$DUP2" "d['changed']")"
check "and says why" "not_active" "$(jget "$DUP2" "d['reason']")"
alice_saw "$BU"
check "exactly one inactive event for two leaves" "inactive" "$DELTA"
bob_saw "$AU"; check "alice's row was not touched by bob's leaves" "<none>" "$DELTA"

# --- step 5: join over a still-active row (V-M6) -----------------------------

echo
echo "== step 5: joining over a still-active row emits inactive, then active =="
# Sitting mesh peers key their peer connection on the active transition. An
# active row overwritten by another active row gives them no edge to react to,
# so they hold a dead connection and the rejoiner gets silence.
curl -s -X POST "$V3/rooms/$ROOM/voice/join" -H "Authorization: Bearer $BT" \
     -H 'Content-Type: application/json' -d '{"device_id":"BOBDEV"}' >/dev/null
BJOIN3=$(curl -s -X POST "$V3/rooms/$ROOM/voice/join" -H "Authorization: Bearer $BT" \
         -H 'Content-Type: application/json' -d '{"device_id":"BOBPHONE"}')
check "second-device join succeeded" "32" "$(printf '%s' "$(jget "$BJOIN3" "d['session_id']")" | wc -c | tr -d ' ')"
alice_saw "$BU"
check "alice sees rejoin, then reset, then the second device's active" \
      "active>inactive>active" "$DELTA"
check "roster shows bob once, unmuted again" "alice:muted=false,bob:muted=false" "$(roster "$AT" "$ROOM")"

# --- step 6: both leave ------------------------------------------------------

echo
echo "== step 6: both leave, roster empties =="
curl -s -X POST "$V3/rooms/$ROOM/voice/leave" -H "Authorization: Bearer $AT" \
     -H 'Content-Type: application/json' -d "{\"session_id\":\"$A_SESSION2\"}" >/dev/null
curl -s -X POST "$V3/rooms/$ROOM/voice/leave" -H "Authorization: Bearer $BT" \
     -H 'Content-Type: application/json' -d "{\"session_id\":\"$(jget "$BJOIN3" "d['session_id']")\"}" >/dev/null
check "roster is empty" "<empty>" "$(roster "$AT" "$ROOM")"
bob_saw "$AU"; check "bob is told alice went inactive" "inactive" "$DELTA"
alice_saw "$BU"; check "alice is told bob went inactive" "inactive" "$DELTA"

echo
echo "== step 7: a state PUT after leaving is refused, not silently re-activating =="
POST_LEAVE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$V3/rooms/$ROOM/voice/state" \
             -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d '{"muted":true}')
check "voice/state on an inactive row is 403" "403" "$POST_LEAVE"
check "roster stays empty" "<empty>" "$(roster "$AT" "$ROOM")"

# --- guards ------------------------------------------------------------------

echo
echo "== server log: no errors =="
ERRS=$(grep -c -E "\[error\]|\[critical\]" "$LOG" 2>/dev/null | tr -d ' ')
check "no error-level log lines" "0" "${ERRS:-0}"
[ "${ERRS:-0}" != "0" ] && grep -E "\[error\]|\[critical\]" "$LOG" | head -5

if [ -n "$REAL_BEFORE" ]; then
    REAL_AFTER=$(find "$REALDATA" -type f -exec shasum {} \; 2>/dev/null | sort)
    if [ "$REAL_BEFORE" = "$REAL_AFTER" ]; then
        ok "live dev data at $REALDATA is byte-identical (untouched)"
    else
        echo "FATAL: $REALDATA CHANGED during this run" >&2
        FAIL=$((FAIL+1))
    fi
else
    ok "no live dev data directory beside this checkout (nothing to protect)"
fi

echo
echo "==================================================="
echo "  VOICE E2E: $PASS passed, $FAIL failed"
echo "==================================================="
[ "$FAIL" -eq 0 ] && rm -rf "$WORK"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
