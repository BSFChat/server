#!/bin/bash
# End-to-end HTTP check of the new endpoints against the real bsfchat-server
# binary. Unit tests call handlers directly and so bypass routing entirely; this
# proves the routes are actually registered and reachable.
set -u
SCRATCH="$(cd "$(dirname "$0")" && pwd)"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
SRV=$(e2e_server_root)
BIN=$(e2e_require_server_bin) || exit 1
RUN="$SCRATCH/e2e-run"
PORT=18449
BASE="http://127.0.0.1:$PORT"
rm -rf "$RUN"; mkdir -p "$RUN/data" "$RUN/media"

cat > "$RUN/server.toml" <<EOF
[server]
name = "e2e.test"
bind_address = "127.0.0.1"
port = $PORT

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
enabled = true
worker_poll_ms = 200
allowed_gateway_prefixes = ["http://127.0.0.1:$((PORT+1))/"]
# The stand-in gateway below runs on loopback, which the SSRF gate refuses
# unless the operator says the gateway really is internal. Same two settings a
# deployment running sygnal in its own compose file needs.
allow_internal_gateway = true
# The server default is "event_id_only"; this run exercises the full payload
# path (the checks below read sender and body out of the notify).
default_payload = "full"
EOF

# A stand-in push gateway: logs each notify body and answers 200 {}.
python3 - "$((PORT+1))" "$RUN/gateway.log" <<'PYEOF' &
import sys, json
from http.server import BaseHTTPRequestHandler, HTTPServer
port=int(sys.argv[1]); logpath=sys.argv[2]
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length',0)); body=self.rfile.read(n)
        with open(logpath,'a') as f: f.write(body.decode()+"\n")
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.end_headers(); self.wfile.write(b'{}')
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',port),H).serve_forever()
PYEOF
GW_PID=$!

( cd "$RUN" && exec "$BIN" --config "$RUN/server.toml" ) > "$RUN/server.log" 2>&1 &
SV_PID=$!
cleanup(){ kill $SV_PID $GW_PID 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

for i in $(seq 1 60); do
  curl -sf "$BASE/_matrix/client/versions" >/dev/null 2>&1 && break
  sleep 0.25
done

PASS=0; FAIL=0
grep -q "Server name: e2e.test" "$RUN/server.log" || { echo "FATAL: config was not honoured (server_name mismatch) — refusing to continue"; tail -20 "$RUN/server.log"; exit 1; }
grep -q "Database: $RUN/data/bsfchat.db" "$RUN/server.log" || { echo "FATAL: config database_path not honoured — refusing to continue"; grep Database "$RUN/server.log"; exit 1; }
check(){ # name expected_substring actual
  if printf '%s' "$3" | grep -q "$2"; then echo "  PASS  $1"; PASS=$((PASS+1));
  else echo "  FAIL  $1"; echo "        expected to contain: $2"; echo "        got: $3"; FAIL=$((FAIL+1)); fi
}
jqf(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(eval('d'+sys.argv[1])))" "$1" 2>/dev/null; }

reg(){ curl -s -X POST "$BASE/_matrix/client/v3/register" -H 'Content-Type: application/json' \
       -d "{\"username\":\"$1\",\"password\":\"e2e-correct-horse-7\"}"; }

echo "== registering users =="
A=$(reg alice); B=$(reg bob); C=$(reg carol)
AT=$(printf '%s' "$A" | jqf "['access_token']" | tr -d '"')
BT=$(printf '%s' "$B" | jqf "['access_token']" | tr -d '"')
CT=$(printf '%s' "$C" | jqf "['access_token']" | tr -d '"')
AU=$(printf '%s' "$A" | jqf "['user_id']" | tr -d '"')
BU=$(printf '%s' "$B" | jqf "['user_id']" | tr -d '"')
[ -n "$AT" ] && [ -n "$BT" ] || { echo "registration failed: $A / $B"; exit 1; }
echo "  alice=$AU bob=$BU"

echo "== create a public room =="
ROOM=$(curl -s -X POST "$BASE/_matrix/client/v3/createRoom" -H "Authorization: Bearer $AT" \
   -H 'Content-Type: application/json' \
   -d '{"name":"general","visibility":"public","preset":"public_chat"}' | jqf "['room_id']" | tr -d '"')
echo "  room=$ROOM"
curl -s -X POST "$BASE/_matrix/client/v3/rooms/$ROOM/join" -H "Authorization: Bearer $BT" >/dev/null
curl -s -X POST "$BASE/_matrix/client/v3/rooms/$ROOM/join" -H "Authorization: Bearer $CT" >/dev/null

echo
echo "== F2: POST /pushers/set + GET /pushers =="
SET=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/_matrix/client/v3/pushers/set" \
  -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' \
  -d "{\"pushkey\":\"bob-device-token\",\"kind\":\"http\",\"app_id\":\"com.bsfchat.app\",
       \"app_display_name\":\"BSFChat\",\"device_display_name\":\"Bob Phone\",\"lang\":\"en\",
       \"data\":{\"url\":\"http://127.0.0.1:$((PORT+1))/_matrix/push/v1/notify\"}}")
check "/pushers/set returns 200" "200" "$SET"
GET=$(curl -s "$BASE/_matrix/client/v3/pushers" -H "Authorization: Bearer $BT")
check "/pushers lists the pusher" "bob-device-token" "$GET"

echo "== F2: SSRF guard rejects a non-allowlisted gateway =="
SSRF=$(curl -s -X POST "$BASE/_matrix/client/v3/pushers/set" -H "Authorization: Bearer $BT" \
  -H 'Content-Type: application/json' \
  -d '{"pushkey":"evil","kind":"http","app_id":"a","data":{"url":"http://169.254.169.254/latest/meta-data/"}}')
check "metadata endpoint rejected" "M_INVALID_PARAM" "$SSRF"

echo "== F2: per-room notify level =="
LVL=$(curl -s "$BASE/_matrix/client/v3/bsfchat/rooms/$ROOM/notify_level" -H "Authorization: Bearer $BT")
check "GET notify_level defaults to mentions" '"mentions"' "$LVL"
PUTL=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  "$BASE/_matrix/client/v3/bsfchat/rooms/$ROOM/notify_level" -H "Authorization: Bearer $BT" \
  -H 'Content-Type: application/json' -d '{"level":"all"}')
check "PUT notify_level returns 200" "200" "$PUTL"
BADL=$(curl -s -X PUT "$BASE/_matrix/client/v3/bsfchat/rooms/$ROOM/notify_level" \
  -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' -d '{"level":"loud"}')
check "invalid level rejected" "M_INVALID_PARAM" "$BADL"

echo
echo "== F1: send a message that @-mentions bob =="
M1=$(curl -s -X PUT "$BASE/_matrix/client/v3/rooms/$ROOM/send/m.room.message/e2e-1" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d "{\"msgtype\":\"m.text\",\"body\":\"hey @Bob look at this\",
       \"m.mentions\":{\"user_ids\":[\"$BU\"]}}")
EV1=$(printf '%s' "$M1" | jqf "['event_id']" | tr -d '"')
check "mention send accepted" '\$' "$EV1"

echo "== F1: highlight_count appears in /sync, distinct from notification_count =="
SY=$(curl -s "$BASE/_matrix/client/v3/sync?timeout=0" -H "Authorization: Bearer $BT")
HC=$(printf '%s' "$SY" | python3 -c "
import sys,json;d=json.load(sys.stdin)
r=d['rooms']['join']['$ROOM']['unread_notifications']
print(f\"notification_count={r.get('notification_count')} highlight_count={r.get('highlight_count')}\")")
check "bob sees 1 unread and 1 highlight" "notification_count=1 highlight_count=1" "$HC"

echo "== F1: @room without MENTION_EVERYONE is refused =="
RW=$(curl -s -X PUT "$BASE/_matrix/client/v3/rooms/$ROOM/send/m.room.message/e2e-room" \
  -H "Authorization: Bearer $CT" -H 'Content-Type: application/json' \
  -d '{"msgtype":"m.text","body":"listen up","m.mentions":{"room":true}}')
check "@room refused for a non-privileged user" "M_FORBIDDEN" "$RW"

echo "== F1: editing a message does not inject a mention for carol =="
curl -s -X POST "$BASE/_matrix/client/v3/rooms/$ROOM/read_marker" -H "Authorization: Bearer $CT" \
  -H 'Content-Type: application/json' -d '{}' >/dev/null
CU=$(printf '%s' "$(curl -s "$BASE/_matrix/client/v3/sync?timeout=0" -H "Authorization: Bearer $CT")" \
  | python3 -c "
import sys,json;d=json.load(sys.stdin)
r=d['rooms']['join']['$ROOM'].get('unread_notifications',{})
print('hl=%s'%r.get('highlight_count'))")
check "carol starts with no highlight" "hl=0" "$CU"
CUID=$(printf '%s' "$C" | jqf "['user_id']" | tr -d '"')
curl -s -X PUT "$BASE/_matrix/client/v3/rooms/$ROOM/send/m.room.message/e2e-edit" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d "{\"msgtype\":\"m.text\",\"body\":\"* hey @Carol\",
       \"m.mentions\":{\"user_ids\":[\"$CUID\"]},
       \"m.new_content\":{\"msgtype\":\"m.text\",\"body\":\"hey @Carol\"},
       \"m.relates_to\":{\"rel_type\":\"m.replace\",\"event_id\":\"$EV1\"}}" >/dev/null
CU2=$(printf '%s' "$(curl -s "$BASE/_matrix/client/v3/sync?timeout=0" -H "Authorization: Bearer $CT")" \
  | python3 -c "
import sys,json;d=json.load(sys.stdin)
r=d['rooms']['join']['$ROOM'].get('unread_notifications',{})
print('hl=%s nc=%s'%(r.get('highlight_count'),r.get('notification_count')))")
check "edit injected no mention and no unread bump" "hl=0 nc=0" "$CU2"

echo
echo "== F3: POST /search =="
curl -s -X PUT "$BASE/_matrix/client/v3/rooms/$ROOM/send/m.room.message/e2e-2" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"msgtype":"m.text","body":"the deployment pipeline is broken"}' >/dev/null
SR=$(curl -s -X POST "$BASE/_matrix/client/v3/search" -H "Authorization: Bearer $BT" \
  -H 'Content-Type: application/json' \
  -d '{"search_categories":{"room_events":{"search_term":"deployment pipeline"}}}')
check "search finds the message" "deployment pipeline is broken" "$SR"
SRC=$(printf '%s' "$SR" | jqf "['search_categories']['room_events']['count']")
check "search count is 1" "^1$" "$SRC"

echo "== F3: hostile FTS5 syntax is neutralised, not executed =="
for q in '"' '*' 'pipeline OR *' 'NEAR(a b' '((((' ; do
  ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/_matrix/client/v3/search" \
    -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' \
    -d "$(python3 -c "import json,sys;print(json.dumps({'search_categories':{'room_events':{'search_term':sys.argv[1]}}}))" "$q")")
  check "search_term [$q] answered cleanly (200)" "200" "$ST"
done

echo "== F3: search never surfaces a room the caller is not in =="
PRIV=$(curl -s -X POST "$BASE/_matrix/client/v3/createRoom" -H "Authorization: Bearer $AT" \
   -H 'Content-Type: application/json' \
   -d '{"name":"private-notes","visibility":"private","preset":"private_chat"}' | jqf "['room_id']" | tr -d '"')
curl -s -X PUT "$BASE/_matrix/client/v3/rooms/$PRIV/send/m.room.message/e2e-p1" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"msgtype":"m.text","body":"kumquat confidential"}' >/dev/null
AS=$(curl -s -X POST "$BASE/_matrix/client/v3/search" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' \
  -d '{"search_categories":{"room_events":{"search_term":"kumquat"}}}' | jqf "['search_categories']['room_events']['count']")
check "alice (member) finds her private message" "^1$" "$AS"
BS=$(curl -s -X POST "$BASE/_matrix/client/v3/search" -H "Authorization: Bearer $BT" \
  -H 'Content-Type: application/json' \
  -d '{"search_categories":{"room_events":{"search_term":"kumquat"}}}' | jqf "['search_categories']['room_events']['count']")
check "bob (non-member) finds nothing" "^0$" "$BS"

echo "== F3: redaction removes content from search =="
RM=$(curl -s -X PUT "$BASE/_matrix/client/v3/rooms/$ROOM/send/m.room.message/e2e-3" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"msgtype":"m.text","body":"regrettable persimmon comment"}' | jqf "['event_id']" | tr -d '"')
curl -s -X PUT "$BASE/_matrix/client/v3/rooms/$ROOM/redact/$RM/e2e-red" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d '{}' >/dev/null
RS=$(curl -s -X POST "$BASE/_matrix/client/v3/search" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' \
  -d '{"search_categories":{"room_events":{"search_term":"persimmon"}}}' | jqf "['search_categories']['room_events']['count']")
check "redacted text is unsearchable" "^0$" "$RS"

echo
echo "== F2: push actually delivered out of band to the gateway =="
for i in $(seq 1 60); do [ -s "$RUN/gateway.log" ] && break; sleep 0.25; done
if [ -s "$RUN/gateway.log" ]; then
  echo "  PASS  gateway received $(wc -l < "$RUN/gateway.log" | tr -d ' ') notification(s)"
  PASS=$((PASS+1))
  python3 - "$RUN/gateway.log" <<'PYEOF'
import sys,json
first=json.loads(open(sys.argv[1]).readline())["notification"]
print("        event_id:", first["event_id"][:16]+"...")
print("        sender:  ", first["sender"])
print("        prio:    ", first["prio"])
print("        devices: ", [d["pushkey"] for d in first["devices"]])
print("        body:    ", first.get("content",{}).get("body"))
PYEOF
  # The queue must have drained.
  Q=$(sqlite3 "$RUN/data/bsfchat.db" "SELECT COUNT(*) FROM push_queue" 2>/dev/null || echo "?")
  check "push_queue drained after delivery" "^0$" "$Q"
else
  echo "  FAIL  gateway received no notification"; FAIL=$((FAIL+1))
fi

echo
echo "== schema =="
SV=$(sqlite3 "$RUN/data/bsfchat.db" "PRAGMA user_version" 2>/dev/null || echo "?")
# Derived from the build's own source of truth, not restated here.
#
# Two branches fixed this independently — one with a `>= 16` floor, this one
# by reading the header. The derived form wins because a floor still drifts
# away from what it is checking; this cannot. This used to
# be a literal pinned "so bumping the schema is a conscious edit", but in
# practice the pin just went stale on every migration (it sat at 12 while the
# schema was 15, then at 16 while it was 18) and a permanently-red check teaches
# people to ignore the whole suite. The conscious-edit tripwire still exists
# where it costs nothing to keep current: EXPECT_EQ(kTargetSchemaVersion, N) in
# tests/test_audit.cpp. What this check is really for is that the server
# actually ran its migrations up to the version this checkout expects.
EXPECT_SV=$(sed -n \
  's/^inline constexpr int kTargetSchemaVersion = \([0-9][0-9]*\);.*/# Pinned on purpose, so bumping the schema is a conscious edit rather than
# something that slides past review — the same convention the C++ migration tests
# use (kTargetSchemaVersion in server/src/store/Migrations.h).
#
# An exact pin here rots, and it had rotted twice: first stuck at 12 while the
# schema reached 15, then at 16 while it reached 18 — failing for its own
# reasons rather than reporting anything, on a script no ctest label runs. What
# this check is actually for is "migrations ran and reached a modern schema",
# so it now asserts a FLOOR. The exact-version tripwire lives in the unit tests
# (test_migration_v11.cpp, test_audit.cpp), where bumping it is a one-line edit
# in front of whoever added the migration.
[ "$SV" -ge 16 ] 2>/dev/null \
    && pass "database is at schema v$SV (>= 16)" \
    || fail "database is at schema v$SV, expected 16 or newer"
/p' \
  "$SRV/src/store/Migrations.h" 2>/dev/null)
if [ -n "$EXPECT_SV" ]; then
  check "database is at schema v$EXPECT_SV (kTargetSchemaVersion)" "^$EXPECT_SV\$" "$SV"
else
  echo "  FAIL  could not read kTargetSchemaVersion from $SRV/src/store/Migrations.h"
  FAIL=$((FAIL+1))
fi
TB=$(sqlite3 "$RUN/data/bsfchat.db" ".tables" 2>/dev/null | tr -s ' \n' ' ')
check "event_mentions exists" "event_mentions" "$TB"
check "pushers exists" "pushers" "$TB"
check "event_search exists" "event_search" "$TB"
check "audit_log exists" "audit_log" "$TB"
check "server_bans exists" "server_bans" "$TB"
IDX=$(sqlite3 "$RUN/data/bsfchat.db" \
  "SELECT group_concat(name) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_audit_log_%'" \
  2>/dev/null || echo "?")
check "audit_log filter indexes exist (v16)" "idx_audit_log_target_room" "$IDX"

echo
echo "== server log: no errors =="
ERRS=$(grep -c -E "\[error\]|\[critical\]" "$RUN/server.log" 2>/dev/null || echo 0)
check "no error-level log lines" "^0$" "$ERRS"
[ "$ERRS" != "0" ] && grep -E "\[error\]|\[critical\]" "$RUN/server.log" | head -5

echo
echo "==================================================="
echo "  E2E: $PASS passed, $FAIL failed"
echo "==================================================="
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
