#!/bin/bash
# End-to-end authorization check against the REAL bsfchat-server binary over HTTP.
#
# Safety: everything lives under a throwaway directory. The real dev database at
# /Users/josh/dev/gamechat/data is checksummed before and after and the script
# HARD-FAILS if a single byte changed, and hard-fails if the server did not
# actually create its database at the configured path (which is how a misparsed
# TOML would show up).
set -uo pipefail

BIN=/Users/josh/dev/gamechat/server/build-perm/bsfchat-server
WORK=$(mktemp -d /tmp/bsfchat-perm-e2e-XXXXXX)
REALDATA=/Users/josh/dev/gamechat/data
PORT=8899
BASE="http://127.0.0.1:${PORT}/_matrix/client/v3"
FAILURES=0
CHECKS=0
SRV_PID=""

cleanup() {
  if [[ -n "${SRV_PID:-}" ]]; then kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; fi
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
workers = 2

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
    printf 'ok   %-58s %s\n' "$1" "$3"
  else
    printf 'FAIL %-58s expected %s got %s  body=%s\n' "$1" "$2" "$3" "$(cat "$WORK/last-body.json" 2>/dev/null)"
    FAILURES=$((FAILURES+1))
  fi
}

jfield() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$WORK/last-body.json" "$1"; }

register() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"pw-$1-12345\",\"auth\":{\"type\":\"m.login.dummy\"}}" >/dev/null
  jfield access_token
}
login() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/login" -H 'Content-Type: application/json' \
    -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"$1\"},\"password\":\"pw-$1-12345\"}" >/dev/null
  jfield access_token
}

# ── phase 1: accounts ────────────────────────────────────────────────────
start_server first
[[ -f "$WORK/e2e.db" ]] || die "server did not create its database at the CONFIGURED path ($WORK/e2e.db) — TOML likely misparsed"

T_ALICE=$(register alice); T_BOB=$(register bob); T_CAROL=$(register carol)
[[ -n "$T_ALICE" && -n "$T_BOB" && -n "$T_CAROL" ]] || { cat "$WORK/server-first.log"; die "registration failed"; }
stop_server

# Restart so bootstrap_roles grants the admin role to the OLDEST account (alice)
# and @everyone to the rest — the real ownership path, not a fixture poke.
start_server second
T_ALICE=$(login alice); T_BOB=$(login bob); T_CAROL=$(login carol)
[[ -n "$T_ALICE" && -n "$T_BOB" ]] || die "login failed after restart"

A="@alice:e2e"; B="@bob:e2e"; C="@carol:e2e"

echo
echo "── T1: kick / ban / unban are SERVER-scoped ─────────────────────────"

curl -s -o "$WORK/last-body.json" -X POST "${BASE}/createRoom" -H "Authorization: Bearer $T_ALICE" \
  -H 'Content-Type: application/json' -d '{"name":"general","visibility":"public"}' >/dev/null
ROOM=$(jfield room_id)
[[ -n "$ROOM" ]] || { cat "$WORK/last-body.json"; die "alice could not create a channel"; }
echo "     room = $ROOM"

check "plain member cannot kick"                403 "$(req POST "/rooms/$ROOM/kick" "$T_BOB" "{\"user_id\":\"$C\"}")"

# Alice grants bob KICK|BAN (0x80|0x100 = 0x180) as a PER-CHANNEL override.
check "admin can write a per-channel override"  200 "$(req PUT "/rooms/$ROOM/state/bsfchat.channel.permissions/user:$B" "$T_ALICE" '{"allow":"0x180","deny":"0x0"}')"

# THE core property: that override must confer nothing.
check "channel override does NOT confer kick"   403 "$(req POST "/rooms/$ROOM/kick" "$T_BOB" "{\"user_id\":\"$C\"}")"
check "channel override does NOT confer ban"    403 "$(req POST "/rooms/$ROOM/ban" "$T_BOB" "{\"user_id\":\"$C\"}")"
check "channel override does NOT confer unban"  403 "$(req POST "/rooms/$ROOM/unban" "$T_BOB" "{\"user_id\":\"$C\"}")"
# ...including through the generic state-PUT route, which was the bypass.
check "state-PUT membership bypass is closed"   403 "$(req PUT "/rooms/$ROOM/state/m.room.member/$C" "$T_BOB" '{"membership":"ban"}')"

check "admin CAN ban (server-wide role)"        200 "$(req POST "/rooms/$ROOM/ban" "$T_ALICE" "{\"user_id\":\"$C\"}")"
check "admin CAN unban"                         200 "$(req POST "/rooms/$ROOM/unban" "$T_ALICE" "{\"user_id\":\"$C\"}")"

echo
echo "── T2: nickname permissions ─────────────────────────────────────────"

check "own nickname with CHANGE_NICKNAME"       200 "$(req PUT "/profile/$B/nickname" "$T_BOB" '{"nickname":"Bobby"}')"
check "GET returns it"                          200 "$(req GET "/profile/$B/nickname" "$T_BOB")"
CHECKS=$((CHECKS+1))
if grep -q 'Bobby' "$WORK/last-body.json"; then printf 'ok   %-58s\n' "GET body carries the nickname";
else printf 'FAIL %-58s body=%s\n' "GET body carries the nickname" "$(cat "$WORK/last-body.json")"; FAILURES=$((FAILURES+1)); fi

check "other's nickname without MANAGE_NICKNAMES" 403 "$(req PUT "/profile/$C/nickname" "$T_BOB" '{"nickname":"Pwned"}')"
check "nickname = another account's username"     400 "$(req PUT "/profile/$B/nickname" "$T_BOB" '{"nickname":"alice"}')"
check "mxid-shaped nickname"                      400 "$(req PUT "/profile/$B/nickname" "$T_BOB" '{"nickname":"@alice:e2e"}')"
check "bidi override in nickname"                 400 "$(req PUT "/profile/$B/nickname" "$T_BOB" '{"nickname":"Bob‮nimda"}')"
check "over-length nickname"                      400 "$(req PUT "/profile/$B/nickname" "$T_BOB" '{"nickname":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')"
check "admin can rename anyone"                   200 "$(req PUT "/profile/$C/nickname" "$T_ALICE" '{"nickname":"Caz"}')"

# Alice defines a nickname-moderator role (MANAGE_NICKNAMES 0x1000 + everyone 0x80f
# = 0x180f) at position 10 and assigns it to bob, so the RANK check can be
# exercised by a real non-admin moderator against an admin.
ROLES='{"roles":[
 {"id":"everyone","name":"@everyone","color":"#99aab5","position":0,"permissions":"0x80f","mentionable":false,"hoist":false},
 {"id":"nickmod","name":"Nickname mod","color":"#43b581","position":10,"permissions":"0x180f","mentionable":true,"hoist":false},
 {"id":"admin","name":"Admin","color":"#f04747","position":100,"permissions":"0x9fff","mentionable":true,"hoist":true}]}'
check "admin can define roles"                   200 "$(req PUT "/rooms/$ROOM/state/bsfchat.server.roles/" "$T_ALICE" "$ROLES")"
check "admin can assign nickmod to bob"          200 "$(req PUT "/rooms/$ROOM/state/bsfchat.member.roles/$B" "$T_ALICE" '{"role_ids":["everyone","nickmod"]}')"

check "moderator with MANAGE_NICKNAMES renames"  200 "$(req PUT "/profile/$C/nickname" "$T_BOB" '{"nickname":"Renamed"}')"
check "moderator cannot rename a HIGHER rank"    403 "$(req PUT "/profile/$A/nickname" "$T_BOB" '{"nickname":"Clown"}')"
check "null clears a nickname"                   200 "$(req PUT "/profile/$C/nickname" "$T_BOB" '{"nickname":null}')"
check "unauthenticated nickname write"           401 "$(req PUT "/profile/$B/nickname" "" '{"nickname":"X"}')"

# A channel-scoped grant of the nickname flags must confer nothing either.
check "channel override for nickname flags"      200 "$(req PUT "/rooms/$ROOM/state/bsfchat.channel.permissions/user:$C" "$T_ALICE" '{"allow":"0x1000","deny":"0x0"}')"
check "channel override does NOT confer rename"  403 "$(req PUT "/profile/$B/nickname" "$T_CAROL" '{"nickname":"Hacked"}')"

# The nickname must reach the member event clients actually render.
check "member state readable"                    200 "$(req GET "/rooms/$ROOM/state/m.room.member/$B" "$T_ALICE")"
CHECKS=$((CHECKS+1))
if python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d.get("displayname")=="Bobby" and d.get("bsfchat.nickname")=="Bobby" else 1)
' "$WORK/last-body.json"; then
  printf 'ok   %-58s\n' "nickname mirrored into m.room.member"
else
  printf 'FAIL %-58s body=%s\n' "nickname mirrored into m.room.member" "$(cat "$WORK/last-body.json")"
  FAILURES=$((FAILURES+1))
fi

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
