#!/bin/bash
# End-to-end check of the server-wide ban list and the unified moderation path,
# against the REAL bsfchat-server binary over HTTP.
#
# Unit tests call handlers directly and so bypass routing, auth middleware and
# JSON round-tripping. These are authorization paths, so they are worth exercising
# through the actual wire.
#
# Safety: everything lives under a throwaway directory. The real dev database at
# /Users/josh/dev/gamechat/data is checksummed before and after and the script
# HARD-FAILS if a single byte changed, and hard-fails if the server did not
# actually create its database at the configured path (which is how a misparsed
# TOML would show up).
set -uo pipefail

BIN=/Users/josh/dev/gamechat/server/build-ban/bsfchat-server
WORK=$(mktemp -d /tmp/bsfchat-ban-e2e-XXXXXX)
REALDATA=/Users/josh/dev/gamechat/data
PORT=8901
BASE="http://127.0.0.1:${PORT}/_matrix/client/v3"
FAILURES=0
CHECKS=0
SRV_PID=""

cleanup() {
  if [[ -n "${SRV_PID:-}" ]]; then kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; fi
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 90; }

snapshot() { find "$REALDATA" -type f -exec shasum {} \; 2>/dev/null | sort; }
snapshot > "$WORK/real-before.txt"
[[ -s "$WORK/real-before.txt" ]] || die "could not checksum $REALDATA; refusing to run blind"

# TOML TABLES, not flat keys. A flat `database_path = ...` parses to nothing and
# the server silently falls back to its default path — which is how a previous run
# migrated the owner's real database.
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

check_body() { # check_body LABEL NEEDLE  (asserts NEEDLE is in the last body)
  CHECKS=$((CHECKS+1))
  if grep -q -- "$2" "$WORK/last-body.json" 2>/dev/null; then
    printf 'ok   %-58s\n' "$1"
  else
    printf 'FAIL %-58s body=%s\n' "$1" "$(cat "$WORK/last-body.json" 2>/dev/null)"
    FAILURES=$((FAILURES+1))
  fi
}

check_no_body() { # check_no_body LABEL NEEDLE
  CHECKS=$((CHECKS+1))
  if grep -q -- "$2" "$WORK/last-body.json" 2>/dev/null; then
    printf 'FAIL %-58s body=%s\n' "$1" "$(cat "$WORK/last-body.json" 2>/dev/null)"
    FAILURES=$((FAILURES+1))
  else
    printf 'ok   %-58s\n' "$1"
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
create_room() { # create_room TOKEN NAME -> room id
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/createRoom" -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/json' -d "{\"name\":\"$2\",\"visibility\":\"public\"}" >/dev/null
  jfield room_id
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

A="@alice:e2e"; B="@bob:e2e"; C="@carol:e2e"

echo
echo "── T1: a ban reaches channels the moderator never named ─────────────"

GENERAL=$(create_room "$T_ALICE" general)
OFFTOPIC=$(create_room "$T_ALICE" offtopic)
SECRET=$(create_room "$T_ALICE" secret-plans)
[[ -n "$GENERAL" && -n "$OFFTOPIC" && -n "$SECRET" ]] || die "channel creation failed"
echo "     general=$GENERAL offtopic=$OFFTOPIC secret=$SECRET"

# Auto-join force-joined every account into all three.
req GET "/joined_rooms" "$T_CAROL" > /dev/null
check_body "carol starts joined to offtopic"          "$OFFTOPIC"
check_body "carol starts joined to secret-plans"      "$SECRET"

# ONE ban request, naming ONE room — what the client's loop issued per room.
BODY_C='{"user_id":"'"$C"'","reason":"e2e"}'
check "alice bans carol via general"          200 "$(req POST "/rooms/$GENERAL/ban" "$T_ALICE" "$BODY_C")"

# Asserted from ALICE's session, not carol's. A ban now revokes carol's tokens, so
# every request of hers answers 401 — and a check that merely looked for the room
# id to be absent from her response body would pass on the error page, whatever
# the membership rows actually say. Reading the state event from an authorised
# account is what proves the projection really happened.
req GET "/rooms/$OFFTOPIC/state/m.room.member/$C" "$T_ALICE" > /dev/null
check_body "carol's membership in offtopic is ban"    '"membership":"ban"'
req GET "/rooms/$SECRET/state/m.room.member/$C" "$T_ALICE" > /dev/null
check_body "...and in the channel never named"        '"membership":"ban"'

# The session revocation itself.
OLD_T_CAROL="$T_CAROL"
check "the ban revoked carol's live session"   401 "$(req GET "/joined_rooms" "$OLD_T_CAROL")"
check "...her sync is refused outright"        401 "$(req GET "/sync?timeout=0" "$OLD_T_CAROL")"

# ...and she cannot simply log back in, which is what would have made the
# revocation theatre: she still knows her password.
LOGIN_CAROL='{"type":"m.login.password","identifier":{"type":"m.id.user","user":"carol"},"password":"pw-carol-12345"}'
check "a banned user cannot log in again"      403 "$(req POST "/login" "" "$LOGIN_CAROL")"
check_body "...and is told why"                       "banned from this server"

echo
echo "── T2: auto-join cannot re-admit a banned user ──────────────────────"

# Creating a public channel force-joins every user on the server. This is what
# silently undid the client-side ban loop.
FRESH=$(create_room "$T_ALICE" after-the-ban)
[[ -n "$FRESH" ]] || die "could not create the post-ban channel"
req GET "/rooms/$FRESH/members" "$T_ALICE" > /dev/null
check_no_body "a channel made AFTER the ban does not re-admit" "$C"

INVITE_C='{"user_id":"'"$C"'"}'
check "banned carol cannot be invited back"   403 "$(req POST "/rooms/$FRESH/invite" "$T_ALICE" "$INVITE_C")"
check_body "...for the ban reason, not a room reason"  "banned from this server"

REREG='{"username":"carol","password":"pw-carol-12345","auth":{"type":"m.login.dummy"}}'
check "a banned identity cannot re-register"  403 "$(req POST "/register" "" "$REREG")"

echo
echo "── T3: the ban survives deletion of the channel it came from ────────"

check "alice deletes the channel she banned from" 200 "$(req DELETE "/rooms/$GENERAL" "$T_ALICE")"
check "the ban still holds after that deletion"   403 "$(req POST "/login" "" "$LOGIN_CAROL")"
check_body "...still for the ban reason"              "banned from this server"

echo
echo "── T4: unban restores access, server-wide ───────────────────────────"

UNBAN_C='{"user_id":"'"$C"'"}'
check "alice unbans carol via offtopic"       200 "$(req POST "/rooms/$OFFTOPIC/unban" "$T_ALICE" "$UNBAN_C")"

# The unban does NOT resurrect the session the ban revoked — those rows are gone.
# The way back in is the ordinary login, which is now permitted again.
check "the revoked session stays revoked"     401 "$(req GET "/joined_rooms" "$OLD_T_CAROL")"
check "carol can log in fresh after the unban" 200 "$(req POST "/login" "" "$LOGIN_CAROL")"
T_CAROL=$(jfield access_token)
[[ -n "$T_CAROL" ]] || die "carol got no token after unban"

check "carol can rejoin offtopic"             200 "$(req POST "/rooms/$OFFTOPIC/join" "$T_CAROL")"
# secret-plans was never named in either the ban or the unban request.
check "carol can rejoin secret-plans too"     200 "$(req POST "/rooms/$SECRET/join" "$T_CAROL")"

echo
echo "── T5: B1 — a state-PUT ban actually bans ───────────────────────────"

req GET "/joined_rooms" "$T_BOB" > /dev/null
check_body "bob starts joined to offtopic"            "$OFFTOPIC"

# THE defect: this wrote the m.room.member event and never the membership row, so
# bob stayed a fully joined member everywhere while clients hid him.
BAN_STATE='{"membership":"ban"}'
check "alice bans bob through the state route" 200 "$(req PUT "/rooms/$OFFTOPIC/state/m.room.member/$B" "$T_ALICE" "$BAN_STATE")"

# Read from alice's session: bob's own is revoked, so his responses would be 401
# error bodies that trivially "do not contain" the room id.
req GET "/rooms/$OFFTOPIC/state/m.room.member/$B" "$T_ALICE" > /dev/null
check_body "bob's membership row really says ban"     '"membership":"ban"'
req GET "/rooms/$SECRET/state/m.room.member/$B" "$T_ALICE" > /dev/null
check_body "...in secret-plans as well"               '"membership":"ban"'

LOGIN_BOB='{"type":"m.login.password","identifier":{"type":"m.id.user","user":"bob"},"password":"pw-bob-12345"}'
check "a state-PUT ban revoked bob's session"  401 "$(req GET "/joined_rooms" "$T_BOB")"
check "...and he cannot log back in"           403 "$(req POST "/login" "" "$LOGIN_BOB")"
check_body "...because he is server-banned"           "banned from this server"

UNBAN_B='{"user_id":"'"$B"'"}'
check "and it is liftable through /unban"      200 "$(req POST "/rooms/$OFFTOPIC/unban" "$T_ALICE" "$UNBAN_B")"
check "bob can log in again"                   200 "$(req POST "/login" "" "$LOGIN_BOB")"
T_BOB=$(jfield access_token)
[[ -n "$T_BOB" ]] || die "bob got no token after unban"
check "bob can come back"                      200 "$(req POST "/rooms/$OFFTOPIC/join" "$T_BOB")"

echo
echo "── T6: authorization still refuses, for the right reasons ───────────"

BAN_C='{"user_id":"'"$C"'"}'
check "a plain member cannot ban"              403 "$(req POST "/rooms/$OFFTOPIC/ban" "$T_BOB" "$BAN_C")"
check_body "...on the permission, not on rank"        "Insufficient permissions to ban"
check "a plain member cannot ban via state-PUT" 403 "$(req PUT "/rooms/$OFFTOPIC/state/m.room.member/$C" "$T_BOB" "$BAN_STATE")"
check_body "...same refusal from either route"        "Insufficient permissions to ban"
check "bob's failed attempts left carol joined" 200 "$(req GET "/rooms/$OFFTOPIC/state/m.room.member/$C" "$T_ALICE")"
check_body "...genuinely still joined"                "join"

echo
echo "── T6b: a kick does not sign the user out of the server ─────────────"

KICK_C='{"user_id":"'"$C"'"}'
check "alice kicks carol from offtopic"        200 "$(req POST "/rooms/$OFFTOPIC/kick" "$T_ALICE" "$KICK_C")"
# A kick is per-channel. Carol keeps her session and the rest of the server.
check "carol's session still works after a kick" 200 "$(req GET "/joined_rooms" "$T_CAROL")"
check_body "...and she is still in secret-plans"     "$SECRET"
check "carol can rejoin the channel she was kicked from" 200 "$(req POST "/rooms/$OFFTOPIC/join" "$T_CAROL")"

echo
echo "── T7: the audit trail survived the rewrite ─────────────────────────"
req GET "/bsfchat/audit_log?limit=50" "$T_ALICE" > /dev/null
check_body "the ban is recorded"                      "member.ban"
check_body "the unban is recorded"                    "member.unban"
check_body "the channel deletion is recorded"         "channel.delete"

stop_server

# ── guard: the real dev database must be byte-identical ──────────────────
snapshot > "$WORK/real-after.txt"
if ! diff -q "$WORK/real-before.txt" "$WORK/real-after.txt" > /dev/null; then
  echo "FATAL: the real dev database at $REALDATA CHANGED during this run:"
  diff "$WORK/real-before.txt" "$WORK/real-after.txt"
  exit 91
fi
echo
echo "real dev database unchanged (verified byte-for-byte)"

echo
echo "══ $((CHECKS - FAILURES))/${CHECKS} checks passed ══"
[[ $FAILURES -eq 0 ]] || exit 1
