#!/bin/bash
# End-to-end check of the server-wide ban list and the unified moderation path,
# against the REAL bsfchat-server binary over HTTP.
#
# Unit tests call handlers directly and so bypass routing, auth middleware and
# JSON round-tripping. These are authorization paths, so they are worth exercising
# through the actual wire.
#
# Safety: everything lives under a throwaway directory. The real dev database at
# the live dev data directory is checksummed before and after and the script
# HARD-FAILS if a single byte changed, and hard-fails if the server did not
# actually create its database at the configured path (which is how a misparsed
# TOML would show up).
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1
WORK=$(mktemp -d /tmp/bsfchat-ban-e2e-XXXXXX)
REALDATA=$(e2e_real_data_dir || echo /nonexistent)
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
    -d "{\"username\":\"$1\",\"password\":\"e2e-correct-horse-7\",\"auth\":{\"type\":\"m.login.dummy\"}}" >/dev/null
  jfield access_token
}
login() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/login" -H 'Content-Type: application/json' \
    -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"$1\"},\"password\":\"e2e-correct-horse-7\"}" >/dev/null
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
LOGIN_CAROL='{"type":"m.login.password","identifier":{"type":"m.id.user","user":"carol"},"password":"e2e-correct-horse-7"}'
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

REREG='{"username":"carol","password":"e2e-correct-horse-7","auth":{"type":"m.login.dummy"}}'
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

LOGIN_BOB='{"type":"m.login.password","identifier":{"type":"m.id.user","user":"bob"},"password":"e2e-correct-horse-7"}'
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

echo
echo "── T8: the server ban LIST is readable over HTTP ────────────────────"
#
# SqliteStore::list_server_bans had no route and no caller, so the client rebuilt
# its bans tab from the membership rows its own sync surfaced — and a user banned
# while holding no membership row anywhere was invisible in it and could not be
# unbanned from it. These checks run against the real routing table.

check "unauthenticated cannot read the ban list" 401 "$(req GET "/bsfchat/server_bans" "")"

# A plain member is refused, and learns nothing.
check "plain member cannot read the ban list" 403 "$(req GET "/bsfchat/server_bans" "$T_BOB")"
check_body "...refused by the permission gate" "M_FORBIDDEN"
check_body "...and for the right reason"       "server ban list"
check_no_body "...leaking no ban list"         "bans"

# A FRESH channel and a FRESH account for this section. Earlier phases left bob
# and carol in states that varied by channel (kicked, banned, rejoined), and
# building on that made two of these checks pass vacuously the first time round:
# the ban silently failed and carol's override silently failed to apply, so the
# escalation 403s below were proving nothing.
BANLIST=$(create_room "$T_ALICE" banlist-e2e)
[[ -n "$BANLIST" ]] || die "could not create the banlist channel"
T_DAVE=$(register dave)
[[ -n "$T_DAVE" ]] || die "could not register dave"
D="@dave:e2e"

check "dave is a member of the new channel" 200 "$(req POST "/rooms/$BANLIST/join" "$T_DAVE")"
check "carol is a member of the new channel" 200 "$(req POST "/rooms/$BANLIST/join" "$T_CAROL")"

# Built in a variable rather than inline: the backslash escaping does not survive
# a nested command substitution, which silently produced M_BAD_JSON and left the
# three list assertions below inspecting an empty ban list.
BAN_BODY='{"user_id":"'"$D"'","reason":"list e2e"}'
check "alice bans dave" 200 "$(req POST "/rooms/$BANLIST/ban" "$T_ALICE" "$BAN_BODY")"

req GET "/bsfchat/server_bans" "$T_ALICE" > /dev/null
check_body "admin sees the banned user"        "$D"
check_body "...with the actor who placed it"   "$A"
check_body "...with the reason"                "list e2e"
check_body "...and a total"                    '"total"'

# Pagination over the real query string.
check "limit=1 is accepted" 200 "$(req GET "/bsfchat/server_bans?limit=1" "$T_ALICE")"
check "a malformed limit is refused" 400 "$(req GET "/bsfchat/server_bans?limit=lots" "$T_ALICE")"
check_body "...as an invalid parameter" "M_INVALID_PARAM"
check "an empty cursor is refused rather than restarting" 400 \
  "$(req GET "/bsfchat/server_bans?after=" "$T_ALICE")"

# The escalation shape: a per-channel BAN_MEMBERS (bit 8 = 0x100) override must
# not unlock the SERVER-WIDE ban list. MANAGE_CHANNELS (bit 5 = 0x20) rides along
# purely so the positive control has something channel-scoped to demonstrate —
# PermissionsEngine applies the ADMINISTRATOR short-circuit to the ROLE base
# before overrides, so an override-granted ADMINISTRATOR does not expand.
req PUT "/rooms/$BANLIST/state/bsfchat.channel.permissions/user:$C" "$T_ALICE" \
  '{"allow":"0x120","deny":"0x0"}' > /dev/null
# Read it back: a PUT answers {"event_id":...}, so asserting on the PUT's body
# would pass whatever was written.
req GET "/rooms/$BANLIST/state/bsfchat.channel.permissions/user:$C" "$T_ALICE" > /dev/null
check_body "carol has a per-channel BAN_MEMBERS override" "0x120"

# Positive control: the override really is live inside that channel, and only
# there. Without this every 403 below could be passing because it never applied.
check "carol can rename the channel her override covers" 200 \
  "$(req PUT "/rooms/$BANLIST/state/m.room.name/" "$T_CAROL" '{"name":"carol-was-here"}')"
check "...and cannot rename one it does not" 403 \
  "$(req PUT "/rooms/$SECRET/state/m.room.name/" "$T_CAROL" '{"name":"nope"}')"

# room_id/channel are parameters this endpoint does NOT define, and they are here
# on purpose: the plausible way to reintroduce the escalation is for somebody to
# add a room filter later and pass it to the permission check as the scope. A
# request that never names a room cannot tell a server-scoped check apart from a
# room-scoped one handed an empty string.
for Q in "" "?limit=1" "?after=%40a%3Ae2e" "?room_id=$BANLIST" "?channel=$BANLIST" \
         "?room_id=$BANLIST&limit=1"; do
  check "channel override does NOT unlock the ban list [$Q]" 403 \
    "$(req GET "/bsfchat/server_bans$Q" "$T_CAROL")"
  check_body "...refused by the permission gate [$Q]" "server ban list"
  check_no_body "...leaking no banned user [$Q]"      "$D"
done

# The round trip the bans tab needs: read the list, unban from it, read again.
UNBAN_BODY='{"user_id":"'"$D"'"}'
check "alice unbans dave from the list" 200 \
  "$(req POST "/rooms/$BANLIST/unban" "$T_ALICE" "$UNBAN_BODY")"
req GET "/bsfchat/server_bans" "$T_ALICE" > /dev/null
check_no_body "an unban removes the entry from the list" "$D"

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
