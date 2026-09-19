#!/bin/bash
# End-to-end authorization check for POST /_matrix/client/v3/createRoom against
# the real bsfchat-server binary, exercising the HTTP routing that unit tests
# bypass.
#
# SAFETY: the owner's live dev database lives in the data/ directory beside
# this checkout (override with BSFCHAT_REAL_DATA).
# An earlier agent misparsed the TOML (it uses [server]/[database] TABLES, not
# flat keys), silently fell back to ./data/bsfchat.db, and migrated the real
# database. Three independent guards below; any one failing aborts:
#   1. cwd is the throwaway dir, so even a relative-path fallback lands there.
#   2. the real DB's size+mtime is recorded before start and re-checked after.
#   3. the run aborts unless the throwaway DB file actually appears.
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
REAL_DB="$(e2e_real_data_dir || echo /nonexistent)/bsfchat.db"
BIN=$(e2e_require_server_bin) || exit 1
PORT=18456
WORK=$(mktemp -d /tmp/bsfchat-e2e.XXXXXX)
ROOT="http://127.0.0.1:$PORT"
BASE="$ROOT/_matrix/client/v3"

fail() { echo "FAIL: $*" >&2; cleanup; exit 1; }

REAL_FINGERPRINT=""
if [ -e "$REAL_DB" ]; then
    REAL_FINGERPRINT=$(stat -f '%z:%m' "$REAL_DB")
    echo "guard: real dev DB fingerprint $REAL_FINGERPRINT"
else
    echo "guard: real dev DB does not exist (nothing to protect)"
fi

SRV_PID=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
}

check_real_db() {
    if [ -n "$REAL_FINGERPRINT" ]; then
        local now
        now=$(stat -f '%z:%m' "$REAL_DB")
        [ "$now" = "$REAL_FINGERPRINT" ] || fail "THE REAL DEV DATABASE WAS TOUCHED ($REAL_FINGERPRINT -> $now)"
    elif [ -e "$REAL_DB" ]; then
        fail "THE REAL DEV DATABASE WAS CREATED"
    fi
}

mkdir -p "$WORK/db" "$WORK/media"
cat > "$WORK/server.toml" <<EOF
[server]
name = "e2e.test"
bind_address = "127.0.0.1"
port = $PORT
workers = 4

[database]
path = "$WORK/db/bsfchat.db"

[media]
path = "$WORK/media/"
max_upload_size_mb = 5
require_auth = true

[auth]
registration_enabled = true
password_hash_cost = 12

[voice]
enabled = false

[push]
# Not exercised here, and push with no gateway allowlist is now a startup error.
enabled = false
EOF

cd "$WORK" || exit 1
"$BIN" --config "$WORK/server.toml" > "$WORK/server.log" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 60); do
    curl -fsS "$ROOT/_matrix/client/versions" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -fsS "$ROOT/_matrix/client/versions" >/dev/null 2>&1 || { cat "$WORK/server.log"; fail "server never came up"; }

# Guard 3: the configured DB must be the one in use.
[ -s "$WORK/db/bsfchat.db" ] || fail "configured database was NOT created — config not honoured, refusing to continue"
[ ! -e "$WORK/data/bsfchat.db" ] || fail "server fell back to ./data/bsfchat.db — config not honoured"
check_real_db
echo "guard: throwaway DB in use at $WORK/db/bsfchat.db"
echo

register() { # localpart -> token on stdout
    curl -sS -X POST "$BASE/register" -H 'Content-Type: application/json' \
        -d "{\"username\":\"$1\",\"password\":\"correct horse battery staple\"}" \
        | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))'
}

# $1=label $2=expected status $3=token $4=json body ; echoes room_id on success
create_room() {
    local out code body
    out=$(curl -sS -o "$WORK/resp" -w '%{http_code}' -X POST "$BASE/createRoom" \
          -H "Authorization: Bearer $3" -H 'Content-Type: application/json' -d "$4")
    code="$out"; body=$(cat "$WORK/resp")
    if [ "$code" != "$2" ]; then
        fail "$1: expected HTTP $2, got $code — $body"
    fi
    # Progress goes to stderr: stdout is the room_id, which callers capture.
    echo "  ok  $1 -> HTTP $code" >&2
    if [ "$code" = "200" ]; then
        printf '%s' "$body" | python3 -c 'import sys,json; print(json.load(sys.stdin)["room_id"])'
    fi
}

put_state() { # $1=label $2=expected $3=token $4=room $5=type $6=stateKey $7=body
    local code body
    code=$(curl -sS -o "$WORK/resp" -w '%{http_code}' -X PUT \
        "$BASE/rooms/$4/state/$5/$6" \
        -H "Authorization: Bearer $3" -H 'Content-Type: application/json' -d "$7")
    body=$(cat "$WORK/resp")
    [ "$code" = "$2" ] || fail "$1: expected HTTP $2, got $code — $body"
    echo "  ok  $1 -> HTTP $code"
}

echo "--- accounts (first registration becomes Admin at bootstrap) ---"
OWNER_TOKEN=$(register owner);   [ -n "$OWNER_TOKEN" ] || fail "owner registration"
BOB_TOKEN=$(register bob);       [ -n "$BOB_TOKEN" ]   || fail "bob registration"
CAROL_TOKEN=$(register carol);   [ -n "$CAROL_TOKEN" ] || fail "carol registration"
echo "  ok  owner / bob / carol registered"
echo

echo "--- 1. owner (Admin role) can create a channel ---"
GENERAL=$(create_room "owner creates #general" 200 "$OWNER_TOKEN" '{"name":"general"}')
echo

echo "--- 2. bob and carol hold only @everyone: creation refused (403) ---"
create_room "bob creates channel"  403 "$BOB_TOKEN"   '{"name":"bob-spam"}'
create_room "bob creates category" 403 "$BOB_TOKEN"   '{"name":"Bob","is_category":true}'
create_room "carol creates channel" 403 "$CAROL_TOKEN" '{"name":"carol-spam"}'
echo

echo "--- 3. owner defines a NON-ADMIN role holding only MANAGE_CHANNELS ---"
# @everyone default 0x080f + MANAGE_CHANNELS 0x0020 = 0x082f. No ADMINISTRATOR.
put_state "define role 'builder'" 200 "$OWNER_TOKEN" "$GENERAL" \
    "bsfchat.server.roles" "" \
    '{"roles":[
        {"id":"everyone","name":"@everyone","position":0,"permissions":"0x080f"},
        {"id":"mod","name":"Moderator","position":10,"permissions":"0x0a9f"},
        {"id":"admin","name":"Admin","position":100,"permissions":"0x9fff"},
        {"id":"builder","name":"Channel Builder","position":5,"permissions":"0x082f"}
    ]}'
put_state "assign 'builder' to bob" 200 "$OWNER_TOKEN" "$GENERAL" \
    "bsfchat.member.roles" "@bob:e2e.test" \
    '{"role_ids":["everyone","builder"]}'
echo

echo "--- 4. THE POSITIVE PATH: bob is not an admin, but his role grants it ---"
BOBCHAN=$(create_room "bob creates a text channel"  200 "$BOB_TOKEN" '{"name":"bob-builds"}')
BOBCAT=$(create_room  "bob creates a category"      200 "$BOB_TOKEN" '{"name":"Projects","is_category":true}')
create_room "bob creates a voice channel" 200 "$BOB_TOKEN" '{"name":"bob-voice","voice":true}' >/dev/null
# Prove bob really is NOT an administrator: MANAGE_SERVER is a different flag.
AUDIT_CODE=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/bsfchat/audit_log" \
             -H "Authorization: Bearer $BOB_TOKEN")
[ "$AUDIT_CODE" = "403" ] || fail "bob should NOT have MANAGE_SERVER (audit log gave HTTP $AUDIT_CODE)"
echo "  ok  bob is still refused the audit log (403) — the grant is scoped, not admin"
echo

echo "--- 5. carol gets MANAGE_CHANNELS as a PER-CHANNEL override on #general ---"
put_state "override: allow MANAGE_CHANNELS for carol in #general" 200 "$OWNER_TOKEN" "$GENERAL" \
    "bsfchat.channel.permissions" "user:@carol:e2e.test" \
    '{"allow":"0x0020","deny":"0x0"}'
# The override must be real — carol can now rename that one channel.
put_state "carol renames #general (override works)" 200 "$CAROL_TOKEN" "$GENERAL" \
    "m.room.name" "" '{"name":"general-renamed-by-carol"}'
# ...but it must NOT let her add channels to the server.
create_room "carol creates channel"  403 "$CAROL_TOKEN" '{"name":"carol-was-here"}'
create_room "carol creates category" 403 "$CAROL_TOKEN" '{"name":"Carol","is_category":true}'
echo

echo "--- 6. a DM is a per-user capability, not channel management ---"
create_room "carol opens a DM" 200 "$CAROL_TOKEN" \
    '{"is_direct":true,"visibility":"private","invite":["@bob:e2e.test"]}' >/dev/null
echo

echo "--- 7. unauthenticated create is 401, not 403 ---"
UNAUTH=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/createRoom" \
         -H 'Content-Type: application/json' -d '{"name":"anon"}')
[ "$UNAUTH" = "401" ] || fail "unauthenticated create gave HTTP $UNAUTH, expected 401"
echo "  ok  unauthenticated create -> HTTP 401"
echo

check_real_db
echo "guard: real dev DB still untouched"
cleanup
echo
echo "ALL E2E AUTHORIZATION CHECKS PASSED"
echo "workdir: $WORK"
