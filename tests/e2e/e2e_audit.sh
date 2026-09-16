#!/bin/bash
# End-to-end check of the moderation audit log against the REAL server binary
# over HTTP.
#
# Safety first: this script refuses to run unless the server demonstrably honours
# the config file's [database] path. An earlier agent misparsed the TOML (it has
# [server]/[database] TABLES, not flat keys), the server silently fell back to
# ./data/bsfchat.db, and it migrated the user's real dev database. Every guard
# below exists because of that.
set -u

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1
REAL_DATA=$(e2e_real_data_dir || true)

WORK=$(mktemp -d /tmp/bsfchat-e2e-audit.XXXXXX)
DB="$WORK/e2e.db"
CONF="$WORK/server.toml"
LOG="$WORK/server.log"
PORT=18${RANDOM:0:3}
[ "$PORT" -lt 18100 ] && PORT=18448
BASE="http://127.0.0.1:$PORT"

fail() { echo "FAIL: $*" >&2; cleanup; exit 1; }
pass() { echo "  ok  $*"; }

SRV_PID=""
cleanup() {
    if [ -n "$SRV_PID" ] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null
        wait "$SRV_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# ── Guard: fingerprint the user's real dev database before we start ─────────
REAL_DB="$REAL_DATA/bsfchat.db"
REAL_FINGERPRINT_BEFORE="(absent)"
if [ -f "$REAL_DB" ]; then
    REAL_FINGERPRINT_BEFORE=$(shasum -a 256 "$REAL_DB" | awk '{print $1}')
fi
echo "Real dev DB fingerprint before: $REAL_FINGERPRINT_BEFORE"

# ── Config: TOML TABLES, not flat keys ─────────────────────────────────────
cat > "$CONF" <<EOF
[server]
name = "e2e.local"
bind_address = "127.0.0.1"
port = $PORT
workers = 4

[database]
path = "$DB"

[media]
path = "$WORK/media/"

[auth]
registration_enabled = true
password_hash_cost = 12

[voice]
enabled = false

[push]
enabled = false
EOF

# Run from a throwaway CWD so that IF the config were ignored, the fallback
# "./data/bsfchat.db" would land here and be caught rather than touching the repo.
cd "$WORK" || fail "cannot cd to $WORK"
"$BIN" --config "$CONF" > "$LOG" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 100); do
    curl -fsS "$BASE/_matrix/client/versions" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -fsS "$BASE/_matrix/client/versions" >/dev/null 2>&1 \
    || { cat "$LOG"; fail "server did not come up on $BASE"; }
pass "server started on port $PORT"

# ── HARD FAIL if the config was not honoured ───────────────────────────────
[ -f "$DB" ] || { cat "$LOG"; fail "config [database].path was NOT honoured: $DB was never created"; }
pass "config honoured: database created at $DB"

[ -e "$WORK/data/bsfchat.db" ] && fail "server fell back to ./data/bsfchat.db — config NOT honoured"
grep -q "Database: $DB" "$LOG" || fail "server log does not report the configured database path"
pass "no fallback database was created"

# ── Helpers ────────────────────────────────────────────────────────────────
# api METHOD PATH TOKEN [BODY] -> prints "HTTPSTATUS<newline>BODY"
api() {
    local method=$1 path=$2 token=$3 body=${4-}
    local args=(-sS -o "$WORK/body" -w '%{http_code}' -X "$method" "$BASE$path")
    [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
    [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
    local code
    code=$(curl "${args[@]}")
    echo "$code"
    cat "$WORK/body"
}
status() { echo "$1" | head -1; }
body()   { echo "$1" | tail -n +2; }
jqv()    { body "$1" | python3 -c "import json,sys; print(json.dumps(eval(\"lambda d: $2\")(json.load(sys.stdin))))"; }

register() {
    local user=$1
    local out
    out=$(api POST /_matrix/client/v3/register "" \
        "{\"username\":\"$user\",\"password\":\"password123\",\"auth\":{\"type\":\"m.login.dummy\"}}")
    [ "$(status "$out")" = "200" ] || { echo "$out" >&2; fail "register $user failed"; }
    body "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

# ── Scenario ───────────────────────────────────────────────────────────────
# alice registers first, so bootstrap_roles gives her Admin.
ALICE_TOKEN=$(register alice)
BOB_TOKEN=$(register bob)
pass "registered alice (owner/admin) and bob"

OUT=$(api POST /_matrix/client/v3/createRoom "$ALICE_TOKEN" \
    '{"name":"announcements","visibility":"public"}')
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "createRoom failed"; }
ROOM=$(body "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["room_id"])')
pass "alice created channel $ROOM"

ROOM_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ROOM")

# Bob must be a member for the ban to be meaningful.
OUT=$(api GET "/_matrix/client/v3/rooms/$ROOM_ENC/members" "$BOB_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "bob cannot see the channel"; }
pass "bob is a member of the channel"

# 1. Bob cannot read the audit log.
OUT=$(api GET /_matrix/client/v3/bsfchat/audit_log "$BOB_TOKEN")
[ "$(status "$OUT")" = "403" ] || { echo "$OUT"; fail "expected 403 for a plain member, got $(status "$OUT")"; }
case "$(body "$OUT")" in *records*) fail "403 response leaked records";; esac
pass "plain member gets 403 with no records"

# 2. Unauthenticated is 401.
OUT=$(api GET /_matrix/client/v3/bsfchat/audit_log "")
[ "$(status "$OUT")" = "401" ] || fail "expected 401 without a token, got $(status "$OUT")"
pass "unauthenticated gets 401"

# 3. Alice bans bob.
OUT=$(api POST "/_matrix/client/v3/rooms/$ROOM_ENC/ban" "$ALICE_TOKEN" \
    "{\"user_id\":\"@bob:e2e.local\",\"reason\":\"e2e ban reason\"}")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "ban failed"; }
pass "alice banned bob"

# 4. Alice reads the audit log and sees it.
OUT=$(api GET /_matrix/client/v3/bsfchat/audit_log "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "admin could not read the audit log"; }
body "$OUT" > "$WORK/audit1.json"
python3 - "$WORK/audit1.json" <<'PY' || fail "ban record missing or wrong"
import json, sys
d = json.load(open(sys.argv[1]))
recs = d["records"]
ban = [r for r in recs if r["action"] == "member.ban"]
assert len(ban) == 1, f"expected exactly one member.ban, got {len(ban)}: {recs}"
r = ban[0]
assert r["actor"] == "@alice:e2e.local", r
assert r["target_user"] == "@bob:e2e.local", r
assert r["reason"] == "e2e ban reason", r
assert r["before"]["membership"] == "join", r
assert r["after"]["membership"] == "ban", r
# The bootstrap role grants are in there too, attributed to the server.
assert any(x["action"] == "role.assign" and x["actor"] == "@server:e2e.local" for x in recs), recs
assert d["total"] >= len(recs)
print("  ok  audit log shows the ban with actor/target/before/after")
PY

# 5. Unban works (the route did not exist before this change) and is recorded.
OUT=$(api POST "/_matrix/client/v3/rooms/$ROOM_ENC/unban" "$ALICE_TOKEN" \
    '{"user_id":"@bob:e2e.local"}')
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "unban failed (route missing?)"; }
pass "alice unbanned bob over HTTP"

OUT=$(api GET /_matrix/client/v3/bsfchat/audit_log "$ALICE_TOKEN")
body "$OUT" > "$WORK/audit2.json"
python3 - "$WORK/audit2.json" <<'PY' || fail "unban record missing or wrong"
import json, sys
recs = json.load(open(sys.argv[1]))["records"]
unban = [r for r in recs if r["action"] == "member.unban"]
assert len(unban) == 1, f"expected one member.unban, got {len(unban)}"
r = unban[0]
assert r["actor"] == "@alice:e2e.local", r
assert r["target_user"] == "@bob:e2e.local", r
assert r["before"]["membership"] == "ban" and r["after"]["membership"] == "leave", r
print("  ok  audit log shows the unban")
PY

# 6. Role change through the real API.
OUT=$(api PUT "/_matrix/client/v3/rooms/$ROOM_ENC/state/bsfchat.member.roles/%40bob%3Ae2e.local" \
    "$ALICE_TOKEN" '{"role_ids":["everyone","mod"]}')
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "role assignment failed"; }
OUT=$(api GET /_matrix/client/v3/bsfchat/audit_log "$ALICE_TOKEN")
body "$OUT" > "$WORK/audit3.json"
python3 - "$WORK/audit3.json" <<'PY' || fail "role.assign record missing"
import json, sys
recs = json.load(open(sys.argv[1]))["records"]
r = [x for x in recs if x["action"] == "role.assign" and x["actor"] == "@alice:e2e.local"]
assert len(r) == 1, f"expected one admin-made role.assign, got {len(r)}"
assert r[0]["target_user"] == "@bob:e2e.local", r
assert r[0]["after"]["added"] == ["mod"], r
print("  ok  audit log shows the role assignment with added/removed")
PY

# 7. Deleting the channel keeps the records that reference it.
OUT=$(api DELETE "/_matrix/client/v3/rooms/$ROOM_ENC" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "delete room failed"; }
OUT=$(api GET /_matrix/client/v3/bsfchat/audit_log "$ALICE_TOKEN")
body "$OUT" > "$WORK/audit4.json"
python3 - "$WORK/audit4.json" "$ROOM" <<'PY' || fail "channel deletion audit wrong"
import json, sys
recs = json.load(open(sys.argv[1]))["records"]
room = sys.argv[2]
dele = [r for r in recs if r["action"] == "channel.delete"]
assert len(dele) == 1, f"expected one channel.delete, got {len(dele)}"
assert dele[0]["target_room"] == room, dele
assert dele[0]["before"]["name"] == "announcements", dele
assert "after" not in dele[0], dele
# The ban and unban records for the now-deleted channel are STILL there. This is
# the property that makes the audit log worth having: delete_room hard-deletes the
# room's events, so anything stored there would be gone.
assert any(r["action"] == "member.ban" and r["target_room"] == room for r in recs), recs
assert any(r["action"] == "member.unban" and r["target_room"] == room for r in recs), recs
print("  ok  channel-deletion record kept the channel's name; ban/unban records survived")
PY

# 8. Pagination over HTTP: walk the whole log one record at a time.
OUT=$(api GET "/_matrix/client/v3/bsfchat/audit_log?limit=1" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || fail "paginated read failed"
body "$OUT" > "$WORK/page1.json"
TOTAL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["total"])' "$WORK/page1.json")
CURSOR=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("next_from",""))' "$WORK/page1.json")
SEEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["records"][0]["id"])' "$WORK/page1.json")
COUNT=1
LAST_ID=$SEEN
while [ -n "$CURSOR" ]; do
    OUT=$(api GET "/_matrix/client/v3/bsfchat/audit_log?limit=1&from=$CURSOR" "$ALICE_TOKEN")
    [ "$(status "$OUT")" = "200" ] || fail "page from=$CURSOR failed"
    body "$OUT" > "$WORK/page.json"
    ID=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["records"]; print(r[0]["id"] if r else "")' "$WORK/page.json")
    [ -n "$ID" ] || break
    [ "$ID" -lt "$LAST_ID" ] || fail "pagination went backwards or repeated: $ID after $LAST_ID"
    LAST_ID=$ID
    COUNT=$((COUNT + 1))
    CURSOR=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("next_from",""))' "$WORK/page.json")
done
[ "$COUNT" = "$TOTAL" ] || fail "pagination saw $COUNT records but total is $TOTAL"
pass "paged through all $TOTAL records one at a time, strictly decreasing ids"

# 9. Malformed cursor is refused rather than silently restarting.
OUT=$(api GET "/_matrix/client/v3/bsfchat/audit_log?from=garbage" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "400" ] || fail "expected 400 for a bad cursor, got $(status "$OUT")"
pass "malformed cursor rejected with 400"

# 10. Audit content is not searchable.
OUT=$(api POST /_matrix/client/v3/search "$ALICE_TOKEN" \
    '{"search_categories":{"room_events":{"search_term":"e2e ban reason"}}}')
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "search request failed"; }
python3 - <<PY || fail "audit content leaked into search results"
import json
d = json.loads(open("$WORK/body").read())
c = d["search_categories"]["room_events"]
assert c["count"] == 0, c
assert c["results"] == [], c
print("  ok  the ban reason is not findable through message search")
PY

# 11. The database enforces append-only even from outside the server.
python3 - "$DB" <<'PY' || fail "append-only is not enforced by the database"
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
for sql in ("UPDATE audit_log SET actor='@nobody:e2e.local'", "DELETE FROM audit_log"):
    try:
        db.execute(sql)
        raise SystemExit(f"FAIL: {sql} was permitted")
    except sqlite3.IntegrityError as e:
        assert "append-only" in str(e), e
print("  ok  UPDATE and DELETE on audit_log are refused by the database")
PY

# ── Guard: the user's real dev database was never touched ───────────────────
REAL_FINGERPRINT_AFTER="(absent)"
if [ -f "$REAL_DB" ]; then
    REAL_FINGERPRINT_AFTER=$(shasum -a 256 "$REAL_DB" | awk '{print $1}')
fi
[ "$REAL_FINGERPRINT_BEFORE" = "$REAL_FINGERPRINT_AFTER" ] \
    || fail "THE REAL DEV DATABASE CHANGED ($REAL_FINGERPRINT_BEFORE -> $REAL_FINGERPRINT_AFTER)"
pass "real dev database at $REAL_DB is byte-identical (untouched)"

echo
echo "ALL E2E CHECKS PASSED (work dir: $WORK)"
cleanup
trap - EXIT
exit 0
