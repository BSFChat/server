#!/bin/bash
# End-to-end check that the profile endpoints always return a JSON OBJECT.
#
# The bug this pins down: handle_get_profile built its response as a
# default-constructed `json resp;` and then only ever assigned keys
# conditionally. A default-constructed nlohmann json IS null, so a freshly
# registered user — no displayname, no avatar, no nickname, not a bot —
# got a 200 whose body was the four characters `null`.
#
# That is not a cosmetic difference. `resp.json()["displayname"]` raises
# TypeError on it rather than KeyError, and so does the defensive-looking
# `resp.json().get("bsfchat.bot", False)`, so the obvious client idioms break
# on exactly the accounts most likely to hit them. The Matrix spec has this
# endpoint returning an object, and the rest of this API returns `{}` for an
# empty result.
#
# Safety first: this script refuses to run unless the server demonstrably
# honours the config file's [database] path. An earlier agent misparsed the
# TOML (it has [server]/[database] TABLES, not flat keys), the server silently
# fell back to ./data/bsfchat.db, and it migrated the user's real dev
# database. Every guard below exists because of that.
set -u

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1
REAL_DATA=$(e2e_real_data_dir || true)

WORK=$(mktemp -d /tmp/bsfchat-e2e-profile.XXXXXX)
DB="$WORK/e2e.db"
CONF="$WORK/server.toml"
LOG="$WORK/server.log"
PORT=18${RANDOM:0:3}
[ "$PORT" -lt 18100 ] && PORT=18452
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

register() {
    local user=$1
    local out
    out=$(api POST /_matrix/client/v3/register "" \
        "{\"username\":\"$user\",\"password\":\"e2e-profile-pw-7Kq2\",\"auth\":{\"type\":\"m.login.dummy\"}}")
    [ "$(status "$out")" = "200" ] || { echo "$out" >&2; fail "register $user failed"; }
    body "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

# assert_object DESCRIPTION BODY
#
# The core assertion. Checks the parsed body is a dict AND that the two idioms
# that a null body breaks actually work on it, because "is a dict" and "the
# client code that reads it does not raise" are the property we care about.
assert_object() {
    local what=$1 raw=$2
    printf '%s' "$raw" > "$WORK/resp.json"
    python3 - "$WORK/resp.json" "$what" <<'PY' || fail "$what: response is not a JSON object"
import json, sys
raw = open(sys.argv[1]).read()
what = sys.argv[2]
d = json.loads(raw)
assert isinstance(d, dict), f"{what}: expected a JSON object, got {type(d).__name__}: {raw!r}"
# The idioms that a bare `null` breaks with TypeError. A missing key must be a
# KeyError (absent), never a TypeError (wrong shape).
try:
    d["displayname"]
except KeyError:
    pass
try:
    d.get("bsfchat.bot", False)
except TypeError:
    raise AssertionError(f"{what}: .get() on the body raised TypeError: {raw!r}")
# An unset field must be an ABSENT KEY, never an explicit null. A client that
# checks `"displayname" in profile` and one that checks the value must agree.
nulls = [k for k, v in d.items() if v is None]
assert not nulls, f"{what}: fields present but explicitly null: {nulls}: {raw!r}"
PY
}

# ── Scenario ───────────────────────────────────────────────────────────────
# alice registers first, so bootstrap_roles gives her Admin. What matters here
# is that she is otherwise BARE: no displayname, no avatar, no nickname. That
# is the account that used to serialise as `null`.
ALICE_TOKEN=$(register alice)
pass "registered alice (bare: no displayname, no avatar, no nickname)"

ALICE="@alice:e2e.local"
ALICE_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ALICE")

# 1. The full profile of a bare user is `{}`, not `null`.
OUT=$(api GET "/_matrix/client/v3/profile/$ALICE_ENC" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "GET profile returned $(status "$OUT")"; }
RAW=$(body "$OUT")
[ "$RAW" = "null" ] && fail "GET profile of a bare user returned the literal \`null\` (the bug)"
assert_object "GET profile (bare user)" "$RAW"
[ "$RAW" = "{}" ] || fail "expected {} for a bare user, got: $RAW"
pass "GET profile of a bare user is {} — an object, not null"

# 2. Same for the two single-field getters, which had the identical pattern.
OUT=$(api GET "/_matrix/client/v3/profile/$ALICE_ENC/displayname" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "GET displayname returned $(status "$OUT")"; }
RAW=$(body "$OUT")
[ "$RAW" = "null" ] && fail "GET displayname of a bare user returned the literal \`null\`"
assert_object "GET displayname (unset)" "$RAW"
pass "GET displayname with none set is an object, not null"

OUT=$(api GET "/_matrix/client/v3/profile/$ALICE_ENC/avatar_url" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "GET avatar_url returned $(status "$OUT")"; }
RAW=$(body "$OUT")
[ "$RAW" = "null" ] && fail "GET avatar_url of a bare user returned the literal \`null\`"
assert_object "GET avatar_url (unset)" "$RAW"
pass "GET avatar_url with none set is an object, not null"

# 3. Unauthenticated reads are REFUSED.
#
#    This assertion is inverted from how it was first written. The endpoints
#    were public when this script landed, and that was the bug: all four GET
#    handlers never called authenticate(), so anyone who could reach the port
#    could walk the account namespace (404 vs 200) and harvest display names,
#    avatars and nicknames, unthrottled. fix/profile-auth closed it.
#
#    The shape guarantee this file exists for is unchanged and still checked
#    above, with a token. What changed is who may ask.
OUT=$(api GET "/_matrix/client/v3/profile/$ALICE_ENC" "")
[ "$(status "$OUT")" = "401" ] || { echo "$OUT"; fail "unauthenticated GET profile returned $(status "$OUT"), expected 401"; }
case "$(body "$OUT")" in
    *M_MISSING_TOKEN*) ;;
    *) echo "$OUT"; fail "no token supplied should be M_MISSING_TOKEN, not $(body "$OUT")" ;;
esac
pass "unauthenticated GET profile is refused with M_MISSING_TOKEN"

# 4. Setting a field still populates it — the fix must not have flattened the
#    response to a permanent {}.
OUT=$(api PUT "/_matrix/client/v3/profile/$ALICE_ENC/displayname" "$ALICE_TOKEN" \
    '{"displayname":"Alice Liddell"}')
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "PUT displayname failed"; }

OUT=$(api GET "/_matrix/client/v3/profile/$ALICE_ENC" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "GET profile after PUT returned $(status "$OUT")"; }
RAW=$(body "$OUT")
assert_object "GET profile (displayname set)" "$RAW"
printf '%s' "$RAW" > "$WORK/resp.json"
python3 - "$WORK/resp.json" <<'PY' || fail "displayname did not survive the round trip"
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("displayname") == "Alice Liddell", d
PY
pass "a set displayname is still reported"

OUT=$(api GET "/_matrix/client/v3/profile/$ALICE_ENC/displayname" "$ALICE_TOKEN")
RAW=$(body "$OUT")
assert_object "GET displayname (set)" "$RAW"
printf '%s' "$RAW" > "$WORK/resp.json"
python3 - "$WORK/resp.json" <<'PY' || fail "single-field displayname getter lost the value"
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("displayname") == "Alice Liddell", d
PY
pass "single-field displayname getter still reports the value"

# 5. A user who does not exist is still a 404 — "empty" and "absent" stay
#    distinguishable. Returning {} for an unknown user would be the obvious
#    wrong way to fix this.
MISSING_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "@nobody:e2e.local")
OUT=$(api GET "/_matrix/client/v3/profile/$MISSING_ENC" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "404" ] || { echo "$OUT"; fail "expected 404 for an unknown user, got $(status "$OUT")"; }
pass "an unknown user is still 404, not an empty object"

OUT=$(api GET "/_matrix/client/v3/profile/$MISSING_ENC/displayname" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "404" ] || fail "expected 404 for unknown user displayname, got $(status "$OUT")"
OUT=$(api GET "/_matrix/client/v3/profile/$MISSING_ENC/avatar_url" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "404" ] || fail "expected 404 for unknown user avatar_url, got $(status "$OUT")"
pass "unknown-user single-field getters are 404 too"

# 6. A second bare user, read by someone else. The first-registered account
#    gets bootstrap roles, so check the plain case too.
BOB_TOKEN=$(register bob)
BOB_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "@bob:e2e.local")
OUT=$(api GET "/_matrix/client/v3/profile/$BOB_ENC" "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "GET bob's profile returned $(status "$OUT")"; }
RAW=$(body "$OUT")
[ "$RAW" = "null" ] && fail "a second bare user's profile returned the literal \`null\`"
assert_object "GET profile (bare non-admin, read by another user)" "$RAW"
pass "a bare non-admin user's profile is an object too"

# ── Guard: the real dev database was never touched ─────────────────────────
REAL_FINGERPRINT_AFTER="(absent)"
if [ -f "$REAL_DB" ]; then
    REAL_FINGERPRINT_AFTER=$(shasum -a 256 "$REAL_DB" | awk '{print $1}')
fi
[ "$REAL_FINGERPRINT_BEFORE" = "$REAL_FINGERPRINT_AFTER" ] \
    || fail "the real dev database CHANGED during this run"
pass "real dev database untouched"

echo
echo "PASS: profile endpoints always return a JSON object"
cleanup
rm -rf "$WORK"
