#!/bin/bash
# End-to-end HTTP Range check against the REAL bsfchat-server binary.
#
# Unit tests drive MediaHandler's content provider directly, or run an
# in-process httplib::Server. This runs the actual server process, so the real
# routing table, the real config parsing and the real socket path are all in
# play. Uses a throwaway database and media directory under a temp root; the
# owner's ./data is never touched, and the script hard-fails if the configured
# database path is not the one the server actually creates.
set -uo pipefail

SRV=/Users/josh/dev/gamechat/server
# build-fix is the build directory this repo's test runs use; build-media was a
# scratch tree from the streaming work and is not guaranteed to exist.
BIN=${BSFCHAT_SERVER_BIN:-$SRV/build-fix/bsfchat-server}
[ -x "$BIN" ] || { echo "server binary not found at $BIN (build it first)" >&2; exit 1; }
ROOT=$(mktemp -d /tmp/bsfchat-media-e2e.XXXXXX)
PORT=18${RANDOM:0:3}
[ "$PORT" -lt 1024 ] && PORT=18449
PASS=0; FAIL=0

cleanup() {
    [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n     %s\n' "$1" "${2:-}"; }
check(){ # name expected actual
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi
}

mkdir -p "$ROOT/data/media"
cat > "$ROOT/server.toml" <<EOF
[server]
name = "e2e.test"
bind_address = "127.0.0.1"
port = $PORT
workers = 4

[database]
path = "$ROOT/data/e2e.db"

[media]
path = "$ROOT/data/media/"
max_upload_size_mb = 200
require_auth = true

[auth]
registration_enabled = true
password_hash_cost = 12

[storage]
type = "local"

[push]
enabled = false
allowed_gateway_prefixes = ["https://push.example.com/"]

[tls]
enabled = false
EOF

echo "== root: $ROOT  port: $PORT =="

# Snapshot the real dev database so we can prove we never touched it.
REAL_DB=/Users/josh/dev/gamechat/data/bsfchat.db
REAL_BEFORE=$(shasum "$REAL_DB" 2>/dev/null | cut -d' ' -f1)

"$BIN" --config "$ROOT/server.toml" > "$ROOT/server.log" 2>&1 &
PID=$!

for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$PORT/_matrix/client/versions" >/dev/null 2>&1 && break
    sleep 0.25
done
if ! curl -sf "http://127.0.0.1:$PORT/_matrix/client/versions" >/dev/null 2>&1; then
    echo "SERVER DID NOT START"; tail -30 "$ROOT/server.log"; exit 1
fi

# ---- HARD GATE: the configured database path must be the one in use. ----
if [ ! -f "$ROOT/data/e2e.db" ]; then
    echo "ABORT: configured database $ROOT/data/e2e.db was not created."
    echo "The config was not honoured; refusing to continue lest a real DB is in use."
    tail -30 "$ROOT/server.log"; exit 1
fi
if [ -n "$REAL_BEFORE" ]; then
    REAL_AFTER=$(shasum "$REAL_DB" | cut -d' ' -f1)
    if [ "$REAL_BEFORE" != "$REAL_AFTER" ]; then
        echo "ABORT: the real dev database at $REAL_DB CHANGED. Stopping now."; exit 1
    fi
fi
ok "throwaway DB honoured ($ROOT/data/e2e.db), real dev DB untouched"

API="http://127.0.0.1:$PORT/_matrix/client/v3"
TOKEN=$(curl -s -X POST "$API/register" -H 'Content-Type: application/json' \
    -d '{"username":"ranger","password":"correct-horse-battery","auth":{"type":"m.login.dummy"}}' \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
if [ -z "$TOKEN" ]; then echo "REGISTER FAILED"; tail -20 "$ROOT/server.log"; exit 1; fi
ok "registered a user and got a token"

# A 50 MB object: the exact size in the defect report.
BIG="$ROOT/big.bin"
dd if=/dev/urandom of="$BIG" bs=1048576 count=50 2>/dev/null
SIZE=$(stat -f%z "$BIG" 2>/dev/null || stat -c%s "$BIG")
check "fixture is 50 MB" "52428800" "$SIZE"

URI=$(curl -s -X POST "http://127.0.0.1:$PORT/_matrix/media/v3/upload?filename=big.mp4" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: video/mp4' \
    --data-binary "@$BIG" | sed -n 's/.*"content_uri":"\([^"]*\)".*/\1/p')
MID=${URI##*/}
if [ -z "$MID" ]; then echo "UPLOAD FAILED"; tail -20 "$ROOT/server.log"; exit 1; fi
ok "uploaded 50 MB, media id $MID"

DL="http://127.0.0.1:$PORT/_matrix/media/v3/download/e2e.test/$MID"
H="Authorization: Bearer $TOKEN"

# --- helpers ---
hdr() { # url range -> raw headers
    if [ -z "$2" ]; then curl -sD - -o /dev/null -H "$H" "$1"
    else curl -sD - -o /dev/null -H "$H" -H "Range: $2" "$1"; fi
}
status()      { hdr "$1" "$2" | head -1 | awk '{print $2}'; }
header_val()  { hdr "$1" "$2" | tr -d '\r' | grep -i "^$3:" | head -1 | cut -d' ' -f2-; }
body_range()  { curl -s -H "$H" -H "Range: $2" "$1"; }
# A real HEAD (-I), not a GET whose body is thrown away. Nothing registers a HEAD
# route — Server::setup_routes calls svr_.Get() only — so this is verifying
# httplib's HEAD-to-Get dispatch against the actual routing table.
head_hdr() {
    if [ -z "${2:-}" ]; then curl -sI -H "$H" "$1"
    else curl -sI -H "$H" -H "Range: $2" "$1"; fi
}
head_status() { head_hdr "$1" "${2:-}" | head -1 | awk '{print $2}'; }
head_val()    { head_hdr "$1" "${2:-}" | tr -d '\r' | grep -i "^$3:" | head -1 | cut -d' ' -f2-; }

# --- 1. plain GET ---
check "200 for a plain GET"          "200"   "$(status "$DL" "")"
check "Accept-Ranges advertised"     "bytes" "$(header_val "$DL" "" Accept-Ranges)"
check "Content-Length is full size"  "$SIZE" "$(header_val "$DL" "" Content-Length)"
check "Content-Type preserved"       "video/mp4" "$(header_val "$DL" "" Content-Type)"

# --- 2. single-byte ranges: first, middle, last ---
check "first byte -> 206"            "206" "$(status "$DL" "bytes=0-0")"
check "first byte Content-Range"     "bytes 0-0/$SIZE" "$(header_val "$DL" "bytes=0-0" Content-Range)"
check "first byte Content-Length"    "1"   "$(header_val "$DL" "bytes=0-0" Content-Length)"

LAST=$((SIZE-1))
check "last byte Content-Range"      "bytes $LAST-$LAST/$SIZE" \
                                     "$(header_val "$DL" "bytes=$LAST-$LAST" Content-Range)"
check "middle window Content-Range"  "bytes 25000000-25000099/$SIZE" \
                                     "$(header_val "$DL" "bytes=25000000-25000099" Content-Range)"

# Byte-exactness against the source file, via dd on the original.
# `dd bs=1 skip=N` would read N bytes one at a time; tail -c seeks.
slice() { tail -c "+$(($1+1))" "$BIG" | head -c "$2" | shasum | cut -d' ' -f1; }
for spec in "0 1" "1 1" "$LAST 1" "25000000 100" "1048570 200000"; do
    set -- $spec; OFF=$1; LEN=$2; END=$((OFF+LEN-1))
    EXP=$(slice "$OFF" "$LEN")
    GOT=$(body_range "$DL" "bytes=$OFF-$END" | shasum | cut -d' ' -f1)
    check "bytes $OFF-$END are byte-exact" "$EXP" "$GOT"
done

# --- 3. open-ended and suffix forms ---
check "open-ended from 0 -> 206"     "206" "$(status "$DL" "bytes=0-")"
check "open-ended Content-Range"     "bytes 49999990-$LAST/$SIZE" \
                                     "$(header_val "$DL" "bytes=49999990-" Content-Range)"
check "suffix Content-Range"         "bytes 52428300-$LAST/$SIZE" \
                                     "$(header_val "$DL" "bytes=-500" Content-Range)"
EXP=$(tail -c 500 "$BIG" | shasum | cut -d' ' -f1)
GOT=$(body_range "$DL" "bytes=-500" | shasum | cut -d' ' -f1)
check "suffix bytes=-500 byte-exact" "$EXP" "$GOT"
check "last-pos past end clamps"     "bytes 52428700-$LAST/$SIZE" \
                                     "$(header_val "$DL" "bytes=52428700-99999999" Content-Range)"

# --- 4. unsatisfiable / malformed ---
check "past-end range -> 416"        "416" "$(status "$DL" "bytes=99999999-99999999")"
check "past-end 416 Content-Range"   "bytes */$SIZE" \
                                     "$(header_val "$DL" "bytes=99999999-99999999" Content-Range)"
check "bytes=-0 -> 416"              "416" "$(status "$DL" "bytes=-0")"
check "bytes=-0 416 Content-Range"   "bytes */$SIZE" "$(header_val "$DL" "bytes=-0" Content-Range)"
check "open-ended past end -> 416"   "416" "$(status "$DL" "bytes=$SIZE-")"
for bad in "bytes=abc-def" "bytes=" "bytes 0-1" "items=0-1" "bytes=-" "bytes=5-1" \
           "bytes=1-2-3" "bytes=99999999999999999999-"; do
    S=$(status "$DL" "$bad")
    case "$S" in
        416|400) ok "malformed [$bad] -> $S (no crash)";;
        *)       bad "malformed [$bad]" "got $S";;
    esac
done

# --- 5. multi-range ---
MR=$(hdr "$DL" "bytes=0-9,100-109")
case "$MR" in
    *206*multipart/byteranges*) ok "2 ranges -> 206 multipart/byteranges";;
    *) bad "2 ranges -> multipart" "$(printf '%s' "$MR" | head -1)";;
esac
check "5 ranges rejected"            "416" "$(status "$DL" "bytes=0-0,2-2,4-4,6-6,8-8")"
check "5 ranges 416 Content-Range"   "bytes */$SIZE" \
                                     "$(header_val "$DL" "bytes=0-0,2-2,4-4,6-6,8-8" Content-Range)"

# --- 6. auth still enforced on range requests ---
check "range without token -> 401"   "401" \
    "$(curl -sD - -o /dev/null -H 'Range: bytes=0-0' "$DL" | head -1 | awk '{print $2}')"
check "range with bad token -> 401"  "401" \
    "$(curl -sD - -o /dev/null -H 'Authorization: Bearer nope' -H 'Range: bytes=0-0' "$DL" \
       | head -1 | awk '{print $2}')"
check "?access_token= + range -> 206" "206" \
    "$(curl -sD - -o /dev/null -H 'Range: bytes=0-0' "$DL?access_token=$TOKEN" \
       | head -1 | awk '{print $2}')"

# --- 7. whole-object integrity over the socket ---
EXP=$(shasum "$BIG" | cut -d' ' -f1)
GOT=$(curl -s -H "$H" "$DL" | shasum | cut -d' ' -f1)
check "full 50 MB download is byte-exact" "$EXP" "$GOT"
GOT=$(body_range "$DL" "bytes=0-$LAST" | shasum | cut -d' ' -f1)
check "explicit full range is byte-exact" "$EXP" "$GOT"

# --- 8. THE memory property, on the real process ---
# 200 one-byte range requests scattered through a 50 MB object. Under the old
# implementation each one allocated 50 MB. Peak RSS of the server process must
# stay far below that.
RSS0=$(ps -o rss= -p "$PID" | tr -d ' ')
for i in $(seq 0 199); do
    OFF=$(( (SIZE / 200) * i ))
    curl -s -o /dev/null -H "$H" -H "Range: bytes=$OFF-$OFF" "$DL"
done
RSS1=$(ps -o rss= -p "$PID" | tr -d ' ')
GROWTH_MB=$(( (RSS1 - RSS0) / 1024 ))
echo "     server RSS: ${RSS0}K -> ${RSS1}K (delta ${GROWTH_MB} MB) over 200 one-byte range requests"
if [ "$GROWTH_MB" -lt 25 ]; then
    ok "200 one-byte ranges on a 50 MB object grew server RSS by ${GROWTH_MB} MB (< 25)"
else
    bad "200 one-byte ranges grew server RSS by ${GROWTH_MB} MB" "expected well under one object"
fi

# Sanity: the same 200 requests but for the whole object each time would be
# 10 GB of transfer, so instead do 8 concurrent FULL downloads and confirm the
# process still does not hold 8 x 50 MB.
RSS2=$(ps -o rss= -p "$PID" | tr -d ' ')
# Wait on the curl PIDs specifically. A bare `wait` also waits on the server,
# which was started with & and never exits — that hung the whole script here.
DL_PIDS=""
for i in 1 2 3 4 5 6 7 8; do
    curl -s -o /dev/null -H "$H" "$DL" &
    DL_PIDS="$DL_PIDS $!"
done
for p in $DL_PIDS; do wait "$p"; done
RSS3=$(ps -o rss= -p "$PID" | tr -d ' ')
CONC_MB=$(( (RSS3 - RSS2) / 1024 ))
echo "     server RSS: ${RSS2}K -> ${RSS3}K (delta ${CONC_MB} MB) over 8 concurrent full downloads"
if [ "$CONC_MB" -lt 60 ]; then
    ok "8 concurrent 50 MB downloads grew server RSS by ${CONC_MB} MB (< 60, i.e. not 8x50)"
else
    bad "8 concurrent full downloads grew RSS by ${CONC_MB} MB" "streaming is not bounded"
fi

# --- 9. zero-length media ---
#
# This block used to infer "rejected" from the ABSENCE of a content_uri and print
# ok. A 500, a 413 or a dropped connection would all have scored the same, so it
# was a check that could not fail for the reason it claimed. Assert the status
# code and the errcode instead, and only then decide which branch to take.
: > "$ROOT/empty.bin"
ESTATUS=$(curl -s -o "$ROOT/empty.resp" -w '%{http_code}' \
    -X POST "http://127.0.0.1:$PORT/_matrix/media/v3/upload?filename=e.txt" \
    -H "$H" -H 'Content-Type: text/plain' --data-binary "@$ROOT/empty.bin")
EURI=$(sed -n 's/.*"content_uri":"\([^"]*\)".*/\1/p' "$ROOT/empty.resp")
if [ "$ESTATUS" = "400" ]; then
    check "empty upload rejected with 400" "400" "$ESTATUS"
    # M_INVALID_PARAM, not M_NOT_JSON: this endpoint takes a raw binary body and
    # never parses JSON, so M_NOT_JSON named a fault that could not occur.
    ECODE=$(sed -n 's/.*"errcode":"\([^"]*\)".*/\1/p' "$ROOT/empty.resp")
    check "empty upload errcode is M_INVALID_PARAM" "M_INVALID_PARAM" "$ECODE"
    if [ "$ECODE" = "M_NOT_JSON" ]; then
        bad "empty upload still reports M_NOT_JSON" "binary endpoint, never parses JSON"
    fi
    [ -z "$EURI" ] || bad "empty upload was refused but still returned a content_uri" "$EURI"
    ok "server refuses zero-length uploads, so there is no empty object to serve"
elif [ -z "$EURI" ]; then
    bad "empty upload failed with status $ESTATUS, not the documented 400" "$(cat "$ROOT/empty.resp")"
else
    EMID=${EURI##*/}
    EDL="http://127.0.0.1:$PORT/_matrix/media/v3/download/e2e.test/$EMID"
    check "empty media -> 200"           "200" "$(status "$EDL" "")"
    check "empty media Content-Length"   "0"   "$(header_val "$EDL" "" Content-Length)"
    check "range on empty media -> 416"  "416" "$(status "$EDL" "bytes=0-0")"
    check "empty 416 Content-Range"      "bytes */0" "$(header_val "$EDL" "bytes=0-0" Content-Range)"
fi

# --- 10. unknown media / wrong server name ---
check "unknown media id -> 404" "404" \
    "$(status "http://127.0.0.1:$PORT/_matrix/media/v3/download/e2e.test/deadbeef" "bytes=0-0")"
check "foreign server name -> 404" "404" \
    "$(status "http://127.0.0.1:$PORT/_matrix/media/v3/download/elsewhere.example/$MID" "")"

# --- 11. HEAD ---
#
# Previously unverified: no HEAD route is registered anywhere, so HEAD working at
# all depends on httplib dispatching it to the Get handler table. Unit tests can
# only show that through an in-process server; this is the real binary's real
# routing table.
check "HEAD -> 200"                "200"   "$(head_status "$DL")"
check "HEAD Content-Length"        "$SIZE" "$(head_val "$DL" "" Content-Length)"
check "HEAD Accept-Ranges"         "bytes" "$(head_val "$DL" "" Accept-Ranges)"
HEAD_BODY=$(curl -s -I -H "$H" "$DL" -o /dev/null -w '%{size_download}')
check "HEAD sends no body"         "0"     "$HEAD_BODY"
check "ranged HEAD -> 206"         "206"   "$(head_status "$DL" "bytes=0-99")"
check "ranged HEAD Content-Range"  "bytes 0-99/$SIZE" "$(head_val "$DL" "bytes=0-99" Content-Range)"
# The same refusals as GET: HEAD must not be a cheaper oracle or a cheaper way to
# make the server do multi-range fan-out work.
check "HEAD past the range cap -> 416" "416" "$(head_status "$DL" "bytes=0-0,2-2,4-4,6-6,8-8")"
check "HEAD unknown media -> 404" "404" \
    "$(head_status "http://127.0.0.1:$PORT/_matrix/media/v3/download/e2e.test/deadbeef")"
UNAUTH_HEAD=$(curl -sI -o /dev/null -w '%{http_code}' "$DL")
check "unauthenticated HEAD -> 401" "401" "$UNAUTH_HEAD"

# --- final: server still healthy, real DB still untouched ---
if curl -sf "http://127.0.0.1:$PORT/_matrix/client/versions" >/dev/null; then
    ok "server still healthy after every malformed/hostile range above"
else
    bad "server unhealthy at end of run" "$(tail -5 "$ROOT/server.log")"
fi
if [ -n "$REAL_BEFORE" ]; then
    REAL_AFTER=$(shasum "$REAL_DB" | cut -d' ' -f1)
    check "real dev database unchanged" "$REAL_BEFORE" "$REAL_AFTER"
fi
if grep -qiE "\[error\]|\[critical\]" "$ROOT/server.log"; then
    bad "server logged errors" "$(grep -iE '\[error\]|\[critical\]' "$ROOT/server.log" | head -5)"
else
    ok "no errors in the server log"
fi

echo
echo "=== $PASS passed, $FAIL failed ==="
exit $(( FAIL > 0 ? 1 : 0 ))
