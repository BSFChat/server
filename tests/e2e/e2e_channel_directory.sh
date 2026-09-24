#!/bin/bash
# End-to-end check of the channel directory against the REAL bsfchat-server
# binary over HTTP.
#
# The unit tests in tests/test_channel_directory.cpp call RoomHandler directly,
# which is the right place for the visibility rule but structurally cannot cover
# three things:
#
#   * that the route is REGISTERED. A handler nothing routes to is a 404, and
#     the one line in core/Server.cpp that fixes that has no unit test.
#   * what a real BOT token gets. The motivating bug is that a bot on a fresh
#     install has no membership anywhere and so could discover nothing; that
#     only means something against a bot created through the real endpoint and
#     excluded from auto-join by the real code. It is also the only caller whose
#     grants and memberships can be made to disagree — a bot arrives holding
#     nothing and is scoped upward one channel at a time — which is what makes
#     T3 able to state "membership is not visibility" in both directions at
#     once. A human cannot: auto-join puts every human in every channel.
#   * what the response looks like ON THE WIRE. The disclosure assertion here
#     is a substring scan over the raw bytes curl received, which is the only
#     form of "the id is nowhere in the response" that cannot be satisfied by a
#     C++ struct that happens not to be serialised.
#
# Safety: everything lives under a throwaway directory, the server is always
# started with an explicit --config, and the real dev database is checksummed
# before and after — the script HARD-FAILS if a byte changed.
#
# Deliberately NO skip-on-404 branch. Some scripts here tolerate a server built
# before their feature landed; this one ships in the same change as the route,
# so a 404 is the failure it is meant to catch and not a reason to go quiet.
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
BIN=$(e2e_require_server_bin) || exit 1
WORK=$(mktemp -d /tmp/bsfchat-chandir-e2e-XXXXXX)
REALDATA=$(e2e_real_data_dir || echo /nonexistent)
PORT=${PORT:-8907}
BASE="http://127.0.0.1:${PORT}/_matrix/client/v3"
E2E_PW="e2e-chandir-pw-4Rt9"
FAILURES=0
CHECKS=0
SRV_PID=""

cleanup() {
  if [[ -n "${SRV_PID:-}" ]]; then kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; fi
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 90; }

snapshot() { find "$REALDATA" -type f -exec shasum {} \; 2>/dev/null | sort; }
if [[ -d "$REALDATA" ]]; then
  snapshot > "$WORK/real-before.txt"
  [[ -s "$WORK/real-before.txt" ]] || die "could not checksum $REALDATA; refusing to run blind"
else
  echo "no live dev data directory alongside this checkout; nothing to guard"
fi

# TOML TABLES, not flat keys. A flat `database_path = ...` parses to nothing and
# the server silently falls back to ./data/bsfchat.db — which is how a previous
# run migrated the owner's real database.
cat > "$WORK/server.toml" <<EOF
[server]
name = "e2e"
bind_address = "127.0.0.1"
port = ${PORT}
workers = 4

[database]
path = "${WORK}/e2e.db"

# This script builds a precise channel topology — a category, a granted
# channel, a joined-but-ungranted channel and a private one — and then asserts
# on the exact set each principal is shown. The first-run channels a new
# deployment creates for itself are correct everywhere else, but here they are
# two rooms the fixture did not put there and did not grant the bot, so the
# directory comparisons would be measuring them instead of the scope rule. The
# behaviour itself is covered by tests/test_first_run.cpp.
[first_run]
create_default_channels = false

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
    printf 'ok   %-62s %s\n' "$1" "$3"
  else
    printf 'FAIL %-62s expected %s got %s  body=%s\n' "$1" "$2" "$3" "$(head -c 400 "$WORK/last-body.json" 2>/dev/null)"
    FAILURES=$((FAILURES+1))
  fi
}

jfield() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$WORK/last-body.json" "$1"; }

register() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"${E2E_PW}\",\"auth\":{\"type\":\"m.login.dummy\"}}" >/dev/null
  jfield access_token
}
login() {
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/login" -H 'Content-Type: application/json' \
    -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"$1\"},\"password\":\"${E2E_PW}\"}" >/dev/null
  jfield access_token
}

# The directory into a named file, so every assertion below reads one snapshot
# rather than racing a fresh request.
dir_to() { # dir_to TOKEN FILE -> prints HTTP status
  curl -s -o "$2" -w '%{http_code}' -X GET "${BASE}/bsfchat/channels" \
    -H "Authorization: Bearer $1"
}

# Queries over one directory snapshot. One python helper rather than greps: a
# `grep -q` for a room id would match it appearing in ANY field, which is
# sometimes the assertion and sometimes its opposite.
#
#   ids            -> comma-joined room_ids, IN ORDER
#   keys           -> the sorted union of every entry's JSON keys
#   joined:<room>  -> true/false/absent
#   catof:<room>   -> the entry's category_id, or "" when it has none
probe() { # probe FILE QUERY...
  python3 - "$1" "${@:2}" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
chans = body.get("channels", [])
by_id = {c.get("room_id"): c for c in chans}
for q in sys.argv[2:]:
    if q == "ids":
        print(",".join(c.get("room_id", "") for c in chans))
    elif q == "keys":
        print(",".join(sorted({k for c in chans for k in c})))
    elif q.startswith("joined:"):
        c = by_id.get(q.split(":", 1)[1])
        print("absent" if c is None else str(c.get("joined")).lower())
    elif q.startswith("catof:"):
        c = by_id.get(q.split(":", 1)[1])
        print("absent" if c is None else c.get("category_id", ""))
    else:
        print("?" + q)
PY
}

# ── phase 0: an admin, a category, three channels, one of them private ───
start_server first
[[ -f "$WORK/e2e.db" ]] || die "server did not create its database at the CONFIGURED path ($WORK/e2e.db) — TOML likely misparsed"

T_ADMIN=$(register alice)
[[ -n "$T_ADMIN" ]] || { cat "$WORK/server-first.log"; die "registration failed"; }
stop_server

# Restart so bootstrap_roles grants the admin role to the OLDEST account — the
# real ownership path, not a fixture poke.
start_server second
T_ADMIN=$(login alice)
[[ -n "$T_ADMIN" ]] || die "login failed after restart"

mkroom() { # mkroom TOKEN JSON -> room id
  curl -s -o "$WORK/last-body.json" -X POST "${BASE}/createRoom" -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/json' -d "$2" >/dev/null
  jfield room_id
}

CAT=$(mkroom "$T_ADMIN" '{"name":"Team","is_category":true}')
[[ -n "$CAT" ]] || { cat "$WORK/last-body.json"; die "could not create the category"; }
GENERAL=$(mkroom "$T_ADMIN" "{\"name\":\"general\",\"parent_id\":\"${CAT}\",\"sort_order\":0}")
LOUNGE=$(mkroom "$T_ADMIN" "{\"name\":\"Lounge\",\"voice\":true,\"parent_id\":\"${CAT}\",\"sort_order\":2}")
SECRET=$(mkroom "$T_ADMIN" "{\"name\":\"staff-only\",\"parent_id\":\"${CAT}\",\"sort_order\":1,\"topic\":\"the quiet room\"}")
for r in "$GENERAL" "$LOUNGE" "$SECRET"; do [[ -n "$r" ]] || die "channel creation failed"; done

# "Private" on this server is not a join rule: it is an @everyone DENY
# VIEW_CHANNEL override on an otherwise public room. VIEW_CHANNEL is bit 0.
check "admin denies @everyone VIEW_CHANNEL on staff-only" 200 \
  "$(req PUT "/rooms/${SECRET}/state/bsfchat.channel.permissions/role:everyone" "$T_ADMIN" \
     '{"allow":0,"deny":1}')"

# staff-only sits at sort_order 1, BETWEEN the two visible channels. If the raw
# order reached the wire, the gap would be the disclosure.
T_BOB=$(register bob)
[[ -n "$T_BOB" ]] || die "could not register a plain user"

STATUS=$(req POST "/bsfchat/bots" "$T_ADMIN" \
  '{"localpart":"bot_dir","display_name":"Directory Bot","description":"exercised by e2e_channel_directory.sh"}')
check "admin creates a bot"                     201 "$STATUS"
BOT_ID=$(jfield user_id)
BOT_TOKEN=$(jfield token)
[[ -n "$BOT_TOKEN" ]] || die "create returned no token: $(cat "$WORK/last-body.json")"

echo
echo "── T1: the route exists and answers an ordinary member ──────────────"
check "GET /bsfchat/channels (bob)"             200 "$(dir_to "$T_BOB" "$WORK/bob.json")"
BOB_IDS=$(probe "$WORK/bob.json" ids)
check "bob sees the category"                   yes "$(grep -q "$CAT" <<<"$BOB_IDS" && echo yes || echo no)"
check "bob sees general"                        yes "$(grep -q "$GENERAL" <<<"$BOB_IDS" && echo yes || echo no)"
check "bob sees the voice channel"              yes "$(grep -q "$LOUNGE" <<<"$BOB_IDS" && echo yes || echo no)"
check "general is filed under the category"     "$CAT" "$(probe "$WORK/bob.json" "catof:${GENERAL}")"

echo
echo "── T2: the private channel is nowhere in bob's response ─────────────"
# The blunt one, over the raw bytes curl received: an id that appears in ANY
# field — an entry, a category_id, an error string — fails here.
check "staff-only id absent from the whole body" no \
  "$(grep -qF "$SECRET" "$WORK/bob.json" && echo yes || echo no)"
check "its topic absent too"                    no \
  "$(grep -qF "the quiet room" "$WORK/bob.json" && echo yes || echo no)"
check "bob's entry key set is exactly the contract" "category_id,joined,name,room_id,type" \
  "$(probe "$WORK/bob.json" keys)"
check "the channel really exists (alice sees it)" yes \
  "$(dir_to "$T_ADMIN" "$WORK/alice.json" >/dev/null; grep -qF "$SECRET" "$WORK/alice.json" && echo yes || echo no)"

echo
echo "── T3: what a bot sees tracks its GRANTS, never its joins ───────────"
# The whole point, and a bot is the only caller that can prove it. A bot does
# not inherit the implicit @everyone role (docs/bot-scoping.md), so it starts
# holding nothing anywhere and is scoped upward one channel at a time — which
# means grants and memberships can be driven APART and then read back:
#
#   general  -> granted VIEW_CHANNEL, never joined  -> MUST be listed
#   Lounge   -> joined by invite, never granted     -> must NOT be listed
#
# A directory that filtered on is_room_member — the /joined_rooms bug, which the
# mutation harness calls M1 — returns exactly the opposite pair. No human can
# stand in for this: every human is force-joined into every channel, so for bob
# the two sets coincide and the wrong filter looks right.

# The baseline, and it is deliberately not "a bot sees nothing": categories are
# exempt from VIEW_CHANNEL so a sidebar can still draw the container around
# channels it cannot open (auth/RoomVisibility.h). An unscoped bot therefore
# sees the container and not one channel inside it.
check "GET /joined_rooms (bot) is empty"        "[]" \
  "$(req GET "/joined_rooms" "$BOT_TOKEN" >/dev/null; python3 -c \
     'import json;print(json.dumps(json.load(open("'"$WORK"'/last-body.json")).get("joined_rooms",None)))')"
check "GET /bsfchat/channels (bot)"             200 "$(dir_to "$BOT_TOKEN" "$WORK/bot0.json")"
check "an unscoped bot is told of the container only" "$CAT" "$(probe "$WORK/bot0.json" ids)"

# Half one: granted, not joined. A user-specific channel override is how an
# operator lets a bot into ONE channel (a role assignment is the server-wide
# spelling). An invite is not an alternative to it: writing an override takes
# MANAGE_ROLES in the channel and inviting does not, which is exactly why the
# two were kept apart (docs/bot-scoping.md §8.3).
#
# 0x1 is VIEW_CHANNEL and nothing else: the minimum this endpoint filters on,
# written as a literal so a change to kEveryoneDefault cannot silently widen it,
# and narrow enough that a gate tightened to any other flag fails here.
check "admin grants the bot VIEW_CHANNEL on general" 200 \
  "$(req PUT "/rooms/${GENERAL}/state/bsfchat.channel.permissions/user:${BOT_ID}" "$T_ADMIN" \
     '{"allow":"0x1","deny":"0x0"}')"

# Half two: joined, not granted. Inviting a bot joins it outright, and that is
# all an invite does — it writes a membership row and confers nothing.
check "admin invites the bot to the voice channel" 200 \
  "$(req POST "/rooms/${LOUNGE}/invite" "$T_ADMIN" "{\"user_id\":\"${BOT_ID}\"}")"
# ...witnessed by someone who can actually read the roster, because otherwise
# the absence below could just as well be an invite that quietly failed. It has
# to be the admin who looks: /joined_rooms is VIEW_CHANNEL-filtered too, so the
# bot's own view of its membership is exactly what is under test here.
check "the bot really is in the voice channel"  yes \
  "$(req GET "/rooms/${LOUNGE}/members" "$T_ADMIN" >/dev/null; \
     grep -qF "$BOT_ID" "$WORK/last-body.json" && echo yes || echo no)"

dir_to "$BOT_TOKEN" "$WORK/bot1.json" >/dev/null
check "the granted channel is listed, unjoined" "${CAT},${GENERAL}" \
  "$(probe "$WORK/bot1.json" ids)"
check "and it is told it has not joined general" false "$(probe "$WORK/bot1.json" "joined:${GENERAL}")"
# "absent" rather than false: the entry is not in the response at all.
check "the joined channel is absent, ungranted" absent \
  "$(probe "$WORK/bot1.json" "joined:${LOUNGE}")"
# One grant is one channel. It did not spill into the private one next door.
check "staff-only absent for the bot too"       no \
  "$(grep -qF "$SECRET" "$WORK/bot1.json" && echo yes || echo no)"

echo
echo "── T4: joined tracks membership and nothing else ────────────────────"
# Grant the channel the bot is ALREADY in, so it can now see two channels whose
# membership differs. `joined` is then the only field that tells them apart,
# which is the distinction a Bots tab has to render: granted, but you still have
# to put it in there before it can post.
check "admin grants the voice channel too"      200 \
  "$(req PUT "/rooms/${LOUNGE}/state/bsfchat.channel.permissions/user:${BOT_ID}" "$T_ADMIN" \
     '{"allow":"0x1","deny":"0x0"}')"
dir_to "$BOT_TOKEN" "$WORK/bot2.json" >/dev/null
check "the voice channel now reads joined=true" true "$(probe "$WORK/bot2.json" "joined:${LOUNGE}")"
check "general still reads joined=false"        false "$(probe "$WORK/bot2.json" "joined:${GENERAL}")"
# And two deliberate grants later the bot's directory is a human's, entry for
# entry and in the same order: there is no bot-flavoured filter in here, only a
# different scope arriving at the same one.
check "the bot now sees what the human sees"    "$BOB_IDS" "$(probe "$WORK/bot2.json" ids)"

echo
echo "── T5: authentication ───────────────────────────────────────────────"
check "no token is refused"                     401 "$(req GET "/bsfchat/channels" "")"
check "a junk token is refused"                 401 "$(req GET "/bsfchat/channels" "not-a-token")"

echo
echo "── T6: being listed is not access ───────────────────────────────────"
# Bob can name the category in the directory. He still cannot read it, and the
# exemption that lists it must not become a way in.
check "admin denies @everyone VIEW_CHANNEL on the category" 200 \
  "$(req PUT "/rooms/${CAT}/state/bsfchat.channel.permissions/role:everyone" "$T_ADMIN" \
     '{"allow":0,"deny":1}')"
dir_to "$T_BOB" "$WORK/bob3.json" >/dev/null
check "the denied category is still named"      yes \
  "$(grep -qF "$CAT" "$WORK/bob3.json" && echo yes || echo no)"
check "but its state is refused"                403 "$(req GET "/rooms/${CAT}/state" "$T_BOB")"

stop_server

if [[ -f "$WORK/real-before.txt" ]]; then
  snapshot > "$WORK/real-after.txt"
  diff -q "$WORK/real-before.txt" "$WORK/real-after.txt" >/dev/null \
    || { echo "FATAL: $REALDATA CHANGED"; exit 91; }
fi

echo
if (( FAILURES == 0 )); then
  echo "PASS: ${CHECKS}/${CHECKS} checks"
  rm -rf "$WORK"
  exit 0
fi
echo "FAIL: ${FAILURES} of ${CHECKS} checks failed (work dir kept: $WORK)"
exit 1
