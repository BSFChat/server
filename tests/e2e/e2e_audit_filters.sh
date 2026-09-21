#!/bin/bash
# End-to-end check of the audit-log FILTERS (schema v16) against the REAL server
# binary over HTTP.
#
# Unit tests call AuditHandler::handle_get_audit_log directly, so they never
# exercise routing or real query-string parsing. This script does: everything
# below goes through curl at a listening socket.
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

WORK=$(mktemp -d /tmp/bsfchat-e2e-auditfilter.XXXXXX)
DB="$WORK/e2e.db"
CONF="$WORK/server.toml"
LOG="$WORK/server.log"
PORT=19${RANDOM:0:3}
[ "$PORT" -lt 19100 ] && PORT=19448
BASE="http://127.0.0.1:$PORT"
HOST="e2e.local"

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

[ -x "$BIN" ] || fail "server binary not found at $BIN (build it first)"

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
name = "$HOST"
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

# The schema this test is about. A FLOOR, not an exact match: the subject is
# the v16 audit_log filter indexes, which every later schema still carries, and
# an exact pin here simply breaks on the next migration (it had already been
# failing at 16 against a v18 schema, unnoticed, because no ctest label runs
# this script).
VER=$(python3 -c 'import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("PRAGMA user_version").fetchone()[0])' "$DB")
[ "$VER" -ge 16 ] 2>/dev/null || fail "expected schema v16 or newer, got v$VER"
pass "fresh database is at schema v$VER (>= 16, which is where the filter indexes arrived)"

# ── Helpers ────────────────────────────────────────────────────────────────
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
urlenc() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }

register() {
    local user=$1
    local out
    out=$(api POST /_matrix/client/v3/register "" \
        "{\"username\":\"$user\",\"password\":\"e2e-correct-horse-7\",\"auth\":{\"type\":\"m.login.dummy\"}}")
    [ "$(status "$out")" = "200" ] || { echo "$out" >&2; fail "register $user failed"; }
    body "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

# audit QUERYSTRING TOKEN -> writes the parsed body to $WORK/audit.json, echoes status
audit() {
    local qs=$1 token=$2
    local out
    out=$(api GET "/_matrix/client/v3/bsfchat/audit_log$qs" "$token")
    body "$out" > "$WORK/audit.json"
    status "$out"
}

# ── Scenario: two moderators, two channels, three targets ──────────────────
# alice registers first, so bootstrap_roles gives her Admin.
ALICE_TOKEN=$(register alice)
BOB_TOKEN=$(register bob)
CAROL_TOKEN=$(register carol)
DAVE_TOKEN=$(register dave)
ERIN_TOKEN=$(register erin)
pass "registered alice (owner/admin), bob, carol, dave, erin"

mkroom() {
    local name=$1
    local out
    out=$(api POST /_matrix/client/v3/createRoom "$ALICE_TOKEN" \
        "{\"name\":\"$name\",\"visibility\":\"public\"}")
    [ "$(status "$out")" = "200" ] || { echo "$out" >&2; fail "createRoom $name failed"; }
    body "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["room_id"])'
}

ROOM_A=$(mkroom general)
ROOM_B=$(mkroom lounge)
ROOM_A_ENC=$(urlenc "$ROOM_A")
ROOM_B_ENC=$(urlenc "$ROOM_B")
pass "alice created two channels: $ROOM_A and $ROOM_B"

# Give bob MANAGE_ROLES etc. so a SECOND actor appears in the log — a filter that
# silently matched everything would be indistinguishable with only one actor.
OUT=$(api PUT "/_matrix/client/v3/rooms/$ROOM_A_ENC/state/bsfchat.member.roles/$(urlenc "@bob:$HOST")" \
    "$ALICE_TOKEN" '{"role_ids":["everyone","mod"]}')
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "granting bob the mod role failed"; }
pass "alice made bob a moderator (recorded as a role.assign by alice)"

# Three moderation actions, chosen so that no single filter dimension can be
# mistaken for another: two different ACTORS, two different ACTIONS, two different
# TARGET USERS and two different TARGET ROOMS, with no two records agreeing on all
# four. The bootstrap "mod" role carries KICK_MEMBERS but not BAN_MEMBERS, so bob
# kicks and only alice bans.
#
# Order matters: bob kicks dave (join -> leave = member.kick) BEFORE alice bans
# him (leave -> ban = member.ban). Reversed, the kick would be a leave-from-ban and
# would be recorded as member.unban.
OUT=$(api POST "/_matrix/client/v3/rooms/$ROOM_A_ENC/kick" "$BOB_TOKEN" \
    "{\"user_id\":\"@dave:$HOST\",\"reason\":\"bob kick in A\"}")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "bob kick failed"; }
OUT=$(api POST "/_matrix/client/v3/rooms/$ROOM_A_ENC/ban" "$ALICE_TOKEN" \
    "{\"user_id\":\"@dave:$HOST\",\"reason\":\"alice ban in A\"}")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "alice ban failed"; }
OUT=$(api POST "/_matrix/client/v3/rooms/$ROOM_B_ENC/kick" "$ALICE_TOKEN" \
    "{\"user_id\":\"@erin:$HOST\",\"reason\":\"alice kick in B\"}")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "alice kick failed"; }
pass "moderation actions performed by two different actors, across two channels, on two targets"

# ── Baseline: the unfiltered log, so every filter below is measured against it ─
audit "" "$ALICE_TOKEN" > /dev/null
[ "$(audit "" "$ALICE_TOKEN")" = "200" ] || fail "admin could not read the audit log"
cp "$WORK/audit.json" "$WORK/all.json"
python3 - "$WORK/all.json" <<'PY' || fail "baseline log is not what the filters will be measured against"
import json, sys
d = json.load(open(sys.argv[1]))
recs = d["records"]
assert len(recs) >= 4, recs
assert "matching" not in d, "an unfiltered response must not carry `matching`"
actors = {r["actor"] for r in recs}
assert len(actors) >= 2, f"need at least two distinct actors for the filters to prove anything: {actors}"
print(f"  ok  baseline: {len(recs)} records, total={d['total']}, actors={sorted(actors)}")
PY

# ── 1. Filter by actor ─────────────────────────────────────────────────────
[ "$(audit "?actor=$(urlenc "@bob:$HOST")" "$ALICE_TOKEN")" = "200" ] || fail "actor filter failed"
python3 - "$WORK/audit.json" "$WORK/all.json" "@bob:$HOST" <<'PY' || fail "actor filter is wrong"
import json, sys
d = json.load(open(sys.argv[1])); all_d = json.load(open(sys.argv[2])); who = sys.argv[3]
recs = d["records"]
assert recs, "actor filter returned nothing at all"
assert all(r["actor"] == who for r in recs), recs
expected = [r for r in all_d["records"] if r["actor"] == who]
assert len(recs) == len(expected), f"{len(recs)} != {len(expected)}"
assert d["matching"] == len(expected), d["matching"]
assert d["total"] == all_d["total"], "total must stay whole-table under a filter"
assert d["total"] > d["matching"], "the filter did not actually narrow anything"
print(f"  ok  actor filter: {len(recs)} of {d['total']} records, all by {who}")
PY

# ── 2. Filter by target user ───────────────────────────────────────────────
[ "$(audit "?target_user=$(urlenc "@dave:$HOST")" "$ALICE_TOKEN")" = "200" ] || fail "target_user filter failed"
python3 - "$WORK/audit.json" "@dave:$HOST" <<'PY' || fail "target_user filter is wrong"
import json, sys
d = json.load(open(sys.argv[1])); who = sys.argv[2]
recs = d["records"]
assert recs, "target_user filter returned nothing"
assert all(r["target_user"] == who for r in recs), recs
# Dave was kicked by BOB, banned by ALICE, and given the @everyone role by the
# SERVER at registration. Three actors, three actions, one target — so a filter
# that had quietly also constrained the actor or the action would return fewer.
assert len(recs) == 3, f"expected dave to appear as a target exactly three times: {recs}"
assert {r["actor"] for r in recs} == {"@alice:e2e.local", "@bob:e2e.local", "@server:e2e.local"}, recs
assert {r["action"] for r in recs} == {"member.kick", "member.ban", "role.assign"}, recs
assert d["matching"] == 3, d
print(f"  ok  target_user filter: all 3 records aimed at {who}, across 3 actors and 3 actions")
PY

# ── 3. Filter by target room ───────────────────────────────────────────────
[ "$(audit "?target_room=$(urlenc "$ROOM_B")" "$ALICE_TOKEN")" = "200" ] || fail "target_room filter failed"
python3 - "$WORK/audit.json" "$ROOM_B" <<'PY' || fail "target_room filter is wrong"
import json, sys
d = json.load(open(sys.argv[1])); room = sys.argv[2]
recs = d["records"]
assert recs, "target_room filter returned nothing"
assert all(r["target_room"] == room for r in recs), recs
print(f"  ok  target_room filter: {len(recs)} records in {room}")
PY

# ── 4. Filter by action ────────────────────────────────────────────────────
[ "$(audit "?action=member.ban" "$ALICE_TOKEN")" = "200" ] || fail "action filter failed"
python3 - "$WORK/audit.json" <<'PY' || fail "action filter is wrong"
import json, sys
d = json.load(open(sys.argv[1]))
recs = d["records"]
# One ban and two kicks were performed. A filter that leaked kicks in would be
# indistinguishable from a broken one if the counts happened to match.
assert len(recs) == 1, f"expected exactly one ban, got {len(recs)}: {recs}"
assert recs[0]["action"] == "member.ban" and recs[0]["reason"] == "alice ban in A", recs
print("  ok  action filter: exactly the one ban, no kicks")
PY

[ "$(audit "?action=member.kick" "$ALICE_TOKEN")" = "200" ] || fail "kick filter failed"
python3 - "$WORK/audit.json" <<'PY' || fail "kick filter swept up bans"
import json, sys
recs = json.load(open(sys.argv[1]))["records"]
assert len(recs) == 2, f"expected the two kicks, got {len(recs)}: {recs}"
assert all(r["action"] == "member.kick" for r in recs), recs
print("  ok  action filter separates the 2 kicks from the 1 ban")
PY

# ── 5. Filters AND together ────────────────────────────────────────────────
# Alice has several records and there are two kicks; the intersection is one. An
# OR would return all of both sets, and either filter alone returns more than one.
[ "$(audit "?actor=$(urlenc "@alice:$HOST")&action=member.kick" "$ALICE_TOKEN")" = "200" ] \
    || fail "combined filter failed"
python3 - "$WORK/audit.json" "@alice:$HOST" <<'PY' || fail "combined filter is not an AND"
import json, sys
d = json.load(open(sys.argv[1])); who = sys.argv[2]
recs = d["records"]
assert len(recs) == 1, f"expected exactly alice's one kick, got {len(recs)}: {recs}"
assert recs[0]["actor"] == who and recs[0]["action"] == "member.kick", recs
assert recs[0]["reason"] == "alice kick in B", recs
assert d["matching"] == 1, d
print("  ok  actor AND action narrowed to the single matching record")
PY

# All four at once.
[ "$(audit "?actor=$(urlenc "@bob:$HOST")&action=member.kick&target_user=$(urlenc "@dave:$HOST")&target_room=$(urlenc "$ROOM_A")" "$ALICE_TOKEN")" = "200" ] \
    || fail "four-way filter failed"
python3 - "$WORK/audit.json" <<'PY' || fail "four-way filter is wrong"
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d["records"]) == 1 and d["matching"] == 1, d
assert d["records"][0]["reason"] == "bob kick in A", d
print("  ok  all four filters at once resolve to the one intended record")
PY

# ── 6. A filter that matches nothing returns nothing ───────────────────────
[ "$(audit "?actor=$(urlenc "@nobody:$HOST")" "$ALICE_TOKEN")" = "200" ] || fail "no-match filter errored"
python3 - "$WORK/audit.json" <<'PY' || fail "a non-matching filter did not return an empty page"
import json, sys
d = json.load(open(sys.argv[1]))
# The failure this rules out: a filter silently dropped somewhere between the
# query string and the SQL, handing back the WHOLE log to a reader who believes
# they looked and found nothing.
assert d["records"] == [], f"expected no records, got {len(d['records'])}"
assert d["matching"] == 0, d
assert d["total"] > 0, "the log is not actually empty, so this proves the filter applied"
assert "next_from" not in d, d
print("  ok  a filter matching nothing returns nothing (and total still shows the real size)")
PY

# ── 7. Empty filter values are refused, not ignored ────────────────────────
for P in actor target_user target_room action; do
    ST=$(audit "?$P=" "$ALICE_TOKEN")
    [ "$ST" = "400" ] || fail "expected 400 for an empty $P, got $ST"
    python3 - "$WORK/audit.json" "$P" <<'PY' || fail "empty $P refused for the wrong reason"
import json, sys
d = json.load(open(sys.argv[1])); name = sys.argv[2]
assert d.get("errcode") == "M_INVALID_PARAM", d
assert name in d.get("error", ""), f"refused, but not because of {name}: {d}"
PY
done
pass "an empty actor/target_user/target_room/action is a 400, naming the parameter"

# ── 8. Filtered pagination over HTTP ───────────────────────────────────────
QS="?action=member.kick&limit=1"
[ "$(audit "$QS" "$ALICE_TOKEN")" = "200" ] || fail "filtered page 1 failed"
MATCHING=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["matching"])' "$WORK/audit.json")
CURSOR=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("next_from",""))' "$WORK/audit.json")
LAST_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["records"][0]["id"])' "$WORK/audit.json")
COUNT=1
while [ -n "$CURSOR" ]; do
    [ "$(audit "?action=member.kick&limit=1&from=$CURSOR" "$ALICE_TOKEN")" = "200" ] \
        || fail "filtered page from=$CURSOR failed"
    ID=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["records"]; print(r[0]["id"] if r else "")' "$WORK/audit.json")
    [ -n "$ID" ] || break
    ACT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["records"][0]["action"])' "$WORK/audit.json")
    [ "$ACT" = "member.kick" ] || fail "the filter was lost on page 2+: got action=$ACT"
    [ "$ID" -lt "$LAST_ID" ] || fail "filtered pagination repeated or went backwards: $ID after $LAST_ID"
    LAST_ID=$ID
    COUNT=$((COUNT + 1))
    CURSOR=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("next_from",""))' "$WORK/audit.json")
done
[ "$COUNT" = "$MATCHING" ] || fail "filtered walk saw $COUNT records but matching said $MATCHING"
pass "paged the filtered set one record at a time: $COUNT of $MATCHING, strictly decreasing ids, filter held on every page"

# ── 9. The permission gate still holds on the filtered path ────────────────
ST=$(audit "?actor=$(urlenc "@alice:$HOST")" "$CAROL_TOKEN")
[ "$ST" = "403" ] || fail "expected 403 for a plain member with a filter, got $ST"
grep -q records "$WORK/audit.json" && fail "the 403 leaked records"
grep -q "M_FORBIDDEN" "$WORK/audit.json" || fail "403 did not carry M_FORBIDDEN"
pass "a plain member gets 403 on the filtered endpoint, with no records"

# The escalation shape: a per-channel override granting MANAGE_SERVER (bit 10 =
# 0x400) inside ONE channel must not unlock the server-wide log — with or
# without filters, and least of all when the filter names that very channel.
#
# MANAGE_CHANNELS (bit 5 = 0x20) is granted alongside it purely so the positive
# control below has something channel-scoped to demonstrate. 0x20|0x400 = 0x420.
#
# ADMINISTRATOR (bit 15 = 0x8000) USED TO BE IN THIS GRANT and is now refused
# at the door, which is a fix rather than a regression — see
# PermissionsEngine::may_write_channel_override on fix/perm-containment. The
# bit was always inert in an override, because compute() takes the
# ADMINISTRATOR short-circuit from the ROLE base BEFORE overrides are applied,
# and that inertness is still pinned as a unit test
# (PermissionContainment.AnAdministratorOverrideStoredByAnOlderBuildConfers
# Nothing, which writes one straight into the store). What has changed is that
# the server no longer ACCEPTS the write, from anybody, because a channel has
# no say over a role-level flag and the grant is always either a
# misunderstanding or an attempt. Asserted in both directions here.
OUT=$(api PUT "/_matrix/client/v3/rooms/$ROOM_A_ENC/state/bsfchat.channel.permissions/$(urlenc "user:@carol:$HOST")" \
    "$ALICE_TOKEN" '{"allow":"0x8420","deny":"0x0"}')
[ "$(status "$OUT")" = "403" ] || { echo "$OUT"; fail "an override granting ADMINISTRATOR was accepted"; }
pass "even an administrator cannot put ADMINISTRATOR into a channel override"

OUT=$(api PUT "/_matrix/client/v3/rooms/$ROOM_A_ENC/state/bsfchat.channel.permissions/$(urlenc "user:@carol:$HOST")" \
    "$ALICE_TOKEN" '{"allow":"0x420","deny":"0x0"}')
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "could not write the per-channel override"; }
pass "alice granted carol MANAGE_SERVER+MANAGE_CHANNELS inside $ROOM_A only"

OUT=$(api GET "/_matrix/client/v3/rooms/$ROOM_A_ENC/state/bsfchat.channel.permissions/$(urlenc "user:@carol:$HOST")" \
    "$ALICE_TOKEN")
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "the override was not stored"; }
echo "$OUT" | grep -q 0x420 || fail "the stored override is not the one we wrote"

# Positive control: the override really IS in effect at channel scope. Without
# this, every 403 below could be passing because the override silently failed to
# apply, and the test would prove nothing at all. Carol can now rename ROOM_A
# (MANAGE_CHANNELS, which the override grants her) — and could not before,
# which is asserted against ROOM_B, where she has no override.
OUT=$(api PUT "/_matrix/client/v3/rooms/$ROOM_A_ENC/state/m.room.name/" "$CAROL_TOKEN" \
    '{"name":"carol-was-here"}')
[ "$(status "$OUT")" = "200" ] || { echo "$OUT"; fail "the override is NOT live in $ROOM_A — the escalation checks below would prove nothing"; }
OUT=$(api PUT "/_matrix/client/v3/rooms/$ROOM_B_ENC/state/m.room.name/" "$CAROL_TOKEN" \
    '{"name":"carol-should-not-be-here"}')
[ "$(status "$OUT")" = "403" ] || { echo "$OUT"; fail "carol has power in $ROOM_B too, so the override is not what is granting it"; }
pass "positive control: carol's override grants power inside $ROOM_A and nowhere else"

for Q in "" \
         "?actor=$(urlenc "@alice:$HOST")" \
         "?target_room=$(urlenc "$ROOM_A")" \
         "?target_user=$(urlenc "@carol:$HOST")" \
         "?action=member.ban" \
         "?target_room=$(urlenc "$ROOM_A")&limit=1"; do
    ST=$(audit "$Q" "$CAROL_TOKEN")
    [ "$ST" = "403" ] || fail "PRIVILEGE ESCALATION: channel override unlocked the audit log for '$Q' (got $ST)"
    grep -q records "$WORK/audit.json" && fail "the 403 for '$Q' leaked records"
    grep -q "M_FORBIDDEN" "$WORK/audit.json" || fail "'$Q' was refused, but not by the permission gate: $(cat "$WORK/audit.json")"
    grep -q "audit log" "$WORK/audit.json" || fail "'$Q' was refused for the wrong reason: $(cat "$WORK/audit.json")"
done
pass "a per-channel MANAGE_SERVER override grants NO access to the server-wide audit log, filtered or not"

# And the same filters do work for someone holding the flag at server scope, so
# the refusals above are about carol and not about the filters being broken.
[ "$(audit "?target_room=$(urlenc "$ROOM_A")" "$ALICE_TOKEN")" = "200" ] || fail "alice cannot use the filter carol was refused"
python3 - "$WORK/audit.json" <<'PY' || fail "the filter carol was refused returns nothing for alice either"
import json, sys
d = json.load(open(sys.argv[1]))
assert d["records"], "the refused query is empty even for an admin, so the 403s proved nothing"
print(f"  ok  the same filter returns {len(d['records'])} records for a server-scope admin")
PY

# ── 10. The v16 indexes exist and are used by the real database ────────────
python3 - "$DB" <<'PY' || fail "the v16 indexes are missing or unused in the live database"
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
idx = {r[0]: r[1] for r in db.execute(
    "SELECT name, sql FROM sqlite_master WHERE type='index' AND name LIKE 'idx_audit_log_%'")}
expected = {"idx_audit_log_actor", "idx_audit_log_action",
            "idx_audit_log_target_user", "idx_audit_log_target_room"}
assert set(idx) == expected, f"expected {expected}, got {set(idx)}"
assert "WHERE target_user <> ''" in idx["idx_audit_log_target_user"], idx["idx_audit_log_target_user"]
assert "WHERE target_room <> ''" in idx["idx_audit_log_target_room"], idx["idx_audit_log_target_room"]

# The statements the server actually runs (see SqliteStore::audit_page_query).
cases = {
    "idx_audit_log_actor": "WHERE actor = ? AND id < ?",
    "idx_audit_log_action": "WHERE action = ? AND id < ?",
    "idx_audit_log_target_user": "WHERE target_user = ? AND target_user <> '' AND id < ?",
    "idx_audit_log_target_room": "WHERE target_room = ? AND target_room <> '' AND id < ?",
}
for index, where in cases.items():
    sql = f"SELECT id, actor FROM audit_log {where} ORDER BY id DESC LIMIT ?"
    # The plan is fixed at prepare time, before any value is bound, so these
    # placeholder bindings cannot teach the planner anything the server would not
    # also be hiding from it — which is the whole point of the `<> ''` guards.
    plan = "\n".join(r[3] for r in db.execute("EXPLAIN QUERY PLAN " + sql, ("x", 0, 1)))
    assert index in plan, f"{index} unused:\n{sql}\n{plan}"
    assert "TEMP B-TREE" not in plan, f"{index} needs a sort pass:\n{plan}"
print("  ok  all four v16 indexes exist, the target ones are partial, and each serves its query")

# The append-only triggers are untouched by v16 and still refuse.
trig = [r[0] for r in db.execute(
    "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log'")]
assert len(trig) == 2, trig
for sql in ("UPDATE audit_log SET actor='@nobody:e2e.local'", "DELETE FROM audit_log"):
    try:
        db.execute(sql)
        raise SystemExit(f"FAIL: {sql} was permitted after v16")
    except sqlite3.IntegrityError as e:
        assert "append-only" in str(e), e
print("  ok  after v16 the database still refuses UPDATE and DELETE on audit_log")
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
echo "ALL AUDIT-FILTER E2E CHECKS PASSED (work dir: $WORK)"
cleanup
trap - EXIT
exit 0
