#!/usr/bin/env python3
"""Mutation harness for "an invite never demotes somebody already in the
channel" (tests/test_invite_idempotency.cpp).

M1 and M2 are the bug itself, reintroduced: both guards removed, one per door.
Those two DO have a before — every one of the five demotion tests was confirmed
red against the unfixed tree — and they are here so the tests keep failing for
the same reason after the next refactor moves the code.

The rest are the reason this file exists, because they are the mistakes a fix
of this shape actually invites:

  * M3 and M4 WIDEN the guard, which is the failure mode that matters. The
    guard has to be join-only: POST /rooms/{id}/invite is the only way back in
    for a user a moderator kicked, and the write it performs is what clears the
    removal marker (was_removed_by_moderator reads the current m.room.member
    event, and a fresh invite carries no bsfchat.removed_by). "Already has a
    membership row" and "is not currently banned" both look like the same
    check and both make every kick permanent, silently, with the endpoint still
    answering 200. A suite that survives these has tested the no-op and not the
    property.

  * M5 turns the no-op into a REFUSAL. Behaviourally defensible and still
    wrong: the bot branch answers 200 for exactly this case, the client's
    add-member dialog has one code path for both, and this endpoint already
    answers seven different situations with one M_FORBIDDEN errcode that
    ChannelInviteModel disambiguates by matching on the message text. It must
    be caught by an assertion on the STATUS, not only on the membership row.

  * M6 keeps the guard but writes the event anyway — the half-fix where the row
    survives and every other member's client still renders the member leaving
    and coming back. Nothing that asserts only on get_membership() can see it.

  * M7 hangs the state route's no-op on the wrong intent, so the flag stops
    covering `join`. It is the mutation that says whether the state-route tests
    are testing the route or just the invite endpoint again.

Controls (`must_pass`) matter as much as the mutation. KickEnforcement.* is
named on the widening cases deliberately: if the demotion tests go red for M3
and the re-admission tests stay green, the harness has proved the two halves
are independently covered, which is the whole argument of this fix.

Run from anywhere:  python3 server/tests/e2e/mutate_invite_idempotency.py
It restores the tree and rebuilds clean on the way out, including after a crash
in the middle of a case.
"""

import subprocess
import sys

from mutate_common import MutationGuard, build_dir, cmake_build, object_files, require_build, \
    server_root

# Resolved from this script's own location (<repo>/tests/e2e/), so a run from a
# worktree mutates THAT worktree. Override with BSFCHAT_SERVER / --srv.
SERVER = server_root()
BUILD = build_dir(SERVER, "build")

HANDLER = SERVER / "src/api/RoomHandler.cpp"

# The property, split by door. Separated so a mutation to one is not credited
# with breaking the other.
NO_DEMOTE_INVITE = ("InviteIdempotency.InvitingAJoinedMemberDoesNotDemoteThem"
                    ":InviteIdempotency.TheDemotionWouldHaveMovedTheRoomOutOfTheJoinedSection"
                    ":InviteIdempotency.RepeatedInvitesOfAJoinedMemberStayANoOp")

NO_DEMOTE_STATE_ROUTE = ("InviteIdempotency.TheStateRouteCannotDemoteAJoinedMemberEither"
                         ":InviteIdempotency.TheStateRouteDoesNotRewriteAnExistingJoin")

# The half the guard must NOT swallow. Re-admission after a kick is the one
# interaction that makes this fix subtle, so it gets its own filter and is
# named as the control on every widening mutation.
READMISSION = ("InviteIdempotency.ReAdmissionAfterAKickStillWrites"
               ":InviteIdempotency.SomebodyWhoLeftCanStillBeInvitedBack"
               ":InviteIdempotency.ASecondInviteToAPendingInviteeIsStillWritten"
               ":KickEnforcement.AnInviteAfterAKickReadmits"
               ":KickEnforcement.AReadmittedUserCanLeaveAndRejoinAgain")

# The ordinary request. None of these guards may touch an invite of somebody who
# is not in the channel, or any deliberate downgrade of somebody who is.
ORDINARY = ("InviteIdempotency.InvitingSomebodyWhoIsNotInTheChannelStillWorks"
            ":InviteIdempotency.TheStateRouteCanStillRemoveAJoinedMember"
            ":KickEnforcement.*:SyncInvites.*:ServerBan.*:PhantomMembership.*")


# ── the exact text of each guard, so a moved one fails loudly here ──────────

INVITE_GUARD = """    if (store_.is_room_member(room_id, target_user)) {
        res.set_content("{}", "application/json");
        get_logger()->info("User {} invited {} to room {}; already a member, nothing written",
                           *user_id, target_user, room_id);
        return;
    }
"""

STATE_ROUTE_GUARD = """    if (intent.no_op_on_existing_join && before == membership::kJoin) {"""


class Mutation:
    """`edits` is a list of (old, new) pairs, each of which must match exactly once."""

    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    # ── M1-M2: the bug, one per door ────────────────────────────────────
    Mutation(
        "M1: handle_invite stops checking whether the target is already a "
        "member, so a human invite demotes them again (the reported bug)",
        HANDLER,
        [(INVITE_GUARD, "")],
        NO_DEMOTE_INVITE,
        # The state route has its own guard and must stay green, which is what
        # says the two are genuinely independent rather than one check reached
        # twice.
        NO_DEMOTE_STATE_ROUTE + ":" + READMISSION + ":" + ORDINARY,
    ),
    Mutation(
        "M2: the state route stops checking, so PUT /state/m.room.member/{user} "
        "with 'invite' demotes a joined member again",
        HANDLER,
        [(STATE_ROUTE_GUARD, "    if (false) {")],
        NO_DEMOTE_STATE_ROUTE,
        NO_DEMOTE_INVITE + ":" + READMISSION + ":" + ORDINARY,
    ),

    # ── M3-M4: the guard widened, which is how this fix breaks kicks ────
    Mutation(
        "M3: the guard becomes \"has any membership row\", so a re-invite after "
        "a kick is swallowed and the kick is permanent",
        HANDLER,
        [("    if (store_.is_room_member(room_id, target_user)) {\n"
          "        res.set_content(\"{}\", \"application/json\");",
          "    if (store_.find_membership(room_id, target_user).has_value()) {\n"
          "        res.set_content(\"{}\", \"application/json\");")],
        READMISSION,
        # The demotion tests must stay green: the point of this mutation is that
        # the bug it introduces is invisible to them.
        NO_DEMOTE_INVITE + ":" + NO_DEMOTE_STATE_ROUTE,
    ),
    Mutation(
        "M4: the guard becomes \"not currently banned\", which reads as the same "
        "check and swallows every re-admission and every pending re-invite",
        HANDLER,
        [("    if (store_.is_room_member(room_id, target_user)) {\n"
          "        res.set_content(\"{}\", \"application/json\");",
          "    if (store_.get_membership(room_id, target_user) != membership::kBan) {\n"
          "        res.set_content(\"{}\", \"application/json\");")],
        READMISSION,
        NO_DEMOTE_INVITE + ":" + NO_DEMOTE_STATE_ROUTE,
    ),

    # ── M5: the no-op becomes a refusal ─────────────────────────────────
    Mutation(
        "M5: an invite of an existing member is REFUSED instead of being a "
        "no-op, so the add-member dialog fails on a gesture that is not an error",
        HANDLER,
        [("    if (store_.is_room_member(room_id, target_user)) {\n"
          "        res.set_content(\"{}\", \"application/json\");",
          "    if (store_.is_room_member(room_id, target_user)) {\n"
          "        res.status = 403;\n"
          "        res.set_content(MatrixError::forbidden(\"Already a member\")"
          ".to_json().dump(), \"application/json\");")],
        NO_DEMOTE_INVITE,
        # The row is still not rewritten, so anything asserting only on
        # get_membership() survives this. Named here so that is explicit.
        READMISSION + ":" + NO_DEMOTE_STATE_ROUTE,
    ),

    # ── M6: the half-fix ────────────────────────────────────────────────
    Mutation(
        "M6: the row is left alone but the member event is emitted anyway, so "
        "every other client renders the member leaving and coming back",
        HANDLER,
        [("    if (store_.is_room_member(room_id, target_user)) {\n"
          "        res.set_content(\"{}\", \"application/json\");",
          "    if (store_.is_room_member(room_id, target_user)) {\n"
          "        emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember),\n"
          "                         target_user, json{{\"membership\", membership::kInvite}});\n"
          "        res.set_content(\"{}\", \"application/json\");")],
        NO_DEMOTE_INVITE,
        READMISSION + ":" + ORDINARY,
    ),

    # ── M7: the state route's flag on the wrong intent ──────────────────
    Mutation(
        "M7: the state route's no-op is hung on the kick intent instead of the "
        "invite intent, so it covers nothing it was meant to and disarms a kick",
        HANDLER,
        [("    i.require_target_exists = true;\n"
          "    // See the field: this is the only intent that can be asked for a state the\n"
          "    // target is already in, and the only one whose write would WEAKEN it.\n"
          "    i.no_op_on_existing_join = true;",
          "    i.require_target_exists = true;"),
         ("    i.records_removal = true;\n    i.verb = \"kick\";",
          "    i.records_removal = true;\n    i.no_op_on_existing_join = true;\n"
          "    i.verb = \"kick\";")],
        NO_DEMOTE_STATE_ROUTE + ":InviteIdempotency.TheStateRouteCanStillRemoveAJoinedMember",
        # The dedicated /invite endpoint has its own guard and is untouched.
        # NOT the re-admission filter: kick_intent also serves POST
        # /rooms/{id}/kick, so this mutation legitimately breaks every test that
        # kicks somebody first — which is the damage, not a broader mutation.
        NO_DEMOTE_INVITE,
    ),
]


def build():
    r = cmake_build(BUILD, target="server_tests")
    return r.returncode == 0, r.stdout + r.stderr


def run_tests(gtest_filter):
    r = subprocess.run([str(BUILD / "tests/server_tests"),
                        "--gtest_filter=" + gtest_filter, "--gtest_brief=1"],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


def apply_edits(text, edits):
    for old, new in edits:
        count = text.count(old)
        if count != 1:
            return None, f"pattern matched {count} times, expected exactly 1: {old[:60]!r}"
        text = text.replace(old, new, 1)
    return text, None


def main():
    require_build(BUILD)
    guard = MutationGuard(SERVER, builds=[BUILD])
    guard.recover()
    problems = []
    caught = 0

    for m in MUTATIONS:
        original = guard.protect(m.path).decode()
        mutated, err = apply_edits(original, m.edits)
        if err:
            problems.append(f"{m.name}: {err}")
            print(f"ERROR     {m.name}\n          {err}")
            continue

        m.path.write_text(mutated)
        # Same-second timestamps: make will happily reuse a stale object.
        for obj in object_files(BUILD, m.path):
            obj.unlink()
        try:
            ok, log = build()
            if not ok:
                problems.append(f"{m.name}: BUILD FAILED (the mutation does not compile)")
                print(f"ERROR     {m.name}\n          build failed:\n{log[-1200:]}")
                continue
            still_green, _ = run_tests(m.must_fail)
            if still_green:
                problems.append(f"{m.name}: tests still pass -> PROPERTY NOT COVERED")
                print(f"SURVIVED  {m.name}\n          {m.must_fail} still green")
                continue
            note = ""
            if m.must_pass:
                control_ok, _ = run_tests(m.must_pass)
                if control_ok:
                    note = "  [control still green]"
                else:
                    note = (f"  [control {m.must_pass} ALSO RED -- mutation is broader "
                            f"than the property; read it]")
                    problems.append(f"{m.name}: control {m.must_pass} also failed")
            caught += 1
            print(f"caught    {m.name}{note}")
        finally:
            guard.restore(m.path)

    print("\nRestoring the tree and rebuilding clean...")
    guard.restore_all()
    ok, log = build()
    if not ok:
        print("ERROR: clean rebuild FAILED after restore!\n" + log[-2000:])
        return 2
    green, out = run_tests("InviteIdempotency.*:KickEnforcement.*:PhantomMembership.*"
                           ":SyncInvites.*:ServerBan.*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
