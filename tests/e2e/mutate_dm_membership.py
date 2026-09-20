#!/usr/bin/env python3
"""Mutation harness for "a direct message stays between exactly two people"
(tests/test_dm_membership.cpp).

Part of this has a before. The generic state route really could add a third
account to a DM on origin/main — m.room.member was missing from the route's
direct-room deny-list and invite_intent() asked only for room-scoped
MANAGE_CHANNELS — so the four refusal tests were confirmed red against that
tree before any of the fix existed. M1-M3 are that hole reopened in the three
places it can be reopened from, and they are here so the tests go on failing for
the same reasons after the next refactor moves the code.

The rest are the ones that could not be established that way, and they are why
this file exists rather than just the test file:

  * M4 is THE WRONG FIX, and the only mutation here that matters more than the
    hole itself. "Refuse every membership write on a direct room" passes every
    refusal test in the suite. It is wrong because a ban is not an act on the
    room — it is an act on the ACCOUNT, projected across every room the target
    has a row in — so blanket-refusing it leaves a banned account joined to
    every DM it was in, still holding the backlog. A suite that survives M4 has
    tested the refusal and not the decision behind it.

  * M5 is the wrong PLACE: the rule put on the state route (m.room.member added
    to the deny-list of types a DM refuses) instead of on the intent. Every
    refusal still holds — and leaving a DM through that route stops working,
    because self-membership goes through the same URL. It says whether the
    "leaving still works" controls do any work at all.

  * M6 REORDERS the rule below the permission check. Everything is still
    refused; only the sentence a plain participant gets changes, and only at one
    of the two doors. That is the drift this whole arrangement exists to stop,
    in its most survivable form.

  * M7 drifts the WORDING at one door by hard-coding it there again, which is
    literally the shape the gap had: a rule written out per-endpoint rather than
    read off the intent. The client matches on this text
    (ChannelInviteModel::explainFailure) as well as on the errcode.

Controls (`must_pass`) matter as much as the mutation. If the ordinary invite,
kick and ban suites go red too, the mutation was broader than the property and
proves nothing about it — which is exactly the failure M4 and M5 are built to
provoke in a fix that was written too broadly.

Run from anywhere:  python3 server/tests/e2e/mutate_dm_membership.py
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

# The gap itself: the generic state route could widen a DM.
STATE_ROUTE = ("DirectRoomMembership.TheStateRouteCannotInviteAThirdPersonIntoADm"
               ":DirectRoomMembership.TheStateRouteCannotForceJoinAThirdPersonIntoADm"
               ":DirectRoomMembership.AnAdministratorIsRefusedTheSameWay"
               ":DirectRoomMembership.BothDoorsRefuseAnInviteWithTheSameSentence")

# Removal, at both doors.
NO_REMOVAL = ("DirectRoomMembership.TheStateRouteCannotRemoveTheOtherParticipant"
              ":DirectRoomMembership.TheDedicatedKickEndpointIsRefusedToo")

# The two doors agreeing — the property the shared field buys, as opposed to the
# refusal itself.
ONE_RULE = ("DirectRoomMembership.BothDoorsRefuseAnInviteWithTheSameSentence"
            ":DirectRoomMembership.AParticipantWithNoPermissionsIsToldItIsADirectMessage"
            ":DirectRoomMembership.TheDedicatedInviteEndpointStillCarriesItsErrcode")

# What a direct room must NOT stop. These are the controls for M1-M3 and the
# targets of M4 and M5.
STILL_WORKS = ("DirectRoomMembership.LeavingADirectMessageStillWorks"
               ":DirectRoomMembership.LeavingADirectMessageThroughTheStateRouteStillWorks"
               ":DirectRoomMembership.BanningFromInsideADirectMessageStillWorks"
               ":DirectRoomMembership.UnbanningFromInsideADirectMessageStillWorks"
               ":DirectRoomMembership.AServerBanPlacedInAChannelStillReachesEveryDirectMessage")

# Ordinary channels, here and in the suites that own those paths. The rule is
# about direct rooms; if these go red it is about membership writes.
ORDINARY = ("DirectRoomMembership.InvitingIntoAnOrdinaryChannelStillWorksAtBothDoors"
            ":DirectRoomMembership.KickingFromAnOrdinaryChannelStillWorksAtBothDoors"
            ":PhantomMembership.*:KickEnforcement.*:ServerBan.*:InviteIdempotency.*")

# ── the exact text of each piece, so a moved one fails loudly here ──────────

SHARED_GUARD = """    if (intent.direct_room_refusal && store_.is_direct_room(room_id)) {
        refusal.message = intent.direct_room_refusal;
        return refusal;
    }
"""

# The permission refusal M6 moves the rule below. The first version of that
# mutation re-inserted the guard immediately ABOVE this block -- where it
# already sits -- and so mutated nothing while reporting SURVIVED. A no-op
# mutation is indistinguishable from an uncovered property, which is the one
# failure mode of a harness that cannot be caught by reading its output.
PERM_REFUSAL = """    if (!perms.can(actor, scope, intent.required)) {
        refusal.message = std::string("Insufficient permissions to ") + intent.verb;
        return refusal;
    }
"""

DENY_LIST = """    if ((evt_type == std::string(event_type::kRoomCategory) ||"""

INVITE_DOOR = """    if (const auto* dm_refusal = invite_intent().direct_room_refusal;
        dm_refusal && refuse_on_direct_room(store_, res, room_id, dm_refusal,
                                            refusal::kInviteDirectRoom)) {
        return;
    }
"""


class Mutation:
    """`edits` is a list of (old, new) pairs, each of which must match exactly once."""

    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    # ── M1-M3: the hole, reopened where it can be reopened ──────────────
    Mutation(
        "M1: invite_intent() stops refusing direct rooms, so the state route "
        "can widen a DM again (the gap, reintroduced)",
        HANDLER,
        [("    i.direct_room_refusal = kInviteIntoDirectRoom;",
          "    i.direct_room_refusal = nullptr;")],
        # The dedicated endpoint reads the SAME field, so it stops refusing too
        # — which is the arrangement being asserted as much as the refusal is.
        STATE_ROUTE + ":DirectRoomMembership.TheDedicatedInviteEndpointStillCarriesItsErrcode"
        ":DirectRoomMembership.AParticipantWithNoPermissionsIsToldItIsADirectMessage",
        STILL_WORKS + ":" + ORDINARY,
    ),
    Mutation(
        "M2: kick_intent() stops refusing direct rooms, so a moderator can "
        "eject the other participant from a two-person conversation",
        HANDLER,
        [('    i.direct_room_refusal = "Cannot remove someone from a direct message";',
          "    i.direct_room_refusal = nullptr;")],
        NO_REMOVAL,
        STATE_ROUTE + ":" + STILL_WORKS + ":" + ORDINARY,
    ),
    Mutation(
        "M3: the shared guard is removed from apply_membership_moderation, so "
        "only the dedicated invite endpoint still enforces the rule",
        HANDLER,
        [(SHARED_GUARD, "")],
        # Everything that goes through the shared path — but NOT the dedicated
        # invite endpoint's own errcode test, which is served by its own call.
        # That asymmetry is the point: one door left standing is exactly the
        # state this change found the server in.
        STATE_ROUTE + ":" + NO_REMOVAL,
        STILL_WORKS + ":" + ORDINARY +
        ":DirectRoomMembership.TheDedicatedInviteEndpointStillCarriesItsErrcode",
    ),

    # ── M4: the wrong fix ───────────────────────────────────────────────
    Mutation(
        "M4: THE BLANKET REFUSAL -- ban and unban are refused on a direct room "
        "too, so a banned account stays joined to every DM it was in",
        HANDLER,
        [("    i.direct_room_refusal = nullptr;\n    i.verb = \"ban\";",
          "    i.verb = \"ban\";"),
         ("    i.direct_room_refusal = nullptr;\n    i.verb = \"unban\";",
          "    i.verb = \"unban\";")],
        "DirectRoomMembership.BanningFromInsideADirectMessageStillWorks"
        ":DirectRoomMembership.UnbanningFromInsideADirectMessageStillWorks",
        # Every refusal still holds -- that is the POINT of this mutation. A
        # suite that only tests refusals cannot tell this apart from the fix.
        STATE_ROUTE + ":" + NO_REMOVAL + ":" + ORDINARY +
        ":DirectRoomMembership.LeavingADirectMessageStillWorks"
        ":DirectRoomMembership.AServerBanPlacedInAChannelStillReachesEveryDirectMessage",
    ),

    # ── M5: the wrong place ─────────────────────────────────────────────
    Mutation(
        "M5: the rule is put on the state route's deny-list of state types "
        "instead of on the intent, so leaving a DM breaks with it",
        HANDLER,
        [(DENY_LIST,
          "    if ((evt_type == std::string(event_type::kRoomMember) ||\n"
          "         evt_type == std::string(event_type::kRoomCategory) ||")],
        # Two failures, and they are the two halves of "wrong place". It breaks
        # LEAVING, because self-membership goes through the same URL and a
        # per-type rule cannot tell the two apart. And it breaks the shared
        # SENTENCE, because the route's deny-list has one message for every
        # type on it ("a direct message is not a channel and its structure
        # cannot be changed") -- true of a category write and wrong about an
        # invite, which the client's add-member dialog is reading.
        "DirectRoomMembership.LeavingADirectMessageThroughTheStateRouteStillWorks"
        ":DirectRoomMembership.BothDoorsRefuseAnInviteWithTheSameSentence",
        # Everything else survives, including POST /leave -- which is why the
        # state-route spelling of "leaving still works" had to be its own test
        # rather than a second assertion on the endpoint one.
        NO_REMOVAL + ":" + ORDINARY +
        ":DirectRoomMembership.TheStateRouteCannotInviteAThirdPersonIntoADm"
        ":DirectRoomMembership.TheStateRouteCannotForceJoinAThirdPersonIntoADm"
        ":DirectRoomMembership.AnAdministratorIsRefusedTheSameWay"
        ":DirectRoomMembership.LeavingADirectMessageStillWorks"
        ":DirectRoomMembership.BanningFromInsideADirectMessageStillWorks",
    ),

    # ── M6: the wrong order ─────────────────────────────────────────────
    Mutation(
        "M6: the rule is moved BELOW the permission check, so a plain "
        "participant is told they lack permission instead",
        HANDLER,
        [(SHARED_GUARD, ""),
         (PERM_REFUSAL, PERM_REFUSAL + "\n" + SHARED_GUARD)],
        "DirectRoomMembership.AParticipantWithNoPermissionsIsToldItIsADirectMessage",
        # Nothing else moves: every act that was refused is still refused, and
        # everything that worked still works. Only the answer a participant
        # without MANAGE_CHANNELS gets changes, and only at one of the doors.
        STATE_ROUTE + ":" + NO_REMOVAL + ":" + STILL_WORKS + ":" + ORDINARY,
    ),

    # ── M7: the wording, drifted at one door ────────────────────────────
    Mutation(
        "M7: handle_invite hard-codes its own sentence again instead of reading "
        "it off the intent, so the two doors drift apart",
        HANDLER,
        [(INVITE_DOOR,
          "    if (refuse_on_direct_room(store_, res, room_id,\n"
          "                              \"You cannot add people to a DM\",\n"
          "                              refusal::kInviteDirectRoom)) {\n"
          "        return;\n"
          "    }\n")],
        "DirectRoomMembership.BothDoorsRefuseAnInviteWithTheSameSentence",
        # Both doors still refuse, and the errcode is untouched -- a status-code
        # assertion cannot see this, which is the whole reason the suite
        # compares the two bodies to each other.
        STATE_ROUTE.replace(
            ":DirectRoomMembership.BothDoorsRefuseAnInviteWithTheSameSentence", "") +
        ":" + NO_REMOVAL + ":" + STILL_WORKS + ":" + ORDINARY +
        ":DirectRoomMembership.TheDedicatedInviteEndpointStillCarriesItsErrcode",
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
                    note = (f"  [control ALSO RED -- mutation is broader than the "
                            f"property; read it]")
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
    green, out = run_tests("DirectRoomMembership.*:PhantomMembership.*:KickEnforcement.*"
                           ":ServerBan.*:InviteIdempotency.*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
