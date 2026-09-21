#!/usr/bin/env python3
"""Mutation harness for "`is_direct` is a claim the server checks, not a hint
it trusts" (finding F3 of docs/audit-permissions-2026-09.md).

None of this has a before in the useful sense. The hole is not a rule that was
written in the wrong place — it is a rule that did not exist, so "reintroduce
the bug" is one mutation (M1) and it is the least interesting one in the file.
Everything that matters here is a WRONG FIX or a RIGHT FIX IN THE WRONG PLACE,
because F3 is a finding where several plausible repairs pass a suite of
refusals and are each wrong for a different reason:

  * M1 is the hole itself, so the proofs go on failing for the reason they were
    written when the next refactor moves the code.

  * M2 IS THE OBVIOUS WRONG FIX AND THE MOST IMPORTANT MUTATION IN THIS FILE.
    "Refuse `is_direct` outright" — no DMs at all — passes every refusal test in
    section 6, passes the audit's F3 proof, and removes the feature the flag
    exists for. A suite that survives M2 has tested the refusal and not the
    decision behind it. Its control is AnOrdinaryMemberCanStillOpenAOneToOneDm,
    which is first in that section for this reason.

  * M3 is the WRONG PLACE: the cap enforced in the invite LOOP (stop after the
    first invitee) instead of on the request. Every force-join assertion still
    holds — only one account is joined — and the room is still created, still
    marked direct, still uncapped in every other respect, and the caller is told
    it worked. It says whether the suite asserts that nothing was WRITTEN or
    only that the victims were not joined.

  * M4 makes the shape rule a PERMISSION instead of a structural rule: applied
    only to callers without MANAGE_CHANNELS, so a moderator can still
    manufacture an unmanageable room. F3's own actor (@everyone) is still
    refused, which is exactly why the moderator test exists beside the cap.

  * M5 is the WRONG ORDER the other way: the rate limit charged ABOVE the shape
    refusals, which turns the budget into an oracle — a caller reads which
    bodies are accepted off the 429 boundary rather than off the 403s.

  * M6 drops the member-count predicate from find_direct_room, which is the
    READ half of the pair rule. Nothing about creation changes; the confused
    deputy comes back, and only the dedup test can see it.

  * M7 widens the delete exception from the broken SHAPE to the ACTOR — "any
    server-scope MANAGE_CHANNELS holder may delete any direct room". This is the
    mutation that makes the audit's DISABLED F3b proof PASS, and it must be
    caught, because it is a real product change wearing a bug fix's clothes. Its
    must_fail list is the regression that has an incident behind it.

Controls (`must_pass`) matter as much as the mutation. If the ordinary invite,
kick and ban suites go red too, the mutation was broader than the property and
proves nothing about it — the failure M2 and M3 are built to provoke in a fix
written too broadly.

Run from anywhere:  python3 server/tests/e2e/mutate_direct_room_shape.py
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
STORE = SERVER / "src/store/SqliteStore.cpp"

# The cap itself, at the door a DM is born through. The audit's own proof is in
# here: it is the acceptance criterion, so it is named rather than assumed.
THE_CAP = ("DirectRoomMembership.IsDirectWithMoreThanOneInviteeIsRefused"
           ":DirectRoomMembership.IsDirectWithNoInviteesIsRefused"
           ":DirectRoomMembership.IsDirectWithOnlySelfIsRefused"
           ":DirectRoomMembership.ADuplicatedInviteeIsNotAWayAroundTheCap"
           ":PermissionAudit2026_09.F3_IsDirectBypassesCreateRoomPermission")

# The cap is structural, not a permission somebody senior gets to skip.
NOT_A_PERMISSION = "DirectRoomMembership.IsDirectIsRefusedForAModeratorToo"

# A DM is not server structure.
NOT_STRUCTURE = "DirectRoomMembership.ADirectRoomCannotBeCreatedAsServerStructure"

# The fan-out half, which is separate from the cap.
THE_BUDGET = ("DirectRoomMembership.CreatingRoomsIsRateLimited"
              ":DirectRoomMembership.TheRateLimitIsChargedBelowTheRefusals")

# The read half of the pair rule.
THE_DEPUTY = "DirectRoomMembership.AManufacturedMultiPartyRoomIsNotHandedBackAsSomebodysDm"

# The delete exception, and the line it must not cross. The regression is in
# another suite on purpose: it predates this work and has an incident behind it.
THE_LINE = ("DirectRoomMembership.AnAdministratorStillCannotDeleteAGenuineTwoPersonDm"
            ":DirectRoomIsolation.AnAdminOutsideADmCannotDeleteIt")

THE_REMEDY = ("DirectRoomMembership.AnAdministratorCanDeleteAManufacturedMultiPartyDirectRoom"
              ":DirectRoomMembership.DeletingAManufacturedRoomIsAuditedAndNamesNobody")

# WHAT MUST NOT STOP WORKING. These are the controls for every mutation here,
# and the targets of M2 and M3. Opening a DM costs no permission and must go on
# costing none: that is the feature `is_direct` exists for.
STILL_WORKS = ("DirectRoomMembership.AnOrdinaryMemberCanStillOpenAOneToOneDm"
               ":DirectRoomMembership.OpeningTheSameDmTwiceStillReturnsTheSameRoom"
               ":DirectRoomMembership.RefusingTheShapeSaysNothingAboutWhoExists"
               ":DirectRoomMembership.AMemberStillCannotCreateAChannel"
               ":RoomHandlerCreate.*")

# The rest of the DM rules, and ordinary channels. The change is about what a
# direct room may BE; if these go red it is about membership writes instead.
ORDINARY = ("DirectRoomMembership.TheStateRouteCannotInviteAThirdPersonIntoADm"
            ":DirectRoomMembership.LeavingADirectMessageStillWorks"
            ":DirectRoomMembership.BanningFromInsideADirectMessageStillWorks"
            ":DirectRoomMembership.InvitingIntoAnOrdinaryChannelStillWorksAtBothDoors"
            ":DirectRoomIsolation.*:PhantomMembership.*:KickEnforcement.*:ServerBan.*")

# ── the exact text of each piece, so a moved one fails loudly here ──────────

SHAPE_GUARD = """        if (const char* refusal = direct_room_shape_refusal(room_req, body, *user_id)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(refusal).to_json().dump(),
                            "application/json");
            return;
        }
"""

THE_LIST_RULE = """    if (req.invite.size() != 1) {
        return "A direct message is a conversation between exactly two people";
    }
"""

THE_BUCKET = """    if (const auto wait = limits_.acquire(SendLimiter::Bucket::kRoomCreate, *user_id)) {
        return send_rate_limited(res, wait,
                                 SendLimiter::message_for(SendLimiter::Bucket::kRoomCreate));
    }
"""

IS_DIRECT_BRANCH = "    const bool is_direct = room_req.is_direct.value_or(false);\n    if (is_direct) {\n"

PAIR_PREDICATE = """          AND (SELECT COUNT(*) FROM room_members m
               WHERE m.room_id = r.room_id AND m.membership = 'join') = 2
"""

SHAPE_SCOPED_DELETE = """        const bool is_a_real_dm = (joined == 2);
        if (is_a_real_dm ||
            !dm_perms.can(*user_id, kServerScope, permission::kManageChannels)) {"""

INVITE_LOOP = """    for (const auto& invitee : room_req.invite) {
        if (invitee == *user_id) continue;"""


class Mutation:
    """`edits` is a list of (old, new) pairs, each of which must match exactly once."""

    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    # ── M1: the hole, reopened ──────────────────────────────────────────
    Mutation(
        "M1: the shape rule is removed from handle_create_room, so `is_direct` "
        "is a caller-controlled bypass again (F3, reintroduced)",
        HANDLER,
        [(SHAPE_GUARD, "")],
        THE_CAP + ":" + NOT_A_PERMISSION + ":" + NOT_STRUCTURE,
        STILL_WORKS + ":" + ORDINARY + ":" + THE_DEPUTY,
    ),

    # ── M2: the wrong fix ───────────────────────────────────────────────
    Mutation(
        "M2: THE BLANKET REFUSAL -- `is_direct` is refused outright, so there "
        "are no direct messages at all",
        HANDLER,
        # The sentence deliberately still says "direct message": a wrong fix
        # that ALSO changed the wording would be caught by the refusal tests
        # for the wrong reason, and the whole point of M2 is that it is caught
        # only by the controls.
        [(THE_LIST_RULE,
          '    return "A direct message cannot be opened";\n')],
        # The FEATURE, not the refusal. Every test in THE_CAP still passes under
        # this mutation -- that is the point of it -- so a suite that named only
        # those would report this fix as correct.
        "DirectRoomMembership.AnOrdinaryMemberCanStillOpenAOneToOneDm"
        ":DirectRoomMembership.OpeningTheSameDmTwiceStillReturnsTheSameRoom"
        ":DirectRoomMembership.RefusingTheShapeSaysNothingAboutWhoExists"
        ":RoomHandlerCreate.AdminCanCreateChannelsAndAnyoneCanOpenADm",
        # Channels are untouched, which is what makes it survivable: the
        # mutation is narrow and wrong rather than broad and obvious.
        "DirectRoomMembership.AMemberStillCannotCreateAChannel:" + THE_CAP,
    ),

    # ── M3: the wrong place ─────────────────────────────────────────────
    Mutation(
        "M3: the cap is enforced in the INVITE LOOP instead of on the request, "
        "so the room is still created and the caller is told it worked",
        HANDLER,
        [(SHAPE_GUARD, ""),
         (INVITE_LOOP,
          "    int joined_so_far = 0;\n"
          "    for (const auto& invitee : room_req.invite) {\n"
          "        if (is_direct && joined_so_far >= 1) break;\n"
          "        ++joined_so_far;\n"
          "        if (invitee == *user_id) continue;")],
        # Only the tests that assert nothing was WRITTEN can see this. The
        # force-join assertions alone cannot: two of the three victims really
        # are left unjoined.
        THE_CAP + ":" + NOT_STRUCTURE,
        STILL_WORKS + ":" + ORDINARY,
    ),

    # ── M4: the wrong order ─────────────────────────────────────────────
    Mutation(
        "M4: the shape rule is applied only to callers WITHOUT "
        "MANAGE_CHANNELS, so a moderator can still manufacture an "
        "unmanageable room",
        HANDLER,
        [(SHAPE_GUARD,
          "        PermissionsEngine shape_perms(store_, config_);\n"
          "        if (!shape_perms.can(*user_id, kServerScope,\n"
          "                             permission::kManageChannels)) {\n"
          + SHAPE_GUARD.rstrip("\n").replace("\n", "\n    ") + "\n"
          "        }\n")],
        # F3's own actor is still refused -- mallory holds no MANAGE_CHANNELS,
        # so the rule still runs for her -- and only the moderator test sees it.
        NOT_A_PERMISSION,
        THE_CAP + ":" + STILL_WORKS + ":" + ORDINARY,
    ),

    # ── M5: the budget as an oracle ─────────────────────────────────────
    Mutation(
        "M5: the rate limit is charged ABOVE the shape refusals, so a caller "
        "can read which bodies are accepted off the 429 boundary",
        HANDLER,
        [(THE_BUCKET, ""),
         (IS_DIRECT_BRANCH, THE_BUCKET + "\n" + IS_DIRECT_BRANCH)],
        "DirectRoomMembership.TheRateLimitIsChargedBelowTheRefusals",
        # Everything is still refused and the limiter still limits. Only the
        # ORDER changes, which no status-code assertion can see.
        THE_CAP + ":DirectRoomMembership.CreatingRoomsIsRateLimited:" + STILL_WORKS,
    ),

    # ── M6: the read half, dropped ──────────────────────────────────────
    Mutation(
        "M6: find_direct_room stops counting members, so a legacy multi-party "
        "room is handed back as two other people's DM (the confused deputy)",
        STORE,
        [(PAIR_PREDICATE, "")],
        THE_DEPUTY,
        # Creation is untouched: no new broken room can be made, and the dedup
        # still works for ordinary DMs. This is only about the ones already in
        # the database, which is exactly why it needs its own test.
        THE_CAP + ":" + STILL_WORKS + ":" + ORDINARY,
    ),

    # ── M7: the product change wearing a bug fix's clothes ──────────────
    Mutation(
        "M7: the delete exception is widened from the broken SHAPE to the "
        "ACTOR, so server-scope MANAGE_CHANNELS can delete ANY direct message "
        "(this is the mutation that makes the audit's DISABLED F3b pass)",
        HANDLER,
        [(SHAPE_SCOPED_DELETE,
          "        if (!dm_perms.can(*user_id, kServerScope, permission::kManageChannels)) {")],
        THE_LINE,
        # The remedy still works, every refusal still holds, and F3b -- an audit
        # proof -- goes GREEN. Nothing but the regression can tell this apart
        # from the fix, which is the whole reason it is in this file.
        THE_REMEDY + ":" + THE_CAP + ":" + STILL_WORKS,
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
                    note = ("  [control ALSO RED -- mutation is broader than the "
                            "property; read it]")
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
    green, out = run_tests("DirectRoomMembership.*:DirectRoomIsolation.*"
                           ":RoomHandlerCreate.*:PermissionAudit2026_09.*"
                           ":PhantomMembership.*:KickEnforcement.*:ServerBan.*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
