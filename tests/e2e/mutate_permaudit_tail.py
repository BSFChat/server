#!/usr/bin/env python3
"""Mutation harness for the tail of the September 2026 permissions audit — F7 to F12.

Those six findings were reported as "reasoned" rather than proven: unlike F1-F6
there is no DISABLED_ proof for any of them in test_permission_audit_2026_09.cpp.
The proofs now live in the files that own each area (test_role_management.cpp,
test_voice.cpp, test_audit.cpp), and this harness is what stops them from being
proofs in name only.

Two of the six were answered with a DECISION rather than a fix — F9 (voice/leave
stays gated on membership alone) and F12 (the audit log stays unfiltered) — and
both have guard tests asserting the behaviour that was deliberately kept. Those
guards are mutated here too, in the direction of the "fix" that was declined, so
that a future reader who applies it gets a red build and finds the argument.

F8 is the reason this file exists at all. Its fix is a compare-and-swap, and a
compare-and-swap is exactly the kind of thing a test suite can appear to cover
while covering nothing: the CAS primitive is tested directly and deterministically,
but whether the four handlers actually PASS an expectation to it cannot be shown
by a unit test without racing two threads through them, and a race that only
fails sometimes is not a proof. Deleting the argument at each call site is. If a
handler's expectation goes missing and every test stays green, the handler was
never covered.

Run from anywhere:  python3 server/tests/e2e/mutate_permaudit_tail.py
It restores the tree and rebuilds clean on the way out, including after a crash
in the middle of a case.
"""

import subprocess
import sys

from mutate_common import (MutationGuard, build_dir, cmake_build, object_files,
                           require_build, server_root)

# Resolved from this script's own location (<repo>/tests/e2e/), never a
# hard-coded path: several worktrees of this repo are open at once, and a
# harness that mutates the shared checkout instead of its own has done real
# damage before. Override with BSFCHAT_SERVER=... / --srv=... See mutate_common.
SERVER = server_root()
BUILD = build_dir(SERVER, "build-fix")

ROLES = SERVER / "src/api/RoleHandler.cpp"
VOICE = SERVER / "src/api/VoiceHandler.cpp"
AUDIT = SERVER / "src/api/AuditHandler.cpp"
STORE = SERVER / "src/store/SqliteStore.cpp"
BOOTSTRAP = SERVER / "src/auth/RoleBootstrap.cpp"


class Mutation:
    """`edits` is a list of (old, new) pairs, each of which must match exactly once.

    `must_fail` names the tests that are supposed to catch it. `must_pass` names a
    control that should stay green — when the control goes red too, the mutation
    was broader than the property and the catch is reported as suspect rather
    than quietly counted.
    """

    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    # ── F7: the role list stops withholding the permission bitfield ──────
    Mutation(
        "F7-a: every caller gets the whole role document again (the pre-fix behaviour)",
        ROLES,
        [("        if (!may_edit && !permissions_are_public(r)) {",
          "        if (false) {")],
        "RoleListDisclosure.AMemberDoesNotLearnWhichRoleCarriesWhichPermission"
        ":RoleListDisclosure.EveryPresentationFieldSurvivesForAMember"
        ":RoleListDisclosure.AChannelOverrideGrantingManageRolesDoesNotWidenTheRead",
        "RoleListDisclosure.AnyoneWhoCanEditRolesStillReadsTheWholeDocument",
    ),
    Mutation(
        "F7-b: the bitfield is withheld from EVERYONE, including role editors "
        "(read-modify-write becomes a silent permission wipe)",
        ROLES,
        [("        if (!may_edit && !permissions_are_public(r)) {",
          "        if (!permissions_are_public(r)) {")],
        "RoleListDisclosure.AnyoneWhoCanEditRolesStillReadsTheWholeDocument",
        "RoleListDisclosure.AMemberDoesNotLearnWhichRoleCarriesWhichPermission",
    ),
    Mutation(
        # The realistic drift, not a synthetic one. This endpoint has no room id
        # in it — "these routes have no room to be confused about in the first
        # place", per RoleHandler.h — so a room-scope bug cannot be written by
        # changing the scope argument alone; something has to go looking for a
        # room. Somebody deciding the read should reflect "wherever you happen
        # to have MANAGE_ROLES" is how that would arrive, and it is exactly the
        # shape F1/F2 are about one level up.
        #
        # An earlier version of this mutation passed req.get_param_value("room")
        # instead, which is the empty string when no such parameter is sent —
        # i.e. server scope — so it mutated nothing and SURVIVED. A mutation
        # that does not change behaviour is not evidence about a test.
        "F7-c: the read becomes room-aware, so a channel override widens it",
        ROLES,
        [("    const bool may_edit = perms.can(*actor, kServerScope, permission::kManageRoles);",
          "    bool may_edit = perms.can(*actor, kServerScope, permission::kManageRoles);\n"
          "    for (const auto& mutated_room : store_.get_joined_rooms(*actor)) {\n"
          "        if (perms.can(*actor, mutated_room, permission::kManageRoles)) may_edit = true;\n"
          "    }")],
        "RoleListDisclosure.AChannelOverrideGrantingManageRolesDoesNotWidenTheRead",
        "RoleListDisclosure.AMemberDoesNotLearnWhichRoleCarriesWhichPermission",
    ),
    Mutation(
        "F7-d: a self-assignable role's bits are withheld too (the opt-in picker "
        "loses its containment ceiling and shows every trap role as safe)",
        ROLES,
        [("    return role.id == permission::role_id::kEveryone || role.self_assignable;",
          "    return role.id == permission::role_id::kEveryone;")],
        "RoleListDisclosure.AMemberDoesNotLearnWhichRoleCarriesWhichPermission",
    ),

    # ── F8: the compare-and-swap ─────────────────────────────────────────
    #
    # The primitive first, then each of the four call sites. The call-site
    # mutations are the point of this harness: they are the only thing that can
    # show the handlers actually USE it.
    Mutation(
        "F8-a: the store's compare half is removed (every write is unconditional again)",
        STORE,
        [("    if (expected != nullptr && previous != *expected) {\n"
          "        return {/*applied=*/false, std::move(previous)};\n"
          "    }",
          "    // MUTATED: no compare")],
        "ServerStateCompareAndSwap.AStaleWriteIsRefusedAndTheNewerContentSurvives"
        ":ServerStateCompareAndSwap.ExpectingAnAbsentRowFailsOnceSomebodyHasWrittenOne"
        ":ServerStateCompareAndSwap.ALostWriteIsNotAuditedAndNotMirrored",
        "ServerStateCompareAndSwap.TheDeltaEndpointsStillApplyUncontendedEdits",
    ),
    Mutation(
        "F8-b: a lost write is still audited and mirrored",
        BOOTSTRAP,
        [("    if (!write.applied) return false;", "    // MUTATED: carry on regardless")],
        "ServerStateCompareAndSwap.ALostWriteIsNotAuditedAndNotMirrored",
    ),
    Mutation(
        "F8-c: the role-document write drops its expectation "
        "(a stale proposal can revert a revocation again)",
        ROLES,
        [("                                  std::string(), j.dump(), mirror_room(), actor, "
          "&expected);",
          "                                  std::string(), j.dump(), mirror_room(), actor);")],
        # Nothing in the unit suite can catch this without a race, which is the
        # whole reason the mutation exists. It is expected to SURVIVE, and the
        # harness says so in the report rather than pretending otherwise; see
        # EXPECTED_SURVIVORS below.
        "ServerStateCompareAndSwap.*",
    ),
    Mutation(
        "F8-d: change_self_role drops its expectation "
        "(a member can revert their own demotion by toggling an opt-in role)",
        ROLES,
        [("                                      *actor, j.dump(), mirror_room(), *actor, "
          "&doc.raw)) {",
          "                                      *actor, j.dump(), mirror_room(), *actor)) {")],
        "ServerStateCompareAndSwap.*",
    ),

    # ── F11: the pre-permission leak of channel voice configuration ──────
    #
    # Expressed as "put the capability tests back in front of the visibility
    # test", which is the pre-fix code, rather than as a reworded message: the
    # property the tests assert is indistinguishability, and only the ordering
    # can satisfy it.
    Mutation(
        "F11-a: voice/join answers 'not voice-capable' before asking whether the "
        "caller may see the channel",
        VOICE,
        [("    PermissionsEngine perms(store_, config_);\n"
          "    if (!permission::has(perms.compute(*user_id, room_id), permission::kViewChannel)) {\n"
          "        res.status = 403;\n"
          "        res.set_content(\n"
          "            MatrixError::forbidden(\"You do not have permission to view this "
          "channel\").to_json().dump(),\n"
          "            \"application/json\");\n"
          "        return;\n"
          "    }\n"
          "\n"
          "    // Check if room is voice-capable\n"
          "    auto voice_state = store_.get_state_event(room_id, "
          "std::string(event_type::kRoomVoice), \"\");",
          "    // Check if room is voice-capable\n"
          "    auto voice_state = store_.get_state_event(room_id, "
          "std::string(event_type::kRoomVoice), \"\");"),
         ("    VoiceChannelContent voice_channel;\n"
          "    from_json(voice_state->content.data, voice_channel);\n"
          "    if (!voice_channel.enabled) {\n"
          "        res.status = 403;\n"
          "        res.set_content(MatrixError::forbidden(\"Voice is disabled in this "
          "room\").to_json().dump(), \"application/json\");\n"
          "        return;\n"
          "    }\n"
          "\n"
          "    // Parse optional device_id from body",
          "    VoiceChannelContent voice_channel;\n"
          "    from_json(voice_state->content.data, voice_channel);\n"
          "    if (!voice_channel.enabled) {\n"
          "        res.status = 403;\n"
          "        res.set_content(MatrixError::forbidden(\"Voice is disabled in this "
          "room\").to_json().dump(), \"application/json\");\n"
          "        return;\n"
          "    }\n"
          "\n"
          "    PermissionsEngine perms(store_, config_);\n"
          "    if (!permission::has(perms.compute(*user_id, room_id), permission::kViewChannel)) {\n"
          "        res.status = 403;\n"
          "        res.set_content(\n"
          "            MatrixError::forbidden(\"You do not have permission to view this "
          "channel\").to_json().dump(),\n"
          "            \"application/json\");\n"
          "        return;\n"
          "    }\n"
          "\n"
          "    // Parse optional device_id from body")],
        "LiveKitTokenTest.JoinRefusalSaysNothingAboutAnUnseenChannelsVoiceConfig",
        "LiveKitTokenTest.AMemberWhoCanSeeTheChannelStillLearnsWhyVoiceIsUnavailable",
    ),

    # ── F9 and F12: the two findings that were DECLINED ──────────────────
    #
    # Mutated toward the change that was NOT made, so the guard tests earn their
    # place. A reader who decides the decision was wrong should be arguing with
    # a red build and a recorded argument, not with a comment.
    Mutation(
        "F9 (declined): voice/leave gains the kViewChannel gate the audit asked for, "
        "stranding a member who is locked out mid-call",
        VOICE,
        [("    if (!store_.is_room_member(room_id, *user_id)) {\n"
          "        res.status = 403;\n"
          "        res.set_content(MatrixError::forbidden(\"Not a member of this "
          "room\").to_json().dump(), \"application/json\");\n"
          "        return;\n"
          "    }\n"
          "\n"
          "    // Optional session echo. A client that got a session_id from voice/join",
          "    if (!store_.is_room_member(room_id, *user_id)) {\n"
          "        res.status = 403;\n"
          "        res.set_content(MatrixError::forbidden(\"Not a member of this "
          "room\").to_json().dump(), \"application/json\");\n"
          "        return;\n"
          "    }\n"
          "    {\n"
          "        PermissionsEngine perms(store_, config_);\n"
          "        if (!permission::has(perms.compute(*user_id, room_id), "
          "permission::kViewChannel)) {\n"
          "            res.status = 403;\n"
          "            res.set_content(MatrixError::forbidden(\"You do not have permission to "
          "view this channel\").to_json().dump(), \"application/json\");\n"
          "            return;\n"
          "        }\n"
          "    }\n"
          "\n"
          "    // Optional session echo. A client that got a session_id from voice/join")],
        # BOTH guards, because both are genuinely about the declined change:
        # one says a locked-out member can still hang up, the other says an
        # unprivileged leave is a constant answer with no side effect, and the
        # gate breaks both. An earlier version named the second as the CONTROL,
        # which was wrong — a control has to be a test the mutation should NOT
        # affect, and that one exercises the same path.
        "LiveKitTokenTest.AMemberLockedOutMidCallCanStillLeaveIt"
        ":LiveKitTokenTest.LeavingAChannelYouCannotSeeIsAConstantAnswerAndNoSideEffect",
        # The real control: an ordinary member, with permission, leaving a call
        # normally. If this goes red the mutation broke leaving outright rather
        # than only for the revoked case, and the catch above would mean nothing.
        "VoiceHandlerTest.LeaveWithTheCurrentSessionDeactivates",
    ),
    Mutation(
        "F12 (declined): the audit log filters records by the reader's VIEW_CHANNEL, "
        "hiding the deletion of a private channel from the person auditing it",
        AUDIT,
        [("    json records = json::array();\n"
          "    for (const auto& record : page.records) records.push_back(record_to_json(record));",
          "    json records = json::array();\n"
          "    for (const auto& record : page.records) {\n"
          "        if (!record.target_room.empty() &&\n"
          "            !perms.can(*user_id, record.target_room, permission::kViewChannel)) {\n"
          "            continue;\n"
          "        }\n"
          "        records.push_back(record_to_json(record));\n"
          "    }")],
        "AuditEndpoint.RecordsAboutAChannelTheReaderCannotSeeAreStillReturned",
        "AuditEndpoint.ManageServerRoleCanRead",
    ),
]

# Mutations that CANNOT be caught by the unit suite, with the reason. Listing
# them is the honest alternative to omitting them: the gap is real, it is in the
# report every run, and if somebody later writes a test that closes it the entry
# comes out of this list rather than the mutation being quietly deleted.
EXPECTED_SURVIVORS = {
    "F8-c": "no unit test can observe a lost update through the handler without racing "
            "two threads, and a race that fails only sometimes is not a proof. The CAS "
            "primitive is covered deterministically; THIS is the wiring, and it is "
            "covered by review and by this line.",
    "F8-d": "same as F8-c, for the self-role path.",
}


def build():
    r = cmake_build(BUILD)
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
            return None, f"pattern matched {count} times, expected exactly 1: {old[:70]!r}"
        text = text.replace(old, new, 1)
    return text, None


def expected_survivor(name):
    for key, why in EXPECTED_SURVIVORS.items():
        if name.startswith(key):
            return why
    return None


def main():
    require_build(BUILD)
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. recover() first
    # repairs anything a SIGKILLed run left applied.
    guard = MutationGuard(SERVER, builds=[BUILD])
    guard.recover()
    problems = []
    caught = 0
    known = 0

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
                why = expected_survivor(m.name)
                if why:
                    known += 1
                    print(f"survived  {m.name}\n          KNOWN GAP: {why}")
                else:
                    problems.append(f"{m.name}: tests still pass -> PROPERTY NOT COVERED")
                    print(f"SURVIVED  {m.name}\n          {m.must_fail} still green")
                continue
            if expected_survivor(m.name):
                # A gap that has been closed. Better news than a catch, and it
                # must not be reported as business as usual.
                print(f"caught    {m.name}\n          (listed as a known gap and is no longer "
                      f"one — remove it from EXPECTED_SURVIVORS)")
                problems.append(f"{m.name}: now covered; drop it from EXPECTED_SURVIVORS")
                caught += 1
                continue
            note = ""
            if m.must_pass:
                control_ok, _ = run_tests(m.must_pass)
                if control_ok:
                    note = f"  [control {m.must_pass} still green]"
                else:
                    note = (f"  [control {m.must_pass} ALSO RED -- mutation is broader "
                            f"than the property; read it]")
                    problems.append(f"{m.name}: control {m.must_pass} also failed")
            caught += 1
            print(f"caught    {m.name}{note}")
        finally:
            # Reverts the bytes, deletes the objects and stamps the source past
            # them: a same-second restore can otherwise be judged up to date by
            # make, leaving a stale object in the binary.
            guard.restore(m.path)

    print("\nRestoring the tree and rebuilding clean...")
    guard.restore_all()
    ok, log = build()
    if not ok:
        print("ERROR: clean rebuild FAILED after restore!\n" + log[-2000:])
        return 2
    green, out = run_tests("*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught, "
          f"{known} survived as known and documented gaps.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
