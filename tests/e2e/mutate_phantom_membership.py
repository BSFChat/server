#!/usr/bin/env python3
"""Mutation harness for "a membership row is never written for an account that
does not exist" (tests/test_phantom_membership.cpp).

Most of what this file covers HAS a before: the guards in RoomHandler.cpp were
added to close a live bug, so six of the ten tests in test_phantom_membership.cpp
were confirmed red against origin/main before a line of the fix existed. M1, M2
and M3 below are those three guards removed again, and they are here so the
tests keep failing for the same reasons after the next refactor moves the code.

The other five are the ones that could not be established that way, and they are
the reason the file exists:

  * M4 REORDERS a check that is already there. The existence refusal is specific
    ("no account on this server has that id") and that is only defensible
    because it sits below the MANAGE_CHANNELS check, where an ordinary member
    cannot reach it. Moved above, every test still passes except the one that
    pins the boundary — so this is the mutation that says whether the
    no-oracle test is doing any work at all. A suite that survives M4 is a
    suite that has tested the refusal and not the disclosure.

  * M5 changes the refusal's WORDING and nothing else. The client keys on it
    (ChannelInviteModel::explainFailure matches on the server's text, because
    handle_invite answers six different situations with one errcode), so the
    string is a contract and drifting it silently is a real regression that
    compiles, passes a status-code assertion and breaks a dialog.

  * M6-M8 are the operator report, which is new code with no before at all.
    They make it find nothing, make it WRITE, and make it cry wolf about every
    bot on the server — the three ways a diagnostic becomes worse than not
    having one.

Controls (`must_pass`) matter as much as the mutation. The RoomHandler cases
name SyncInvites.* and ServerBan.*: these guards must be confined to "the target
does not exist", and if the ordinary invite and ban suites also go red then the
mutation was broader than the property and proves nothing about it.

Run from anywhere:  python3 server/tests/e2e/mutate_phantom_membership.py
It restores the tree and rebuilds clean on the way out, including after a crash
in the middle of a case.
"""

import subprocess
import sys
from pathlib import Path

from mutate_common import MutationGuard, build_dir, cmake_build, object_files, require_build, \
    server_root

# Resolved from this script's own location (<repo>/tests/e2e/), so a run from a
# worktree mutates THAT worktree. Override with BSFCHAT_SERVER / --srv.
SERVER = server_root()
BUILD = build_dir(SERVER, "build")

HANDLER = SERVER / "src/api/RoomHandler.cpp"
STORE = SERVER / "src/store/SqliteStore.cpp"
CLI = SERVER / "src/cli/AdminCli.cpp"

# The write-path half: no membership row for an account that does not exist.
NO_PHANTOM = ("PhantomMembership.InvitingAnIdWithNoAccountIsRefusedAndWritesNothing"
              ":PhantomMembership.InvitingAnIdFromAnotherHomeserverIsRefusedTheSameWay"
              ":PhantomMembership.AFictionalBotIdIsRefusedRatherThanJoinedOutright"
              ":PhantomMembership.TheStateRouteCannotForceJoinAnIdWithNoAccount"
              ":PhantomMembership.BanningAnIdWithNoAccountReservesItWithoutAMembershipRow")

# The disclosure half. Separated because M4 must break THIS and nothing else.
NO_ORACLE = ("PhantomMembership.AnUnprivilegedCallerLearnsNothingAboutWhetherAnAccountExists"
             ":PhantomMembership.TheRefusalDoesNotSayWhichKindOfWrongIdItWas")

# The controls: the ordinary invite, the ordinary ban, the ordinary kick. None
# of the guards may touch a request about an account that does exist.
ORDINARY = ("PhantomMembership.InvitingARealAccountStillWorks"
            ":PhantomMembership.TheStateRouteStillMovesARealAccount"
            ":PhantomMembership.BanningARealNonMemberStillWritesTheRowInTheOriginRoom"
            ":SyncInvites.*:ServerBan.*:KickEnforcement.*")

REPORT = "AdminCli.ListOrphan*"
# The rest of the CLI. A report that breaks grant-admin is a different bug.
CLI_CONTROL = "AdminCli.Grant*:AdminCli.ListUsers*:AdminCli.Refuses*"

# ── the exact text of each guard, so a moved one fails loudly here ──────────

INVITE_GUARD = """    if (!store_.user_exists(target_user)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden(kNoSuchAccount).to_json().dump(),
                        "application/json");
        return;
    }
"""

PERMS_CHECK = """    PermissionsEngine perms(store_, config_);
    // Inviting piggybacks on MANAGE_CHANNELS for now"""


class Mutation:
    """`edits` is a list of (old, new) pairs, each of which must match exactly once."""

    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    # ── M1-M3: the three guards, removed ────────────────────────────────
    Mutation(
        "M1: handle_invite stops checking that the invitee exists "
        "(the reported bug, reintroduced)",
        HANDLER,
        [("    if (!store_.user_exists(target_user)) {\n        res.status = 403;",
          "    if (false) {\n        res.status = 403;")],
        NO_PHANTOM,
        ORDINARY,
    ),
    Mutation(
        "M2: the generic state route stops checking, so PUT "
        "/state/m.room.member/{ghost} force-joins again",
        HANDLER,
        [("    i.require_target_exists = true;\n    i.verb = \"invite\";",
          "    i.verb = \"invite\";")],
        "PhantomMembership.TheStateRouteCannotForceJoinAnIdWithNoAccount",
        ORDINARY,
    ),
    Mutation(
        "M3: the ban projection invents a membership row in the origin room for "
        "an id with no account",
        HANDLER,
        [("only_when.empty() && !origin_room.empty() && store_.user_exists(target_user) &&",
          "only_when.empty() && !origin_room.empty() &&")],
        "PhantomMembership.BanningAnIdWithNoAccountReservesItWithoutAMembershipRow",
        ORDINARY,
    ),

    # ── M4: the disclosure boundary ─────────────────────────────────────
    Mutation(
        "M4: the existence refusal is moved ABOVE the MANAGE_CHANNELS check, so "
        "any member of the channel can walk the account namespace",
        HANDLER,
        [(INVITE_GUARD, ""), (PERMS_CHECK, INVITE_GUARD + "\n" + PERMS_CHECK)],
        NO_ORACLE,
        # Everything else is expected to stay green — that is the POINT of this
        # mutation. The refusal still works, the rows are still not written, and
        # only the caller who may not ask can now ask.
        NO_PHANTOM + ":" + ORDINARY,
    ),

    # ── M5: the wording the client keys on ──────────────────────────────
    Mutation(
        "M5: the refusal is reworded, so it no longer says what went wrong "
        "(the client matches on this text)",
        HANDLER,
        [('const char* const kNoSuchAccount = "There is no account on this server with that id";',
          'const char* const kNoSuchAccount = "Cannot invite that user";')],
        NO_PHANTOM,
        # The "one wording for every kind of wrong id" test compares refusals to
        # each other, so it cannot see this. Named as a control to make that
        # explicit rather than leaving it to be discovered.
        "PhantomMembership.TheRefusalDoesNotSayWhichKindOfWrongIdItWas",
    ),

    # ── M6-M8: the operator report ──────────────────────────────────────
    Mutation(
        "M6: the report finds nothing, whatever is in the database",
        STORE,
        [("WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.user_id = m.user_id)",
          "WHERE 0")],
        "AdminCli.ListOrphanMembersFindsARowLeftByTheOldInvitePath",
        CLI_CONTROL,
    ),
    Mutation(
        "M7: the report CLEANS UP what it finds instead of reporting it",
        CLI,
        [("    auto orphans = store.list_orphan_memberships();",
          "    auto orphans = store.list_orphan_memberships();\n"
          "    for (const auto& row : orphans) "
          "store.set_membership(row.room_id, row.user_id, \"leave\");")],
        "AdminCli.ListOrphanMembersDeletesNothing",
        CLI_CONTROL,
    ),
    Mutation(
        "M8: the report counts every bot on the server as a phantom",
        STORE,
        [("WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.user_id = m.user_id)",
          "WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.user_id = m.user_id "
          "AND u.kind != 'bot')")],
        "AdminCli.ListOrphanMembersDoesNotCountABotAsAPhantom",
        CLI_CONTROL,
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
    green, out = run_tests("PhantomMembership.*:AdminCli.*:SyncInvites.*:ServerBan.*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
