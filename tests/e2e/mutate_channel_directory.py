#!/usr/bin/env python3
"""Mutation harness for the channel directory (GET /bsfchat/channels).

A new endpoint has no "before" to fail against — the tests in
tests/test_channel_directory.cpp could not be compiled against a tree without
it, so "confirmed failing first" has to be established some other way. This is
that other way, and M1 is the whole reason the file exists: it rewrites the
directory's filter to the NAIVE implementation — filter on membership, exactly
the way GET /joined_rooms once did — and requires the security tests to go red.
A directory whose tests stay green under M1 is a directory whose tests are not
testing the thing that matters, because on this data model every account holds a
membership row for every private channel (docs/membership-vs-visibility.md).

The rest break one property each: the DM exclusion, the parent-id check, the
field set, the ordering, the category exemption, the `joined` field, and the
gate's strength in the OTHER direction (tightened to MANAGE_CHANNELS, which must
break the ordinary-member controls — a test suite that only ever asserts denial
passes just as happily against an endpoint that denies everybody).

Controls (`must_pass`) matter as much as the mutation here. Several cases name
`RoomVisibility.*` — the /joined_rooms suite — because these mutations must be
confined to the directory; if the older endpoint's tests also go red, the
mutation was broader than the property and the result proves nothing about it.

Run from anywhere:  python3 server/tests/e2e/mutate_channel_directory.py
It restores the tree and rebuilds clean on the way out, including after a crash
in the middle of a case.
"""

import subprocess
import sys
from pathlib import Path

from mutate_common import MutationGuard, build_dir, cmake_build, require_build, server_root

# Resolved from this script's own location (<repo>/tests/e2e/), so a run from a
# worktree mutates THAT worktree. Override with BSFCHAT_SERVER / --srv.
SERVER = server_root()
BUILD = build_dir(SERVER, "build")

VISIBILITY = SERVER / "src/auth/RoomVisibility.cpp"
STORE = SERVER / "src/store/SqliteStore.cpp"
HANDLER = SERVER / "src/api/RoomHandler.cpp"

# The security half of tests/test_channel_directory.cpp: every test whose
# subject is "a caller must not learn about a room it may not see" — plus the
# one whose subject is the converse, that being IN a room is not a licence to be
# told about it. That last one is the sharpest detector of M1 there is: under a
# membership filter its two assertions swap places, so it cannot pass by
# accident, and it belongs with the security half because it is the same
# sentence read the other way round.
DISCLOSURE = ("ChannelDirectory.DeniedUserLearnsNothingAboutAPrivateChannel"
              ":ChannelDirectory.UserSpecificAllowOverrideReinstatesTheChannel"
              ":ChannelDirectory.RoleAllowOverrideReinstatesTheChannel"
              ":ChannelDirectory.DirectMessagesAreNeverListed"
              ":ChannelDirectory.CategoryIdNeverNamesARoomTheCallerCannotSee"
              ":ChannelDirectory.OrderingDoesNotDiscloseWhatWasFiltered"
              ":ChannelDirectory.AChannelTheCallerJoinedWithoutAGrantIsNotListed")

# The other half — the controls. If these are the ones a mutation breaks, the
# endpoint has been made useless rather than unsafe, which is its own bug.
#
# The first of them is asserted with a BOT, and since bot scoping that is no
# longer a bot holding the server's defaults: it holds one explicit per-channel
# grant and no membership anywhere. That is what makes it a control worth having
# — a mutation that tightens the gate stops honouring the grant, and one that
# loosens it stops needing it.
CAPABILITY = ("ChannelDirectory.ACallerThatIsAMemberOfNothingStillSeesTheChannels"
              ":ChannelDirectory.AnOrdinaryMemberSeesThePublicChannels"
              ":ChannelDirectory.ADeniedCategoryIsStillNamedAsAContainer")


class Mutation:
    """`edits` is a list of (old, new) pairs, each of which must match exactly once."""

    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


FILTER_LINE = "if (!can_view_room(store, perms, user_id, row.room_id)) continue;"

MUTATIONS = [
    # ── M1: the naive implementation ─────────────────────────────────────
    Mutation(
        "M1: the directory filters on MEMBERSHIP instead of VIEW_CHANNEL "
        "(the /joined_rooms bug, reintroduced on a new endpoint)",
        VISIBILITY,
        [(FILTER_LINE, "if (!store.is_room_member(row.room_id, user_id)) continue;")],
        DISCLOSURE + ":" + CAPABILITY,
        "RoomVisibility.*",
    ),
    Mutation(
        "M2: no filter at all — every room on the server, to anybody with a token",
        VISIBILITY,
        [(FILTER_LINE, "if (false) continue;")],
        DISCLOSURE,
        "RoomVisibility.*",
    ),
    Mutation(
        "M3: the category exemption dropped, so the directory and the sidebar "
        "disagree about which containers exist",
        VISIBILITY,
        [(FILTER_LINE,
          "if (!perms.can(user_id, row.room_id, permission::kViewChannel)) continue;")],
        "ChannelDirectory.ADeniedCategoryIsStillNamedAsAContainer",
        "ChannelDirectory.DeniedUserLearnsNothingAboutAPrivateChannel"
        ":ChannelDirectory.DirectMessagesAreNeverListed",
    ),
    Mutation(
        "M4: the gate tightened to MANAGE_CHANNELS — denial tests alone would "
        "not notice an endpoint that answers nobody",
        VISIBILITY,
        [(FILTER_LINE,
          "if (!perms.can(user_id, row.room_id, permission::kManageChannels)) continue;")],
        CAPABILITY,
        "RoomVisibility.*",
    ),
    # ── M5: direct messages ──────────────────────────────────────────────
    Mutation(
        "M5: DMs enter the candidate set, where compute() clears their overrides "
        "and @everyone's VIEW_CHANNEL passes — every conversation on the server",
        STORE,
        [(" FROM rooms r WHERE r.is_direct = 0", " FROM rooms r WHERE 1 = 1")],
        "ChannelDirectory.DirectMessagesAreNeverListed",
        "ChannelDirectory.DeniedUserLearnsNothingAboutAPrivateChannel"
        ":ChannelDirectory.AnOrdinaryMemberSeesThePublicChannels",
    ),
    # ── M6: the parent id ────────────────────────────────────────────────
    Mutation(
        "M6: category_id echoed from state without checking it against the "
        "visible set, so a child names the private channel it is filed under",
        VISIBILITY,
        [("if (visible_categories.count(c.parent_id) == 0) continue;", "if (false) continue;")],
        "ChannelDirectory.CategoryIdNeverNamesARoomTheCallerCannotSee",
        "ChannelDirectory.ADeniedCategoryIsStillNamedAsAContainer",
    ),
    # ── M7: the field set ────────────────────────────────────────────────
    Mutation(
        "M7: a member count added to each entry — a population oracle on a "
        "channel the caller has not entered",
        HANDLER,
        [('        json j{{"room_id", e.room_id},',
          '        json j{{"member_count",\n'
          '                static_cast<int>(store_.get_room_members(e.room_id).size())},\n'
          '               {"room_id", e.room_id},')],
        "ChannelDirectory.AnEntryCarriesNoReconnaissanceFields"
        ":ChannelDirectory.DeniedUserLearnsNothingAboutAPrivateChannel",
        "ChannelDirectory.ChildrenFollowTheirCategoryInOrder",
    ),
    # ── M8: the ordering ─────────────────────────────────────────────────
    Mutation(
        "M8: the sort reversed — the list is still dense, so only a test that "
        "pins the actual order notices",
        VISIBILITY,
        [("return std::tie(a.sort_order, a.entry.room_id) < "
          "std::tie(b.sort_order, b.entry.room_id);",
          "return std::tie(a.sort_order, a.entry.room_id) > "
          "std::tie(b.sort_order, b.entry.room_id);")],
        "ChannelDirectory.ChildrenFollowTheirCategoryInOrder"
        ":ChannelDirectory.OrderingDoesNotDiscloseWhatWasFiltered",
        "ChannelDirectory.DeniedUserLearnsNothingAboutAPrivateChannel",
    ),
    # ── M9: the membership field ─────────────────────────────────────────
    Mutation(
        "M9: `joined` hard-coded true — a bot would never know it has to join",
        VISIBILITY,
        [("c.entry.joined = joined.count(row.room_id) > 0;", "c.entry.joined = true;")],
        "ChannelDirectory.ACallerThatIsAMemberOfNothingStillSeesTheChannels",
        "ChannelDirectory.DeniedUserLearnsNothingAboutAPrivateChannel",
    ),
]


def object_files(source: Path):
    """Every compiled object for `source`, across every CMake target."""
    stem = source.name + ".o"
    return [p for p in BUILD.rglob(stem) if "_deps" not in str(p)]


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
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. recover() first
    # repairs anything a SIGKILLed run left applied.
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
        for obj in object_files(m.path):
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
                    note = f"  [control still green]"
                else:
                    note = (f"  [control {m.must_pass} ALSO RED -- mutation is broader "
                            f"than the property; read it]")
                    problems.append(f"{m.name}: control {m.must_pass} also failed")
            caught += 1
            print(f"caught    {m.name}{note}")
        finally:
            # Reverts the bytes, deletes the objects and stamps the source
            # past them: a same-second restore can otherwise be judged up
            # to date by make, leaving a stale object in the binary.
            guard.restore(m.path)

    print("\nRestoring the tree and rebuilding clean...")
    guard.restore_all()
    ok, log = build()
    if not ok:
        print("ERROR: clean rebuild FAILED after restore!\n" + log[-2000:])
        return 2
    green, out = run_tests("ChannelDirectory.*:RoomVisibility.*:CategoryVisibility.*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
