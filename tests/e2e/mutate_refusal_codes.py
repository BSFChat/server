#!/usr/bin/env python3
"""Mutation harness for the invite refusal codes (`bsfchat.errcode`).

WHY THIS FILE EXISTS AT ALL. The usual "confirm it fails first" does not work
here: the tests cannot be compiled against a tree without the change, because
the constants they check do not exist there — there is no `refusal::` namespace
to fail against, only a build error. Same situation mutate_channel_directory.py
is in, and the same answer: establish the failing-first property by BREAKING the
thing on purpose, once per property, and requiring the tests to go red.

WHAT MAKES THESE CODES WORTH MUTATION-TESTING. A `bsfchat.errcode` value is a
WIRE CONTRACT with a program in another repository, compiled separately.
Nothing links the two sides, so a typo'd code is not an error anywhere — it is
a client branch that silently never fires while the prose fallback keeps the
dialog looking like it works. That is strictly worse than having no code. M6 is
the mutation that proves the pinning tests would catch it, and it is the whole
reason those tests are written as hand-typed literals rather than as
`refusal::kX == refusal::kX`, which passes against any typo at all.

The rest break one rule each:

  * M1 a refusal loses its code            — the client silently falls back
  * M2 two refusals share a code           — the substring collision, relocated
  * M3 the code says what the prose would not (existence, to a caller who
       failed the permission check) — the ORACLE, and the one that matters
  * M4 the three shapes of wrong id get three codes — the namespace walk the
       single wording refuses to hand out
  * M5 the code replaces the sentence      — nothing left for a person to read
  * M6 a code is misspelt in protocol      — see above
  * M7 `errcode` becomes the new code      — every existing M_FORBIDDEN
       consumer breaks on upgrade
  * M8 an absent reason serialised as ""   — an unclassified refusal stops
       being byte-identical to what it was

TWO REPOSITORIES. The protocol mutations (M6-M8) change protocol's header and
serialiser, which the server links. So both build trees are rebuilt and both
test binaries are run. The protocol checkout is taken from the SERVER BUILD'S
OWN CMake cache (FETCHCONTENT_SOURCE_DIR_BSFCHAT_PROTOCOL) when that is set, so
a worktree pair wired together by a -D flag is mutated as the pair it is
rather than through a sibling-directory guess that would find the shared
checkout several other sessions have open.

Run from anywhere:  python3 server/tests/e2e/mutate_refusal_codes.py
It restores both trees and rebuilds clean on the way out, including after a
crash in the middle of a case.
"""

import re
import subprocess
import sys
from pathlib import Path

from mutate_common import (MutationGuard, build_dir, cmake_build, protocol_root,
                           require_build, server_root)

SERVER = server_root()
BUILD = build_dir(SERVER, "build")


def protocol_checkout() -> Path:
    """The protocol sources this server build actually compiles against.

    Read out of the build tree rather than guessed at, because the guess is
    `<server>/../protocol` — which, from a worktree under wt/, is either
    nothing at all or, worse, somebody else's. A build configured with
    -DFETCHCONTENT_SOURCE_DIR_BSFCHAT_PROTOCOL points somewhere specific and
    that is the tree whose header ends up in the binary under test.
    """
    cache = BUILD / "CMakeCache.txt"
    if cache.is_file():
        m = re.search(r"^FETCHCONTENT_SOURCE_DIR_BSFCHAT_PROTOCOL:\w+=(.+)$",
                      cache.read_text(), re.M)
        if m and Path(m.group(1)).is_dir():
            return Path(m.group(1))
    return protocol_root()


PROTOCOL = protocol_checkout()
PROTO_BUILD = PROTOCOL / "build"

HANDLER = SERVER / "src/api/RoomHandler.cpp"
PROTO_H = PROTOCOL / "include/bsfchat/ErrorCodes.h"
PROTO_CPP = PROTOCOL / "src/ErrorCodes.cpp"

# The contract half: a named refusal carries a named code, and the sentence is
# still there beside it.
CONTRACT = ("InviteRefusalCodes.CallerIsNotInTheRoom"
            ":InviteRefusalCodes.TheRoomIsADirectMessage"
            ":InviteRefusalCodes.CallerLacksManageChannels"
            ":InviteRefusalCodes.TargetIsBannedFromThisRoom"
            ":InviteRefusalCodes.TargetIsBannedFromTheServer"
            ":InviteRefusalCodes.NoAccountHoldsTheId"
            ":InviteRefusalCodes.TargetIsADeactivatedBot")

# The disclosure half. PhantomMembership.* is named alongside the new tests on
# purpose: those predate this change and assert byte equality of the whole
# body, so they are the check that a NEW FIELD did not quietly step outside
# the guarantee they were written to hold.
DISCLOSURE = ("InviteRefusalCodes.AnUnprivilegedCallerStillLearnsNothingAboutExistence"
              ":InviteRefusalCodes.OneCodeForEveryShapeOfWrongId"
              ":PhantomMembership.AnUnprivilegedCallerLearnsNothingAboutWhetherAnAccountExists"
              ":PhantomMembership.TheRefusalDoesNotSayWhichKindOfWrongIdItWas")


class Mutation:
    """`edits` is a list of (old, new) pairs, each of which must match exactly once.

    `suite` says which binary carries the tests: "server", "protocol", or
    "both" when the same defect has to be visible from each side of the wire.
    """

    def __init__(self, name, path, edits, must_fail, must_pass="", suite="server"):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass
        self.suite = suite


BANNED_ROOM = ('MatrixError::forbidden("User is banned from this room",\n'
               '                                               refusal::kInviteTargetBannedRoom)')
BANNED_SERVER = ('MatrixError::forbidden("User is banned from this server",\n'
                 '                                               refusal::kInviteTargetBannedServer)')
NO_PERMISSION = ('MatrixError::forbidden("Insufficient permissions to invite",\n'
                 '                                               refusal::kInviteNoPermission)')
NO_ACCOUNT = ('MatrixError::forbidden(kNoSuchAccount,\n'
              '                                               refusal::kInviteNoSuchAccount)')

MUTATIONS = [
    # ── M1: a refusal loses its code ─────────────────────────────────────
    Mutation(
        "M1: the banned-here refusal is left unclassified — the client falls "
        "back to the prose and nothing anywhere says it happened",
        HANDLER,
        [(BANNED_ROOM, 'MatrixError::forbidden("User is banned from this room")')],
        "InviteRefusalCodes.TargetIsBannedFromThisRoom"
        ":InviteRefusalCodes.NoTwoRefusalsShareACode",
        DISCLOSURE,
    ),
    # ── M2: two refusals share a code ────────────────────────────────────
    Mutation(
        "M2: server-wide ban reuses the per-room ban's code — the substring "
        "collision this work removes, moved into a field",
        HANDLER,
        [(BANNED_SERVER,
          'MatrixError::forbidden("User is banned from this server",\n'
          '                                               refusal::kInviteTargetBannedRoom)')],
        "InviteRefusalCodes.TargetIsBannedFromTheServer"
        ":InviteRefusalCodes.NoTwoRefusalsShareACode",
        "InviteRefusalCodes.TargetIsBannedFromThisRoom",
    ),
    # ── M3: the oracle ───────────────────────────────────────────────────
    Mutation(
        "M3: the permission refusal classifies by whether the target EXISTS — "
        "same sentence, different code, so the field is a cheaper account "
        "oracle than the prose ever was",
        HANDLER,
        [(NO_PERMISSION,
          'MatrixError::forbidden("Insufficient permissions to invite",\n'
          '                                               store_.user_exists(target_user)\n'
          '                                                   ? refusal::kInviteNoPermission\n'
          '                                                   : refusal::kInviteNoSuchAccount)')],
        "InviteRefusalCodes.AnUnprivilegedCallerStillLearnsNothingAboutExistence"
        ":PhantomMembership.AnUnprivilegedCallerLearnsNothingAboutWhetherAnAccountExists",
        CONTRACT,
    ),
    # ── M4: the namespace walk ───────────────────────────────────────────
    Mutation(
        "M4: 'not an mxid at all' gets its own code — a tempting refinement, "
        "and a machine-readable version of the distinction the single wording "
        "deliberately refuses to draw",
        HANDLER,
        [(NO_ACCOUNT,
          'MatrixError::forbidden(kNoSuchAccount,\n'
          '                                               std::string_view(\n'
          '                                                   target_user.starts_with("@")\n'
          '                                                       ? "BSFCHAT.INVITE_NO_SUCH_ACCOUNT"\n'
          '                                                       : "BSFCHAT.INVITE_MALFORMED_ID"))')],
        "InviteRefusalCodes.OneCodeForEveryShapeOfWrongId"
        ":PhantomMembership.TheRefusalDoesNotSayWhichKindOfWrongIdItWas",
        "InviteRefusalCodes.NoAccountHoldsTheId"
        ":InviteRefusalCodes.AnUnprivilegedCallerStillLearnsNothingAboutExistence",
    ),
    # ── M5: the code replaces the sentence ───────────────────────────────
    Mutation(
        "M5: the sentence becomes the code — a person reading the dialog on a "
        "client that does not know this code is shown a machine identifier",
        HANDLER,
        [(BANNED_ROOM,
          'MatrixError::forbidden(std::string(refusal::kInviteTargetBannedRoom),\n'
          '                                               refusal::kInviteTargetBannedRoom)')],
        "InviteRefusalCodes.TargetIsBannedFromThisRoom",
        "InviteRefusalCodes.NoTwoRefusalsShareACode",
    ),
    # ── M6: the typo, which is the whole point ───────────────────────────
    Mutation(
        "M6: one code misspelt in protocol (BANNED_SEVER) — no build error on "
        "either side, just a client branch that silently never fires",
        PROTO_H,
        [('"BSFCHAT.INVITE_TARGET_BANNED_SERVER"', '"BSFCHAT.INVITE_TARGET_BANNED_SEVER"')],
        "RefusalReasons.EveryCodeIsSpeltExactlyThis"
        "|InviteRefusalCodes.TargetIsBannedFromTheServer",
        "RefusalReasons.NoTwoCodesCollide|InviteRefusalCodes.NoTwoRefusalsShareACode",
        suite="both",
    ),
    # ── M7: the compatibility break ──────────────────────────────────────
    Mutation(
        "M7: the new code REPLACES M_FORBIDDEN in `errcode` — the shipped "
        "client's generic 403 routing (ServerConnection.cpp) stops matching on "
        "the day the server upgrades",
        PROTO_CPP,
        [('nlohmann::json j = {{"errcode", errcode}, {"error", error}};',
          'nlohmann::json j = {{"errcode", reason.empty() ? errcode : reason},\n'
          '                        {"error", error}};')],
        "RefusalReasons.TheErrcodeStaysMForbidden|InviteRefusalCodes.CallerIsNotInTheRoom",
        # NOT ItSurvivesARoundTrip as the control: this mutation legitimately
        # breaks it too, because from_json reads `errcode` back out of the
        # field M7 has overwritten. That is the mutation being correct, not
        # broad — a round trip through a corrupted envelope is corrupted.
        "RefusalReasons.EveryCodeIsSpeltExactlyThis|InviteRefusalCodes.ASuccessCarriesNoCode",
        suite="both",
    ),
    # ── M8: the unclassified refusals stop being what they were ──────────
    Mutation(
        "M8: an absent reason is written out as \"\" — every one of the 106 "
        "refusals nobody classified quietly grows a field",
        PROTO_CPP,
        [('if (!reason.empty()) j[std::string(refusal::kField)] = reason;',
          'j[std::string(refusal::kField)] = reason;')],
        "RefusalReasons.ARefusalWithNoReasonIsTheExactBodyItAlwaysWas"
        "|InviteRefusalCodes.AnUnclassifiedRefusalIsTheExactBodyItAlwaysWas",
        "RefusalReasons.EveryCodeIsSpeltExactlyThis|InviteRefusalCodes.NoAccountHoldsTheId",
        suite="both",
    ),
]


def object_files(source: Path):
    """Every compiled object for `source`, across both build trees.

    _deps is NOT excluded here, unlike the other harnesses: protocol is built
    INSIDE the server's _deps tree, so excluding it would leave the mutated
    header's object in place and the server binary unchanged — a mutation that
    appears to survive when it was never actually applied.
    """
    stem = source.name + ".o"
    found = []
    for build in (BUILD, PROTO_BUILD):
        if build.is_dir():
            found += list(build.rglob(stem))
    # A header has no object of its own; everything that includes it has to go.
    if source.suffix in (".h", ".hpp"):
        for build in (BUILD, PROTO_BUILD):
            if build.is_dir():
                found += [p for p in build.rglob("*.o")
                          if "ErrorCodes" in p.name or "RoomHandler" in p.name
                          or "test_error_codes" in p.name
                          or "test_invite_refusal_codes" in p.name]
    return found


def build(m):
    """Rebuild whichever trees this mutation can have reached."""
    logs = []
    r = cmake_build(BUILD, target="server_tests")
    logs.append(r.stdout + r.stderr)
    if r.returncode != 0:
        return False, "\n".join(logs)
    if m.suite in ("protocol", "both"):
        if not (PROTO_BUILD / "CMakeCache.txt").is_file():
            return False, f"no configured protocol build tree at {PROTO_BUILD}"
        r = cmake_build(PROTO_BUILD, target="protocol_tests")
        logs.append(r.stdout + r.stderr)
        if r.returncode != 0:
            return False, "\n".join(logs)
    return True, "\n".join(logs)


def run_tests(m, gtest_filter):
    """Run `gtest_filter` on the binaries this mutation's suite names.

    A "both" filter is written `protocol-side|server-side`, because the two
    binaries do not share a filter vocabulary and a single string would
    silently select nothing on one of them — which reads as green.
    """
    if m.suite == "both":
        proto_filter, server_filter = gtest_filter.split("|", 1)
        targets = [(PROTO_BUILD / "tests/protocol_tests", proto_filter),
                   (BUILD / "tests/server_tests", server_filter)]
    elif m.suite == "protocol":
        targets = [(PROTO_BUILD / "tests/protocol_tests", gtest_filter)]
    else:
        targets = [(BUILD / "tests/server_tests", gtest_filter)]

    ok, out = True, []
    for binary, flt in targets:
        r = subprocess.run([str(binary), "--gtest_filter=" + flt, "--gtest_brief=1"],
                           capture_output=True, text=True)
        # A filter that matched nothing exits 0 and proves nothing, so it is a
        # failure of the harness rather than a pass of the test.
        if "0 tests from 0 test suites ran" in r.stdout:
            return False, f"{binary.name}: filter {flt!r} matched no tests"
        ok = ok and r.returncode == 0
        out.append(r.stdout + r.stderr)
    return ok, "\n".join(out)


def apply_edits(text, edits):
    for old, new in edits:
        count = text.count(old)
        if count != 1:
            return None, f"pattern matched {count} times, expected exactly 1: {old[:60]!r}"
        text = text.replace(old, new, 1)
    return text, None


def main():
    require_build(BUILD)
    print(f"server   {SERVER}\nprotocol {PROTOCOL}\n")
    guard = MutationGuard(SERVER, builds=[BUILD, PROTO_BUILD])
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
        for obj in object_files(m.path):
            obj.unlink(missing_ok=True)
        try:
            ok, log = build(m)
            if not ok:
                problems.append(f"{m.name}: BUILD FAILED (the mutation does not compile)")
                print(f"ERROR     {m.name}\n          build failed:\n{log[-1200:]}")
                continue
            still_green, why = run_tests(m, m.must_fail)
            if still_green:
                problems.append(f"{m.name}: tests still pass -> PROPERTY NOT COVERED")
                print(f"SURVIVED  {m.name}\n          {m.must_fail} still green")
                continue
            note = ""
            if m.must_pass:
                control_ok, _ = run_tests(m, m.must_pass)
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
            for obj in object_files(m.path):
                obj.unlink(missing_ok=True)

    print("\nRestoring both trees and rebuilding clean...")
    guard.restore_all()
    ok, log = build(MUTATIONS[-1])   # rebuilds server AND protocol
    if not ok:
        print("ERROR: clean rebuild FAILED after restore!\n" + log[-2000:])
        return 2
    green, out = run_tests(MUTATIONS[-1], "RefusalReasons.*|InviteRefusalCodes.*:PhantomMembership.*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
