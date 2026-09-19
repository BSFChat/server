#!/usr/bin/env python3
"""Mutation check for the newly added HEAD coverage on the media download endpoint.

HEAD was previously untested: no HEAD route is registered anywhere (only
svr_.Get), so HEAD working at all rests on httplib dispatching it to the Get
handler table. The new MediaHeadTest asserts it is routed, that it reports the
right metadata, that it reads NOTHING from storage, and that it is refused and
capped exactly like GET.

These mutations exist to show those assertions can actually fail. Same discipline
as mutate_audit_filters.py: object files are deleted before each rebuild (make
misses same-second timestamps), a non-compiling mutation is an ERROR rather than
a catch, and each case names a control that should stay green.
"""

import subprocess
import sys
from pathlib import Path

from mutate_common import MutationGuard, build_dir, cmake_build, require_build, server_root

# Resolved from this script's own location (<repo>/tests/e2e/), so a run from a
# worktree mutates THAT worktree and not whichever checkout was hard-coded here.
# Override with BSFCHAT_SERVER=... / --srv=... See mutate_common.
SERVER = server_root()
BUILD = build_dir(SERVER, "build-fix")
HANDLER = SERVER / "src/api/MediaHandler.cpp"

MUTATIONS = [
    (
        "the whole-object read is reinstated (the defect the tripwire watches for)",
        [("    auto info = storage_->stat(media_id);\n    if (!info) {",
          "    auto whole = storage_->download(media_id);\n"
          "    auto info = storage_->stat(media_id);\n    if (!info) {")],
        "MediaHeadTest.HeadDoesNotReadTheObject",
        "MediaHttpTest.NoRangeServesWholeObjectWithAcceptRanges",
    ),
    (
        # NOTE: this mutation is caught by the GET test, NOT by the HEAD test.
        # httplib sets `Accept-Ranges: bytes` itself on a HEAD response when the
        # handler did not (httplib.h: `if (req.method == "HEAD" &&
        # !res.has_header("Accept-Ranges"))`), so a HEAD assertion cannot tell
        # our header from httplib's. The HEAD test still asserts it, because it
        # is the client-visible contract — but the line in MediaHandler.cpp is
        # pinned by the GET path, which httplib does not backstop.
        "Accept-Ranges is no longer advertised by the handler",
        [('res.set_header("Accept-Ranges", "bytes");', "(void)0;")],
        "MediaHttpTest.NoRangeServesWholeObjectWithAcceptRanges",
        "MediaHeadTest.HeadIsRoutedToTheGetHandlerAndReturnsTheMetadata",
    ),
    (
        "the multi-range cap is raised past what the request asks for",
        [("constexpr size_t kMaxRangeCount = 4;", "constexpr size_t kMaxRangeCount = 1024;")],
        "MediaHeadTest.HeadIsRefusedAndCappedExactlyLikeGet",
        "",
    ),
]


def object_files(source: Path):
    stem = source.name + ".o"
    return [p for p in BUILD.rglob(stem) if "_deps" not in str(p)]


def build():
    r = cmake_build(BUILD)
    return r.returncode == 0, r.stdout + r.stderr


def run_tests(f):
    r = subprocess.run([str(BUILD / "tests/server_tests"), "--gtest_filter=" + f,
                        "--gtest_brief=1"], capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


def main():
    # Snapshots every file before it is mutated and reverts on the way out
    # however this process ends — normally, on an exception, on Ctrl-C or a
    # kill. recover() first repairs anything a SIGKILLed run left applied.
    require_build(BUILD)
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. recover() first
    # repairs anything a SIGKILLed run left applied.
    guard = MutationGuard(SERVER, builds=[BUILD])
    guard.recover()
    problems = []
    caught = 0
    for name, edits, must_fail, must_pass in MUTATIONS:
        original = guard.protect(HANDLER).decode()
        text = original
        bad = None
        for old, new in edits:
            if text.count(old) != 1:
                bad = f"pattern matched {text.count(old)} times: {old[:60]!r}"
                break
            text = text.replace(old, new, 1)
        if bad:
            problems.append(f"{name}: {bad}")
            print(f"ERROR     {name}\n          {bad}")
            continue

        HANDLER.write_text(text)
        for obj in object_files(HANDLER):
            obj.unlink()
        try:
            ok, log = build()
            if not ok:
                problems.append(f"{name}: BUILD FAILED")
                print(f"ERROR     {name}\n          build failed:\n{log[-1200:]}")
                continue
            green, _ = run_tests(must_fail)
            if green:
                problems.append(f"{name}: {must_fail} still passes -> NOT COVERED")
                print(f"SURVIVED  {name}")
                continue
            note = ""
            if must_pass:
                ctl, _ = run_tests(must_pass)
                note = f"  [control {must_pass} {'still green' if ctl else 'ALSO RED'}]"
                if not ctl:
                    problems.append(f"{name}: control also failed")
            caught += 1
            print(f"caught    {name}{note}")
        finally:
            # Reverts the bytes, deletes the objects and stamps the source
            # past them: a same-second restore can otherwise be judged up
            # to date by make, leaving a stale object in the binary.
            guard.restore(HANDLER)

    print("\nRestoring and rebuilding clean...")
    guard.restore_all()
    ok, log = build()
    if not ok:
        print("ERROR: clean rebuild failed!\n" + log[-2000:])
        return 2
    green, out = run_tests("*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2
    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
