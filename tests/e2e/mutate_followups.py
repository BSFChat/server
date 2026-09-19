#!/usr/bin/env python3
"""Mutation harness for the three follow-ups: the server ban-list endpoint (F1),
the mention-on-edit comment (F2, behaviour untouched) and the empty-upload
errcode (F3).

Same discipline as mutate_audit_filters.py and mutate_media_head.py: object files
are deleted before each rebuild (make misses same-second timestamps), a mutation
that does not compile is an ERROR rather than a catch, and each case names a
control that must stay green so a mutation broader than the property is visible
instead of being counted as a pass.

F2 is deliberately absent: it was a comment-only change with no behavioural
delta, so there is no property to break. The load-bearing behaviour it describes
(never recording mentions for a replace) is already pinned by the mention tests,
and the last mutation below re-confirms that rather than pretending the comment
itself is testable.
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

STORE = SERVER / "src/store/SqliteStore.cpp"
ROOMS = SERVER / "src/api/RoomHandler.cpp"
MEDIA = SERVER / "src/api/MediaHandler.cpp"
EVENTS = SERVER / "src/api/EventHandler.cpp"


class Mutation:
    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    # ── F1: the gate ─────────────────────────────────────────────────────
    Mutation(
        "F1: the ban list is scoped to a room instead of the server (the escalation)",
        ROOMS,
        [("if (!perms.can(*user_id, kServerScope, permission::kBanMembers)) {\n"
          "        return refuse(403, MatrixError::forbidden(\n"
          '            "Insufficient permissions to read the server ban list"));',
          'if (!perms.can(*user_id, req.get_param_value("room_id"), permission::kBanMembers)) {\n'
          "        return refuse(403, MatrixError::forbidden(\n"
          '            "Insufficient permissions to read the server ban list"));')],
        "ServerBanList.PerChannelOverrideDoesNotGrantAccess",
        "ServerBanList.PlainMemberIsRefusedForTheRightReason",
    ),
    Mutation(
        "F1: the permission check is dropped entirely",
        ROOMS,
        [("if (!perms.can(*user_id, kServerScope, permission::kBanMembers)) {",
          "if (false) {")],
        "ServerBanList.PlainMemberIsRefusedForTheRightReason"
        ":ServerBanList.BanMembersCanReadAndKickOnlyModeratorCannot"
        ":ServerBanList.PerChannelOverrideDoesNotGrantAccess",
        "ServerBanList.RequiresAuthentication",
    ),
    Mutation(
        "F1: gated on KICK_MEMBERS, so a kick-only moderator sees the ban list",
        ROOMS,
        [("if (!perms.can(*user_id, kServerScope, permission::kBanMembers)) {",
          "if (!perms.can(*user_id, kServerScope, permission::kKickMembers)) {")],
        "ServerBanList.BanMembersCanReadAndKickOnlyModeratorCannot",
        "ServerBanList.PlainMemberIsRefusedForTheRightReason",
    ),
    # ── F1: pagination ───────────────────────────────────────────────────
    Mutation(
        "F1: the keyset cursor becomes inclusive, so pages overlap",
        STORE,
        [('if (after) sql += "WHERE user_id > ? ";', 'if (after) sql += "WHERE user_id >= ? ";')],
        "ServerBanList.PaginatesOverTheWholeListWithoutRepeatingOrSkipping"
        ":ServerBanList.ACursorSurvivesBansPlacedAndLiftedMidWalk",
    ),
    Mutation(
        "F1: ordered by created_at, the column that moves under a re-ban",
        STORE,
        [('sql += "ORDER BY user_id ASC LIMIT ?";', 'sql += "ORDER BY created_at ASC LIMIT ?";')],
        "ServerBanList.PaginatesOverTheWholeListWithoutRepeatingOrSkipping",
    ),
    Mutation(
        "F1: the over-fetched row is returned, so next_from is never set",
        STORE,
        [("    if (page.bans.size() > static_cast<size_t>(limit)) {\n"
          "        page.bans.pop_back();",
          "    if (false) {\n        page.bans.pop_back();")],
        "ServerBanList.PaginatesOverTheWholeListWithoutRepeatingOrSkipping"
        ":ServerBanList.ClampsAnOversizedLimit",
    ),
    # ── F1: the response body ────────────────────────────────────────────
    Mutation(
        "F1: display_name is dropped, so a bans tab shows a bare MXID",
        ROOMS,
        [("if (auto name = effective_display_name(store_, ban.user_id)) {\n"
          '            entry["display_name"] = *name;\n        }',
          "if (false) { }")],
        "ServerBanList.SurfacesABanNoMembershipRowCouldReveal",
        "ServerBanList.OmitsFieldsTheDatabaseHasNoValueFor",
    ),
    Mutation(
        "F1: empty actor/reason are emitted as \"\" instead of omitted",
        ROOMS,
        [('if (!ban.actor.empty()) entry["actor"] = ban.actor;\n'
          '        if (!ban.reason.empty()) entry["reason"] = ban.reason;',
          'entry["actor"] = ban.actor;\n        entry["reason"] = ban.reason;')],
        "ServerBanList.OmitsFieldsTheDatabaseHasNoValueFor",
        "ServerBanList.SurfacesABanNoMembershipRowCouldReveal",
    ),
    Mutation(
        "F1: an empty cursor is silently ignored instead of refused",
        ROOMS,
        [('if (value.empty()) {\n            return refuse(400, MatrixError::invalid_param("after must not be empty"));\n        }',
          "if (value.empty()) { }")],
        "ServerBanList.RejectsAMalformedLimitOrAnEmptyCursor",
    ),
    # ── F3: the errcode ──────────────────────────────────────────────────
    Mutation(
        "F3: the empty-upload errcode reverts to M_NOT_JSON",
        MEDIA,
        [('MatrixError::invalid_param("No file data provided").to_json().dump(),',
          'std::string(R"({"errcode":"M_NOT_JSON","error":"No file data provided"})"),')],
        "MediaHeadTest.AnEmptyUploadIsRefusedAsAnInvalidParameterNotAsBadJson",
    ),
    # ── F2: the behaviour the comment describes, re-confirmed ────────────
    Mutation(
        "F2 (behaviour, not the comment): mentions ARE recorded for an edit",
        EVENTS,
        [("if (!edit_target && !mentions.empty()) {", "if (!mentions.empty()) {")],
        "*Mention*",
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
    for m in MUTATIONS:
        original = guard.protect(m.path).decode()
        text = original
        bad = None
        for old, new in m.edits:
            if text.count(old) != 1:
                bad = f"pattern matched {text.count(old)} times: {old[:70]!r}"
                break
            text = text.replace(old, new, 1)
        if bad:
            problems.append(f"{m.name}: {bad}")
            print(f"ERROR     {m.name}\n          {bad}")
            continue

        m.path.write_text(text)
        for obj in object_files(m.path):
            obj.unlink()
        try:
            ok, log = build()
            if not ok:
                problems.append(f"{m.name}: BUILD FAILED")
                print(f"ERROR     {m.name}\n          build failed:\n{log[-1200:]}")
                continue
            green, _ = run_tests(m.must_fail)
            if green:
                problems.append(f"{m.name}: {m.must_fail} still passes -> NOT COVERED")
                print(f"SURVIVED  {m.name}\n          {m.must_fail} still green")
                continue
            note = ""
            if m.must_pass:
                ctl, _ = run_tests(m.must_pass)
                if ctl:
                    note = f"  [control {m.must_pass} still green]"
                else:
                    note = (f"  [control {m.must_pass} ALSO RED -- broader than the "
                            f"property; read it]")
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
