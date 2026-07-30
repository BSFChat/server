#!/usr/bin/env python3
"""Mutation harness for the audit-log filters (P1) and insert_event atomicity (P2).

A passing test suite proves nothing on its own: it may be passing because the
property holds, or because nothing is actually checking it. Each mutation below
breaks exactly one property and asserts that the named tests FAIL. A mutation that
leaves the suite green is a test that was not testing anything.

Three traps this harness exists to avoid, all hit for real during this work:
  * `make` misses same-second timestamps and silently relinks stale objects, so
    every mutation deletes the object files for the file it patched, in EVERY
    target, before rebuilding.
  * A test can "fail" for the wrong reason. Each case may name a control filter
    (`must_pass`) that should stay green; when the control also goes red the
    mutation was broader than the property and the result is reported as such
    rather than quietly counted as a catch.
  * A mutation that does not compile is an ERROR, not a detected mutation.

Run from anywhere:  python3 server/tests/e2e/mutate_audit_filters.py
It restores the tree and rebuilds clean on the way out, including after a crash
in the middle of a case.
"""

import subprocess
import sys
from pathlib import Path

SERVER = Path("/Users/josh/dev/gamechat/server")
BUILD = SERVER / "build-fix"

STORE = SERVER / "src/store/SqliteStore.cpp"
MIGRATIONS = SERVER / "src/store/Migrations.cpp"
HANDLER = SERVER / "src/api/AuditHandler.cpp"


class Mutation:
    """`edits` is a list of (old, new) pairs, each of which must match exactly once.

    Several pairs are sometimes needed to express a mutation FAITHFULLY. Reverting
    P2's fix, for example, means removing the BEGIN, the COMMIT and the ROLLBACK
    together: removing only the BEGIN leaves a COMMIT with no open transaction,
    which breaks every single insert rather than reinstating the specific defect,
    and a suite that goes uniformly red proves nothing about the property.
    """

    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    # ── P2: insert_event / search-index atomicity ────────────────────────
    Mutation(
        "P2-a: the transaction removed entirely (the code exactly as it was before the fix)",
        STORE,
        [
            # Anchored on the following line: delete_room opens its transaction
            # with the identical two lines, and patching that one instead would
            # be measuring a completely different property.
            ('    exec("BEGIN IMMEDIATE");\n    try {\n        // Monotonic',
             "    try {\n        // Monotonic"),
            ('        exec("COMMIT");\n        return stream_pos;',
             "        return stream_pos;"),
            ('        try {\n            exec("ROLLBACK");\n        } catch (...) {\n        }\n'
             '        throw;',
             "        throw;"),
        ],
        "SearchIndexAtomicity.*",
        "Search.*",
    ),
    Mutation(
        "P2-b: commit instead of rolling back on failure",
        STORE,
        [('        try {\n            exec("ROLLBACK");\n        } catch (...) {\n        }\n'
          '        throw;',
          '        try {\n            exec("COMMIT");\n        } catch (...) {\n        }\n'
          '        throw;')],
        "SearchIndexAtomicity.*",
        "Search.*",
    ),
    # ── P1: the indexes ──────────────────────────────────────────────────
    Mutation(
        "P1-a: partial-index guard dropped from the query builder",
        STORE,
        [('if (partial_index) clause += " AND " + std::string(column) + " <> \'\'";',
          'if (partial_index) clause += "";')],
        "AuditFilterPlan.*",
        "AuditFilter.ByActorReturnsOnlyThatActorsRecords",
    ),
    Mutation(
        "P1-b: target_user index made non-partial (the query guard then excludes it)",
        MIGRATIONS,
        [('exec(db, "CREATE INDEX IF NOT EXISTS idx_audit_log_target_user "\n'
          '             "ON audit_log(target_user) WHERE target_user <> \'\'");',
          'exec(db, "CREATE INDEX IF NOT EXISTS idx_audit_log_target_user "\n'
          '             "ON audit_log(target_user)");')],
        "AuditFilterPlan.*:AuditFilterMigration.PreExisting*",
        "AuditFilter.*",
    ),
    Mutation(
        "P1-c: the actor index is never created",
        MIGRATIONS,
        [('exec(db, "CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor)");',
          "(void)0;")],
        "AuditFilterPlan.*:AuditFilterMigration.PreExisting*",
        "AuditFilter.*",
    ),
    # ── P1: filter semantics ─────────────────────────────────────────────
    Mutation(
        "P1-d: the actor filter is silently ignored (the whole log comes back)",
        STORE,
        [('    add(filter.actor, "actor", false);',
          '    if (false) add(filter.actor, "actor", false);')],
        "AuditFilter.ByActorReturnsOnlyThatActorsRecords"
        ":AuditFilter.FiltersAreAndedNotOred"
        ":AuditFilter.AFilterThatMatchesNothingReturnsNothing"
        ":AuditEndpoint.FilterParametersReachTheQuery",
    ),
    Mutation(
        "P1-e: filters ORed instead of ANDed",
        STORE,
        [('out.sql += (i == 0 ? " " : " AND ") + clauses[i];',
          'out.sql += (i == 0 ? " " : " OR ") + clauses[i];')],
        "AuditFilter.FiltersAreAndedNotOred:AuditEndpoint.FilterParametersReachTheQuery",
    ),
    Mutation(
        "P1-f: `total` becomes the filtered count, hiding how big the log really is",
        STORE,
        [('    auto count = prepare(db_, "SELECT COUNT(*) FROM audit_log");',
          "    auto count = prepare(db_, audit_match_count_query(filter).sql);")],
        "AuditFilter.ByActorReturnsOnlyThatActorsRecords"
        ":AuditFilter.AFilterThatMatchesNothingReturnsNothing",
    ),
    # ── P1: pagination ───────────────────────────────────────────────────
    Mutation(
        "P1-g: the cursor becomes inclusive, so a page repeats its predecessor's last row",
        STORE,
        [('if (with_cursor) conditions += (conditions.empty() ? " " : " AND ") + '
          'std::string("id < ?");',
          'if (with_cursor) conditions += (conditions.empty() ? " " : " AND ") + '
          'std::string("id < ? + 1");')],
        "AuditFilterPagination.*:AuditEndpoint.FilteredPaginationWalksTheWholeMatchingSet"
        ":AuditPagination.*",
    ),
    # ── P1: the endpoint ─────────────────────────────────────────────────
    Mutation(
        "P1-h: an empty filter value is silently ignored instead of refused",
        HANDLER,
        [("        if (value.empty()) {\n"
          "            return send_error(res, 400, MatrixError::invalid_param(\n"
          '                std::string(p.name) + " must not be empty"));\n'
          "        }",
          "        if (value.empty()) continue;")],
        "AuditEndpoint.RejectsAnEmptyFilterValueRatherThanIgnoringIt",
        "AuditEndpoint.RejectsAMalformedCursor",
    ),
    Mutation(
        "P1-i: the permission gate is scoped to the filtered channel (the escalation shape)",
        HANDLER,
        [('if (!perms.can(*user_id, "", permission::kManageServer)) {',
          'if (!perms.can(*user_id, req.get_param_value("target_room"), '
          "permission::kManageServer)) {")],
        "AuditEndpoint.PerChannelOverrideDoesNotGrantFilteredAccessEither",
        "AuditEndpoint.PerChannelOverrideDoesNotGrantAccess",
    ),
]


def object_files(source: Path):
    """Every compiled object for `source`, across every CMake target."""
    stem = source.name + ".o"
    return [p for p in BUILD.rglob(stem) if "_deps" not in str(p)]


def build():
    r = subprocess.run(["cmake", "--build", ".", "-j8"], cwd=BUILD,
                       capture_output=True, text=True)
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
    problems = []
    caught = 0

    for m in MUTATIONS:
        original = m.path.read_text()
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
                    note = f"  [control {m.must_pass} still green]"
                else:
                    note = (f"  [control {m.must_pass} ALSO RED -- mutation is broader "
                            f"than the property; read it]")
                    problems.append(f"{m.name}: control {m.must_pass} also failed")
            caught += 1
            print(f"caught    {m.name}{note}")
        finally:
            m.path.write_text(original)
            for obj in object_files(m.path):
                obj.unlink()

    print("\nRestoring the tree and rebuilding clean...")
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
