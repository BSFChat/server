#!/usr/bin/env python3
"""Mutation-test the containment rule: F1, F2 and F6 of the September 2026
permissions audit.

The rule is one sentence — "nobody may confer access they do not hold, and
nobody may strip access from a principal that holds more than they do" — stated
once in auth/Permissions.h and enforced in three places. That shape is exactly
what a mutation run is for: a rule with three enforcement points and one
statement can lose an enforcement point without any test noticing, which is how
this defect reached its third instance in the first place.

Every mutation below puts one piece of the OLD, broken behaviour back, one at a
time, and names the test that must notice. Two of them do the opposite and make
the rule STRICTER than it should be, because a containment rule that refuses
ordinary administration is not a safe one, it is one somebody will shortly
loosen in the wrong place — and the tests that pin legitimate administration
have to be shown to bite as well.

Run from this worktree, against this worktree:

    nice -n 19 python3 tests/e2e/mutate_containment.py
"""
import subprocess
import sys

from mutate_common import MutationGuard, build_dir, cmake_build, require_build, server_root

# The checkout this harness mutates is the one it LIVES in, never a hard-coded
# path: several worktrees of this repo are open at once. See mutate_common.
SRV = server_root()
BUILD = build_dir(SRV, "build")
TESTBIN = BUILD / "tests" / "server_tests"

# (label, file, old, new, gtest_filter, timeout_s)
MUTATIONS = [
 # ── F1: scope ───────────────────────────────────────────────────────────────
 #
 # The one-line form of the finding: the server's identity evaluated in the
 # room the write happened to land in. Note the mutation is now a single word
 # in a table rather than a missing entry in a list of exceptions, which is the
 # structural half of the fix.
 ("F1: bsfchat.server.info back to room scope",
  "src/api/RoomHandler.cpp",
  "        if (type == event_type::kServerInfo) {\n"
  "            return {true, permission::kManageServer, Scope::kServer, Home::kRoomState};",
  "        if (type == event_type::kServerInfo) {\n"
  "            return {true, permission::kManageServer, Scope::kRoom, Home::kRoomState};",
  "PermissionContainment.F1_*:PermissionContainment.F2b_*:"
  "PermissionContainment.AChannelDenyCannotBlockAServerWideRename", 300),

 # The scope column read backwards. If nothing fails here the table is
 # decorative and the next type added to it will be gated wherever the default
 # happens to point.
 ("F1: the scope column is ignored entirely",
  "src/api/RoomHandler.cpp",
  "    const std::string perm_scope = gate.scope == Scope::kServer ? kServerScope : room_id;",
  "    const std::string perm_scope = room_id;",
  "PermissionContainment.F1_*:ServerScopedSettings.*:RoomTypeScope.*", 300),

 # ── F2: containment ─────────────────────────────────────────────────────────
 ("F2: containment removed (MANAGE_ROLES is the whole gate again)",
  "src/auth/Permissions.cpp",
  "    if (const permission::Flags beyond = changed & ~held; beyond != 0) {",
  "    if (const permission::Flags beyond = 0; beyond != 0) {",
  "PermissionContainment.F2a_*:PermissionContainment.F2b_*:"
  "PermissionContainment.RemovingADenyIsAGrantAndIsContainedToo", 300),

 # The audit's own sketch of the rule — "the bits the write ADDS, allow &
 # ~previous.allow, and symmetrically for deny". It is right about two of the
 # four edits and misses the two that are spelled as removals, of which
 # dropping a DENY is a grant.
 ("F2: containment scoped to added bits only (misses un-denying)",
  "src/auth/Permissions.cpp",
  "    const permission::Flags changed =\n"
  "        (proposed.allow ^ before.allow) | (proposed.deny ^ before.deny);",
  "    const permission::Flags changed =\n"
  "        (proposed.allow & ~before.allow) | (proposed.deny & ~before.deny);",
  "PermissionContainment.RemovingADenyIsAGrantAndIsContainedToo", 300),

 # Containment measured at SERVER scope instead of in the channel. Stricter,
 # not looser — and it breaks the case the route exists for, where the actor's
 # authority over a channel is itself an override.
 ("F2: containment measured at server scope, not in the channel",
  "src/auth/Permissions.cpp",
  "    const permission::Flags held = compute(actor_id, room_id);",
  "    const permission::Flags held = compute(actor_id, std::string());",
  "PermissionContainment.AChannelManagerMayShareWhatTheChannelGaveThem", 300),

 # ── F2: rank ────────────────────────────────────────────────────────────────
 ("F2: no rank check on a user: override",
  "src/auth/Permissions.cpp",
  "        if (!outranks(actor_id, target)) {",
  "        if (false) {",
  "PermissionContainment.F2c_*:PermissionContainment.WithdrawingAnAllowFromASeniorIsRefused",
  300),

 ("F2: no rank check on a role: override",
  "src/auth/Permissions.cpp",
  "    if (role_pos >= highest_role_position(actor_id)) {",
  "    if (false) {",
  "PermissionContainment.NoTakeAwayAgainstARoleRankedAboveYou", 300),

 # The other direction: rank applied to GRANTS as well as take-aways. A
 # channel's own manager could then not let their own administrators in, which
 # is ordinary administration and has to keep working.
 ("F2: rank applied to grants as well as take-aways",
  "src/auth/Permissions.cpp",
  "    if (taken == 0) return {};",
  "    if (false) return {};",
  "PermissionContainment.ABuilderCanStillGrantAccessIncludingToASenior", 300),

 # @everyone treated as a principal with rank. Refusing this refuses "@everyone
 # DENY VIEW_CHANNEL", which is how a private channel is made on this server.
 ("F2: @everyone loses its rank exemption",
  "src/auth/Permissions.cpp",
  "    if (role_id == permission::role_id::kEveryone) return {};",
  "    if (false) return {};",
  "PermissionContainment.AChannelManagerAtPositionZeroMayStillDenyEveryone", 300),

 ("F2: ADMINISTRATOR may be granted by an override again",
  "src/auth/Permissions.cpp",
  "    if (permission::has(proposed.allow, permission::kAdministrator) &&\n"
  "        !permission::has(before.allow, permission::kAdministrator)) {",
  "    if (false) {",
  "PermissionContainment.AnOverrideMayNotGrantAdministratorEvenFromAnAdmin", 300),

 ("F2: an override may name anything again",
  "src/auth/Permissions.cpp",
  '    if (state_key.rfind("user:", 0) != 0 && state_key.rfind("role:", 0) != 0) {',
  "    if (false) {",
  "PermissionContainment.AnOverrideMustNameAUserOrARole", 300),

 # The engine is the authority; the handler is a caller. Deleting the call is
 # the mutation that matters most, because it is the one a refactor performs by
 # accident.
 ("F2: the handler stops consulting the engine",
  "src/api/RoomHandler.cpp",
  "        if (!verdict.allowed) {\n"
  "            get_logger()->warn(\"Refused channel override by {} on {} ({}): {}\", *user_id,",
  "        if (false) {\n"
  "            get_logger()->warn(\"Refused channel override by {} on {} ({}): {}\", *user_id,",
  "PermissionContainment.F2a_*:PermissionContainment.F2c_*", 300),

 # ...and the redundant gate inside the engine, which exists so that a SECOND
 # caller cannot skip the first half. Deliberately redundant today, so it is
 # pinned by a test that calls the engine directly rather than by the route.
 ("F2: the engine trusts its caller to have checked MANAGE_ROLES",
  "src/auth/Permissions.cpp",
  "    if (!can(actor_id, room_id, permission::kManageRoles)) {",
  "    if (false) {",
  "PermissionContainment.TheEngineIsTheAuthorityAndRechecksManageRoles", 300),

 # ── F6: rank learns to see channels ─────────────────────────────────────────
 ("F6: rank measures role position only, as before",
  "src/auth/Permissions.cpp",
  "    return channel_access_excess(target_id, actor_id) == 0;",
  "    return true;",
  "PermissionContainment.F6_*", 300),

 # The subtraction that keeps the channel half from swallowing the role half.
 # Without it a moderator cannot moderate anybody holding a flag they lack,
 # anywhere on a server that has a single private channel.
 ("F6: the server-scope role gap is no longer subtracted",
  "src/auth/Permissions.cpp",
  "        excess |= (compute(subject_id, room_id) & ~compute(actor_id, room_id)) & ~role_gap;",
  "        excess |= (compute(subject_id, room_id) & ~compute(actor_id, room_id));",
  "PermissionContainment.RankStillGovernsTheRoleHalf", 300),

 # The room list the sweep walks. An empty list is a silent no-op that makes
 # every F6 assertion pass for the wrong reason.
 ("F6: the sweep looks at no rooms",
  "src/store/SqliteStore.cpp",
  '        "SELECT DISTINCT room_id FROM events WHERE event_type = ? AND state_key IS NOT NULL");',
  '        "SELECT DISTINCT room_id FROM events WHERE event_type = ? AND state_key IS NULL");',
  "PermissionContainment.F6_*", 300),

 # NO MUTATION FOR THE ADMINISTRATOR EARLY RETURN in channel_access_excess, and
 # that absence is deliberate rather than an oversight. compute() already
 # returns kAllFlags for an administrator and for @server in every room, so the
 # sweep reaches zero for them with or without the early return: it is a cost
 # short-circuit and there is no observable behaviour to break. A mutation
 # there would SURVIVE for the correct reason, which would report a coverage
 # gap that does not exist and train the next reader to ignore survivors. The
 # exemption ITSELF is pinned instead, by behaviour, in
 # PermissionContainment.AnAdministratorIsBoundByNeitherHalfOfTheRule and by
 # the administrator control in F6_TokenRotationIsRefusedForAChannelScopedBot.
]


def run(cmd, timeout=None):
    return subprocess.run(cmd, shell=True, cwd=SRV, capture_output=True,
                          text=True, timeout=timeout)


def main():
    results = []
    require_build(BUILD)
    # The guard snapshots each file before it is touched and reverts however
    # this process ends — normally, on an exception, on Ctrl-C or a kill — and
    # journals to disk so even a SIGKILL is repaired by the next run rather
    # than by somebody eventually noticing a mutant in `git diff`.
    with MutationGuard(SRV, builds=[BUILD]) as guard:
        backups = {f: guard.protect(SRV / f).decode() for f in {m[1] for m in MUTATIONS}}

        for label, relpath, old, new, filt, tmo in MUTATIONS:
            path = SRV / relpath
            src = backups[relpath]
            if old not in src:
                # A SKIP is a FAILURE of this harness, not a pass: it means the
                # anchor drifted and the guard it names was never mutated.
                results.append((label, "SKIP", "mutation anchor not found — RE-ANCHOR ME"))
                continue
            assert src.count(old) == 1, f"{label}: anchor not unique ({src.count(old)})"
            path.write_text(src.replace(old, new, 1))

            try:
                build = cmake_build(BUILD, target="server_tests", cwd=SRV, timeout=1800)
                if build.returncode != 0:
                    results.append((label, "BUILD-FAIL",
                                    "mutation did not compile (still counts as detected)"))
                    continue
                try:
                    t = run(f"'{TESTBIN}' --gtest_filter='{filt}'", timeout=tmo)
                    if t.returncode != 0:
                        names = [l.strip() for l in t.stdout.splitlines()
                                 if l.strip().startswith("[  FAILED  ]")]
                        results.append((label, "DETECTED", "; ".join(names[:3]) or "test failed"))
                    else:
                        results.append((label, "*** SURVIVED ***", "tests still passed!"))
                except subprocess.TimeoutExpired:
                    results.append((label, "DETECTED",
                                    f"test hung (>{tmo}s) — blocked, which is the failure"))
            finally:
                # Purges the objects and stamps the source past them: a restore
                # that only rewrites the bytes can be skipped by make, leaving
                # the mutant's behaviour in a binary built from a clean tree.
                guard.restore(path)

        guard.restore_all()
        cmake_build(BUILD, target="server_tests", cwd=SRV, timeout=1800)

    print("\n" + "=" * 100)
    print("MUTATION TEST RESULTS — containment rule (F1/F2/F6)")
    print("=" * 100)
    bad = 0
    for label, status, detail in results:
        print(f"{status:>18}  {label}")
        if detail:
            print(f"{'':>18}  -> {detail}")
        if "SURVIVED" in status or status == "SKIP":
            bad += 1
    print("=" * 100)
    print(f"{len(results) - bad}/{len(results)} mutations detected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
