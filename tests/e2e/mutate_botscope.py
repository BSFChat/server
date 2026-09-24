#!/usr/bin/env python3
"""Mutation-test bot scoping: break each guard, confirm a test fails, revert.

The feature is small and almost entirely made of REMOVALS — a grant that is no
longer handed out, a sweep that no longer runs, a path a bot may no longer
take. A test suite for a removal is easy to write and easy to get wrong,
because "the bot has no permissions" passes just as well when the permission
system is broken for everybody. So every mutation below puts the OLD behaviour
back, one guard at a time, and the test that must notice is named beside it.
"""
import subprocess, sys

from mutate_common import MutationGuard, build_dir, cmake_build, require_build, server_root

# The checkout this harness mutates is the one it LIVES in, never a hard-coded
# path: these scripts sit at <repo>/tests/e2e/, and several worktrees of this
# repo are open at once. See mutate_common for the overrides.
SRV = server_root()
BUILD = build_dir(SRV, "build")
TESTBIN = BUILD / "tests" / "server_tests"

# (label, file, old, new, gtest_filter, timeout_s)
MUTATIONS = [
 # The rule itself: @everyone becomes implicit again for everybody.
 ("bot inherits @everyone again",
  "src/auth/Permissions.cpp",
  "    const bool implicit_everyone = permission::inherits_everyone_role(user_id);",
  "    const bool implicit_everyone = true;",
  "BotScoping.ANewBotHoldsNoPermissionAnywhere", 180),

 # ...and the same rule inverted, which is the far more damaging direction:
 # nobody inherits it, and the server grants nothing to anyone by default.
 ("nobody inherits @everyone",
  "src/auth/Permissions.cpp",
  "    const bool implicit_everyone = permission::inherits_everyone_role(user_id);",
  "    const bool implicit_everyone = false;",
  "BotScoping.AnOrdinaryMemberIsUnaffected", 180),

 # The un-bootstrapped fallback, which hands out kEveryoneDefault with no
 # document to read it out of.
 ("un-bootstrapped fallback ignores the rule",
  "src/auth/Permissions.cpp",
  "        return implicit_everyone ? permission::kEveryoneDefault : 0;",
  "        return permission::kEveryoneDefault;",
  "BotScoping.AnUnbootstrappedServerDoesNotHandABotTheDefault", 180),

 # The boot sweep that would undo an operator's scoping overnight.
 ("bootstrap assigns @everyone to bots again",
  "src/auth/RoleBootstrap.cpp",
  "        if (bot::is_bot_user_id(user_id)) continue;\n\n        auto current = store.get_member_role_ids(user_id);",
  "        auto current = store.get_member_role_ids(user_id);",
  "BotScoping.BootstrapDoesNotGrantEveryoneToABotOnTheNextRestart", 180),

 # The backfill's discriminator. Sweeping on "has no roles" rather than "has no
 # assignment document" un-scopes every bot created after the upgrade.
 ("backfill sweeps on roles, not on the document",
  "src/auth/RoleBootstrap.cpp",
  "        if (store.get_server_state(std::string(event_type::kMemberRoles), user_id)) continue;",
  "        if (!store.get_member_role_ids(user_id).empty()) continue;",
  "BotScoping.TheBackfillDoesNotTouchABotCreatedAfterTheUpgrade", 180),

 # ...and the backfill itself, which is what keeps an existing deployment
 # working across the upgrade.
 ("backfill removed",
  "src/auth/RoleBootstrap.cpp",
  "    backfill_bot_everyone(store, config, canonical);",
  "    (void)0;",
  "BotScoping.AnExistingBotWithNoAssignmentIsBackfilledOnce", 180),

 # The escape that needs no privilege at all.
 ("a bot may self-assign roles again",
  "src/auth/Permissions.cpp",
  "    if (bot::is_bot_user_id(actor_id)) {\n        return {false, \"A bot account cannot assign roles to itself; ask an administrator\"};\n    }",
  "    // MUTATED",
  "BotScoping.ABotCannotSelfAssignARole", 180),

 # Creation writes the scope document rather than leaving an absence.
 ("creation writes no assignment",
  "src/api/BotHandler.cpp",
  "        write_server_scoped_state(store_, config_, std::string(event_type::kMemberRoles),\n                                  user_id, j.dump(), pick_server_state_mirror_room(store_),\n                                  *actor);",
  "        // MUTATED",
  "BotScoping.CreationRecordsAnExplicitEmptyAssignment", 180),

 # The access read: the caller-visibility filter is the disclosure boundary.
 ("access report lists every channel on the server",
  "src/api/BotHandler.cpp",
  "    const auto directory = visible_channel_directory(store_, perms, actor);",
  "    const auto directory = visible_channel_directory(store_, perms, \"@server:\" + config_.server_name);",
  "BotAccess.ShowsOnlyChannelsTheCallerMayBeToldAbout", 180),

 # ...and the answer is about the BOT, not about whoever asked.
 ("access report answers about the caller",
  "src/api/BotHandler.cpp",
  "            {\"permissions\", permission::flags_to_hex(perms.compute(user_id, entry.room_id))},",
  "            {\"permissions\", permission::flags_to_hex(perms.compute(actor, entry.room_id))},",
  "BotAccess.ReportsTheBotsEffectivePermissionsPerChannel", 180),

 # ...and it is bot administration, so it carries bot administration's gate.
 ("access read skips the bot-admin gate",
  "src/api/BotHandler.cpp",
  "    auto ctx = authorize_bot_admin(req, res, user_id, \"read a bot's access\");\n    if (!ctx) return;\n    const auto& actor = ctx->actor;",
  "    auto authed = authenticate(store_, req.get_header_value(\"Authorization\"));\n    if (!authed) return send_error(res, 401, auth_error(req.get_header_value(\"Authorization\")));\n    auto bot_rec = store_.get_bot(user_id);\n    if (!bot_rec) return send_error(res, 404, MatrixError::not_found(\"No such bot\"));\n    std::optional<BotAdminContext> ctx = BotAdminContext{.actor = *authed, .bot = *bot_rec};\n    const auto& actor = ctx->actor;",
  "BotAccess.IsGatedOnManageBotsAtServerScope:BotAccess.RefusesForABotThatOutranksTheCaller", 180),

 # ── and the discoverability half ────────────────────────────────────────
 #
 # Scoping was right and still produced a silent dead end, because nothing
 # between "bot created" and "403 about a channel" said so. These five put the
 # silence back, one statement at a time. A mutation here does not break
 # security — it breaks an operator's afternoon, which is the failure that
 # actually happened.

 # The whole classification collapses back to the old sentence.
 ("the refusal blames the channel again",
  "src/api/ChannelAccessRefusal.h",
  "    if (!is_unscoped_bot(store, user_id)) {",
  "    if (true) {",
  "BotFirstRun.TheRefusalNamesTheBotsRolesAndNotTheChannel", 180),

 # The predicate loses its first half, so an ordinary member with an empty
 # assignment document — who still holds @everyone implicitly — is told they
 # have no roles. The wrong explanation is worse than the vague one.
 ("unscoped means 'no roles' for humans too",
  "src/api/ChannelAccessRefusal.h",
  "    if (permission::inherits_everyone_role(user_id)) return false;\n    return store.get_member_role_ids(user_id).empty();",
  "    return store.get_member_role_ids(user_id).empty();",
  "BotFirstRun.AHumanDeniedInAChannelStillGetsTheChannelRefusal", 180),

 # Creation goes back to reporting a token and nothing about scope.
 ("creation stops declaring the empty scope",
  "src/api/BotHandler.cpp",
  "        {\"role_ids\", std::move(role_ids)},\n        {std::string(bot::kWarningKey),",
  "        {\"role_ids_unused\", std::move(role_ids)},\n        {\"unused\",",
  "BotFirstRun.CreationSaysTheBotHoldsNothing", 180),

 # The join goes back to a bare 200, which is the response that made the dead
 # end look like a working setup.
 ("the join stops warning",
  "src/api/RoomHandler.cpp",
  "    if (warning) joined[std::string(bot::kWarningKey)] = *warning;",
  "    if (false) joined[std::string(bot::kWarningKey)] = *warning;",
  "BotFirstRun.TheJoinWarnsThatItGrantedNothing", 180),

 # The access summary answers "some bit is set" instead of "can it get in".
 # SEND_MESSAGES without VIEW_CHANNEL is access to nothing, so this reports a
 # scoped-out bot as reachable — the exact wrong answer to the only question
 # the field exists for.
 ("access summary counts any permission bit",
  "src/api/BotHandler.cpp",
  "        if (permission::has(permission::flags_from_hex(c.value(\"permissions\", \"0x0\")),\n                            permission::kViewChannel)) {",
  "        if (permission::flags_from_hex(c.value(\"permissions\", \"0x0\")) != 0) {",
  "BotAccess.SaysInOneFieldWhetherTheBotCanSeeAnythingAtAll", 180),
]

def run(cmd, timeout=None):
    return subprocess.run(cmd, shell=True, cwd=SRV, capture_output=True,
                          text=True, timeout=timeout)


def main():
    results = []
    # Every mutation below is applied in place. The guard snapshots each file
    # before it is touched and reverts on the way out however this process ends
    # — normally, on an exception, on Ctrl-C or a kill — and leaves a journal
    # behind, so even a SIGKILL is repaired by the next run rather than by
    # someone eventually noticing a mutant in `git diff`.
    require_build(BUILD)
    with MutationGuard(SRV, builds=[BUILD]) as guard:
        backups = {f: guard.protect(SRV / f).decode() for f in {m[1] for m in MUTATIONS}}

        for label, relpath, old, new, filt, tmo in MUTATIONS:
            path = SRV / relpath
            src = backups[relpath]
            if old not in src:
                results.append((label, "SKIP", "mutation anchor not found"))
                continue
            assert src.count(old) == 1, f"{label}: anchor not unique ({src.count(old)})"
            path.write_text(src.replace(old, new, 1))

            try:
                build = cmake_build(BUILD, cwd=SRV, timeout=900)
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

        # restore + rebuild clean
        guard.restore_all()
        cmake_build(BUILD, cwd=SRV, timeout=900)

    print("\n" + "=" * 100)
    print("MUTATION TEST RESULTS")
    print("=" * 100)
    survived = 0
    for label, status, detail in results:
        print(f"{status:>18}  {label}")
        if detail:
            print(f"{'':>18}  -> {detail}")
        if "SURVIVED" in status or status == "SKIP":
            survived += 1
    print("=" * 100)
    print(f"{len(results) - survived}/{len(results)} mutations detected")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
