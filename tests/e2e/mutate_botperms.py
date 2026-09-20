#!/usr/bin/env python3
"""Mutation-test GET /bsfchat/permissions/{userId} — the read a bot uses to ask
"may this person administer me?".

Every line of PermissionsHandler.cpp that this endpoint's safety rests on is
broken here exactly once, and the named tests must notice. The point is not
coverage in the line sense: the handler is short and almost every line is a
guard, so a mutant that survives is a guard with no test, which is how a read
endpoint quietly turns into an enumeration oracle.

Three mutants in particular exist because this codebase has shipped that exact
shape of bug before:

  * "VIEW_CHANNEL term dropped" and "category exemption imported" — membership
    is not visibility here. Every channel is created public and force-joined,
    so a rule written on membership alone means everyone may read everyone.
  * "MANAGE_ROLES read branch evaluated at CHANNEL scope" — a per-channel grant
    unlocking a server-wide capability is what two audits found twice.
  * "unknown user answered 404" — a refusal that differs from the stranger's
    refusal is an account-existence oracle whatever the status code says.

And one mutant lives in the PROTOCOL checkout rather than this one: moving
MANAGE_BOTS off bit 13 must break the test that pins the hex a bot author copies
out of docs/bots.md. Without that, protocol drift is invisible to this suite in
exactly the way it was invisible to the client's role-editor test.

Usage:

    nice -n 19 python3 tests/e2e/mutate_botperms.py
    nice -n 19 python3 tests/e2e/mutate_botperms.py --build=/path/to/build

The checkouts are resolved from this script's own location, so a run from a
worktree mutates THAT worktree and its sibling protocol worktree. See
mutate_common for the overrides and for what happens if a run is killed.
"""
import hashlib
import io
import os
import subprocess
import sys

from mutate_common import (MutationGuard, build_dir, build_jobs, protocol_root, require_build,
                           run_dir, server_root)

SRV = server_root()
PROTO = protocol_root()
BUILD = build_dir(SRV, 'build')
TESTBIN = BUILD / 'tests' / 'server_tests'

HANDLER = str(SRV / 'src/api/PermissionsHandler.cpp')
PERMS_H = str(PROTO / 'include/bsfchat/Permissions.h')
BOOTSTRAP = str(SRV / 'src/auth/RoleBootstrap.cpp')

# (label, absolute file, find, replace, gtest filter expected to FAIL)
MUTATIONS = [
    # ── the authorization rule ───────────────────────────────────────────────
    ("A1 self-bypass removed", HANDLER,
     "    if (caller == target) return true;",
     "    if (false && caller == target) return true;",
     "BotPermissionQueryAccess.ACallerMayAlwaysAskAboutItself"),

    ("A2 every read refused", HANDLER,
     "    if (caller == target) return true;",
     "    return false;\n    if (caller == target) return true;",
     "BotPermissionQueryAccess.ASharedChannelIsEnoughAndNeedsNoPrivilege"),

    ("A3 MANAGE_ROLES read branch removed", HANDLER,
     "    if (perms.can(caller, kServerScope, permission::kManageRoles)) return true;",
     "    if (false) return true;",
     "BotPermissionQueryAccess.ManageRolesAtServerScopeAsksAboutAnyone"),

    ("A4 MANAGE_ROLES read branch evaluated at CHANNEL scope", HANDLER,
     "    if (perms.can(caller, kServerScope, permission::kManageRoles)) return true;",
     "    for (const auto& r : store_.get_joined_rooms(caller))\n"
     "        if (perms.can(caller, r, permission::kManageRoles)) return true;",
     "BotPermissionQueryAccess.ManageRolesInsideOneChannelUnlocksNothing"),

    ("A5 VIEW_CHANNEL term dropped (membership alone)", HANDLER,
     "        if (perms.can(caller, room_id, permission::kViewChannel)) return true;",
     "        return true;",
     "BotPermissionQueryAccess.MembershipWithoutViewChannelIsNotEnough"),

    ("A6 category exemption imported from can_view_room", HANDLER,
     "        if (perms.can(caller, room_id, permission::kViewChannel)) return true;",
     "        if (can_view_room(store_, perms, caller, room_id)) return true;",
     "BotPermissionQueryAccess.ACategoryDoesNotCountAsASharedChannel"),

    ("A7 shared-room intersection dropped", HANDLER,
     "        if (!shared.count(room_id)) continue;",
     "        (void)shared;",
     "BotPermissionQueryAccess.ACallerSharingNothingIsRefused"),

    ("A8 authentication removed", HANDLER,
     "    if (!caller) {\n        send_error(res, 401, auth_error(req.get_header_value(\"Authorization\")));\n        return;\n    }",
     "    if (!caller) { caller = \"@nobody:test\"; }",
     "BotPermissionQueryAccess.AnUnauthenticatedRequestIsRefused"),

    ("A9 server-ban check removed", HANDLER,
     "    if (store_.is_server_banned(*caller)) {",
     "    if (false && store_.is_server_banned(*caller)) {",
     "BotPermissionQueryAccess.ABannedCallerIsRefused"),

    # ── not an oracle, not spoofable ─────────────────────────────────────────
    ("B1 existence check removed (the @server actor becomes answerable)", HANDLER,
     "    if (!store_.user_exists(target)) {\n        send_error(res, 403, MatrixError::forbidden(kRefusal));\n        return;\n    }",
     "    if (false) {\n        send_error(res, 403, MatrixError::forbidden(kRefusal));\n        return;\n    }",
     "BotPermissionQueryAccess.TheSyntheticServerActorIsNotQueryable"),

    ("B2 unknown user answered 404 instead of the uniform refusal", HANDLER,
     "    if (!store_.user_exists(target)) {\n        send_error(res, 403, MatrixError::forbidden(kRefusal));",
     "    if (!store_.user_exists(target)) {\n        send_error(res, 404, MatrixError::not_found(\"User not found\"));",
     "BotPermissionQueryAccess.AnUnknownUserIsRefusedIdenticallyToAStranger"),

    ("B3 the target's role ids added to the response", HANDLER,
     '        {"scope", "server"},',
     '        {"scope", "server"},\n        {"role_ids", perms.roles_of(target)},',
     "BotPermissionQuery.TheResponseDisclosesTheMaskAndNothingElse"),

    # ── the answer itself ────────────────────────────────────────────────────
    ("C1 answer computed at CHANNEL scope", HANDLER,
     "    const permission::Flags flags = perms.compute(target, kServerScope);",
     "    auto _rooms = store_.get_joined_rooms(target);\n"
     "    const permission::Flags flags = perms.compute(target, _rooms.empty() ? kServerScope : _rooms.front());",
     "BotPermissionQueryScope.AChannelOverrideCannotGrantManageBotsInTheAnswer:"
     "BotPermissionQueryScope.AChannelOverrideCannotRemoveAServerScopedFlagFromTheAnswer"),

    ("C2 answer memoised across calls (a cache to go stale)", HANDLER,
     "    const permission::Flags flags = perms.compute(target, kServerScope);",
     "    static std::string _last;\n"
     "    static permission::Flags _lastf = 0;\n"
     "    if (_last != target) { _lastf = perms.compute(target, kServerScope); _last = target; }\n"
     "    const permission::Flags flags = _lastf;",
     "BotPermissionQuery.AReassignmentIsVisibleToTheVeryNextCall:"
     "BotPermissionQuery.ARoleEditIsVisibleToTheVeryNextCall"),

    ("C3 answer replaced by the everyone-default constant", HANDLER,
     "    const permission::Flags flags = perms.compute(target, kServerScope);",
     "    const permission::Flags flags = permission::kEveryoneDefault;",
     "BotPermissionQuery.AnAdministratorReadsBackEveryFlagTheProtocolDefines:"
     "BotPermissionQuery.ManageBotsHeldThroughARoleIsReported:"
     "BotPermissionQuery.TheAnswerIsThePermissionsEngineAnswerAtServerScope"),

    ("C4 answer replaced by the all-flags constant", HANDLER,
     "    const permission::Flags flags = perms.compute(target, kServerScope);",
     "    const permission::Flags flags = permission::kAllFlags;",
     "BotPermissionQuery.APlainMemberReadsBackExactlyTheEveryoneDefault"),

    ("C5 scope field mislabelled", HANDLER,
     '        {"scope", "server"},',
     '        {"scope", "channel"},',
     "BotPermissionQuery.AnAdministratorReadsBackEveryFlagTheProtocolDefines"),

    # ── the mirror room stops moving on its own ─────────────────────────────
    ("E1 mirror room recomputed on every call again", BOOTSTRAP,
     "    if (auto pinned = store.get_meta(kMirrorRoomKey);\n"
     "        pinned && !pinned->empty() && store.room_exists(*pinned)) {\n"
     "        return *pinned;\n    }",
     "    if (false) {\n        return {};\n    }",
     "ServerStateMirrorRoom.ThePinnedRoomDoesNotFollowTheRoomList"),

    ("E2 pinned room not checked for existence", BOOTSTRAP,
     "        pinned && !pinned->empty() && store.room_exists(*pinned)) {",
     "        pinned && !pinned->empty()) {",
     "ServerStateMirrorRoom.TheMirrorMovesOnlyWhenThePinnedRoomIsDeleted"),

    ("E3 choice never recorded", BOOTSTRAP,
     "    store.set_meta(kMirrorRoomKey, chosen);",
     "    (void)kMirrorRoomKey;",
     "ServerStateMirrorRoom.TheFirstCallPinsTheRoomTheServerWasAlreadyUsing"),

    ("E4 a roomless server pins an empty mirror", BOOTSTRAP,
     "    if (non_cat.empty()) return {};",
     "    if (non_cat.empty()) { store.set_meta(kMirrorRoomKey, \"\"); return {}; }",
     "ServerStateMirrorRoom.AServerWithNoChannelsHasNoMirrorRoom"),

    # ── the wire contract, mutated in the PROTOCOL checkout ──────────────────
    ("D1 protocol moves MANAGE_BOTS off bit 13", PERMS_H,
     "constexpr Flags kManageBots       = 1ULL << 13;",
     "constexpr Flags kManageBots       = 1ULL << 16;",
     "BotPermissionQuery.TheDocumentedHexForManageBotsIsWhatTheEndpointReports"),
]


def sha(path):
    return hashlib.sha256(io.open(path, 'rb').read()).hexdigest()


def build():
    r = subprocess.run(['nice', '-n', '19', 'cmake', '--build', str(BUILD),
                        '--target', 'server_tests', '-j', build_jobs()],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def run_tests(filt):
    r = subprocess.run([str(TESTBIN), '--gtest_filter=' + filt, '--gtest_brief=1'],
                       capture_output=True, text=True, cwd=run_dir(SRV))
    return r.returncode, r.stdout + r.stderr


def main():
    require_build(BUILD)
    # Snapshots each file before it is mutated and reverts however this process
    # ends. Both checkouts are registered, because D1 mutates the protocol one.
    guard = MutationGuard(SRV, builds=[BUILD])
    guard.recover()
    results = []
    for label, src, find, repl, filt in MUTATIONS:
        original = guard.protect(src).decode()
        before = sha(src)

        if find not in original:
            results.append((label, 'SKIP', 'anchor text not found - mutation not applied'))
            print('SKIP        %s (anchor not found)' % label)
            continue

        assert original.count(find) == 1, 'anchor is ambiguous for: ' + label
        io.open(src, 'w', encoding='utf-8').write(original.replace(find, repl))

        try:
            rc, out = build()
            if rc != 0:
                errs = [l for l in out.splitlines() if 'error:' in l][:3]
                results.append((label, 'BUILD-FAIL', '; '.join(errs)))
                print('BUILD-FAIL  %s' % label)
                continue

            rc, out = run_tests(filt)
            if rc != 0:
                failed = [l.strip() for l in out.splitlines()
                          if l.startswith('[  FAILED  ]') and '.' in l]
                results.append((label, 'CAUGHT', '; '.join(sorted(set(failed))[:4])))
                print('CAUGHT      %s' % label)
            else:
                results.append((label, 'NOT CAUGHT', 'tests still passed: ' + filt))
                print('NOT CAUGHT  %s   <-- coverage gap' % label)
        finally:
            # Reverts the bytes, deletes the objects and stamps the source past
            # them: a same-second restore can otherwise be judged up to date,
            # leaving a stale object in the binary and misattributing the NEXT
            # mutation's result.
            guard.restore(src)
            assert sha(src) == before, 'failed to restore ' + src

    guard.restore_all()
    rc, _ = build()
    print('\nfinal clean rebuild rc=%d' % rc)

    print('\n===== MUTATION RESULTS =====')
    caught = sum(1 for _, s, _ in results if s == 'CAUGHT')
    for label, status, detail in results:
        print('%-11s %-58s %s' % (status, label, detail))
    print('\n%d/%d mutations caught' % (caught, len(results)))
    return 0 if caught == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
