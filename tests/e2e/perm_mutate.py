#!/usr/bin/env python3
"""Mutation-test the T1/T2 permission properties.

For each mutation: break exactly one property in the source, DELETE the affected
object file (make's one-second timestamp granularity otherwise silently reuses a
stale object and the result gets misattributed), rebuild, run the tests that are
supposed to catch it, then restore the file and verify it is byte-identical.

A mutation is only meaningful if the named tests FAIL. A mutation that leaves them
green means the property is not actually covered.
"""
import hashlib
import io
import os
import subprocess
import sys

from mutate_common import MutationGuard, build_dir, build_jobs, require_build, run_dir, server_root

# Resolved from this script's own location (<repo>/tests/e2e/), so a run from a
# worktree mutates THAT worktree and not whichever checkout was hard-coded here.
# Override with BSFCHAT_SERVER=... / --srv=... See mutate_common.
SRV = str(server_root())
BUILD = str(build_dir(server_root(), 'build-perm'))
OBJ = os.path.join(BUILD, 'tests/CMakeFiles/server_tests.dir/__/src')
TESTBIN = os.path.join(BUILD, 'tests/server_tests')

# (label, relpath, object relpath, find, replace, gtest filter expected to FAIL)
MUTATIONS = [
    ("T1 kick uses channel scope",
     'src/api/RoomHandler.cpp', 'api/RoomHandler.cpp.o',
     'if (!perms.can(*user_id, kServerScope, permission::kKickMembers)) {\n        res.status = 403;\n        res.set_content(MatrixError::forbidden("Insufficient permissions to kick")',
     'if (!perms.can(*user_id, room_id, permission::kKickMembers)) {\n        res.status = 403;\n        res.set_content(MatrixError::forbidden("Insufficient permissions to kick")',
     'ModerationScope.PerChannelOverrideDoesNotConferKick'),

    ("T1 ban uses channel scope",
     'src/api/RoomHandler.cpp', 'api/RoomHandler.cpp.o',
     'if (!perms.can(*user_id, kServerScope, permission::kBanMembers)) {\n        res.status = 403;\n        res.set_content(MatrixError::forbidden("Insufficient permissions to ban")',
     'if (!perms.can(*user_id, room_id, permission::kBanMembers)) {\n        res.status = 403;\n        res.set_content(MatrixError::forbidden("Insufficient permissions to ban")',
     'ModerationScope.PerChannelOverrideDoesNotConferBan'),

    ("T1 unban uses channel scope",
     'src/api/RoomHandler.cpp', 'api/RoomHandler.cpp.o',
     'if (!perms.can(*user_id, kServerScope, permission::kBanMembers)) {\n        res.status = 403;\n        res.set_content(MatrixError::forbidden("Insufficient permissions to unban")',
     'if (!perms.can(*user_id, room_id, permission::kBanMembers)) {\n        res.status = 403;\n        res.set_content(MatrixError::forbidden("Insufficient permissions to unban")',
     'ModerationScope.PerChannelOverrideDoesNotConferUnban'),

    ("T1 state-PUT membership back to channel scope (the bypass)",
     'src/api/RoomHandler.cpp', 'api/RoomHandler.cpp.o',
     'const bool is_server_scoped_permission = is_server_scoped || is_member_moderation;',
     'const bool is_server_scoped_permission = is_server_scoped;',
     'StatePutBypass.PerChannelKickOverrideCannotBanThroughStatePut'),

    ("T1 state-PUT rank check removed",
     'src/api/RoomHandler.cpp', 'api/RoomHandler.cpp.o',
     'if (is_member_moderation && !state_key.empty() && !perms.outranks(*user_id, state_key)) {',
     'if (false) {',
     'StatePutBypass.CannotModerateAUserOfHigherRankThroughStatePut'),

    ("T2 own-nickname gate uses a flag everyone has",
     'src/api/ProfileHandler.cpp', 'api/ProfileHandler.cpp.o',
     'if (!perms.can(*user_id, kServerScope, permission::kChangeNickname)) {',
     'if (!perms.can(*user_id, kServerScope, permission::kViewChannel)) {',
     'NicknameGating.OwnWithoutChangeNicknameIsRefused'),

    ("T2 other-nickname gate uses CHANGE instead of MANAGE",
     'src/api/ProfileHandler.cpp', 'api/ProfileHandler.cpp.o',
     'if (!perms.can(*user_id, kServerScope, permission::kManageNicknames)) {',
     'if (!perms.can(*user_id, kServerScope, permission::kChangeNickname)) {',
     'NicknameGating.OtherWithoutManageNicknamesIsRefused'),

    ("T2 nickname rank check removed",
     'src/api/ProfileHandler.cpp', 'api/ProfileHandler.cpp.o',
     'if (!perms.outranks(*user_id, target_user_id)) {',
     'if (false) {',
     'NicknameGating.CannotRenameAUserOfHigherRank'),

    ("T2 nickname audit fires on self instead of on others",
     'src/api/ProfileHandler.cpp', 'api/ProfileHandler.cpp.o',
     '    if (!is_self) {\n        audit_nickname_change(store_, *user_id, target_user_id, previous, next);',
     '    if (is_self) {\n        audit_nickname_change(store_, *user_id, target_user_id, previous, next);',
     'NicknameAudit.ModeratorRenamingSomeoneElseIsRecordedOnce:NicknameAudit.RenamingYourselfIsNotAModerationAction'),

    ("T2 member events use the global name, not the effective one",
     'src/identity/Nickname.cpp', 'identity/Nickname.cpp.o',
     'if (auto name = effective_display_name(store, user_id)) content["displayname"] = *name;',
     'if (auto name = store.get_display_name(user_id)) content["displayname"] = *name;',
     'NicknameStorage.IsMirroredIntoEveryJoinedRoomsMemberEvent:NicknameStorage.SurvivesAnUnrelatedProfileChange'),

    ("T2 impersonation check disabled",
     'src/identity/Nickname.cpp', 'identity/Nickname.cpp.o',
     'if (mxid != target_user && store.user_exists(mxid)) {',
     'if (false) {',
     'NicknameValidation.RejectsAnotherMembersUsername'),

    ("T2 unsafe-character check disabled",
     'src/identity/Nickname.cpp', 'identity/Nickname.cpp.o',
     'bool is_forbidden_codepoint(std::uint32_t cp) {\n    if (cp < 0x20 || cp == 0x7F) return true;              // C0 controls, DEL',
     'bool is_forbidden_codepoint(std::uint32_t cp) {\n    if (cp == 0xDEADBEEF) return true;\n    if (false) return true;',
     'NicknameValidation.RejectsMxidShapedAndUnsafeCharacters'),

    ("T2 UTF-8 validation accepts anything",
     'src/identity/Nickname.cpp', 'identity/Nickname.cpp.o',
     'bool decode_utf8(const std::string& s, std::vector<std::uint32_t>& out) {\n    std::size_t i = 0;',
     'bool decode_utf8(const std::string& s, std::vector<std::uint32_t>& out) {\n    for (char c : s) out.push_back(static_cast<unsigned char>(c));\n    if (!out.empty()) return true;\n    std::size_t i = 0;',
     'NicknameValidation.RejectsMalformedUtf8AtTheValidator'),

    ("T2 blank nickname stored instead of clearing",
     'src/api/ProfileHandler.cpp', 'api/ProfileHandler.cpp.o',
     'if (has_value && !is_blank_nickname(body["nickname"].get<std::string>())) {',
     'if (has_value) {',
     'NicknameValidation.TrimsWhitespaceAndTreatsBlankAsClear'),
]


def sha(path):
    return hashlib.sha256(io.open(path, 'rb').read()).hexdigest()


def build():
    r = subprocess.run(['nice', '-n', '19', 'make', '-C', BUILD, 'server_tests',
                        '-j' + build_jobs()], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def run_tests(filt):
    r = subprocess.run([TESTBIN, '--gtest_filter=' + filt, '--gtest_brief=1'],
                       capture_output=True, text=True, cwd=run_dir(SRV))
    return r.returncode, r.stdout + r.stderr


def main():
    require_build(BUILD)
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. recover() first
    # repairs anything a SIGKILLed run left applied.
    guard = MutationGuard(SRV, builds=[BUILD])
    guard.recover()
    results = []
    for label, rel, objrel, find, repl, filt in MUTATIONS:
        src = os.path.join(SRV, rel)
        obj = os.path.join(OBJ, objrel)
        original = guard.protect(src).decode()
        before = sha(src)

        if find not in original:
            results.append((label, 'SKIP', 'anchor text not found - mutation not applied'))
            print('SKIP  %s (anchor not found)' % label)
            continue

        assert original.count(find) == 1, 'anchor is ambiguous for: ' + label
        io.open(src, 'w', encoding='utf-8').write(original.replace(find, repl))

        try:
            # Delete the object so make CANNOT reuse a stale one written in the
            # same filesystem-timestamp second.
            if os.path.exists(obj):
                os.remove(obj)
            rc, out = build()
            if rc != 0:
                errs = [l for l in out.splitlines() if 'error:' in l][:3]
                results.append((label, 'BUILD-FAIL', '; '.join(errs)))
                print('BUILD-FAIL  %s' % label)
                continue

            rc, out = run_tests(filt)
            if rc != 0:
                failed = [l.strip() for l in out.splitlines() if l.startswith('[  FAILED  ]') and '.' in l]
                results.append((label, 'CAUGHT', '; '.join(sorted(set(failed))[:4])))
                print('CAUGHT      %s' % label)
            else:
                results.append((label, 'NOT CAUGHT', 'tests still passed: ' + filt))
                print('NOT CAUGHT  %s   <-- coverage gap' % label)
        finally:
            # Reverts the bytes, deletes the objects and stamps the source past
            # them: a same-second restore can otherwise be judged up to date by
            # make, leaving a stale object in the binary.
            guard.restore(src)
            assert sha(src) == before, 'failed to restore ' + src

    # Rebuild clean at the end so the tree is left in a good state.
    guard.restore_all()
    rc, out = build()
    print('\nfinal clean rebuild rc=%d' % rc)

    print('\n===== MUTATION RESULTS =====')
    caught = sum(1 for _, s, _ in results if s == 'CAUGHT')
    for label, status, detail in results:
        print('%-11s %-58s %s' % (status, label, detail))
    print('\n%d/%d mutations caught' % (caught, len(results)))
    return 0 if caught == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
