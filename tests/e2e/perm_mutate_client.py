#!/usr/bin/env python3
"""Mutation-test the client-side nickname properties.

Same discipline as the server sweep: break one property, DELETE the object file so
make cannot reuse a same-second stale one, rebuild only the test target, run the
tests that should catch it, restore, verify byte-identical.
"""
import hashlib
import io
import os
import subprocess
import sys

CLIENT = '/Users/josh/dev/gamechat/client'
BUILD = os.path.join(CLIENT, 'build')
TESTBIN = os.path.join(BUILD, 'tests/test_models')
RUNDIR = '/private/tmp/claude-501/-Users-josh-dev-gamechat/a93cf36b-3c49-4af9-bbf5-265c130484f9/scratchpad/testrun'

# The object for MemberListModel.cpp as compiled INTO the test target.
OBJ_CANDIDATES = [
    os.path.join(BUILD, 'tests/CMakeFiles/test_models.dir/__/src/model/MemberListModel.cpp.o'),
    os.path.join(BUILD, 'tests/CMakeFiles/test_models.dir/__/src/util/PermissionMath.cpp.o'),
]

MUTATIONS = [
    ("client ignores bsfchat.nickname in member events",
     'src/model/MemberListModel.cpp',
     'event.content.data.value(std::string("bsfchat.nickname"), std::string()));',
     'event.content.data.value(std::string("bsfchat.nickname.ignored"), std::string()));',
     'testMemberListNicknamePreferredOverGlobalName testMemberListNicknameLookupByUserId'),

    ("client keeps a stale nickname when one is cleared",
     'src/model/MemberListModel.cpp',
     '            m_members[idx].nickname = nickname;\n',
     '',
     'testMemberListNicknameIsClearedByAnEventWithoutIt'),

    ("client treats nickname flags as channel-scoped",
     'src/util/PermissionMath.cpp',
     'if (channelOverrides == nullptr) return base;',
     'if (false) return base; // mutated',
     'testPermissionsModerationAndNicknameFlagsAreServerScopeOnly'),
]


def sha(p):
    return hashlib.sha256(io.open(p, 'rb').read()).hexdigest()


def build():
    r = subprocess.run(['cmake', '--build', BUILD, '--target', 'test_models', '-j8'],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def run(funcs):
    r = subprocess.run([TESTBIN] + funcs, capture_output=True, text=True, cwd=RUNDIR)
    return r.returncode, r.stdout + r.stderr


def main():
    results = []
    for label, rel, find, repl, funcs in MUTATIONS:
        src = os.path.join(CLIENT, rel)
        original = io.open(src, encoding='utf-8').read()
        before = sha(src)
        if find not in original:
            results.append((label, 'SKIP', 'anchor not found'))
            print('SKIP  ' + label)
            continue
        assert original.count(find) == 1, 'ambiguous anchor: ' + label
        io.open(src, 'w', encoding='utf-8').write(original.replace(find, repl))
        try:
            for o in OBJ_CANDIDATES:
                if os.path.exists(o):
                    os.remove(o)
            rc, out = build()
            if rc != 0:
                errs = [l for l in out.splitlines() if 'error:' in l][:2]
                results.append((label, 'BUILD-FAIL', '; '.join(errs)))
                print('BUILD-FAIL  ' + label)
                continue
            rc, out = run(funcs.split())
            if rc != 0:
                fails = [l.strip() for l in out.splitlines() if l.startswith('FAIL!')]
                results.append((label, 'CAUGHT', '; '.join(fails[:3])))
                print('CAUGHT      ' + label)
            else:
                results.append((label, 'NOT CAUGHT', 'still passed: ' + funcs))
                print('NOT CAUGHT  %s   <-- coverage gap' % label)
        finally:
            io.open(src, 'w', encoding='utf-8').write(original)
            assert sha(src) == before, 'failed to restore ' + src
            for o in OBJ_CANDIDATES:
                if os.path.exists(o):
                    os.remove(o)

    rc, _ = build()
    print('\nfinal clean rebuild rc=%d' % rc)
    print('\n===== CLIENT MUTATION RESULTS =====')
    caught = sum(1 for _, st, _ in results if st == 'CAUGHT')
    for label, st, detail in results:
        print('%-11s %-52s %s' % (st, label, detail))
    print('\n%d/%d mutations caught' % (caught, len(results)))
    return 0 if caught == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
