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

from mutate_common import MutationGuard, build_dir, build_jobs, client_root, require_build, run_dir

# This script lives in the server repo but patches the CLIENT one, so there is
# no location to derive that from with certainty — see mutate_common.client_root
# for the search order and the BSFCHAT_CLIENT override. Resolved lazily so that
# importing this module to read MUTATIONS stays free of side effects.
CLIENT = None
BUILD = None
TESTBIN = None
OBJ_CANDIDATES = []


def resolve():
    global CLIENT, BUILD, TESTBIN, OBJ_CANDIDATES
    CLIENT = client_root()
    BUILD = build_dir(CLIENT, 'build')
    TESTBIN = os.path.join(BUILD, 'tests/test_models')
    # The object for MemberListModel.cpp as compiled INTO the test target.
    OBJ_CANDIDATES = [
        os.path.join(BUILD, 'tests/CMakeFiles/test_models.dir/__/src/model/MemberListModel.cpp.o'),
        os.path.join(BUILD, 'tests/CMakeFiles/test_models.dir/__/src/util/PermissionMath.cpp.o'),
    ]

MUTATIONS = [
    ("client treats nickname flags as channel-scoped",
     'src/util/PermissionMath.cpp',
     'if (channelOverrides == nullptr) return base;',
     'if (false) return base; // mutated',
     'testPermissionsModerationAndNicknameFlagsAreServerScopeOnly'),
]


def sha(p):
    return hashlib.sha256(io.open(p, 'rb').read()).hexdigest()


def build():
    r = subprocess.run(['nice', '-n', '19', 'cmake', '--build', BUILD,
                        '--target', 'test_models', '-j', build_jobs()],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def run(funcs):
    r = subprocess.run([TESTBIN] + funcs, capture_output=True, text=True, cwd=run_dir(CLIENT))
    return r.returncode, r.stdout + r.stderr


def main():
    resolve()
    require_build(BUILD)
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. recover() first
    # repairs anything a SIGKILLed run left applied.
    guard = MutationGuard(CLIENT, builds=[BUILD])
    guard.recover()
    results = []
    for label, rel, find, repl, funcs in MUTATIONS:
        src = os.path.join(CLIENT, rel)
        original = guard.protect(src).decode()
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
            # Reverts the bytes, deletes the objects and stamps the source past
            # them: a same-second restore can otherwise be judged up to date by
            # make, leaving a stale object in the binary.
            guard.restore(src)
            for o in OBJ_CANDIDATES:
                if os.path.exists(o):
                    os.remove(o)
            assert sha(src) == before, 'failed to restore ' + src

    guard.restore_all()
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
