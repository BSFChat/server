#!/usr/bin/env python3
"""Self-test for mutate_common: the revert must survive every way a run can end.

The mutation harnesses patch source files in place, so the only thing standing
between an interrupted run and a mutant committed by somebody else is the
revert. That makes the revert worth testing directly, which is what this does,
against a throwaway checkout in a temp directory — it never touches a real one.

    python3 tests/e2e/test_mutate_common.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import mutate_common as mc  # noqa: E402

PRISTINE = "int answer() { return 42; }\n"
MUTANT = "int answer() { return 0; }\n"

failures = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"\n        {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def fake_repo(tmp: Path) -> Path:
    """The minimum shape server_root() will accept, plus a build tree."""
    root = (tmp / "server").resolve()
    tmp.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    (root / "src").mkdir(parents=True)
    (root / "tests/e2e").mkdir(parents=True)
    (root / "CMakeLists.txt").write_text("project(fake)\n")
    (root / "src/Answer.cpp").write_text(PRISTINE)
    obj = root / "build-fix/tests/CMakeFiles/server_tests.dir/__/src/Answer.cpp.o"
    obj.parent.mkdir(parents=True)
    obj.write_bytes(b"stale object")
    subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True)
    return root


# ── 1. paths come from the script's location, not a hard-coded absolute ──────

def test_resolution(tmp):
    root = fake_repo(tmp)
    shutil.copy2(HERE / "mutate_common.py", root / "tests/e2e/mutate_common.py")
    probe = root / "tests/e2e/probe.py"
    probe.write_text("import sys, pathlib\n"
                     "sys.path.insert(0, str(pathlib.Path(__file__).parent))\n"
                     "import mutate_common as mc\n"
                     "print(mc.server_root())\n"
                     "print(mc.build_dir(mc.server_root(), 'build-fix'))\n")
    out = subprocess.run([sys.executable, str(probe)], capture_output=True, text=True,
                         cwd=tmp).stdout.split()
    check("server_root() resolves to the checkout the script lives in",
          out and Path(out[0]) == root, f"got {out}")
    check("build_dir() lands under that same checkout",
          len(out) > 1 and Path(out[1]) == root / "build-fix", f"got {out}")

    env = dict(os.environ, BSFCHAT_SERVER=str(root))
    other = subprocess.run([sys.executable, str(probe)], capture_output=True, text=True,
                           cwd=tmp, env=env).stdout.split()
    check("BSFCHAT_SERVER overrides the derived path", other and Path(other[0]) == root)

    argv = subprocess.run([sys.executable, str(probe), "--srv", str(root)],
                          capture_output=True, text=True, cwd=tmp).stdout.split()
    check("--srv overrides the derived path", argv and Path(argv[0]) == root)


# ── 2. the revert restores bytes AND defeats make's whole-second compare ─────

def test_restore_bumps_mtime(tmp):
    root = fake_repo(tmp)
    src = root / "src/Answer.cpp"
    build = root / "build-fix"
    obj = build / "tests/CMakeFiles/server_tests.dir/__/src/Answer.cpp.o"

    guard = mc.MutationGuard(root, builds=[build])
    original = guard.protect(src).decode()
    src.write_text(MUTANT)
    # The object is rebuilt from the mutant and lands in the same second as the
    # restore that follows — the exact situation that left a stale object behind.
    obj.write_bytes(b"object built from the mutant")
    obj_mtime = obj.stat().st_mtime

    guard.restore(src)
    check("restore puts the original bytes back", src.read_text() == original)
    check("restore deletes the object built from the mutant", not obj.exists())
    check("restored source is stamped past the mutant's object",
          src.stat().st_mtime > obj_mtime,
          f"src={src.stat().st_mtime} obj={obj_mtime}")
    guard.restore_all()
    guard.release()


def test_make_actually_rebuilds(tmp):
    """The end-to-end version of the above, with a real make."""
    if not shutil.which("make"):
        print("  SKIP  make not on PATH")
        return
    root = fake_repo(tmp)
    src, build = root / "src/Answer.cpp", root / "build-fix"
    stamp = root / "out.txt"
    (root / "Makefile").write_text(
        f"out.txt: src/Answer.cpp\n\tcp src/Answer.cpp out.txt\n")
    subprocess.run(["make", "-s"], cwd=root, capture_output=True)

    guard = mc.MutationGuard(root, builds=[build])
    guard.protect(src)
    src.write_text(MUTANT)
    # The harnesses delete the objects before the mutated build for exactly the
    # reason this test exists; stand in for that so the mutation is definitely
    # compiled in and the restore is what is actually under test below.
    future = time.time() + 2
    os.utime(src, (future, future))
    subprocess.run(["make", "-s"], cwd=root, capture_output=True)
    check("make picked up the mutation", stamp.read_text() == MUTANT)

    guard.restore(src)  # same second as the mutated build, deliberately
    subprocess.run(["make", "-s"], cwd=root, capture_output=True)
    check("make rebuilds after the restore instead of reusing a stale artifact",
          stamp.read_text() == PRISTINE,
          f"artifact still holds: {stamp.read_text()!r}")
    guard.restore_all()
    guard.release()


# ── 3. an interrupted run cannot leave a mutation behind ─────────────────────

RUNNER = '''
import sys, time, pathlib
sys.path.insert(0, {here!r})
import mutate_common as mc
root = pathlib.Path({root!r})
src = root / "src/Answer.cpp"
guard = mc.MutationGuard(root, builds=[root / "build-fix"])
guard.recover()
guard.protect(src)
src.write_text({mutant!r})
print("MUTATED", flush=True)
time.sleep(60)
'''


def _spawn(root, tmp):
    runner = tmp / f"runner_{time.time_ns()}.py"
    runner.write_text(RUNNER.format(here=str(HERE), root=str(root), mutant=MUTANT))
    p = subprocess.Popen([sys.executable, str(runner)], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "MUTATED"
    return p


def test_signal_reverts(tmp, signame, signum):
    root = fake_repo(tmp)
    src = root / "src/Answer.cpp"
    p = _spawn(root, tmp)
    check(f"{signame}: the mutation is applied before the signal",
          src.read_text() == MUTANT)
    p.send_signal(signum)
    p.wait(timeout=30)
    check(f"{signame} mid-run leaves the source reverted", src.read_text() == PRISTINE,
          f"left behind: {src.read_text()!r}")


def test_sigkill_recovered_by_next_run(tmp):
    """SIGKILL is the one no handler can catch, so the journal has to cover it."""
    root = fake_repo(tmp)
    src = root / "src/Answer.cpp"
    p = _spawn(root, tmp)
    p.kill()
    p.wait(timeout=30)
    check("SIGKILL does leave the mutation behind (nothing in-process can help)",
          src.read_text() == MUTANT)

    guard = mc.MutationGuard(root, builds=[root / "build-fix"])
    guard.recover()
    check("the next run's recover() repairs what the SIGKILL left",
          src.read_text() == PRISTINE, f"left behind: {src.read_text()!r}")
    check("recover() clears the journal once it is done",
          not (mc._journal_dir(root) / "journal.json").exists())
    guard.release()


def test_exception_reverts(tmp):
    root = fake_repo(tmp)
    src = root / "src/Answer.cpp"
    try:
        with mc.MutationGuard(root, builds=[root / "build-fix"]) as guard:
            guard.protect(src)
            src.write_text(MUTANT)
            raise RuntimeError("anchor not unique")
    except RuntimeError:
        pass
    check("an exception mid-run leaves the source reverted", src.read_text() == PRISTINE)
    guard.release()


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        print("path resolution");            test_resolution(tmp / "a")
        print("restore vs make timestamps"); test_restore_bumps_mtime(tmp / "b")
        test_make_actually_rebuilds(tmp / "c")
        print("interruption");               test_exception_reverts(tmp / "d")
        import signal
        test_signal_reverts(tmp / "e", "SIGINT", signal.SIGINT)
        test_signal_reverts(tmp / "f", "SIGTERM", signal.SIGTERM)
        test_sigkill_recovered_by_next_run(tmp / "g")

    print()
    if failures:
        print(f"{len(failures)} FAILED: " + ", ".join(failures))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
