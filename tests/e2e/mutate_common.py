#!/usr/bin/env python3
"""Shared plumbing for the mutation harnesses in this directory.

Every harness here works the same destructive way: it patches a source file IN
PLACE, rebuilds, runs the tests that are supposed to catch the mutation, and
reverts. That is fine right up until something goes wrong, and three things went
wrong for real:

  * The target checkout was a hard-coded absolute path to the SHARED checkout.
    Running a harness from a worktree silently mutated and rebuilt the shared
    tree instead — the one several sessions have open at once.

  * An interrupted run (Ctrl-C, a timeout, a kill) left the mutation applied.
    On 2026-09-19 an interrupted run left the "F2 delivery moved INLINE onto the
    send path" mutant sitting in src/push/PushService.cpp in the shared checkout,
    where another session could have committed it as real work.

  * A restore that only rewrites the bytes is not enough. make compares whole
    seconds, so a file restored within the same second as the mutated build can
    be judged up to date and its stale object reused — the suite then behaves as
    if the mutant were still applied, long after the source is clean again.

So: paths are resolved from the script's own location, the revert is registered
with atexit and the fatal signals before the first byte is written, a journal on
disk lets the NEXT run repair what a SIGKILL left behind, and the restore purges
the object files and pushes the source mtime past them.

Overrides, for the rare case where the tree you want is not the tree the script
lives in:

    BSFCHAT_SERVER=/path/to/server   # or --srv=/path/to/server
    BSFCHAT_CLIENT=/path/to/client   # or --client=/path/to/client
    BSFCHAT_PROTOCOL=/path/to/protocol
    BSFCHAT_BUILD=/path/to/build     # or --build=/path/to/build
    BSFCHAT_BUILD_JOBS=2             # other workers build concurrently

Importing this module, or any harness that uses it, has no side effects.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── path resolution ──────────────────────────────────────────────────────────


def _from_argv(flag: str, argv=None) -> str | None:
    """Read `--flag=value` or `--flag value` out of argv without consuming it."""
    argv = sys.argv if argv is None else argv
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return None


def server_root(argv=None) -> Path:
    """The server checkout to mutate.

    The harnesses live at <repo>/tests/e2e/, so the repo root is two levels up
    from this file. Resolving it that way is the whole point: a harness run from
    a worktree mutates THAT worktree, not whichever checkout someone hard-coded.
    """
    override = _from_argv("--srv", argv) or os.environ.get("BSFCHAT_SERVER")
    root = Path(override).expanduser() if override else Path(__file__).resolve().parents[2]
    root = root.resolve()
    if not (root / "CMakeLists.txt").is_file() or not (root / "src").is_dir():
        raise SystemExit(f"not a server checkout: {root}")
    return root


def sibling_repo(name: str, argv=None) -> Path:
    """A sibling checkout of the server repo — `client`, `protocol`, and so on.

    Some harnesses live in the server repo but patch its siblings, so there is
    no location to derive those from with certainty. Preference order is the
    explicit override, then a checkout next to the server root (the plain
    workspace layout), then the matching sibling worktree. Falling back to the
    SHARED checkout is allowed but says so out loud, because a silent fallback
    to a tree other sessions have open is exactly the hazard this module exists
    to stop.
    """
    env = "BSFCHAT_" + name.upper()
    override = _from_argv("--" + name, argv) or os.environ.get(env)
    if override:
        root = Path(override).expanduser().resolve()
        if not (root / "CMakeLists.txt").is_file():
            raise SystemExit(f"not a {name} checkout: {root}")
        return root

    srv = server_root(argv)
    sibling = srv.parent / name
    if (sibling / "CMakeLists.txt").is_file():
        return sibling.resolve()

    # <workspace>/wt/server-foo  ->  <workspace>/wt/<name>-foo
    if srv.parent.name == "wt" and srv.name.startswith("server-"):
        suffix = srv.name[len("server-"):]
        twin = srv.parent / f"{name}-{suffix}"
        if (twin / "CMakeLists.txt").is_file():
            return twin.resolve()
        shared = srv.parent.parent / name
        if (shared / "CMakeLists.txt").is_file():
            print(f"WARNING: no {name} worktree beside {srv.name}; falling back to the\n"
                  f"         SHARED checkout {shared}. Other sessions have it open.\n"
                  f"         Set {env}=... to point somewhere else.",
                  file=sys.stderr)
            return shared.resolve()

    raise SystemExit(f"cannot locate the {name} checkout; set {env}=/path/to/{name}")


def client_root(argv=None) -> Path:
    """The client checkout, for the harnesses that mutate client sources."""
    return sibling_repo("client", argv)


def protocol_root(argv=None) -> Path:
    """The protocol checkout, for the harnesses that mutate the signer."""
    return sibling_repo("protocol", argv)


def build_dir(root: Path, default_name: str, argv=None) -> Path:
    """The build tree to rebuild into, under `root` unless overridden."""
    override = _from_argv("--build", argv) or os.environ.get("BSFCHAT_BUILD")
    return Path(override).expanduser().resolve() if override else (root / default_name)


def build_jobs() -> str:
    """Other workers build this repo concurrently; stay small and nice."""
    return os.environ.get("BSFCHAT_BUILD_JOBS", "2")


def require_build(build: Path) -> Path:
    """Refuse to start against a build tree that was never configured.

    A harness counts a mutation that fails to compile as detected, which is
    sound — but an unconfigured build tree fails to compile EVERY mutation, so
    the run reports a perfect score having tested nothing at all. That trap got
    much easier to fall into once these scripts started following the worktree
    they are run from, since a fresh worktree has no build tree yet.
    """
    build = Path(build)
    if not (build / "CMakeCache.txt").is_file():
        raise SystemExit(
            f"no configured build tree at {build}\n"
            f"Every mutation would fail to compile and be counted as detected, so the\n"
            f"run would report a perfect score without testing anything. Configure it:\n"
            f"  nice -n 19 cmake -S {build.parent} -B {build} -DCMAKE_BUILD_TYPE=Debug\n"
            f"  nice -n 19 cmake --build {build} -j2\n"
            f"or point the harness elsewhere with BSFCHAT_BUILD=/path/to/build.")
    return build


def cmake_build(build: Path, target: str | None = None, **kwargs):
    """`cmake --build`, niced and throttled per this repo's build rules."""
    cmd = ["nice", "-n", "19", "cmake", "--build", str(build)]
    if target:
        cmd += ["--target", target]
    cmd += ["-j", build_jobs()]
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(cmd, **kwargs)


def run_dir(root: Path) -> Path:
    """A scratch cwd for test binaries that insist on running somewhere writable.

    Created on demand and keyed to the checkout, because the alternative these
    scripts used — an absolute path into one session's scratchpad — stops
    existing the moment that session does, and every later run dies on it.
    """
    tag = hashlib.sha256(str(root).encode()).hexdigest()[:12]
    d = Path(os.environ.get("BSFCHAT_RUNDIR",
                            Path(tempfile.gettempdir()) / ("bsfchat-testrun-" + tag)))
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── restoring a mutated source ───────────────────────────────────────────────


def object_files(build: Path, source: Path, include_deps: bool | None = None) -> list[Path]:
    """Every compiled object for `source`, across every CMake target.

    Objects under `_deps` are third-party by default and skipped, since an
    unrelated dependency can easily ship a file of the same name. A source that
    lives OUTSIDE the build's own repo is a different story: the sibling repos
    (protocol, client) are pulled in by FetchContent and compiled under `_deps`,
    so for those the dep tree is the only place their objects exist.
    """
    if not build.is_dir():
        return []
    if include_deps is None:
        try:
            source.relative_to(build.parent)
            include_deps = False
        except ValueError:
            include_deps = True
    return [p for p in build.rglob(source.name + ".o")
            if include_deps or "_deps" not in p.parts]


def restore_source(path: Path, original: bytes, builds=()) -> None:
    """Put `original` back and make sure the next build actually recompiles it.

    Rewriting the bytes is only half the job. make's timestamp comparison is
    whole-second, so a source restored in the same second as the mutated build
    can be judged up to date and its object reused — the binary then keeps the
    mutant's behaviour with a clean tree on disk, which is the most confusing
    possible failure. So the objects are deleted outright, and the restored
    source is stamped past the newest of them as a second line of defence for
    any artifact (a library, a link-stage binary, a ccache entry) not found by
    name.
    """
    objs = [o for b in builds for o in object_files(Path(b), path)]
    newest = 0.0
    for o in objs:
        try:
            newest = max(newest, o.stat().st_mtime)
        except OSError:
            pass
    path.write_bytes(original)
    for o in objs:
        try:
            o.unlink()
        except OSError:
            pass
    stamp = max(time.time(), newest + 2.0)
    os.utime(path, (stamp, stamp))


# ── the guard ────────────────────────────────────────────────────────────────


def _journal_dir(root: Path) -> Path:
    """Somewhere per-checkout, outside the working tree, that git never sees."""
    try:
        gitdir = subprocess.run(["git", "rev-parse", "--absolute-git-dir"], cwd=root,
                                capture_output=True, text=True, timeout=10)
        if gitdir.returncode == 0 and gitdir.stdout.strip():
            return Path(gitdir.stdout.strip()) / "bsfchat-mutation"
    except (OSError, subprocess.SubprocessError):
        pass
    tag = hashlib.sha256(str(root).encode()).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / ("bsfchat-mutation-" + tag)


class MutationGuard:
    """Holds the pristine copy of every file a harness is about to mutate.

    Register a file with `protect()` BEFORE mutating it. From that moment the
    revert is armed three ways: the context manager's exit for the normal path
    and for exceptions, atexit and SIGINT/SIGTERM/SIGHUP for an interrupted run,
    and an on-disk journal for the one case nothing in-process can catch — a
    SIGKILL — which the next run of any harness repairs on startup.
    """

    def __init__(self, root: Path, builds=()):
        self.root = Path(root)
        self.builds = [Path(b) for b in builds]
        self.originals: dict[Path, bytes] = {}
        self._dir = _journal_dir(self.root)
        self._journal = self._dir / "journal.json"
        self._armed = False
        self._prev_handlers: dict[int, object] = {}

    # -- recovery from a previous run that never got to revert ---------------

    def recover(self) -> None:
        """Repair anything a killed run left behind, before mutating anything."""
        if not self._journal.is_file():
            return
        try:
            entries = json.loads(self._journal.read_text())
        except (OSError, ValueError):
            entries = []
        repaired = []
        for e in entries:
            path, backup = Path(e["path"]), Path(e["backup"])
            if not backup.is_file():
                continue
            original = backup.read_bytes()
            if path.is_file() and path.read_bytes() == original:
                continue
            restore_source(path, original, self.builds)
            repaired.append(path)
        if repaired:
            print("RECOVERED: a previous run was killed with mutations applied.\n"
                  "           These files have been restored from its journal:", file=sys.stderr)
            for p in repaired:
                print(f"             {p}", file=sys.stderr)
            print("           Rebuild before trusting any test result.", file=sys.stderr)
        self._clear_journal()

    def _clear_journal(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)

    def _write_journal(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        entries = []
        for path, original in self.originals.items():
            backup = self._dir / (hashlib.sha256(str(path).encode()).hexdigest()[:16] + ".orig")
            if not backup.is_file():
                backup.write_bytes(original)
            entries.append({"path": str(path), "backup": str(backup)})
        tmp = self._dir / "journal.json.tmp"
        tmp.write_text(json.dumps(entries, indent=1))
        tmp.replace(self._journal)

    # -- arming --------------------------------------------------------------

    def protect(self, path) -> bytes:
        """Snapshot `path` and arm its revert. Returns the pristine text."""
        path = Path(path).resolve()
        if path not in self.originals:
            self.originals[path] = path.read_bytes()
            self._write_journal()
        self._arm()
        return self.originals[path]

    def _arm(self) -> None:
        if self._armed:
            return
        self._armed = True
        atexit.register(self.restore_all)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                self._prev_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._on_signal)
            except (ValueError, OSError):
                pass  # not the main thread, or the platform lacks the signal

    def _on_signal(self, signum, frame):
        print(f"\ninterrupted (signal {signum}) — reverting mutations...", file=sys.stderr)
        self.restore_all()
        previous = self._prev_handlers.get(signum, signal.SIG_DFL)
        try:
            signal.signal(signum, previous if callable(previous) else signal.SIG_DFL)
        except (ValueError, OSError):
            pass
        os.kill(os.getpid(), signum)

    # -- reverting -----------------------------------------------------------

    def restore(self, path) -> None:
        """Revert one file to its pristine copy."""
        path = Path(path).resolve()
        if path in self.originals:
            restore_source(path, self.originals[path], self.builds)

    def restore_all(self) -> None:
        """Revert every protected file. Safe to call more than once."""
        for path, original in list(self.originals.items()):
            try:
                restore_source(path, original, self.builds)
            except OSError as exc:
                print(f"FAILED TO RESTORE {path}: {exc}", file=sys.stderr)
        self._clear_journal()

    def release(self) -> None:
        """Drop the armed state after a clean finish.

        Only for a caller that has already restored and knows the tree will not
        be there later (the self-test's temp checkouts). Harnesses do not need
        it: leaving the revert armed until the process exits is the point.
        """
        self.originals.clear()
        self._clear_journal()

    def __enter__(self):
        self.recover()
        return self

    def __exit__(self, *exc):
        self.restore_all()
        return False
