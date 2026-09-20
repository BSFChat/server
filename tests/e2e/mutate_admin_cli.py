#!/usr/bin/env python3
"""Mutation harness for the offline admin CLI (`bsfchat-server grant-admin`).

The point of this command is NOT that the named account ends up with the admin
role. The SSH recovery it replaces achieved that, by hand-writing rows into
`server_state` and `events`, and it was still wrong in three ways: no audit
record, no /sync mirror event, and a stream position picked by hand.

So the first mutation here is the SSH recovery itself, expressed in C++: write
the authoritative row directly and skip the choke point. If the suite stays
green under that, then the tests are measuring the role list and nothing that
matters.

Run from anywhere:  python3 server/tests/e2e/mutate_admin_cli.py
It restores the tree and rebuilds clean on the way out, including after a crash
in the middle of a case.
"""

import subprocess
import sys
from pathlib import Path

from mutate_common import MutationGuard, build_dir, cmake_build, require_build, server_root

SERVER = server_root()
BUILD = build_dir(SERVER, "build-ar")

CLI = SERVER / "src/cli/AdminCli.cpp"
AUTH = SERVER / "src/api/AuthHandler.cpp"

WRITE_CALL = (
    "    write_server_scoped_state(store, config, std::string(event_type::kMemberRoles),\n"
    "                              args.user_id, j.dump(), pick_server_state_mirror_room(store),\n"
    "                              console_actor(config));"
)


class Mutation:
    def __init__(self, name, path, edits, must_fail, must_pass=""):
        self.name = name
        self.path = path
        self.edits = edits
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    Mutation(
        "A1: the authoritative row written directly, choke point skipped (the SSH recovery)",
        CLI,
        [(WRITE_CALL,
          "    store.set_server_state(std::string(event_type::kMemberRoles),\n"
          "                           args.user_id, console_actor(config), j.dump());")],
        "AdminCli.GrantAdminWritesAuthoritativeStateAndAuditAndSyncMirror"
        ":AdminCli.GrantAdminIsIdempotentAndDoesNotRepeatTheAuditRecord",
        # Control: the role list itself still ends up right, which is exactly
        # why asserting on it would have proved nothing.
        "AdminCli.GrantAdminKeepsTheRolesTheAccountAlreadyHad",
    ),
    Mutation(
        "A2: no room to mirror into, so no client learns about the grant",
        CLI,
        [(WRITE_CALL,
          "    write_server_scoped_state(store, config, std::string(event_type::kMemberRoles),\n"
          "                              args.user_id, j.dump(), std::string(),\n"
          "                              console_actor(config));")],
        "AdminCli.GrantAdminWritesAuthoritativeStateAndAuditAndSyncMirror",
        "AdminCli.GrantAdminKeepsTheRolesTheAccountAlreadyHad",
    ),
    Mutation(
        "A3: attributed to the bootstrap actor, so the audit log cannot tell "
        "a console grant from a startup one",
        CLI,
        [('std::string console_actor(const Config& config) {\n'
          '    return "@console:" + config.server_name;',
          'std::string console_actor(const Config& config) {\n'
          '    return "@server:" + config.server_name;')],
        "AdminCli.GrantAdminWritesAuthoritativeStateAndAuditAndSyncMirror",
    ),
    Mutation(
        "A4: runs happily behind a live server (the stream-position collision)",
        CLI,
        [("    if (!probe(config.bind_address, config.port)) return false;",
          "    if (true) return false;")],
        "AdminCli.RefusesToWriteBehindARunningServer",
        "AdminCli.GrantAdminWritesAuthoritativeStateAndAuditAndSyncMirror",
    ),
    Mutation(
        "A5: falls back to the built-in (relative) database path when --config is omitted",
        CLI,
        [('    if (out.config_path.empty()) {\n'
          '        out.error = "--config is required; this command will not guess which '
          'database to write to";\n'
          "        return out;\n"
          "    }",
          '    if (out.config_path.empty()) out.config_path = "./bsfchat-server.toml";')],
        "AdminCli.RefusesWithoutAConfigRatherThanGuessingADatabase",
    ),
    Mutation(
        "A6: a typo'd user id creates the account instead of refusing",
        CLI,
        [("    if (!store.user_exists(args.user_id)) {",
          "    if (!store.user_exists(args.user_id) && (store.create_user(args.user_id, \"\"), "
          "false)) {")],
        "AdminCli.RefusesAnAccountThatDoesNotExistInsteadOfCreatingIt",
    ),
    Mutation(
        "A7: the grant replaces the account's roles instead of adding to them",
        CLI,
        [("    std::vector<std::string> updated = current;\n"
          "    if (updated.empty()) updated.push_back(std::string(permission::role_id::kEveryone));",
          "    std::vector<std::string> updated;\n"
          "    updated.push_back(std::string(permission::role_id::kEveryone));")],
        "AdminCli.GrantAdminKeepsTheRolesTheAccountAlreadyHad",
    ),
    Mutation(
        "A8: `console` is registrable, so the audit actor is forgeable",
        AUTH,
        [('    if (skeleton == localpart_skeleton("server") || '
          'skeleton == localpart_skeleton("console") ||',
          '    if (skeleton == localpart_skeleton("server") ||')],
        "AuthHandlerTest.RegisterReservesTheConsoleActorUnderItsSkeletonToo",
        "AuthHandlerTest.RegisterReservesTheServerNameUnderItsSkeletonToo",
    ),
]


def object_files(source: Path):
    """Every compiled object for `source`, across every CMake target."""
    stem = source.name + ".o"
    return [p for p in BUILD.rglob(stem) if "_deps" not in str(p)]


def build():
    r = cmake_build(BUILD)
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
    require_build(BUILD)
    guard = MutationGuard(SERVER, builds=[BUILD])
    guard.recover()
    problems = []
    caught = 0

    for m in MUTATIONS:
        original = guard.protect(m.path).decode()
        mutated, err = apply_edits(original, m.edits)
        if err:
            problems.append(f"{m.name}: {err}")
            print(f"ERROR     {m.name}\n          {err}")
            continue

        m.path.write_text(mutated)
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
            guard.restore(m.path)

    print("\nRestoring the tree and rebuilding clean...")
    guard.restore_all()
    ok, log = build()
    if not ok:
        print("ERROR: clean rebuild FAILED after restore!\n" + log[-2000:])
        return 2
    green, out = run_tests("AdminCli.*:AuthHandlerTest.*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
