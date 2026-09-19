#!/usr/bin/env python3
"""Mutation-test the audit-log tests.

For each mutation: break one property in the source, rebuild, run the tests that
are supposed to detect it, and confirm they FAIL. Then revert. A mutation that
leaves the suite green means the corresponding test proves nothing.
"""
import subprocess, sys, os, re

from mutate_common import MutationGuard, build_dir, cmake_build, require_build, server_root

# Resolved from this script's own location (<repo>/tests/e2e/), so a run from a
# worktree mutates THAT worktree and not whichever checkout was hard-coded here.
# Override with BSFCHAT_SERVER=... / --srv=... See mutate_common.
SERVER = str(server_root())
BUILD = str(build_dir(server_root(), "build-fix"))

# (label, file, old, new, ctest -R regex)
MUTATIONS = [
    (
        "M1 kick does not record",
        "src/api/RoomHandler.cpp",
        """    audit_membership_change(store_, *user_id, room_id, target_user, previous_membership,
                            std::string(membership::kLeave), reason);

    res.set_content("{}", "application/json");
    get_logger()->info("User {} kicked {} from room {}", *user_id, target_user, room_id);""",
        """    res.set_content("{}", "application/json");
    get_logger()->info("User {} kicked {} from room {}", *user_id, target_user, room_id);""",
        "AuditWrites.KickWritesExactlyOneRecord",
    ),
    (
        "M2 wrong actor recorded (target attributed as actor)",
        "src/audit/AuditLog.cpp",
        """    SqliteStore::AuditRecord record;
    record.actor = actor;
    record.action = membership_audit_action(before_membership, after_membership);
    record.target_user = target_user;""",
        """    SqliteStore::AuditRecord record;
    record.actor = target_user;
    record.action = membership_audit_action(before_membership, after_membership);
    record.target_user = target_user;""",
        "AuditWrites.KickWritesExactlyOneRecord|AuditWrites.BanWritesExactlyOneRecord|AuditWrites.UnbanWorksAndWritesExactlyOneRecord",
    ),
    (
        "M3 room deletion audited AFTER delete_room",
        "src/api/RoomHandler.cpp",
        """    audit_room_deletion(store_, *user_id, room_id);

    store_.delete_room(room_id);""",
        """    store_.delete_room(room_id);
    audit_room_deletion(store_, *user_id, room_id);""",
        "AuditWrites.ChannelDeletionIsRecordedAndOutlivesTheChannel|AuditWrites.CategoryDeletionUsesTheCategoryAction",
    ),
    (
        "M4 audit gate evaluated per-channel instead of at server scope",
        "src/api/AuditHandler.cpp",
        """    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, "", permission::kManageServer)) {""",
        """    PermissionsEngine perms(store_, config_);
    bool granted = perms.can(*user_id, "", permission::kManageServer);
    for (const auto& mut_room : store_.get_joined_rooms(*user_id)) {
        if (perms.can(*user_id, mut_room, permission::kManageServer)) granted = true;
    }
    if (!granted) {""",
        "AuditEndpoint.PerChannelOverrideDoesNotGrantAccess",
    ),
    (
        "M5 audit gate uses a flag every member has",
        "src/api/AuditHandler.cpp",
        """    if (!perms.can(*user_id, "", permission::kManageServer)) {""",
        """    if (!perms.can(*user_id, "", permission::kViewChannel)) {""",
        "AuditEndpoint.PlainMemberIsRefused|AuditEndpoint.ModeratorWithoutManageServerIsRefused",
    ),
    (
        "M6 id is a plain rowid (reusable) instead of AUTOINCREMENT",
        "src/store/Migrations.cpp",
        "            id           INTEGER PRIMARY KEY AUTOINCREMENT,",
        "            id           INTEGER PRIMARY KEY,",
        "AuditMigration.FreshDatabaseGetsV13WithAnAppendOnlySchema|AuditPagination.IdsAreNeverReusedEvenAfterARowIsForciblyRemoved",
    ),
    (
        "M7 append-only triggers removed",
        "src/store/Migrations.cpp",
        """    exec(db, R"(
        CREATE TRIGGER IF NOT EXISTS audit_log_is_append_only_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
        END
    )");
    exec(db, R"(
        CREATE TRIGGER IF NOT EXISTS audit_log_is_append_only_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
        END
    )");""",
        "    // triggers removed by mutation test",
        "AuditMigration.FreshDatabaseGetsV13WithAnAppendOnlySchema|AuditImmutability.TheDatabaseItselfRejectsAnUpdate|AuditImmutability.TheDatabaseItselfRejectsADelete",
    ),
    (
        "M8 pagination cursor is inclusive (id <= ?)",
        "src/store/SqliteStore.cpp",
        'if (before_id) sql += "WHERE id < ? ";',
        'if (before_id) sql += "WHERE id <= ? ";',
        "AuditPagination.IsStableWhenNewRecordsLandBetweenPages|AuditPagination.IsStableUnderConcurrentWriters",
    ),
    (
        "M9 pagination ordered by timestamp instead of monotonic id",
        "src/store/SqliteStore.cpp",
        'sql += "ORDER BY id DESC LIMIT ?";',
        'sql += "ORDER BY created_at DESC LIMIT ?";',
        "AuditPagination.IsStableWhenNewRecordsLandBetweenPages|AuditPagination.IsStableUnderConcurrentWriters",
    ),
    (
        "M10 audit reason leaks into a searchable message event",
        "src/audit/AuditLog.cpp",
        """    record.before_json = json{{"membership", before_membership}}.dump();
    record.after_json = json{{"membership", after_membership}}.dump();
    store.append_audit_record(record);""",
        """    record.before_json = json{{"membership", before_membership}}.dump();
    record.after_json = json{{"membership", after_membership}}.dump();
    store.append_audit_record(record);
    if (!reason.empty() && !room_id.empty()) {
        store.insert_event("$mut" + std::to_string(store.get_current_stream_position()),
                           room_id, actor, "m.room.message", std::nullopt,
                           json{{"msgtype", "m.text"}, {"body", reason}}.dump(), 1);
    }""",
        "AuditSearch.RecordsNeverEnterTheMessageSearchIndex",
    ),
    (
        "M11 delete_room also prunes the room's audit records",
        "src/store/SqliteStore.cpp",
        """        run("DELETE FROM events WHERE room_id = ?");""",
        """        exec("DROP TRIGGER IF EXISTS audit_log_is_append_only_delete");
        run("DELETE FROM audit_log WHERE target_room = ?");
        exec("CREATE TRIGGER audit_log_is_append_only_delete BEFORE DELETE ON audit_log "
             "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted'); END");
        run("DELETE FROM events WHERE room_id = ?");""",
        "AuditImmutability.DeletingARoomDoesNotDisturbItsAuditRecords",
    ),
    (
        "M12 unchanged roles recorded as updates (diff removed)",
        "src/audit/AuditLog.cpp",
        """            if (before_payload != after_payload) {
                append_role_record(store, actor, audit_action::kRoleUpdate, id,
                                   before_payload, after_payload);
            }""",
        """            append_role_record(store, actor, audit_action::kRoleUpdate, id,
                               before_payload, after_payload);""",
        "AuditWrites.ARoleWriteThatChangesNothingRecordsNothing|AuditWrites.RoleCreationUpdateAndDeletionRecordPermissionBitfields",
    ),
    (
        "M13 role assignment before-state read after the write (stale before)",
        "src/auth/RoleBootstrap.cpp",
        """    auto previous = store.set_server_state(evt_type, state_key, actor, content_json);""",
        """    store.set_server_state(evt_type, state_key, actor, content_json);
    auto previous = store.get_server_state(evt_type, state_key);""",
        "AuditWrites.RoleAssignmentChangeRecordsWhatWasAddedAndRemoved|AuditWrites.RoleCreationUpdateAndDeletionRecordPermissionBitfields|AuditWrites.BootstrapRoleAssignmentIsAttributedToTheServer",
    ),
    (
        "M14 membership transition ignored (kick and unban conflated)",
        "src/audit/AuditLog.cpp",
        """    if (after_membership == membership::kLeave) {
        return before_membership == membership::kBan ? audit_action::kMemberUnban
                                                     : audit_action::kMemberKick;
    }""",
        """    if (after_membership == membership::kLeave) return audit_action::kMemberKick;""",
        "AuditWrites.UnbanWorksAndWritesExactlyOneRecord|AuditWrites.MembershipActionNameFollowsTheTransition",
    ),
    (
        "M15 ban via the generic state endpoint is not recorded",
        "src/api/RoomHandler.cpp",
        """    } else if (is_other_membership) {
        audit_membership_change(store_, *user_id, room_id, state_key, previous_membership,
                                content.value("membership", ""), content.value("reason", ""));
    }""",
        "    }",
        "AuditWrites.BanThroughTheGenericStateEndpointIsAlsoRecorded",
    ),
]


def build():
    r = cmake_build(BUILD)
    return r.returncode == 0, r.stdout + r.stderr


def run_tests(regex):
    r = subprocess.run(["ctest", "-R", regex], cwd=BUILD, capture_output=True, text=True)
    return r.returncode, r.stdout


SUMMARY = re.compile(r"(\d+)% tests passed, (\d+) tests failed out of (\d+)")


def main():
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. The old sidecar
    # .mutbak copy could not do that: an interrupted run left both the mutation
    # and the backup sitting in the tree. recover() repairs what a SIGKILL left.
    require_build(BUILD)
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. recover() first
    # repairs anything a SIGKILLed run left applied.
    guard = MutationGuard(SERVER, builds=[BUILD])
    guard.recover()
    results = []
    for label, rel, old, new, regex in MUTATIONS:
        path = os.path.join(SERVER, rel)
        try:
            src = guard.protect(path).decode()
            n = src.count(old)
            if n != 1:
                results.append((label, "BAD-ANCHOR", f"anchor matched {n} times"))
                continue
            open(path, "w").write(src.replace(old, new))
            # Make certain the change is actually in the binary. mtime alone is not
            # enough: two consecutive mutations to the SAME file can land inside
            # make's timestamp resolution and it will consider the object current,
            # which shows up as a bogus "not detected". Delete the object files for
            # this translation unit so the compile cannot be skipped.
            os.utime(path, None)
            stem = os.path.basename(rel)
            subprocess.run(["find", BUILD, "-name", stem + ".o", "-delete"],
                           capture_output=True)
            # The same hazard applies in reverse on the way out; guard.restore()
            # purges the objects and stamps the restored source past them.
            ok, log = build()
            if not ok:
                results.append((label, "BUILD-FAILED", log[-600:].replace("\n", " ")))
                continue
            unit = os.path.basename(rel)
            if unit not in log:
                results.append((label, "NOT-RECOMPILED", f"{unit} absent from the build log"))
                continue

            rc, out = run_tests(regex)
            m = SUMMARY.search(out)
            failed, total = (int(m.group(2)), int(m.group(3))) if m else (0, 0)
            if total == 0:
                results.append((label, "NO-TESTS-MATCHED", regex))
                continue
            results.append((
                label,
                "DETECTED" if failed > 0 else "NOT DETECTED",
                f"{failed}/{total} targeted tests failed (ctest rc={rc})",
            ))
        finally:
            guard.restore(path)
            print(f"... done: {label}", flush=True)

    guard.restore_all()
    ok, log = build()
    print("\n=== restored build:", "OK" if ok else "FAILED\n" + log)
    print("\n=== MUTATION RESULTS ===")
    bad = 0
    for label, verdict, detail in results:
        print(f"{verdict:14} | {label} — {detail}")
        if verdict != "DETECTED":
            bad = 1
    return bad


if __name__ == "__main__":
    sys.exit(main())
