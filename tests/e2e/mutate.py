#!/usr/bin/env python3
"""Mutation-test the F1/F2 work: break each fix, confirm a test fails, revert."""
import subprocess, sys, shutil, os, pathlib

SRV = pathlib.Path("/Users/josh/dev/gamechat/server")
BUILD = SRV / "build-fix"
TESTBIN = BUILD / "tests" / "server_tests"

# (label, file, old, new, gtest_filter, timeout_s)
MUTATIONS = [
 ("F4a count_unread ignores edits",
  "src/store/SqliteStore.cpp",
  '"AND replaces IS NULL "\n        "AND redacted_by IS NULL "',
  '"AND redacted_by IS NULL "',
  "UnreadCount.EditingYourOwnMessageDoesNotBumpEveryoneElsesBadge", 120),

 ("F4b count_unread ignores redactions",
  "src/store/SqliteStore.cpp",
  '"AND replaces IS NULL "\n        "AND redacted_by IS NULL "',
  '"AND replaces IS NULL "',
  "UnreadCount.RedactedMessagesStopCountingAsUnread", 120),

 ("F1 self-mention drop removed",
  "src/api/EventHandler.cpp",
  "        if (target == sender) continue;",
  "        // MUTATED",
  "Mentions.SelfMentionDoesNotBadgeYourOwnRoom", 120),

 ("F1 VIEW_CHANNEL check on mention target removed",
  "src/api/EventHandler.cpp",
  "        if (!perms.can(target, room_id, permission::kViewChannel)) continue;",
  "        // MUTATED",
  "Mentions.MentioningSomeoneWithoutViewChannelIsDropped", 120),

 ("F1 membership check on mention target removed",
  "src/api/EventHandler.cpp",
  "        if (!store.is_room_member(room_id, target)) continue;",
  "        // MUTATED",
  "Mentions.MentioningANonMemberIsDropped", 120),

 ("F1 MENTION_EVERYONE gate removed",
  "src/api/EventHandler.cpp",
  "            if (!permission::has(user_perms, permission::kMentionEveryone)) {\n                out.error = {403, MatrixError::forbidden(\n                    \"You don't have permission to mention everyone\")};\n                return out;\n            }",
  "            // MUTATED",
  "Mentions.RoomWideMentionRequiresMentionEveryone:Mentions.RoomWidePermissionIsEnforcedOnEditsToo", 120),

 ("F1 @room sentinel forgery guard removed",
  "src/api/EventHandler.cpp",
  "        if (target == kRoomMentionSentinel) continue;",
  "        // MUTATED",
  "Mentions.RoomSentinelCannotBeForgedThroughUserIds", 120),

 ("F1 edits allowed to record mentions",
  "src/api/EventHandler.cpp",
  "    if (!edit_target && !mentions.empty()) {",
  "    if (!mentions.empty()) {",
  "Mentions.EditingAMessageCannotInjectAFreshMention", 120),

 ("F1 redaction no longer clears mentions",
  "src/store/SqliteStore.cpp",
  '    if (newly_redacted) {\n        auto del = prepare(db_, "DELETE FROM event_mentions WHERE event_id = ?");',
  '    if (false) {\n        auto del = prepare(db_, "DELETE FROM event_mentions WHERE event_id = ?");',
  "Mentions.RedactingAMessageClearsItsMentionBadge", 120),

 ("F1 mention rows survive room deletion",
  "src/store/SqliteStore.cpp",
  '        run("DELETE FROM event_mentions WHERE room_id = ?");',
  '        // MUTATED',
  "Mentions.DeletingARoomLeavesNoOrphanedMentionRows", 120),

 ("F2 sender excluded from push candidates removed",
  "src/store/SqliteStore.cpp",
  '"  AND p.user_id != ? AND p.kind = \'http\' AND p.url != \'\'"',
  '"  AND p.user_id != COALESCE(NULL, \'\') AND p.kind = \'http\' AND p.url != \'\'"',
  "PushEvaluation.SenderIsNeverPushedForTheirOwnMessage", 120),

 ("F2 VIEW_CHANNEL gate on push removed",
  "src/push/PushService.cpp",
  "            if (!perms.can(user_id, n.room_id, permission::kViewChannel)) return false;",
  "            // MUTATED",
  "PushEvaluation.UsersWithoutViewChannelAreNeverPushed", 120),

 ("F2 edits allowed to push again",
  "src/api/EventHandler.cpp",
  "    if (push_ && !edit_target && evt_type == std::string(event_type::kRoomMessage)) {",
  "    if (push_ && evt_type == std::string(event_type::kRoomMessage)) {",
  "PushEvaluation.EditsDoNotFireASecondNotification", 120),

 ("F2 rejected pusher no longer removed",
  "src/push/PushService.cpp",
  "                int removed = store_.delete_pushers_by_pushkey(pushkey);",
  "                int removed = 0; (void)pushkey;",
  "PushDelivery.RejectedPushkeyRemovesThePusher", 120),

 ("F2 event_id_only privacy mode ignored",
  "src/push/PushService.cpp",
  '        if (pusher.format != "event_id_only") {',
  "        if (true) {",
  "PushEvaluation.EventIdOnlyPushersDoNotLeakMessageContent", 120),

 ("F2 gateway URL validation removed (SSRF)",
  "src/api/PushHandler.cpp",
  "    const bool http = url.rfind(\"http://\", 0) == 0;",
  "    if (true) return true;\n    const bool http = url.rfind(\"http://\", 0) == 0;",
  "Pushers.GatewayUrlMustBeAbsoluteHttpAndCarryNoCredentials:Pushers.GatewayAllowlistIsEnforcedWhenConfigured", 120),

 ("F2 queue lease removed (duplicate delivery)",
  "src/store/SqliteStore.cpp",
  "        sqlite3_bind_int64(upd.get(), 1, now_ms + lease_ms);",
  "        sqlite3_bind_int64(upd.get(), 1, now_ms);",
  "PushDelivery.LeasePreventsTheSameRowBeingDeliveredTwice", 120),

 ("F2 pushkey reassignment no longer evicts old owner",
  "src/api/PushHandler.cpp",
  "        int removed = store_.delete_pushers_by_pushkey_except(pushkey, *user_id, app_id);",
  "        int removed = 0;",
  "Pushers.RegisteringAPushkeyTakesItFromWhoeverHadItBefore", 120),

 ("v9 backfill of `replaces` removed",
  "src/store/Migrations.cpp",
  "            auto target = replacement_target(text_or_empty(sel.get(), 1));\n            if (target) rows.emplace_back(text_or_empty(sel.get(), 0), *target);",
  "            // MUTATED",
  "MigrationV11.ReplacesIsBackfilledFromExistingContent:MigrationV11.UnreadCountOnUpgradedDataExcludesEditsAndRedactions", 120),

 ("F2 delivery moved INLINE onto the send path",
  "src/push/PushService.cpp",
  "    if (queue.empty()) return 0;\n    // A local INSERT and nothing more. Delivery happens on the worker thread.\n    store_.enqueue_pushes(queue);",
  "    if (queue.empty()) return 0;\n    store_.enqueue_pushes(queue);\n    drain_once();",
  "PushDelivery.SendPathDoesNotWaitOnTheGateway", 45),
]


def run(cmd, timeout=None):
    return subprocess.run(cmd, shell=True, cwd=SRV, capture_output=True,
                          text=True, timeout=timeout)


def main():
    results = []
    backups = {}
    files = {m[1] for m in MUTATIONS}
    for f in files:
        backups[f] = (SRV / f).read_text()

    for label, relpath, old, new, filt, tmo in MUTATIONS:
        path = SRV / relpath
        src = backups[relpath]
        if old not in src:
            results.append((label, "SKIP", "mutation anchor not found"))
            continue
        assert src.count(old) == 1, f"{label}: anchor not unique ({src.count(old)})"
        path.write_text(src.replace(old, new, 1))

        build = run("cmake --build build-fix -j8", timeout=900)
        if build.returncode != 0:
            results.append((label, "BUILD-FAIL",
                            "mutation did not compile (still counts as detected)"))
            path.write_text(src)
            continue

        try:
            t = run(f"./build-fix/tests/server_tests --gtest_filter='{filt}'", timeout=tmo)
            if t.returncode != 0:
                names = [l.strip() for l in t.stdout.splitlines() if l.strip().startswith("[  FAILED  ]")]
                results.append((label, "DETECTED", "; ".join(names[:3]) or "test failed"))
            else:
                results.append((label, "*** SURVIVED ***", "tests still passed!"))
        except subprocess.TimeoutExpired:
            results.append((label, "DETECTED", f"test hung (>{tmo}s) — blocked, which is the failure"))

        path.write_text(src)

    # restore + rebuild clean
    for f, src in backups.items():
        (SRV / f).write_text(src)
    run("cmake --build build-fix -j8", timeout=900)

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


sys.exit(main())
