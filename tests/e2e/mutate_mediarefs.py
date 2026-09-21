#!/usr/bin/env python3
"""Mutation-test the media-reference authorisation work (audit finding F5).

Each mutation breaks exactly one property. A property is only actually covered
if a named test fails when it is broken. Object files are deleted before each
rebuild: make's timestamp granularity means a same-second edit can otherwise be
silently skipped, which produces confidently wrong mutation results.

Two directions are mutated on purpose, because `media_refs` decides two
different things:

  * OVER-collection is the finding. A reference nobody was allowed to create
    restores access to a revoked or redacted object, AND keeps its bytes off
    the media reaper's orphan list forever. M1-M3, M5-M8 break that guard.
  * UNDER-collection is the way a fix of this shape goes wrong. A legitimate
    reference that stops being recorded makes a working image 404 for everyone
    but its uploader — and, once the reaper is armed, gets the bytes deleted.
    M4, M9, M10, M11 revert one ingest path each and must be caught by a test
    that asserts a binding SURVIVES.
"""
import os, subprocess, sys

from mutate_common import MutationGuard, build_dir, build_jobs, require_build, server_root

# Resolved from this script's own location (<repo>/tests/e2e/), so a run from a
# worktree mutates THAT worktree and not whichever checkout was hard-coded here.
# Override with BSFCHAT_SERVER=... / --srv=... See mutate_common.
SRV = str(server_root())
BUILD = str(build_dir(server_root(), "build"))
OBJDIR = f"{BUILD}/tests/CMakeFiles/server_tests.dir/__/src"

REFS = f"{SRV}/src/store/MediaReferences.cpp"
STORE = f"{SRV}/src/store/SqliteStore.cpp"
ACCESS = f"{SRV}/src/auth/MediaAccess.cpp"
EVENTS = f"{SRV}/src/api/EventHandler.cpp"
PROFILE = f"{SRV}/src/api/ProfileHandler.cpp"
ROOMS = f"{SRV}/src/api/RoomHandler.cpp"
AUTOJOIN = f"{SRV}/src/auth/AutoJoin.cpp"

OBJ = {
    REFS: f"{OBJDIR}/store/MediaReferences.cpp.o",
    STORE: f"{OBJDIR}/store/SqliteStore.cpp.o",
    ACCESS: f"{OBJDIR}/auth/MediaAccess.cpp.o",
    EVENTS: f"{OBJDIR}/api/EventHandler.cpp.o",
    PROFILE: f"{OBJDIR}/api/ProfileHandler.cpp.o",
    ROOMS: f"{OBJDIR}/api/RoomHandler.cpp.o",
    AUTOJOIN: f"{OBJDIR}/auth/AutoJoin.cpp.o",
}

# Everything that reads or writes the media ACL. Wide on purpose: an
# over-collection mutation should show up as a failure somewhere in the media
# suite even when the test that names the property lives elsewhere.
FILT = ("MediaReferenceAuthz.*:MediaAcl.*:MediaAclMigration.*:MediaReaperTest.*"
        ":MediaTicketMint.*:MediaTicketDownload.*:NicknameStorage.*")

# (name, file, find, replace, gtest_filter, tests expected to FAIL,
#  tests expected to still PASS)
MUTATIONS = [
    ("M1 MediaReferences::permits says yes to everything — the pre-F5 index, "
     "where naming an id was the act that granted it",
     REFS,
     "    return std::binary_search(uris_.begin(), uris_.end(), mxc_uri);",
     "    (void)mxc_uri;\n    return true;",
     FILT,
     ["MediaReferenceAuthz.F5_ASenderCanRebindMediaItMayNotRead",
      "MediaReferenceAuthz.ARedactionCannotBeUndoneByALaterMention",
      "MediaReferenceAuthz.AChannelIconIsVettedLikeAnyOtherReference",
      "MediaReferenceAuthz.AnUnauthorisedMentionCannotKeepAnObjectOffTheOrphanList"],
     ["MediaReferenceAuthz.AForwardByAMemberOfTheSourceRoomWidensAccess",
      "MediaReferenceAuthz.AReplyQuotingAnImageCarriesItsOwnBinding",
      "MediaReferenceAuthz.TheReaperLeavesLegitimatelyReferencedMediaAlone"]),

    ("M2 the door drops its half of the rule: insert_event indexes every uri "
     "the content names again, whatever the caller vouched for",
     STORE,
     "            if (!media.permits(uri)) continue;",
     "            // authorisation check removed",
     FILT,
     ["MediaReferenceAuthz.F5_ASenderCanRebindMediaItMayNotRead",
      "MediaReferenceAuthz.ARedactionCannotBeUndoneByALaterMention",
      "MediaReferenceAuthz.ARedactionReasonCannotRebindTheObjectItDeletes",
      "MediaReferenceAuthz.AnUnauthorisedMentionCannotKeepAnObjectOffTheOrphanList"],
     ["MediaReferenceAuthz.AForwardByAMemberOfTheSourceRoomWidensAccess"]),

    ("M3 MediaAccess::vet stops asking may_read_uri and vouches for every uri "
     "it extracted",
     ACCESS,
     "        if (may_read_uri(principal, uri)) permitted.push_back(std::move(uri));",
     "        permitted.push_back(std::move(uri));",
     FILT,
     ["MediaReferenceAuthz.F5_ASenderCanRebindMediaItMayNotRead",
      "MediaReferenceAuthz.ARedactionCannotBeUndoneByALaterMention",
      "MediaReferenceAuthz.AChannelIconIsVettedLikeAnyOtherReference",
      "MediaReferenceAuthz.AnUnauthorisedMentionCannotKeepAnObjectOffTheOrphanList"],
     ["MediaReferenceAuthz.AForwardByAMemberOfTheSourceRoomWidensAccess",
      "MediaReferenceAuthz.AReplyQuotingAnImageCarriesItsOwnBinding"]),

    ("M4 the send path stops vetting and binds nothing — the under-collection "
     "direction, where an attachment 404s for everyone but its uploader",
     EVENTS,
     "    int64_t stream_pos = insert_event_vetted(store_, config_, event_id, room_id, *user_id,\n"
     "                                             evt_type, std::nullopt, content.dump(), now_ms());",
     "    int64_t stream_pos = store_.insert_event(event_id, room_id, *user_id, evt_type,\n"
     "                                             std::nullopt, content.dump(), now_ms());",
     FILT,
     ["MediaReferenceAuthz.AMentionByAReaderStillBinds",
      "MediaReferenceAuthz.AForwardByAMemberOfTheSourceRoomWidensAccess",
      "MediaReferenceAuthz.AReplyQuotingAnImageCarriesItsOwnBinding",
      "MediaReferenceAuthz.AnEditThatSwapsTheAttachmentBindsTheNewOne",
      "MediaReferenceAuthz.TheReaperLeavesLegitimatelyReferencedMediaAlone"],
     ["MediaReferenceAuthz.F5_ASenderCanRebindMediaItMayNotRead"]),

    ("M5 avatar_url is stored unvalidated again — the fall-through that makes a "
     "redacted object readable by every account on the server",
     PROFILE,
     "        if (!meta || meta->uploader != *user_id) {",
     "        if (false) {",
     FILT,
     ["MediaReferenceAuthz.ARedactedObjectCannotBeMadeServerPublicByWearingIt",
      "MediaReferenceAuthz.AnAttachmentYouCanSeeIsStillNotYoursToWear",
      "MediaReferenceAuthz.AnAvatarThatIsNotAnObjectHereIsRefusedIdentically"],
     ["MediaReferenceAuthz.YourOwnUploadIsStillAValidAvatar"]),

    ("M6 the avatar test is weakened from 'you uploaded it' to 'you can read "
     "it', which is the laundering route: adopt a colleague's attachment, wait "
     "for it to be redacted, and it is public",
     PROFILE,
     "        if (!meta || meta->uploader != *user_id) {",
     "        MediaAccess probe(store_, config_);\n"
     "        if (!meta || !probe.may_read(*user_id, avatar_url.substr(prefix.size()), *meta)) {",
     FILT,
     ["MediaReferenceAuthz.AnAttachmentYouCanSeeIsStillNotYoursToWear"],
     ["MediaReferenceAuthz.YourOwnUploadIsStillAValidAvatar",
      "MediaReferenceAuthz.AnAvatarThatIsNotAnObjectHereIsRefusedIdentically"]),

    ("M7 the redaction event is vetted like any other, so its `reason` can "
     "re-create the binding the redaction just deleted",
     EVENTS,
     "    store_.insert_event(event_id, room_id, *user_id,\n"
     "                        std::string(event_type::kRoomRedaction),\n"
     "                        std::nullopt, content.dump(), now_ms());",
     "    insert_event_vetted(store_, config_, event_id, room_id, *user_id,\n"
     "                        std::string(event_type::kRoomRedaction),\n"
     "                        std::nullopt, content.dump(), now_ms());",
     FILT,
     ["MediaReferenceAuthz.ARedactionReasonCannotRebindTheObjectItDeletes"],
     ["MediaReferenceAuthz.ARedactionCannotBeUndoneByALaterMention"]),

    ("M8 a member event is vouched for by whoever wrote it instead of by its "
     "subject, so an avatar's reachability depends on who moved the membership",
     ACCESS,
     "        (event_type == std::string(bsfchat::event_type::kRoomMember) && state_key && !state_key->empty())\n"
     "            ? *state_key\n"
     "            : sender;",
     "        sender;",
     FILT,
     ["MediaReferenceAuthz.AMemberEventBindsTheSubjectsAvatarNotTheSendersReach"],
     ["MediaReferenceAuthz.AutoJoinBindsTheJoinersAvatarInEveryChannel",
      "MediaReferenceAuthz.F5_ASenderCanRebindMediaItMayNotRead"]),

    ("M9 RoomHandler's state writes stop being vetted — every channel and "
     "server icon binds nothing",
     ROOMS,
     "    insert_event_vetted(store_, config_, event_id, room_id, sender, event_type, state_key,\n"
     "                        content.dump(), now_ms());",
     "    store_.insert_event(event_id, room_id, sender, event_type, state_key,\n"
     "                        content.dump(), now_ms());",
     FILT,
     ["MediaReferenceAuthz.AChannelIconIsVettedLikeAnyOtherReference",
      "MediaReferenceAuthz.AMemberEventBindsTheSubjectsAvatarNotTheSendersReach"],
     ["MediaReferenceAuthz.AutoJoinBindsTheJoinersAvatarInEveryChannel"]),

    ("M10 the profile fan-out stops being vetted, so changing your avatar "
     "unbinds it everywhere",
     PROFILE,
     "        insert_event_vetted(store_, config_, event_id, room_id, user_id,\n"
     "                            std::string(event_type::kRoomMember),\n"
     "                            user_id, room_content.dump(), now_ms());",
     "        store_.insert_event(event_id, room_id, user_id,\n"
     "                            std::string(event_type::kRoomMember),\n"
     "                            user_id, room_content.dump(), now_ms());",
     FILT,
     ["MediaReferenceAuthz.AMemberEventBindsTheSubjectsAvatarNotTheSendersReach"],
     ["MediaReferenceAuthz.YourOwnUploadIsStillAValidAvatar"]),

    ("M11 the force-join path stops being vetted, so a new member's avatar is "
     "unreachable in every channel they were put into",
     AUTOJOIN,
     "    insert_event_vetted(store, config, event_id, room_id, user_id,\n"
     "                        std::string(event_type::kRoomMember),\n"
     "                        user_id, content.dump(), now_ms());",
     "    store.insert_event(event_id, room_id, user_id,\n"
     "                        std::string(event_type::kRoomMember),\n"
     "                        user_id, content.dump(), now_ms());",
     FILT,
     ["MediaReferenceAuthz.AutoJoinBindsTheJoinersAvatarInEveryChannel"],
     ["MediaReferenceAuthz.AMemberEventBindsTheSubjectsAvatarNotTheSendersReach"]),

    ("M12 rule 3 reads 'no room recorded' as 'everybody' again — the read side "
     "the write side is now paired with",
     ACCESS,
     "    return store_.is_avatar_of(mxc_uri, meta.uploader);",
     "    return true;",
     FILT,
     ["MediaAcl.UnattachedMediaIsVisibleOnlyToItsUploader",
      "MediaAcl.RedactingTheMessageRevokesTheGrantItCarried",
      "MediaReferenceAuthz.ARedactedObjectCannotBeMadeServerPublicByWearingIt",
      "MediaReferenceAuthz.ARedactionCannotBeUndoneByALaterMention"],
     ["MediaAcl.AMemberOfTheChannelCanDownloadWhatWasPostedInIt"]),

    ("M13 the avatar rule goes back to 'is this ANYBODY's avatar', so a row "
     "laundered before the write check existed still grants",
     STORE,
     '        "SELECT 1 FROM users WHERE user_id = ? AND avatar_url = ? LIMIT 1");\n'
     '    sqlite3_bind_text(stmt.get(), 1, user_id.c_str(), -1, SQLITE_TRANSIENT);\n'
     '    sqlite3_bind_text(stmt.get(), 2, mxc_uri.c_str(), -1, SQLITE_TRANSIENT);',
     '        "SELECT 1 FROM users WHERE avatar_url = ? LIMIT 1");\n'
     '    (void)user_id;\n'
     '    sqlite3_bind_text(stmt.get(), 1, mxc_uri.c_str(), -1, SQLITE_TRANSIENT);',
     FILT,
     ["MediaReferenceAuthz.AnAlreadyLaunderedAvatarRowGrantsNothing"],
     ["MediaReferenceAuthz.YourOwnUploadIsStillAValidAvatar",
      "MediaAcl.AProfileAvatarIsReadableByAnyAuthenticatedUser"]),

    ("M14 the reaper's avatar clause drops the uploader condition, so wearing "
     "somebody else's redacted image keeps its bytes on disk forever",
     STORE,
     '        "  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.avatar_url = ? || m.media_id "\n'
     '        "                     AND u.user_id = m.uploader) "',
     '        "  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.avatar_url = ? || m.media_id) "',
     FILT,
     ["MediaReferenceAuthz.AnAlreadyLaunderedAvatarRowGrantsNothing"],
     ["MediaReaperTest.AProfileAvatarIsNeverCollected",
      "MediaReferenceAuthz.TheReaperLeavesLegitimatelyReferencedMediaAlone"]),
]


def build():
    r = subprocess.run(["nice", "-n", "19", "make", "-C", BUILD,
                        "-j" + build_jobs(), "server_tests"],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


def run(filt):
    r = subprocess.run([f"{BUILD}/tests/server_tests", f"--gtest_filter={filt}"],
                       capture_output=True, text=True, cwd=f"{BUILD}/tests")
    failed = set()
    for line in r.stdout.splitlines():
        if line.startswith("[  FAILED  ] ") and "(" in line:
            failed.add(line.split("] ", 1)[1].split(" (")[0])
    return failed, r.stdout


def main():
    require_build(BUILD)
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. recover() first
    # repairs anything a SIGKILLed run left applied.
    guard = MutationGuard(SRV, builds=[BUILD])
    guard.recover()
    results = []
    for name, path, find, repl, filt, expect_fail, expect_pass in MUTATIONS:
        orig = guard.protect(path).decode()
        if find not in orig:
            results.append((name, "SETUP-ERROR", "pattern not found"))
            print(f"!! {name}: pattern not found", flush=True)
            continue
        assert orig.count(find) == 1, f"{name}: pattern not unique"
        try:
            open(path, "w").write(orig.replace(find, repl))
            # Delete the object file: make's 1-second timestamp granularity can
            # otherwise skip the rebuild and attribute a stale binary's result.
            o = OBJ[path]
            if os.path.exists(o):
                os.remove(o)
            ok, log = build()
            if not ok:
                results.append((name, "BUILD-FAIL", log[-1500:]))
                print(f"!! {name}: build failed", flush=True)
                continue
            failed, out = run(filt)
            missing = [t for t in expect_fail if t not in failed]
            wrongly = [t for t in expect_pass if t in failed]
            status = "OK" if not missing and not wrongly else "WEAK"
            detail = f"failed={sorted(failed)}"
            if missing:
                detail += f" | EXPECTED-TO-FAIL-BUT-PASSED={missing}"
            if wrongly:
                detail += f" | COLLATERAL={wrongly}"
            results.append((name, status, detail))
            print(f"[{status}] {name}\n    {detail}", flush=True)
        finally:
            # Reverts the bytes, deletes the objects and stamps the source past
            # them: a same-second restore can otherwise be judged up to date by
            # make, leaving a stale object in the binary.
            guard.restore(path)

    print("\n=== revert + rebuild ===", flush=True)
    guard.restore_all()
    ok, log = build()
    print("rebuild ok" if ok else log[-2000:], flush=True)
    failed, _ = run("*")
    print("post-revert failures:", sorted(failed) or "none", flush=True)

    print("\n=== SUMMARY ===")
    for n, s, d in results:
        print(f"{s:12} {n}")
    return 0 if all(s == "OK" for _, s, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
