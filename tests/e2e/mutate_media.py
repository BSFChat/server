#!/usr/bin/env python3
"""Mutation-test the media range/streaming work.

Each mutation breaks exactly one property. A property is only actually covered
if a named test fails when it is broken. Object files are deleted before each
rebuild: make's timestamp granularity means a same-second edit can otherwise be
silently skipped, which produces confidently wrong mutation results.
"""
import os, subprocess, sys

from mutate_common import MutationGuard, build_dir, build_jobs, require_build, server_root

# Resolved from this script's own location (<repo>/tests/e2e/), so a run from a
# worktree mutates THAT worktree and not whichever checkout was hard-coded here.
# Override with BSFCHAT_SERVER=... / --srv=... See mutate_common.
SRV = str(server_root())
BUILD = str(build_dir(server_root(), "build-media"))
OBJDIR = f"{BUILD}/tests/CMakeFiles/server_tests.dir/__/src"

MEDIA_H = f"{SRV}/src/api/MediaHandler.cpp"
LOCAL = f"{SRV}/src/storage/LocalStorage.cpp"

OBJ = {
    MEDIA_H: f"{OBJDIR}/api/MediaHandler.cpp.o",
    LOCAL: f"{OBJDIR}/storage/LocalStorage.cpp.o",
}

# (name, file, find, replace, gtest_filter, tests expected to FAIL,
#  tests expected to still PASS)
MUTATIONS = [
    ("M1 LocalStorage reads whole file then slices (the original defect, "
     "pushed down into the backend)",
     LOCAL,
     """    // Only the requested window is ever allocated — never the whole file.
    out.resize(length);
    ifs.read(out.data(), static_cast<std::streamsize>(length));
    if (ifs.bad()) {
        out.clear();
        return false;
    }
    out.resize(static_cast<size_t>(ifs.gcount()));
    return true;""",
     """    std::ifstream whole(file_path, std::ios::binary);
    std::ostringstream oss;
    oss << whole.rdbuf();
    std::string all = oss.str();
    if (offset < all.size()) out = all.substr(offset, length);
    return true;""",
     "LocalStorageTest.*",
     ["LocalStorageTest.SmallRangeOnLargeFileDoesNotMaterialiseTheFile"],
     ["LocalStorageTest.DownloadRangeWindows"]),

    ("M2 handler goes back to storage_->download() + in-memory slicing",
     MEDIA_H,
     """            if (!storage->download_range(media_id, offset, want, *scratch)) {
                return false;
            }""",
     """            auto whole = storage->download(media_id);
            if (!whole) return false;
            *scratch = std::get<0>(*whole).substr(offset, want);""",
     "MediaRangeHandler.*:MediaHttpTest.*",
     ["MediaRangeHandler.OneByteRangeOnFiftyMegabyteObjectReadsOneByte",
      "MediaRangeHandler.ProviderIsContiguousAndOrderedAcrossChunks"],
     ["MediaHttpTest.MiddleWindow"]),

    ("M3 chunk cap removed: provider serves the entire requested range at once",
     MEDIA_H,
     "            want = std::min(want, kDownloadChunkBytes);",
     "            // chunk cap removed",
     "MediaRangeHandler.*",
     ["MediaRangeHandler.WholeFiftyMegabyteObjectStreamsInBoundedChunks",
      "MediaRangeHandler.NoRangeHeaderStillStreamsRatherThanMaterialising"],
     ["MediaRangeHandler.OneByteRangeOnFiftyMegabyteObjectReadsOneByte"]),

    ("M4 416 loses its Content-Range header",
     MEDIA_H,
     """        res.set_header("Content-Range", "bytes */" + std::to_string(info->size));""",
     """        // Content-Range dropped""",
     "MediaRangeHandler.*:MediaHttpTest.*",
     ["MediaRangeHandler.UnsatisfiableRangeGetsContentRangeStar",
      "MediaHttpTest.RangeStartingPastEndIsUnsatisfiable",
      "MediaHttpTest.ZeroLengthSuffixRangeIsUnsatisfiable"],
     []),

    ("M5 satisfiability pre-check removed entirely (httplib's own bare 416)",
     MEDIA_H,
     "    if (!req.ranges.empty() && ranges_unsatisfiable(req.ranges, info->size)) {",
     "    if (false) {",
     "MediaHttpTest.*",
     ["MediaHttpTest.RangeStartingPastEndIsUnsatisfiable",
      "MediaHttpTest.TooManyRangesIsRejectedNotAmplified"],
     ["MediaHttpTest.MiddleWindow"]),

    ("M6 multi-range cap raised to httplib's 1024",
     MEDIA_H,
     "constexpr size_t kMaxRangeCount = 4;",
     "constexpr size_t kMaxRangeCount = 1024;",
     "MediaRangeHandler.*:MediaHttpTest.*",
     ["MediaRangeHandler.TooManyRangesRejected",
      "MediaHttpTest.TooManyRangesIsRejectedNotAmplified"],
     ["MediaHttpTest.MultiRangeReturnsMultipartByteranges"]),

    ("M7 Accept-Ranges header dropped",
     MEDIA_H,
     """    res.set_header("Accept-Ranges", "bytes");""",
     """    // Accept-Ranges dropped""",
     "MediaHttpTest.*:MediaRangeHandler.*",
     ["MediaHttpTest.NoRangeServesWholeObjectWithAcceptRanges",
      "MediaRangeHandler.OneByteRangeOnFiftyMegabyteObjectReadsOneByte"],
     []),

    ("M8 zero-length range treated as satisfiable",
     MEDIA_H,
     "    return 0 <= first && first <= last && last <= len - 1;",
     "    return 0 <= first && first <= last + 1 && last <= len - 1;",
     "MediaHttpTest.*",
     ["MediaHttpTest.ZeroLengthSuffixRangeIsUnsatisfiable"],
     ["MediaHttpTest.MiddleWindow"]),

    ("M9 off-by-one seek in download_range",
     LOCAL,
     "    ifs.seekg(static_cast<std::streamoff>(offset), std::ios::beg);",
     "    ifs.seekg(static_cast<std::streamoff>(offset) + 1, std::ios::beg);",
     "LocalStorageTest.*:MediaHttpTest.*",
     ["LocalStorageTest.DownloadRangeWindows",
      "MediaHttpTest.MiddleWindow",
      "MediaHttpTest.LargeObjectRangesAreCorrectOverTheWire"],
     []),

    ("M10 stat() uses a non-zero size as its existence test, so an empty "
     "object looks missing",
     LOCAL,
     "    if (ec || !std::filesystem::is_regular_file(status)) {",
     "    if (ec || !std::filesystem::is_regular_file(status) ||\n"
     "        std::filesystem::file_size(file_path, ec) == 0) {",
     "LocalStorageTest.*:MediaHttpTest.*",
     ["LocalStorageTest.StatEmptyObjectIsFoundWithZeroSize",
      "MediaHttpTest.EmptyObjectServesZeroBytes",
      "MediaHttpTest.AnyRangeOnAnEmptyObjectIsUnsatisfiable"],
     ["MediaHttpTest.MiddleWindow"]),

    ("M11 media auth bypassed on download",
     MEDIA_H,
     "    if (config_.require_media_auth && !authenticate_media(req)) {",
     "    if (false && !authenticate_media(req)) {",
     "MediaHttpTest.*:MediaRangeHandler.*",
     ["MediaHttpTest.UnauthenticatedRangeRequestIs401",
      "MediaRangeHandler.RangeRequestStillRequiresAuth"],
     ["MediaHttpTest.QueryParamTokenAuthorisesARangeRequest"]),

    ("M12 ?access_token= fallback removed (QML Image.source path)",
     MEDIA_H,
     "    if (req.has_param(\"access_token\")) {",
     "    if (false) {",
     "MediaHttpTest.*",
     ["MediaHttpTest.QueryParamTokenAuthorisesARangeRequest"],
     ["MediaHttpTest.FirstByte"]),
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
