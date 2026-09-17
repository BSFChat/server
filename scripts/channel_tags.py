#!/usr/bin/env python3
"""Decide which image tags a pushed git tag should publish.

This is the server-side half of the release-channel rules the desktop
client already implements in client/src/core/ReleaseSelection.h. The two
must agree, because a user on the beta channel gets their app from GitHub
Releases and their server from ghcr.io, and "beta" has to mean the same
thing in both places.

    stable  = published non-prerelease tags, vX.Y.Z
    beta    = stable tags AND prereleases, vX.Y.Z-rc.N / -beta.N
              (newest of EITHER wins, so a stable release that is the
              newest thing in the repo also moves :latest-beta)

The one rule that makes this a script rather than a metadata-action
template: a moving tag points at the HIGHEST version, not at the most
recently pushed one. Cutting v0.0.43.1-style hotfix v0.0.43 after v0.0.44
has shipped must NOT drag :latest back onto the older line. docker
metadata-action's `type=semver` has no notion of the other tags in the
repo, so it cannot express that; we compare against every v* tag instead.

Usage:
    channel_tags.py --tag v0.0.44 --image ghcr.io/bsfchat/server \\
                    [--all-tags-file tags.txt | --all-tags v0.0.43,v0.0.44]

With neither --all-tags-file nor --all-tags it runs `git tag --list 'v*'`
in the current repository.

Writes GITHUB_OUTPUT-style key=value lines to stdout, and also appends
them to $GITHUB_OUTPUT when that is set:

    version=0.0.44            version without the leading v
    prerelease=false          for the GitHub Release's prerelease flag
    latest=true               whether this tag takes :latest
    latest_beta=true          whether this tag takes :latest-beta
    tags=ghcr.io/...:0.0.44,ghcr.io/...:0.0,ghcr.io/...:latest,...

Exits 1 with a message on a tag that is not vMAJOR.MINOR.PATCH[-pre].
"""

import argparse
import os
import re
import subprocess
import sys

# Deliberately strict, and the same grammar the client's release job
# enforces. An unparseable tag must fail the build rather than publish an
# image whose version string was silently synthesised.
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


class Version:
    """A parsed semver, ordered by semver.org §11 precedence."""

    __slots__ = ("major", "minor", "patch", "pre", "raw")

    def __init__(self, major, minor, patch, pre, raw):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.pre = pre  # tuple of identifier strings; empty => stable
        self.raw = raw

    @property
    def is_prerelease(self):
        return bool(self.pre)

    @property
    def core(self):
        return (self.major, self.minor, self.patch)

    def __repr__(self):  # pragma: no cover - debugging aid
        return "Version(%s)" % self.raw


def parse_tag(tag):
    """Parse 'v1.2.3-rc.4' -> Version, or None if it is not a release tag.

    Returning None rather than raising is what lets the repo hold tags
    that are not releases at all (say `nightly` or `v2-old`) without them
    poisoning the comparison.
    """
    if tag is None:
        return None
    m = TAG_RE.match(tag.strip())
    if not m:
        return None
    pre = ()
    if m.group(4) is not None:
        ids = m.group(4).split(".")
        # An empty identifier ("1.2.3-rc..1", trailing dot) is malformed.
        if any(i == "" for i in ids):
            return None
        pre = tuple(ids)
    return Version(int(m.group(1)), int(m.group(2)), int(m.group(3)), pre, tag.strip())


def _id_key(identifier):
    """Sort key for one prerelease identifier.

    Numeric identifiers compare numerically (so rc.10 > rc.9, which is
    exactly what a lexical sort gets wrong) and always rank BELOW
    alphanumeric ones. The leading 0/1 encodes that class ordering.
    """
    if identifier.isdigit():
        return (0, int(identifier), "")
    return (1, 0, identifier)


def compare(a, b):
    """-1 / 0 / +1 under semver precedence."""
    if a.core != b.core:
        return -1 if a.core < b.core else 1

    # Same core version. A prerelease has LOWER precedence than the
    # release it precedes: 0.0.44-rc.1 < 0.0.44. A string compare gets
    # this backwards, which would let an RC take :latest.
    if not a.pre and not b.pre:
        return 0
    if not a.pre:
        return 1
    if not b.pre:
        return -1

    for x, y in zip(a.pre, b.pre):
        kx, ky = _id_key(x), _id_key(y)
        if kx != ky:
            return -1 if kx < ky else 1
    # All shared identifiers equal: more identifiers wins (rc.1.1 > rc.1).
    if len(a.pre) != len(b.pre):
        return -1 if len(a.pre) < len(b.pre) else 1
    return 0


def compute(pushed_tag, all_tags):
    """Work out the channel assignment for `pushed_tag`.

    Returns a dict with version/prerelease/latest/latest_beta/line keys.
    Raises ValueError if the pushed tag is not a release tag.
    """
    pushed = parse_tag(pushed_tag)
    if pushed is None:
        raise ValueError(
            "tag %r is not vMAJOR.MINOR.PATCH[-prerelease]; retag rather than "
            "publishing an image with a synthesised version" % (pushed_tag,)
        )

    known = [v for v in (parse_tag(t) for t in all_tags) if v is not None]
    # The pushed tag may or may not be in the list we were handed (a
    # shallow CI checkout, a tag that has not been fetched). Include it
    # unconditionally; duplicates are harmless because comparison is by
    # value and we only ever ask "is anything strictly greater".
    known.append(pushed)

    # :latest — highest STABLE version. Only a stable tag can take it, and
    # only when nothing stable outranks it. "Strictly greater" (not >=)
    # means re-pushing the same tag re-asserts :latest rather than losing
    # it to its own duplicate entry.
    latest = False
    if not pushed.is_prerelease:
        latest = not any(
            (not v.is_prerelease) and compare(v, pushed) > 0 for v in known
        )

    # :latest-beta — highest of stable OR prerelease. A stable release is
    # eligible here too: beta testers must not be stranded on an older RC
    # once the real release lands.
    latest_beta = not any(compare(v, pushed) > 0 for v in known)

    # X.Y line tag, same rule one level down: the highest stable patch on
    # that minor line. Prereleases never take it.
    line = False
    if not pushed.is_prerelease:
        line = not any(
            (not v.is_prerelease)
            and v.major == pushed.major
            and v.minor == pushed.minor
            and compare(v, pushed) > 0
            for v in known
        )

    # Rebuilt from the parsed components rather than sliced off the raw
    # tag: that drops any `+build` metadata, which semver says takes no
    # part in precedence and which docker rejects in a tag name anyway.
    version = "%d.%d.%d" % pushed.core
    if pushed.pre:
        version += "-" + ".".join(pushed.pre)

    return {
        "version": version,
        "prerelease": pushed.is_prerelease,
        "latest": latest,
        "latest_beta": latest_beta,
        "line": line,
        "line_tag": "%d.%d" % (pushed.major, pushed.minor),
    }


def image_tags(result, image):
    """Full image references for docker/build-push-action, in push order."""
    tags = ["%s:%s" % (image, result["version"])]
    if result["line"]:
        tags.append("%s:%s" % (image, result["line_tag"]))
    if result["latest"]:
        tags.append("%s:latest" % image)
    if result["latest_beta"]:
        tags.append("%s:latest-beta" % image)
    return tags


def git_tags():
    out = subprocess.run(
        ["git", "tag", "--list", "v*"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    return [line for line in out.splitlines() if line.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tag", required=True, help="the pushed git tag, e.g. v0.0.44")
    ap.add_argument("--image", default="ghcr.io/bsfchat/server")
    ap.add_argument("--all-tags", help="comma-separated tag list (testing)")
    ap.add_argument("--all-tags-file", help="file with one tag per line")
    args = ap.parse_args(argv)

    if args.all_tags_file:
        with open(args.all_tags_file) as fh:
            tags = [line for line in fh.read().splitlines() if line.strip()]
    elif args.all_tags is not None:
        tags = [t for t in args.all_tags.split(",") if t.strip()]
    else:
        tags = git_tags()

    try:
        result = compute(args.tag, tags)
    except ValueError as exc:
        # ::error:: makes this show up as a job annotation, not just a log line.
        print("::error::%s" % exc, file=sys.stderr)
        return 1

    refs = image_tags(result, args.image)
    lines = [
        "version=%s" % result["version"],
        "prerelease=%s" % ("true" if result["prerelease"] else "false"),
        "latest=%s" % ("true" if result["latest"] else "false"),
        "latest_beta=%s" % ("true" if result["latest_beta"] else "false"),
        "tags=%s" % ",".join(refs),
    ]
    for line in lines:
        print(line)

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as fh:
            fh.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
