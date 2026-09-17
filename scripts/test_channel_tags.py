#!/usr/bin/env python3
"""Table-driven tests for scripts/channel_tags.py.

Run directly (`python3 scripts/test_channel_tags.py`) or via ctest
(`ctest --test-dir build -R channel_tags`). No third-party dependencies:
this has to run on a bare CI runner before anything else is installed.

The cases below are the ones that make a moving tag wrong in practice.
Each entry is (name, pushed_tag, existing_tags, expected_latest,
expected_latest_beta).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import channel_tags as ct  # noqa: E402


CASES = [
    # --- the ordinary path ----------------------------------------------
    (
        "first ever stable release takes both channels",
        "v0.1.0",
        [],
        True,
        True,
    ),
    (
        "newest stable takes both channels",
        "v0.0.44",
        ["v0.0.42", "v0.0.43", "v0.0.44"],
        True,
        True,
    ),
    # --- hotfix on an older line ----------------------------------------
    # The case docker metadata-action's type=semver gets wrong: it would
    # move :latest back onto 0.0.43 simply because that tag was pushed
    # most recently, downgrading every deployment tracking stable.
    (
        "hotfix on an older line must not steal :latest",
        "v0.0.43",
        ["v0.0.43", "v0.0.44", "v0.0.45"],
        False,
        False,
    ),
    (
        "hotfix on an older line still gets its own X.Y.Z tag",
        "v1.2.3",
        ["v1.2.3", "v2.0.0"],
        False,
        False,
    ),
    # --- prereleases ------------------------------------------------------
    (
        "an rc never takes :latest, but takes :latest-beta when newest",
        "v0.0.45-rc.1",
        ["v0.0.44", "v0.0.45-rc.1"],
        False,
        True,
    ),
    (
        "rc after the stable it precedes is NOT newer (0.0.44-rc.1 < 0.0.44)",
        "v0.0.44-rc.1",
        ["v0.0.44", "v0.0.44-rc.1"],
        False,
        False,
    ),
    (
        "stable after its own rcs takes both channels back",
        "v0.0.44",
        ["v0.0.44-rc.1", "v0.0.44-rc.2", "v0.0.44"],
        True,
        True,
    ),
    (
        "rc.10 outranks rc.9 (numeric, not lexical)",
        "v0.0.44-rc.10",
        ["v0.0.44-rc.9", "v0.0.44-rc.10"],
        False,
        True,
    ),
    (
        "rc.9 pushed after rc.10 does not take :latest-beta",
        "v0.0.44-rc.9",
        ["v0.0.44-rc.9", "v0.0.44-rc.10"],
        False,
        False,
    ),
    (
        "an older rc line loses to a newer stable",
        "v0.0.43-rc.5",
        ["v0.0.43-rc.5", "v0.0.44"],
        False,
        False,
    ),
    (
        "beta identifier is treated like rc",
        "v0.1.0-beta.2",
        ["v0.0.44", "v0.1.0-beta.1", "v0.1.0-beta.2"],
        False,
        True,
    ),
    # --- re-pushing / non-release tags ------------------------------------
    (
        "re-pushing the current newest tag re-asserts both channels",
        "v0.0.44",
        ["v0.0.44"],
        True,
        True,
    ),
    (
        "tags that are not releases are ignored, not fatal",
        "v0.0.44",
        ["nightly", "v2-old", "release-candidate", "v0.0.44"],
        True,
        True,
    ),
    (
        "the pushed tag need not be in the list (shallow checkout)",
        "v0.0.45",
        ["v0.0.43", "v0.0.44"],
        True,
        True,
    ),
    (
        "major version ordering",
        "v0.9.9",
        ["v0.9.9", "v1.0.0"],
        False,
        False,
    ),
]


class ChannelTable(unittest.TestCase):
    def test_table(self):
        for name, tag, existing, want_latest, want_beta in CASES:
            with self.subTest(name):
                got = ct.compute(tag, existing)
                self.assertEqual(got["latest"], want_latest, "%s: latest" % name)
                self.assertEqual(
                    got["latest_beta"], want_beta, "%s: latest-beta" % name
                )


class VersionParsing(unittest.TestCase):
    def test_accepts(self):
        for tag in ["v0.0.1", "v1.2.3", "v10.20.30", "v1.2.3-rc.1",
                    "v1.2.3-beta.10", "v1.2.3-alpha", "v1.2.3-rc.1+abc123"]:
            self.assertIsNotNone(ct.parse_tag(tag), tag)

    def test_rejects(self):
        # No leading v, wrong component count, empty identifiers, junk.
        for tag in ["1.2.3", "v1.2", "v1.2.3.4", "v1.2.x", "v1.2.3-",
                    "v1.2.3-rc..1", "", "vv1.2.3", "v1.2.3-rc.1!"]:
            self.assertIsNone(ct.parse_tag(tag), tag)

    def test_build_metadata_is_ignored_for_precedence(self):
        a = ct.parse_tag("v1.2.3+aaa")
        b = ct.parse_tag("v1.2.3+bbb")
        self.assertEqual(ct.compare(a, b), 0)

    def test_prerelease_below_its_release(self):
        self.assertEqual(
            ct.compare(ct.parse_tag("v0.0.44-rc.1"), ct.parse_tag("v0.0.44")), -1
        )

    def test_numeric_identifier_below_alphanumeric(self):
        # semver.org §11.4.3: numeric identifiers always have lower
        # precedence than alphanumeric ones.
        self.assertEqual(
            ct.compare(ct.parse_tag("v1.0.0-1"), ct.parse_tag("v1.0.0-alpha")), -1
        )

    def test_more_identifiers_wins(self):
        self.assertEqual(
            ct.compare(ct.parse_tag("v1.0.0-rc.1.1"), ct.parse_tag("v1.0.0-rc.1")), 1
        )

    def test_build_metadata_is_stripped_from_the_image_tag(self):
        # '+' is not a legal character in a docker tag, so it must not
        # survive into the published name.
        self.assertEqual(
            ct.compute("v1.2.3+abc123", ["v1.2.3+abc123"])["version"], "1.2.3"
        )

    def test_bad_tag_raises(self):
        with self.assertRaises(ValueError):
            ct.compute("not-a-tag", ["v1.0.0"])


class ImageTags(unittest.TestCase):
    IMAGE = "ghcr.io/bsfchat/server"

    def refs(self, tag, existing):
        return ct.image_tags(ct.compute(tag, existing), self.IMAGE)

    def test_newest_stable_pushes_every_moving_tag(self):
        self.assertEqual(
            self.refs("v0.0.44", ["v0.0.43", "v0.0.44"]),
            [
                "ghcr.io/bsfchat/server:0.0.44",
                "ghcr.io/bsfchat/server:0.0",
                "ghcr.io/bsfchat/server:latest",
                "ghcr.io/bsfchat/server:latest-beta",
            ],
        )

    def test_rc_pushes_only_its_own_tag_and_beta(self):
        self.assertEqual(
            self.refs("v0.0.45-rc.1", ["v0.0.44", "v0.0.45-rc.1"]),
            [
                "ghcr.io/bsfchat/server:0.0.45-rc.1",
                "ghcr.io/bsfchat/server:latest-beta",
            ],
        )

    def test_hotfix_on_old_line_pushes_only_its_own_tag(self):
        # 1.2.4 is the newest on the 1.2 line, so it takes :1.2 — but
        # 2.0.0 exists, so it takes neither channel tag.
        self.assertEqual(
            self.refs("v1.2.4", ["v1.2.3", "v1.2.4", "v2.0.0"]),
            [
                "ghcr.io/bsfchat/server:1.2.4",
                "ghcr.io/bsfchat/server:1.2",
            ],
        )

    def test_superseded_patch_does_not_take_the_line_tag(self):
        self.assertEqual(
            self.refs("v1.2.3", ["v1.2.3", "v1.2.4"]),
            ["ghcr.io/bsfchat/server:1.2.3"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
