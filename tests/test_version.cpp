// Version-string parsing for the build banner and /_matrix/client/versions.
//
// The cases here are deliberately the same ones the client's
// test_update_channel covers, because a disagreement between the two
// about what "-rc.1" means is the bug this whole channel scheme exists
// to prevent.

#include <gtest/gtest.h>

#include "core/Version.h"

using namespace bsfchat::build;

TEST(BuildVersion, ParsesPlainRelease) {
    const auto v = parse_version("0.0.44");
    ASSERT_TRUE(v.valid);
    EXPECT_EQ(v.major, 0);
    EXPECT_EQ(v.minor, 0);
    EXPECT_EQ(v.patch, 44);
    EXPECT_FALSE(v.is_prerelease());
}

TEST(BuildVersion, ParsesLeadingV) {
    const auto v = parse_version("v1.2.3");
    ASSERT_TRUE(v.valid);
    EXPECT_EQ(v.major, 1);
    EXPECT_EQ(v.minor, 2);
    EXPECT_EQ(v.patch, 3);
}

TEST(BuildVersion, ParsesPrereleaseIdentifiers) {
    const auto v = parse_version("0.0.44-rc.2");
    ASSERT_TRUE(v.valid);
    ASSERT_EQ(v.pre.size(), 2u);
    EXPECT_EQ(v.pre[0], "rc");
    EXPECT_EQ(v.pre[1], "2");
    EXPECT_TRUE(v.is_prerelease());
}

TEST(BuildVersion, DropsBuildMetadata) {
    const auto v = parse_version("0.0.44-rc.2+abc123");
    ASSERT_TRUE(v.valid);
    ASSERT_EQ(v.pre.size(), 2u);
    EXPECT_EQ(v.pre[1], "2");
}

TEST(BuildVersion, TrimsWhitespace) {
    EXPECT_TRUE(parse_version("  1.2.3\n").valid);
}

TEST(BuildVersion, RejectsMalformed) {
    // Four components, two components, non-numeric core, empty
    // identifiers, trailing punctuation, junk. Each of these must come
    // back invalid rather than being coerced into some nearby number.
    for (const char* bad : {"1.2", "1.2.3.4", "1.2.x", "", "1.2.3-",
                            "1.2.3-rc..1", "..", "1.2.3-rc.1!", "abc"}) {
        EXPECT_FALSE(parse_version(bad).valid) << bad;
    }
}

TEST(BuildVersion, RejectsOverflowRatherThanWrapping) {
    EXPECT_FALSE(parse_version("999999999999.0.0").valid);
}

TEST(BuildVersion, ChannelOf) {
    EXPECT_EQ(channel_of("0.0.44"), "stable");
    EXPECT_EQ(channel_of("0.0.44-rc.1"), "beta");
    EXPECT_EQ(channel_of("0.0.44-beta.3"), "beta");
    EXPECT_EQ(channel_of("0.0.0-dev"), "dev");
    EXPECT_EQ(channel_of("0.0.44-dev.abc123"), "dev");
    // An unplaceable string must NOT report itself as a stable release.
    EXPECT_EQ(channel_of("not-a-version"), "dev");
    EXPECT_EQ(channel_of(""), "dev");
}

TEST(BuildVersion, CompiledInVersionIsUsable) {
    // Whatever CMake resolved must itself parse — a build configured with
    // a broken -DBSFCHAT_SERVER_VERSION should fail here rather than ship
    // an image that reports nonsense on its versions endpoint.
    const auto v = parse_version(kVersion);
    EXPECT_TRUE(v.valid) << "BSFCHAT_SERVER_VERSION=" << kVersion;
    EXPECT_FALSE(version_string().empty());
    EXPECT_FALSE(revision_string().empty());
    EXPECT_NE(describe().find(version_string()), std::string::npos);
}
