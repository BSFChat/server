// The running build's version, and just enough parsing to answer "is
// this a prerelease?" without dragging in a semver library.
//
// Header-only and free of every other server header on purpose: it is
// included by main.cpp, by AuthHandler (for /_matrix/client/versions)
// and by the unit tests, and none of those should acquire a dependency
// on the others through this.
//
// BSFCHAT_SERVER_VERSION / BSFCHAT_SERVER_REVISION are compile
// definitions set by cmake/Version.cmake. The #ifndef fallbacks exist
// so this header still compiles in a scratch translation unit (an IDE
// index pass, a one-off repro) rather than erroring out — a build that
// reaches production always has the -D, because CMakeLists adds it
// unconditionally.
#pragma once

#include <string>
#include <string_view>
#include <vector>

#ifndef BSFCHAT_SERVER_VERSION
#define BSFCHAT_SERVER_VERSION "0.0.0-dev"
#endif

#ifndef BSFCHAT_SERVER_REVISION
#define BSFCHAT_SERVER_REVISION "unknown"
#endif

namespace bsfchat::build {

inline constexpr std::string_view kVersion = BSFCHAT_SERVER_VERSION;
inline constexpr std::string_view kRevision = BSFCHAT_SERVER_REVISION;

struct VersionInfo {
    bool valid = false;
    int major = 0;
    int minor = 0;
    int patch = 0;
    // Dot-separated prerelease identifiers, e.g. {"rc","2"}. Empty for a
    // stable version.
    std::vector<std::string> pre;

    bool is_prerelease() const { return !pre.empty(); }
};

// Parse "0.0.44", "0.0.44-rc.2", "v0.0.44-rc.2+sha". Strict: anything
// that is not exactly three numeric components with an optional
// well-formed prerelease comes back invalid, because the alternative is
// coercing "0.0.44.1" into a number and reporting a channel it is not on.
//
// Mirrors client/src/core/ReleaseSelection.h's parseVersion so the two
// halves of a deployment agree on what a prerelease is.
inline VersionInfo parse_version(std::string_view in) {
    VersionInfo v;
    std::string s(in);

    // Trim surrounding whitespace.
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return v;
    const auto last = s.find_last_not_of(" \t\r\n");
    s = s.substr(first, last - first + 1);

    if (!s.empty() && (s.front() == 'v' || s.front() == 'V')) s.erase(0, 1);

    // Build metadata takes no part in precedence; drop it.
    if (const auto plus = s.find('+'); plus != std::string::npos) s.erase(plus);

    std::string pre;
    const auto dash = s.find('-');
    if (dash != std::string::npos) {
        pre = s.substr(dash + 1);
        s.erase(dash);
    }

    // Split the core on '.'.
    int parts[3] = {0, 0, 0};
    std::size_t idx = 0, begin = 0, count = 0;
    while (count < 4) {
        const auto dot = s.find('.', begin);
        const std::string part =
            s.substr(begin, dot == std::string::npos ? std::string::npos : dot - begin);
        if (count >= 3) return v;               // four or more components
        if (part.empty()) return v;
        for (const char c : part)
            if (c < '0' || c > '9') return v;
        try {
            parts[idx++] = std::stoi(part);
        } catch (...) {
            return v;                            // overflow, not wraparound
        }
        ++count;
        if (dot == std::string::npos) break;
        begin = dot + 1;
    }
    if (count != 3) return v;

    if (dash != std::string::npos) {
        if (pre.empty()) return v;               // trailing '-'
        std::size_t p = 0;
        while (true) {
            const auto dot = pre.find('.', p);
            const std::string id =
                pre.substr(p, dot == std::string::npos ? std::string::npos : dot - p);
            if (id.empty()) return v;            // ".." or trailing '.'
            for (const char c : id) {
                const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                                (c >= 'A' && c <= 'Z') || c == '-';
                if (!ok) return v;
            }
            v.pre.push_back(id);
            if (dot == std::string::npos) break;
            p = dot + 1;
        }
    }

    v.major = parts[0];
    v.minor = parts[1];
    v.patch = parts[2];
    v.valid = true;
    return v;
}

// "stable" / "beta" / "dev" — which release channel a build belongs to,
// for the startup banner and the versions endpoint. An unparseable
// version reports "dev" rather than "stable": a build we cannot place
// must not claim to be a supported release.
inline std::string channel_of(std::string_view version) {
    const VersionInfo v = parse_version(version);
    if (!v.valid) return "dev";
    if (!v.is_prerelease()) return "stable";
    if (v.pre.front() == "dev") return "dev";
    return "beta";
}

inline std::string version_string() { return std::string(kVersion); }
inline std::string revision_string() { return std::string(kRevision); }

// "0.0.44-rc.2 (rev 1a2b3c4, beta channel)" — one line, for the startup
// log and anywhere a human is being told what is running.
inline std::string describe() {
    return version_string() + " (rev " + revision_string() + ", " +
           channel_of(kVersion) + " channel)";
}

} // namespace bsfchat::build
