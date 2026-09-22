#include "core/Utf8.h"

#include <algorithm>
#include <cstdint>

namespace bsfchat {

namespace {

// Length of the well-formed sequence starting at s[i], or 0 if the bytes there
// are not one. Mirrors the decoder in identity/Nickname.cpp (overlongs,
// surrogates and out-of-range values are all malformed), minus the code-point
// output nobody here needs.
std::size_t sequence_length(std::string_view s, std::size_t i) {
    const auto b0 = static_cast<unsigned char>(s[i]);
    std::size_t len = 0;
    std::uint32_t cp = 0;
    if (b0 < 0x80) return 1;
    if ((b0 & 0xE0) == 0xC0) { len = 2; cp = b0 & 0x1Fu; }
    else if ((b0 & 0xF0) == 0xE0) { len = 3; cp = b0 & 0x0Fu; }
    else if ((b0 & 0xF8) == 0xF0) { len = 4; cp = b0 & 0x07u; }
    else return 0;

    if (i + len > s.size()) return 0;
    for (std::size_t k = 1; k < len; ++k) {
        const auto bk = static_cast<unsigned char>(s[i + k]);
        if ((bk & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (bk & 0x3Fu);
    }
    if (len == 2 && cp < 0x80) return 0;
    if (len == 3 && cp < 0x800) return 0;
    if (len == 4 && cp < 0x10000) return 0;
    if (cp > 0x10FFFF) return 0;
    if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
    return len;
}

} // namespace

bool is_valid_utf8(std::string_view s) {
    for (std::size_t i = 0; i < s.size();) {
        const auto len = sequence_length(s, i);
        if (len == 0) return false;
        i += len;
    }
    return true;
}

std::string truncate_utf8(std::string_view s, std::size_t max_codepoints) {
    std::string out;
    out.reserve(std::min(s.size(), max_codepoints * 4));
    std::size_t taken = 0;
    for (std::size_t i = 0; i < s.size() && taken < max_codepoints;) {
        const auto len = sequence_length(s, i);
        if (len == 0) {  // malformed byte: drop it, never copy it
            ++i;
            continue;
        }
        out.append(s.substr(i, len));
        i += len;
        ++taken;
    }
    return out;
}

} // namespace bsfchat
