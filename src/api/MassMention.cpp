#include "api/MassMention.h"

#include <array>
#include <cctype>
#include <string>

namespace bsfchat {

namespace {

// Letters, digits, '_', and any non-ASCII byte (part of a UTF-8 letter as far
// as this test is concerned — "café@here" is inside a word).
bool is_token_byte(unsigned char c) {
    return std::isalnum(c) != 0 || c == '_' || c >= 0x80;
}

bool starts_with_ci(std::string_view s, std::string_view prefix) {
    if (s.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) != prefix[i]) return false;
    }
    return true;
}

// Is the '@' at `at` inside a URL? Looks back over the whitespace-delimited
// word it sits in for a scheme separator or a leading "www.".
bool inside_url(std::string_view text, std::size_t at) {
    std::size_t start = at;
    while (start > 0 && !std::isspace(static_cast<unsigned char>(text[start - 1]))) --start;
    const auto word = text.substr(start, at - start);
    return word.find("://") != std::string_view::npos || starts_with_ci(word, "www.");
}

// The plain-text scan over one run of addressable text.
bool segment_mentions_everyone(std::string_view text) {
    static constexpr std::array<std::string_view, 3> kTokens = {"everyone", "here", "room"};
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '@') continue;
        if (i > 0 && is_token_byte(static_cast<unsigned char>(text[i - 1]))) continue;
        const auto rest = text.substr(i + 1);
        for (auto token : kTokens) {
            if (!starts_with_ci(rest, token)) continue;
            const std::size_t end = i + 1 + token.size();
            if (end < text.size() && is_token_byte(static_cast<unsigned char>(text[end]))) {
                continue;
            }
            if (inside_url(text, i)) continue;
            return true;
        }
    }
    return false;
}

// Plain body: everything outside backtick spans. A run of N backticks opens a
// span closed by the next run of exactly N (CommonMark's rule, which covers
// ``` fences too); an unclosed run is literal text.
bool plain_mentions_everyone(std::string_view text) {
    std::string addressable;
    addressable.reserve(text.size());
    std::size_t i = 0;
    while (i < text.size()) {
        if (text[i] != '`') {
            addressable += text[i++];
            continue;
        }
        std::size_t run = 0;
        while (i + run < text.size() && text[i + run] == '`') ++run;
        const std::string fence(run, '`');
        std::size_t search = i + run;
        std::size_t close = std::string_view::npos;
        while ((search = text.find(fence, search)) != std::string_view::npos) {
            std::size_t after = search + run;
            if (after < text.size() && text[after] == '`') {
                // A longer run is not this span's closer.
                while (after < text.size() && text[after] == '`') ++after;
                search = after;
                continue;
            }
            close = search;
            break;
        }
        if (close == std::string_view::npos) {
            addressable.append(text.substr(i, run));
            i += run;
            continue;
        }
        addressable += ' ';  // the span separates what is either side of it
        i = close + run;
    }
    return segment_mentions_everyone(addressable);
}

bool html_mentions_everyone(std::string_view html) {
    int inert = 0;
    std::size_t i = 0;
    while (i < html.size()) {
        if (html[i] == '<') {
            const auto close = html.find('>', i);
            if (close == std::string_view::npos) {
                return inert == 0 && segment_mentions_everyone(html.substr(i));
            }
            const auto tag = html.substr(i, close - i + 1);
            std::size_t n = 1;
            const bool closing = n < tag.size() && tag[n] == '/';
            if (closing) ++n;
            std::string name;
            while (n < tag.size() && std::isalnum(static_cast<unsigned char>(tag[n]))) {
                name += static_cast<char>(std::tolower(static_cast<unsigned char>(tag[n])));
                ++n;
            }
            if (name == "a" || name == "code" || name == "pre") {
                if (closing) {
                    if (inert > 0) --inert;
                } else if (tag.size() < 2 || tag[tag.size() - 2] != '/') {
                    ++inert;
                }
            }
            i = close + 1;
            continue;
        }
        auto next = html.find('<', i);
        if (next == std::string_view::npos) next = html.size();
        if (inert == 0 && segment_mentions_everyone(html.substr(i, next - i))) return true;
        i = next;
    }
    return false;
}

} // namespace

bool text_mentions_everyone(std::string_view text, bool html) {
    return html ? html_mentions_everyone(text) : plain_mentions_everyone(text);
}

} // namespace bsfchat
