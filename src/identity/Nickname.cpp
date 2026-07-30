#include "identity/Nickname.h"

#include "core/Config.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace bsfchat {

using json = nlohmann::json;

namespace {

// Decodes UTF-8 into code points. Returns false on any malformed sequence:
// overlong encodings, truncated continuations, surrogates and out-of-range
// values. Validating rather than tolerating matters because every later check
// (length, character blacklist) reasons about code points, and a decoder that
// guesses at broken input lets a nickname smuggle bytes past those checks and
// still render as something else in a client.
bool decode_utf8(const std::string& s, std::vector<std::uint32_t>& out) {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto b0 = static_cast<unsigned char>(s[i]);
        std::uint32_t cp = 0;
        std::size_t len = 0;
        if (b0 < 0x80) { cp = b0; len = 1; }
        else if ((b0 & 0xE0) == 0xC0) { cp = b0 & 0x1Fu; len = 2; }
        else if ((b0 & 0xF0) == 0xE0) { cp = b0 & 0x0Fu; len = 3; }
        else if ((b0 & 0xF8) == 0xF0) { cp = b0 & 0x07u; len = 4; }
        else return false;

        if (i + len > s.size()) return false;
        for (std::size_t k = 1; k < len; ++k) {
            const auto bk = static_cast<unsigned char>(s[i + k]);
            if ((bk & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (bk & 0x3Fu);
        }
        // Overlong encodings and surrogates are the classic way to hide one
        // string inside another that compares as different but renders the same.
        if (len == 2 && cp < 0x80) return false;
        if (len == 3 && cp < 0x800) return false;
        if (len == 4 && cp < 0x10000) return false;
        if (cp > 0x10FFFF) return false;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;

        out.push_back(cp);
        i += len;
    }
    return true;
}

// Characters that let a rendered nickname disagree with the stored one. Bidi
// overrides and isolates can reorder surrounding text — including a user id
// printed next to the name — and zero-width/invisible characters let two
// nicknames be indistinguishable on screen while differing as strings. Neither
// belongs in a name that exists to identify a person.
bool is_forbidden_codepoint(std::uint32_t cp) {
    if (cp < 0x20 || cp == 0x7F) return true;              // C0 controls, DEL
    if (cp >= 0x80 && cp <= 0x9F) return true;             // C1 controls
    if (cp == 0x00AD) return true;                         // soft hyphen
    if (cp >= 0x200B && cp <= 0x200F) return true;         // ZW*, LRM/RLM
    if (cp >= 0x202A && cp <= 0x202E) return true;         // bidi embedding/override
    if (cp >= 0x2060 && cp <= 0x2064) return true;         // word joiner, invisible ops
    if (cp >= 0x2066 && cp <= 0x2069) return true;         // bidi isolates
    if (cp == 0xFEFF) return true;                         // BOM / ZWNBSP
    if (cp >= 0xFFF9 && cp <= 0xFFFB) return true;         // interlinear annotation
    if (cp == 0x061C) return true;                         // arabic letter mark
    if (cp >= 0xE0000 && cp <= 0xE007F) return true;       // tag characters
    return false;
}

std::string trim_ascii(const std::string& s) {
    const auto is_space = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
    };
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && is_space(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && is_space(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string ascii_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    });
    return s;
}

} // namespace

bool is_blank_nickname(const std::string& raw) {
    return trim_ascii(raw).empty();
}

NicknameCheck validate_nickname(const std::string& raw, const std::string& target_user,
                                const Config& config, SqliteStore& store) {
    NicknameCheck out;
    const std::string value = trim_ascii(raw);

    if (value.empty()) {
        out.error = "Nickname may not be empty; omit it or send null to clear";
        return out;
    }

    std::vector<std::uint32_t> cps;
    if (!decode_utf8(value, cps)) {
        out.error = "Nickname is not valid UTF-8";
        return out;
    }

    for (auto cp : cps) {
        if (is_forbidden_codepoint(cp)) {
            out.error = "Nickname contains a control, invisible or text-direction character";
            return out;
        }
    }

    if (cps.size() > kMaxNicknameCodepoints) {
        out.error = "Nickname may be at most " + std::to_string(kMaxNicknameCodepoints) +
                    " characters";
        return out;
    }

    // A nickname beginning with '@' reads as a user id in every surface that
    // renders names next to mxids, which is the cheapest possible impersonation.
    if (value.front() == '@') {
        out.error = "Nickname may not begin with '@'";
        return out;
    }

    // Nicknames are not required to be unique — Discord allows duplicates, and
    // identity is carried by the immutable user id that clients render alongside
    // the name. What is refused is the one collision that is unambiguously an
    // impersonation attempt: taking the LOCALPART of somebody else's account, so
    // that "Bob" in a member list is the exact string a reader would use to look
    // up the real @bob.
    for (const auto& candidate : {value, ascii_lower(value)}) {
        const std::string mxid = "@" + candidate + ":" + config.server_name;
        if (mxid != target_user && store.user_exists(mxid)) {
            out.error = "Nickname is another member's username";
            return out;
        }
    }

    out.ok = true;
    out.normalised = value;
    return out;
}

std::optional<std::string> effective_display_name(SqliteStore& store,
                                                  const std::string& user_id) {
    if (auto nick = store.get_nickname(user_id)) return nick;
    return store.get_display_name(user_id);
}

json member_event_content(SqliteStore& store, const std::string& user_id,
                          const std::string& membership) {
    json content = {{"membership", membership}};

    // Profile fields are only meaningful for a present member. A leave/ban event
    // carrying a name is how a departing user's forged name used to persist in
    // client caches, and it is information the event does not need.
    if (membership != std::string(bsfchat::membership::kJoin) &&
        membership != std::string(bsfchat::membership::kInvite)) {
        return content;
    }

    if (auto name = effective_display_name(store, user_id)) content["displayname"] = *name;
    if (auto nick = store.get_nickname(user_id)) content[kNicknameContentKey] = *nick;
    if (auto av = store.get_avatar_url(user_id)) content["avatar_url"] = *av;
    return content;
}

} // namespace bsfchat
