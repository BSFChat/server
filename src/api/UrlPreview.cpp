#include "api/UrlPreview.h"

#include "core/Utf8.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <vector>

namespace bsfchat::url_preview {

namespace {

char lower(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), lower);
    return out;
}

bool is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

bool ends_with(const std::string& s, std::string_view suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Case-insensitive match of the lowercase literal `lit` at `pos`.
bool imatch(std::string_view s, std::size_t pos, std::string_view lit) {
    if (pos + lit.size() > s.size()) return false;
    for (std::size_t k = 0; k < lit.size(); ++k) {
        if (lower(s[pos + k]) != lit[k]) return false;
    }
    return true;
}

std::size_t ifind(std::string_view s, std::string_view lit, std::size_t from) {
    if (lit.empty()) return from;
    for (std::size_t i = from; i + lit.size() <= s.size(); ++i) {
        if (lower(s[i]) == lit[0] && imatch(s, i, lit)) return i;
    }
    return std::string_view::npos;
}

void append_utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xc0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xe0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    } else {
        out += static_cast<char>(0xf0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    }
}

constexpr uint32_t kReplacement = 0xfffd;

// Decodes one UTF-8 sequence at s[i]; advances i. Invalid input (overlong,
// surrogate, out of range, truncated) yields U+FFFD and consumes one byte.
uint32_t next_codepoint(std::string_view s, std::size_t& i) {
    const auto b0 = static_cast<unsigned char>(s[i]);
    if (b0 < 0x80) {
        ++i;
        return b0;
    }
    int len = 0;
    uint32_t cp = 0;
    uint32_t min = 0;
    if ((b0 & 0xe0) == 0xc0) { len = 2; cp = b0 & 0x1f; min = 0x80; }
    else if ((b0 & 0xf0) == 0xe0) { len = 3; cp = b0 & 0x0f; min = 0x800; }
    else if ((b0 & 0xf8) == 0xf0) { len = 4; cp = b0 & 0x07; min = 0x10000; }
    else { ++i; return kReplacement; }
    if (i + len > s.size()) { ++i; return kReplacement; }
    for (int k = 1; k < len; ++k) {
        const auto b = static_cast<unsigned char>(s[i + k]);
        if ((b & 0xc0) != 0x80) { ++i; return kReplacement; }
        cp = (cp << 6) | (b & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) { ++i; return kReplacement; }
    i += len;
    return cp;
}

// windows-1252's 0x80..0x9F, which ISO-8859-1 leaves as C1 controls. 0 marks
// the five undefined slots.
constexpr uint16_t kCp1252High[32] = {
    0x20ac, 0, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
    0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017d, 0,
    0, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0, 0x017e, 0x0178,
};

uint32_t cp1252(unsigned char b) {
    if (b >= 0x80 && b < 0xa0) {
        const uint32_t m = kCp1252High[b - 0x80];
        return m ? m : kReplacement;
    }
    return b;
}

std::string sanitise_utf8(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) append_utf8(out, next_codepoint(s, i));
    return out;
}

std::string single_byte_to_utf8(std::string_view s) {
    std::string out;
    out.reserve(s.size() * 2);
    for (char c : s) append_utf8(out, cp1252(static_cast<unsigned char>(c)));
    return out;
}

struct NamedEntity {
    const char* name;
    uint32_t cp;
};

constexpr NamedEntity kEntities[] = {
    {"amp", 38}, {"lt", 60}, {"gt", 62}, {"quot", 34}, {"apos", 39},
    {"nbsp", 160}, {"iexcl", 161}, {"cent", 162}, {"pound", 163}, {"yen", 165},
    {"sect", 167}, {"copy", 169}, {"laquo", 171}, {"reg", 174}, {"deg", 176},
    {"plusmn", 177}, {"middot", 183}, {"raquo", 187}, {"iquest", 191},
    {"times", 215}, {"divide", 247}, {"szlig", 223},
    {"agrave", 224}, {"aacute", 225}, {"acirc", 226}, {"auml", 228}, {"aring", 229},
    {"ccedil", 231}, {"egrave", 232}, {"eacute", 233}, {"ecirc", 234}, {"euml", 235},
    {"iacute", 237}, {"ntilde", 241}, {"oacute", 243}, {"ouml", 246}, {"oslash", 248},
    {"uacute", 250}, {"uuml", 252},
    {"Auml", 196}, {"Eacute", 201}, {"Ouml", 214}, {"Uuml", 220},
    {"ndash", 0x2013}, {"mdash", 0x2014}, {"lsquo", 0x2018}, {"rsquo", 0x2019},
    {"sbquo", 0x201a}, {"ldquo", 0x201c}, {"rdquo", 0x201d}, {"bdquo", 0x201e},
    {"bull", 0x2022}, {"hellip", 0x2026}, {"prime", 0x2032}, {"lsaquo", 0x2039},
    {"rsaquo", 0x203a}, {"euro", 0x20ac}, {"trade", 0x2122}, {"larr", 0x2190},
    {"rarr", 0x2192}, {"hearts", 0x2665}, {"zwj", 0x200d}, {"zwnj", 0x200c},
};

// Bidirectional overrides and isolates. Dropped from titles because they let
// a page render one string while containing another.
bool is_bidi_control(uint32_t cp) {
    return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) ||
           cp == 0x200e || cp == 0x200f || cp == 0x061c;
}

// RFC 3986 section 5.2.4, on the path only.
std::string remove_dot_segments(std::string_view path) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    const bool trailing_slash_needed =
        path.empty() || path.back() == '/' ||
        (path.size() >= 2 && path.substr(path.size() - 2) == "/.") ||
        (path.size() >= 3 && path.substr(path.size() - 3) == "/..");
    while (i < path.size()) {
        if (path[i] == '/') { ++i; continue; }
        std::size_t e = path.find('/', i);
        if (e == std::string_view::npos) e = path.size();
        auto seg = path.substr(i, e - i);
        if (seg == "..") {
            if (!out.empty()) out.pop_back();
        } else if (seg != ".") {
            out.push_back(seg);
        }
        i = e;
    }
    std::string result;
    for (auto seg : out) {
        result += '/';
        result.append(seg);
    }
    if (result.empty() || (trailing_slash_needed && result.back() != '/')) result += '/';
    return result;
}

std::string percent_encode_unsafe(std::string_view s, bool in_path) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        const bool unsafe = c >= 0x80 || c == '"' || c == '<' || c == '>' || c == '`' ||
                            c == '{' || c == '}' || c == '|' || c == '^' ||
                            (in_path && c == '\\');
        if (unsafe) {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0xf];
        } else {
            out += ch;
        }
    }
    return out;
}

std::string origin_of(const ParsedUrl& u) {
    std::string o = u.scheme + "://" + (u.host_is_ipv6 ? "[" + u.host + "]" : u.host);
    if (!u.default_port()) o += ":" + std::to_string(u.port);
    return o;
}

std::nullopt_t refuse(std::string* why, const char* reason) {
    if (why) *why = reason;
    return std::nullopt;
}

}  // namespace

std::string ParsedUrl::normalised() const { return origin_of(*this) + path_query; }

std::optional<ParsedUrl> parse_url(std::string_view url, std::string* why) {
    if (url.empty()) return refuse(why, "URL is empty");
    if (url.size() > kMaxUrlLength) return refuse(why, "URL is too long");
    for (char ch : url) {
        const auto c = static_cast<unsigned char>(ch);
        if (c <= 0x20 || c == 0x7f)
            return refuse(why, "URL contains whitespace or control characters");
    }

    const auto colon = url.find(':');
    if (colon == std::string_view::npos) return refuse(why, "URL is not absolute");
    ParsedUrl out;
    out.scheme = to_lower(url.substr(0, colon));
    if (out.scheme != "http" && out.scheme != "https")
        return refuse(why, "Only http and https URLs can be previewed");
    if (url.substr(colon + 1, 2) != "//") return refuse(why, "URL is not absolute");

    const std::size_t auth_start = colon + 3;
    // A backslash ends the authority, as it does in browsers for these schemes,
    // so "http://a.com\@b.com" names a.com here exactly as it does there.
    std::size_t auth_end = url.find_first_of("/?#\\", auth_start);
    if (auth_end == std::string_view::npos) auth_end = url.size();
    std::string_view authority = url.substr(auth_start, auth_end - auth_start);
    if (authority.find('@') != std::string_view::npos)
        return refuse(why, "URLs with credentials cannot be previewed");

    std::string_view host = authority;
    std::string_view port;
    bool has_port = false;
    if (!host.empty() && host.front() == '[') {
        const auto close = host.find(']');
        if (close == std::string_view::npos) return refuse(why, "Invalid host");
        if (close + 1 < host.size()) {
            if (host[close + 1] != ':') return refuse(why, "Invalid host");
            port = host.substr(close + 2);
            has_port = true;
        }
        host = host.substr(1, close - 1);
        out.host_is_ipv6 = true;
    } else if (const auto c = host.rfind(':'); c != std::string_view::npos) {
        if (host.find(':') != c) return refuse(why, "Invalid host");
        port = host.substr(c + 1);
        host = host.substr(0, c);
        has_port = true;
    }

    out.port = out.scheme == "https" ? 443 : 80;
    if (has_port && !port.empty()) {
        if (port.size() > 5 || port.find_first_not_of("0123456789") != std::string_view::npos)
            return refuse(why, "Invalid port");
        const int p = std::stoi(std::string(port));
        if (p < 1 || p > 65535) return refuse(why, "Invalid port");
        out.port = p;
    }

    out.host = to_lower(host);
    if (out.host_is_ipv6) {
        in6_addr tmp{};
        // Rejects zone ids ("fe80::1%25eth0") along with everything else odd.
        if (inet_pton(AF_INET6, out.host.c_str(), &tmp) != 1)
            return refuse(why, "Invalid host");
    } else {
        while (!out.host.empty() && out.host.back() == '.') out.host.pop_back();
        if (out.host.empty() || out.host.size() > 253) return refuse(why, "Invalid host");
        for (char ch : out.host) {
            const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' ||
                            ch == '.' || ch == '_';
            if (!ok) return refuse(why, "Host must be ASCII (use punycode)");
        }
        std::size_t i = 0;
        while (i <= out.host.size()) {
            auto e = out.host.find('.', i);
            if (e == std::string::npos) e = out.host.size();
            if (e == i || e - i > 63) return refuse(why, "Invalid host");
            i = e + 1;
        }
        if (out.host.find('.') == std::string::npos)
            return refuse(why, "Host is not a public name");
        for (const char* suffix : {"localhost", "local", "internal", "home.arpa", "localdomain"}) {
            const std::string s(suffix);
            if (out.host == s || ends_with(out.host, "." + s))
                return refuse(why, "Host is not a public name");
        }
    }

    std::string_view rest = url.substr(auth_end);
    if (const auto hash = rest.find('#'); hash != std::string_view::npos) rest = rest.substr(0, hash);
    std::string_view path = rest;
    std::string_view query;
    if (const auto q = rest.find('?'); q != std::string_view::npos) {
        path = rest.substr(0, q);
        query = rest.substr(q);
    }
    out.path_query = remove_dot_segments(percent_encode_unsafe(path, true)) +
                     percent_encode_unsafe(query, false);
    if (out.path_query.size() > kMaxUrlLength) return refuse(why, "URL is too long");
    return out;
}

std::optional<std::string> resolve_reference(const ParsedUrl& base, std::string_view ref) {
    // Browsers strip surrounding whitespace and embedded tab/newline.
    std::string r;
    r.reserve(ref.size());
    for (char c : ref) {
        if (c != '\t' && c != '\n' && c != '\r') r += c;
    }
    const auto first = r.find_first_not_of(" \f");
    if (first == std::string::npos) return std::nullopt;
    r = r.substr(first, r.find_last_not_of(" \f") - first + 1);
    if (r.size() > kMaxUrlLength) return std::nullopt;

    // Has a scheme: [alpha][alnum+-.]*':' before any of "/?#".
    if (std::isalpha(static_cast<unsigned char>(r[0]))) {
        std::size_t i = 1;
        while (i < r.size() && (std::isalnum(static_cast<unsigned char>(r[i])) || r[i] == '+' ||
                                r[i] == '-' || r[i] == '.'))
            ++i;
        if (i < r.size() && r[i] == ':') return r;
    }
    if (r.rfind("//", 0) == 0) return base.scheme + ":" + r;

    const std::string origin = origin_of(base);
    std::string base_path = base.path_query.substr(0, base.path_query.find('?'));
    if (r[0] == '/') return origin + r;
    if (r[0] == '?') return origin + base_path + r;
    if (r[0] == '#') return base.normalised();
    return origin + base_path.substr(0, base_path.rfind('/') + 1) + r;
}

OgTags parse_html(std::string_view s) {
    // Values are capped as they are copied: an attribute is not storage, and
    // clean_text truncates far below this anyway.
    constexpr std::size_t kMaxRawValue = 16 * 1024;
    constexpr std::size_t kMaxAttrs = 32;

    OgTags out;
    std::optional<std::string> tw_title, tw_desc, tw_image, title_tag, meta_desc;
    std::optional<std::string> og_image_alt;  // og:image:url / og:image:secure_url

    auto set_once = [](std::optional<std::string>& slot, std::string_view v) {
        if (!slot) slot = std::string(v.substr(0, kMaxRawValue));
    };

    const std::size_t n = s.size();
    std::size_t i = 0;
    std::vector<std::pair<std::string, std::string_view>> attrs;
    while (i < n) {
        const std::size_t lt = s.find('<', i);
        if (lt == std::string_view::npos) break;
        if (s.compare(lt, 4, "<!--") == 0) {
            const auto e = s.find("-->", lt + 4);
            if (e == std::string_view::npos) break;
            i = e + 3;
            continue;
        }
        std::size_t k = lt + 1;
        bool closing = false;
        if (k < n && s[k] == '/') { closing = true; ++k; }
        std::string name;
        while (k < n && std::isalnum(static_cast<unsigned char>(s[k])) && name.size() < 16) {
            name += lower(s[k]);
            ++k;
        }
        if (name.empty()) { i = lt + 1; continue; }

        // Walk the attributes, quote-aware, to find the real end of the tag.
        const bool collect = !closing && name == "meta";
        attrs.clear();
        while (k < n) {
            while (k < n && (is_ws(s[k]) || s[k] == '/')) ++k;
            if (k >= n) break;
            if (s[k] == '>') { ++k; break; }
            const std::size_t an = k;
            while (k < n && !is_ws(s[k]) && s[k] != '=' && s[k] != '>' && s[k] != '/') ++k;
            if (k == an) { ++k; continue; }
            std::string aname = to_lower(s.substr(an, std::min<std::size_t>(k - an, 32)));
            while (k < n && is_ws(s[k])) ++k;
            std::string_view value;
            if (k < n && s[k] == '=') {
                ++k;
                while (k < n && is_ws(s[k])) ++k;
                if (k < n && (s[k] == '"' || s[k] == '\'')) {
                    const char q = s[k];
                    auto e = s.find(q, k + 1);
                    if (e == std::string_view::npos) e = n;
                    value = s.substr(k + 1, e - k - 1);
                    k = std::min(n, e + 1);
                } else {
                    const std::size_t vs = k;
                    while (k < n && !is_ws(s[k]) && s[k] != '>') ++k;
                    value = s.substr(vs, k - vs);
                }
            }
            if (collect && attrs.size() < kMaxAttrs) attrs.emplace_back(std::move(aname), value);
        }
        const std::size_t tag_end = k;

        if (!closing && (name == "script" || name == "style" || name == "template" ||
                         name == "noscript" || name == "textarea")) {
            const auto e = ifind(s, "</" + name, tag_end);
            i = e == std::string_view::npos ? n : e;
            continue;
        }
        if (!closing && name == "title") {
            const auto e = ifind(s, "</title", tag_end);
            if (e == std::string_view::npos) break;
            set_once(title_tag, s.substr(tag_end, e - tag_end));
            i = e;
            continue;
        }
        if (collect) {
            std::string key;
            std::optional<std::string_view> content;
            std::string http_equiv;
            for (const auto& [an, av] : attrs) {
                if ((an == "property" || an == "name") && key.empty()) key = to_lower(av.substr(0, 64));
                else if (an == "content" && !content) content = av;
                else if (an == "charset") set_once(out.charset, av);
                else if (an == "http-equiv") http_equiv = to_lower(av.substr(0, 64));
            }
            if (content) {
                const auto v = *content;
                if (http_equiv == "content-type") {
                    auto cs = charset_from_content_type(v);
                    if (!cs.empty()) set_once(out.charset, cs);
                }
                if (key == "og:title") set_once(out.title, v);
                else if (key == "og:description") set_once(out.description, v);
                else if (key == "og:site_name") set_once(out.site_name, v);
                else if (key == "og:url") set_once(out.url, v);
                else if (key == "og:image") set_once(out.image, v);
                else if (key == "og:image:url" || key == "og:image:secure_url") set_once(og_image_alt, v);
                else if (key == "og:image:width") set_once(out.image_width, v);
                else if (key == "og:image:height") set_once(out.image_height, v);
                else if (key == "twitter:title") set_once(tw_title, v);
                else if (key == "twitter:description") set_once(tw_desc, v);
                else if (key == "twitter:image" || key == "twitter:image:src") set_once(tw_image, v);
                else if (key == "description") set_once(meta_desc, v);
            }
        }
        i = std::max(tag_end, lt + 1);
    }

    if (!out.title) out.title = tw_title ? tw_title : title_tag;
    if (!out.description) out.description = tw_desc ? tw_desc : meta_desc;
    if (!out.image) out.image = og_image_alt ? og_image_alt : tw_image;
    return out;
}

std::string decode_entities(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        if (s[i] != '&') { out += s[i++]; continue; }
        if (i + 1 < s.size() && s[i + 1] == '#') {
            std::size_t k = i + 2;
            const bool hex = k < s.size() && (s[k] == 'x' || s[k] == 'X');
            if (hex) ++k;
            const std::size_t digits_start = k;
            uint64_t v = 0;
            while (k < s.size() && k - digits_start < 8 &&
                   (hex ? std::isxdigit(static_cast<unsigned char>(s[k]))
                        : std::isdigit(static_cast<unsigned char>(s[k])))) {
                const char c = lower(s[k]);
                v = v * (hex ? 16 : 10) + static_cast<uint64_t>(c <= '9' ? c - '0' : c - 'a' + 10);
                ++k;
            }
            if (k == digits_start) { out += s[i++]; continue; }
            if (k < s.size() && s[k] == ';') ++k;
            uint32_t cp = static_cast<uint32_t>(v);
            if (v == 0 || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) cp = kReplacement;
            else if (v >= 0x80 && v < 0xa0) cp = cp1252(static_cast<unsigned char>(v));
            append_utf8(out, cp);
            i = k;
            continue;
        }
        const auto semi = s.find(';', i + 1);
        if (semi != std::string_view::npos && semi - i - 1 <= 8) {
            const auto name = s.substr(i + 1, semi - i - 1);
            bool matched = false;
            for (const auto& e : kEntities) {
                if (name == e.name) {
                    append_utf8(out, e.cp);
                    matched = true;
                    break;
                }
            }
            if (matched) { i = semi + 1; continue; }
        }
        out += s[i++];
    }
    return out;
}

std::string charset_from_content_type(std::string_view content_type) {
    const auto p = ifind(content_type, "charset=", 0);
    if (p == std::string_view::npos) return {};
    std::size_t k = p + 8;
    while (k < content_type.size() && (content_type[k] == '"' || content_type[k] == '\'')) ++k;
    std::size_t e = k;
    while (e < content_type.size() && content_type[e] != ';' && content_type[e] != '"' &&
           content_type[e] != '\'' && !is_ws(content_type[e]))
        ++e;
    return to_lower(content_type.substr(k, std::min<std::size_t>(e - k, 40)));
}

std::optional<std::string> clean_text(std::string_view raw, std::string_view charset,
                                      std::size_t max_codepoints) {
    const std::string cs = to_lower(charset);
    const bool single_byte = cs == "iso-8859-1" || cs == "latin1" || cs == "latin-1" ||
                             cs == "windows-1252" || cs == "cp1252" || cs == "iso8859-1";
    // Transcode BEFORE decoding entities: a numeric reference decodes to UTF-8,
    // which a later single-byte pass would mangle.
    const std::string decoded =
        decode_entities(single_byte ? single_byte_to_utf8(raw) : sanitise_utf8(raw));

    std::string out;
    out.reserve(decoded.size());
    bool pending_space = false;
    for (std::size_t i = 0; i < decoded.size();) {
        const uint32_t cp = next_codepoint(decoded, i);
        const bool space = cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r' || cp == '\f' ||
                           cp == 0xa0 || cp == 0x2028 || cp == 0x2029;
        if (space) { pending_space = true; continue; }
        if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0) || is_bidi_control(cp)) continue;
        if (pending_space && !out.empty()) out += ' ';
        pending_space = false;
        append_utf8(out, cp);
    }
    out = truncate_utf8(out, max_codepoints);
    while (!out.empty() && out.back() == ' ') out.pop_back();
    if (out.empty()) return std::nullopt;
    return out;
}

std::optional<std::pair<int, int>> image_dimensions(std::string_view d) {
    auto u8 = [&](std::size_t i) { return static_cast<uint32_t>(static_cast<unsigned char>(d[i])); };
    auto be16 = [&](std::size_t i) { return (u8(i) << 8) | u8(i + 1); };
    auto le16 = [&](std::size_t i) { return u8(i) | (u8(i + 1) << 8); };
    auto le24 = [&](std::size_t i) { return u8(i) | (u8(i + 1) << 8) | (u8(i + 2) << 16); };
    auto be32 = [&](std::size_t i) { return (be16(i) << 16) | be16(i + 2); };
    auto result = [](uint64_t w, uint64_t h) -> std::optional<std::pair<int, int>> {
        if (w == 0 || h == 0 || w > 0x7fffffff || h > 0x7fffffff) return std::nullopt;
        return std::make_pair(static_cast<int>(w), static_cast<int>(h));
    };

    // PNG: signature, then the IHDR chunk, which the spec requires to be first.
    if (d.size() >= 24 && d.compare(0, 8, std::string_view("\x89PNG\r\n\x1a\n", 8)) == 0 &&
        d.compare(12, 4, "IHDR") == 0) {
        return result(be32(16), be32(20));
    }
    // GIF: logical screen descriptor.
    if (d.size() >= 10 && (d.compare(0, 6, "GIF87a") == 0 || d.compare(0, 6, "GIF89a") == 0)) {
        return result(le16(6), le16(8));
    }
    // WebP: RIFF container, first chunk VP8 / VP8L / VP8X.
    if (d.size() >= 30 && d.compare(0, 4, "RIFF") == 0 && d.compare(8, 4, "WEBP") == 0) {
        const auto chunk = d.substr(12, 4);
        if (chunk == "VP8 " && u8(23) == 0x9d && u8(24) == 0x01 && u8(25) == 0x2a)
            return result(le16(26) & 0x3fff, le16(28) & 0x3fff);
        if (chunk == "VP8L" && u8(20) == 0x2f) {
            const uint32_t b0 = u8(21), b1 = u8(22), b2 = u8(23), b3 = u8(24);
            return result(1 + (((b1 & 0x3f) << 8) | b0),
                          1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6)));
        }
        if (chunk == "VP8X") return result(1 + le24(24), 1 + le24(27));
        return std::nullopt;
    }
    // JPEG: walk the marker segments to the first SOFn.
    if (d.size() >= 4 && u8(0) == 0xff && u8(1) == 0xd8) {
        std::size_t i = 2;
        while (i + 4 <= d.size()) {
            if (u8(i) != 0xff) return std::nullopt;
            uint32_t m = u8(i + 1);
            if (m == 0xff) { ++i; continue; }  // fill byte
            if (m == 0xd8 || m == 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
            if (m == 0xd9 || m == 0xda) return std::nullopt;  // EOI / SOS before any SOF
            const uint32_t len = be16(i + 2);
            if (len < 2) return std::nullopt;
            const bool sof = m >= 0xc0 && m <= 0xcf && m != 0xc4 && m != 0xc8 && m != 0xcc;
            if (sof) {
                if (i + 9 > d.size()) return std::nullopt;
                return result(be16(i + 7), be16(i + 5));
            }
            i += 2 + len;
        }
    }
    return std::nullopt;
}

bool cache_fresh(int64_t fetched_at_ms, int64_t now_ms, bool negative) {
    if (now_ms < fetched_at_ms) return false;
    return now_ms - fetched_at_ms < (negative ? kNegativeTtlMs : kPositiveTtlMs);
}

}  // namespace bsfchat::url_preview
