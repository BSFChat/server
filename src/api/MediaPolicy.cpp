#include "api/MediaPolicy.h"

#include <algorithm>
#include <array>
#include <cctype>

namespace bsfchat::media_policy {

namespace {

// Lowercase the essence of a Content-Type: drop parameters (`; charset=utf-8`),
// surrounding whitespace and case. `TEXT/HTML ; charset=x` and `text/html` must
// not be two different things to the allowlist below.
std::string canonicalise(std::string_view raw) {
    auto semi = raw.find(';');
    if (semi != std::string_view::npos) raw = raw.substr(0, semi);
    while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.front()))) {
        raw.remove_prefix(1);
    }
    while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.back()))) {
        raw.remove_suffix(1);
    }
    std::string out(raw);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool starts_with(std::string_view body, std::string_view magic) {
    return body.size() >= magic.size() && body.compare(0, magic.size(), magic) == 0;
}

// --- sniffers -----------------------------------------------------------
//
// Only the families on the inline allowlist plus PDF are sniffed. These are
// FORMAT checks, not security checks: their job is to catch a declared type
// that the bytes do not support, so the answer becomes octet-stream instead of
// a renderable type.
//
// Why downgrade rather than reject the upload with a 4xx: the security
// property we need is "the served Content-Type can never make a browser
// execute the body in our origin", and octet-stream + attachment gives us that
// unconditionally. Rejecting would additionally require our sniffers to be
// exhaustively right about every valid encoding of every accepted format —
// an unusual but legitimate MP4 brand, a WebP variant, a JPEG with a leading
// APP segment we did not anticipate — and every gap would be a user unable to
// post a real file, with no security gain over the downgrade. A wrong sniffer
// here costs an attachment instead of an inline preview; a wrong rejection
// costs a working feature. So: sniff to downgrade, never to refuse.

bool is_png(std::string_view b) { return starts_with(b, std::string_view("\x89PNG\r\n\x1a\n", 8)); }
bool is_jpeg(std::string_view b) { return starts_with(b, std::string_view("\xff\xd8\xff", 3)); }
bool is_gif(std::string_view b) {
    return starts_with(b, "GIF87a") || starts_with(b, "GIF89a");
}
bool is_riff(std::string_view b, std::string_view form) {
    return b.size() >= 12 && starts_with(b, "RIFF") && b.compare(8, 4, form) == 0;
}
bool is_webp(std::string_view b) { return is_riff(b, "WEBP"); }
bool is_bmp(std::string_view b) { return starts_with(b, "BM"); }
bool is_pdf(std::string_view b) { return starts_with(b, "%PDF-"); }

// ISO base media file format (MP4, M4A, QuickTime, AVIF/HEIF): a `ftyp` box at
// offset 4. The brand that follows distinguishes them, but every one of those
// brands is a non-executing container, so the box marker is check enough — and
// the declared type, already allowlisted, picks which of them we say it is.
bool is_isobmff(std::string_view b) { return b.size() >= 12 && b.compare(4, 4, "ftyp") == 0; }

// Matroska/WebM share the EBML header; Ogg and the two WAVE forms are literal.
bool is_ebml(std::string_view b) { return starts_with(b, std::string_view("\x1a\x45\xdf\xa3", 4)); }
bool is_ogg(std::string_view b) { return starts_with(b, "OggS"); }
bool is_wav(std::string_view b) { return is_riff(b, "WAVE"); }
bool is_flac(std::string_view b) { return starts_with(b, "fLaC"); }

// MP3 is either an ID3v2 tag or a bare MPEG audio frame sync.
bool is_mp3(std::string_view b) {
    if (starts_with(b, "ID3")) return true;
    return b.size() >= 2 && static_cast<unsigned char>(b[0]) == 0xff &&
           (static_cast<unsigned char>(b[1]) & 0xe0) == 0xe0;
}

// AAC in an ADTS stream, or in an ISO container (`.m4a`).
bool is_aac(std::string_view b) {
    if (is_isobmff(b)) return true;
    return b.size() >= 2 && static_cast<unsigned char>(b[0]) == 0xff &&
           (static_cast<unsigned char>(b[1]) & 0xf6) == 0xf0;
}

using Sniffer = bool (*)(std::string_view);

struct Entry {
    std::string_view type;
    Sniffer sniff;
    bool inline_safe;
};

// THE ALLOWLIST. Nothing not named here can ever be a stored content type.
//
// Deliberately absent, and why:
//   text/html, application/xhtml+xml, image/svg+xml, text/xml, application/xml
//       — all of them execute script in the origin that serves them. SVG is the
//         trap: it is an "image", clients will happily hand it to a renderer,
//         and it carries <script> and external references. There is no way to
//         serve one of these safely from the chat origin, so they are not a
//         storable type at all; an SVG upload is stored, and served, as
//         application/octet-stream.
//   text/plain — sniffable only by exclusion, and a text/* response is exactly
//         what content sniffing in older browsers escalates to HTML. Costs a
//         download instead of a preview; the client has no text preview anyway.
//   application/json, text/csv, everything else — no client feature needs them
//         to keep their type, so they get none.
//
// `inline_safe` is a second, narrower column rather than a second list, so the
// two answers cannot drift apart. PDF is storable but NOT inline: a browser's
// built-in PDF viewer is a scripting host, and no client feature depends on
// previewing a PDF in place.
constexpr std::array<Entry, 16> kAllowlist{{
    {"image/png",       is_png,     true},
    {"image/jpeg",      is_jpeg,    true},
    {"image/gif",       is_gif,     true},
    {"image/webp",      is_webp,    true},
    {"image/bmp",       is_bmp,     true},
    {"image/avif",      is_isobmff, true},
    {"image/heic",      is_isobmff, true},
    {"video/mp4",       is_isobmff, true},
    {"video/quicktime", is_isobmff, true},
    {"video/webm",      is_ebml,    true},
    {"audio/mpeg",      is_mp3,     true},
    {"audio/mp4",       is_aac,     true},
    {"audio/aac",       is_aac,     true},
    {"audio/ogg",       is_ogg,     true},
    {"audio/wav",       is_wav,     true},
    {"audio/flac",      is_flac,    true},
}};

// Two spellings the wild uses for types already on the list. Mapped rather than
// listed so there is still exactly one canonical stored spelling per format.
struct Alias {
    std::string_view from;
    std::string_view to;
};
constexpr std::array<Alias, 4> kAliases{{
    {"image/jpg",     "image/jpeg"},
    {"audio/x-wav",   "audio/wav"},
    {"audio/wave",    "audio/wav"},
    {"audio/x-m4a",   "audio/mp4"},
}};

const Entry* find(std::string_view type) {
    for (const auto& e : kAllowlist) {
        if (e.type == type) return &e;
    }
    return nullptr;
}

constexpr std::string_view kOctetStream = "application/octet-stream";

// A quoted-string may not contain a quote or a backslash (RFC 9110 s5.6.4), and
// a field value may not contain CR, LF or NUL at all — httplib 0.47 validates
// that and DROPS a header whose value fails, which for Content-Disposition
// would mean no header and therefore inline rendering. Anything outside
// printable ASCII is dropped too: the RFC 6266 way to carry a non-ASCII
// filename is `filename*`, and a bare high byte here is at best ignored.
std::string sanitise_filename(std::string_view filename) {
    std::string out;
    out.reserve(filename.size());
    for (char c : filename) {
        auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u > 0x7e) continue;   // controls (CR, LF, NUL) and non-ASCII
        if (c == '"' || c == '\\') continue;  // would escape the quoted-string
        if (c == '/') continue;               // never suggest a path to the client
        out.push_back(c);
    }
    // Leading dots and whitespace produce hidden or ambiguous files on save.
    size_t first = out.find_first_not_of(". \t");
    if (first == std::string::npos) return {};
    out.erase(0, first);
    // A name is a name, not a document. 200 bytes is far past any real filename
    // and keeps the header comfortably inside any proxy's field-size limit.
    if (out.size() > 200) out.resize(200);
    return out;
}

} // namespace

std::string normalise_content_type(std::string_view declared, std::string_view body) {
    std::string type = canonicalise(declared);
    for (const auto& a : kAliases) {
        if (a.from == type) {
            type = std::string(a.to);
            break;
        }
    }

    // PDF is the one storable-but-not-inline type, so it is checked here rather
    // than carried in kAllowlist, whose every row is inline-safe.
    if (type == "application/pdf") {
        return is_pdf(body) ? type : std::string(kOctetStream);
    }

    const Entry* entry = find(type);
    if (!entry) return std::string(kOctetStream);
    if (!entry->sniff(body)) return std::string(kOctetStream);
    return type;
}

bool is_inline_safe(std::string_view stored_type) {
    const Entry* entry = find(canonicalise(stored_type));
    return entry != nullptr && entry->inline_safe;
}

std::string content_disposition(bool serve_inline, std::string_view filename) {
    std::string disposition = serve_inline ? "inline" : "attachment";
    std::string safe = sanitise_filename(filename);
    if (safe.empty()) return disposition;
    return disposition + "; filename=\"" + safe + "\"";
}

} // namespace bsfchat::media_policy
