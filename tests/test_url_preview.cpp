// Server-side URL previews (docs/url-previews.md).
//
//   1. Address classification — every refused range, the IPv6 spellings of
//      IPv4, the operator denylist.
//   2. URL parsing / normalisation / reference resolution.
//   3. Open Graph extraction, entities, charsets, hostile input.
//   4. Image header dimensions.
//   5. Cache freshness.
//   6. The handler end to end against a local httplib server. The real filter
//      REFUSES 127.0.0.1, so those tests use the TestSeams (an injected
//      resolver plus allow_loopback, which relaxes loopback and nothing else),
//      and the first of them proves the unseamed handler refuses the same URL
//      without ever connecting. No test touches the network.

#include <gtest/gtest.h>

#include "api/MediaHandler.h"
#include "api/UrlPreview.h"
#include "api/UrlPreviewHandler.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "auth/MediaAccess.h"
#include "core/Config.h"
#include "http/OutboundAddress.h"
#include "storage/LocalStorage.h"
#include "store/SqliteStore.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <regex>
#include <string>
#include <thread>

using namespace bsfchat;
using namespace bsfchat::url_preview;
using json = nlohmann::json;

namespace {

outbound::IpAddress ip(const std::string& s) {
    auto a = outbound::IpAddress::parse(s);
    EXPECT_TRUE(a.has_value()) << s;
    return a.value_or(outbound::IpAddress{});
}

bool refused(const std::string& s) { return outbound::builtin_refusal(ip(s)) != nullptr; }

}  // namespace

// ── 1. Address classification ──────────────────────────────────────────────

TEST(UrlPreviewAddress, RefusesEveryNonGlobalIPv4Range) {
    for (const char* a : {"0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1",
                          "100.127.255.255", "127.0.0.1", "127.1.2.3", "169.254.169.254",
                          "169.254.0.1", "172.16.0.1", "172.31.255.255", "192.168.0.1",
                          "192.168.255.255", "192.0.0.8", "192.0.2.1", "192.88.99.1",
                          "198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9",
                          "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255"}) {
        EXPECT_TRUE(refused(a)) << a;
    }
}

TEST(UrlPreviewAddress, AllowsPublicIPv4IncludingRangeNeighbours) {
    for (const char* a : {"8.8.8.8", "1.1.1.1", "93.184.216.34", "9.255.255.255", "11.0.0.0",
                          "100.63.255.255", "100.128.0.0", "126.255.255.255", "128.0.0.0",
                          "169.253.255.255", "169.255.0.0", "172.15.255.255", "172.32.0.0",
                          "192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0",
                          "223.255.255.255"}) {
        EXPECT_FALSE(refused(a)) << a;
    }
}

TEST(UrlPreviewAddress, RefusesNonGlobalIPv6AndEveryIPv4Embedding) {
    for (const char* a : {"::", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.0.0.1",
                          "::ffff:169.254.169.254",
                          // Mapped is refused even when the IPv4 half is public.
                          "::ffff:8.8.8.8", "0:0:0:0:0:ffff:0808:0808",
                          // IPv4-compatible.
                          "::127.0.0.1", "::10.0.0.1", "::8.8.8.8",
                          // NAT64, well-known and local-use.
                          "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::808:808", "64:ff9b:1::1",
                          "fc00::1", "fdff:ffff::1", "fe80::1", "febf:ffff::1", "fec0::1",
                          "ff02::1", "ff05::2", "2001:db8::1", "2001::1", "2001:0:4136:e378::1",
                          "100::1",
                          // 6to4 wrapping 192.168.1.1 / 127.0.0.1.
                          "2002:c0a8:0101::1", "2002:7f00:1::"}) {
        EXPECT_TRUE(refused(a)) << a;
    }
}

TEST(UrlPreviewAddress, AllowsGlobalIPv6) {
    for (const char* a : {"2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001::200e",
                          "2002:0808:0808::1", "2001:db9::1", "fbff::1"}) {
        EXPECT_FALSE(refused(a)) << a;
    }
}

TEST(UrlPreviewAddress, OperatorDenylist) {
    auto v4 = outbound::parse_cidr("203.0.114.0/24");
    auto v6 = outbound::parse_cidr("2a01:4f8::/32");
    auto one = outbound::parse_cidr("8.8.4.4");
    ASSERT_TRUE(v4 && v6 && one);
    const std::vector<outbound::Cidr> deny{*v4, *v6, *one};
    EXPECT_NE(outbound::refusal(ip("203.0.114.77"), deny), nullptr);
    EXPECT_EQ(outbound::refusal(ip("203.0.115.1"), deny), nullptr);
    EXPECT_NE(outbound::refusal(ip("2a01:4f8:1:2::3"), deny), nullptr);
    EXPECT_EQ(outbound::refusal(ip("2a01:4f9::1"), deny), nullptr);
    EXPECT_NE(outbound::refusal(ip("8.8.4.4"), deny), nullptr);
    EXPECT_EQ(outbound::refusal(ip("8.8.4.5"), deny), nullptr);
    // A v4 range never matches a v6 address.
    EXPECT_FALSE(v4->contains(ip("::ffff:203.0.114.1")));
    auto any = outbound::parse_cidr("0.0.0.0/0");
    ASSERT_TRUE(any);
    EXPECT_TRUE(any->contains(ip("8.8.8.8")));

    for (const char* bad : {"", "abc", "10.0.0.0/33", "1.2.3.4/", "::/129", "10.0.0.0/-1",
                            "10.0.0/8", "1.2.3.4/8/9", "fe80::1%eth0"}) {
        EXPECT_FALSE(outbound::parse_cidr(bad).has_value()) << bad;
    }
}

// ── 2. URL parsing ─────────────────────────────────────────────────────────

TEST(UrlPreviewUrl, NormalisesSchemeHostPortPathAndDropsFragment) {
    auto u = parse_url("HTTPS://Example.COM./a/./b/../c?x=1&y=%20#frag");
    ASSERT_TRUE(u);
    EXPECT_EQ(u->scheme, "https");
    EXPECT_EQ(u->host, "example.com");
    EXPECT_EQ(u->port, 443);
    EXPECT_EQ(u->normalised(), "https://example.com/a/c?x=1&y=%20");

    EXPECT_EQ(parse_url("http://example.com")->normalised(), "http://example.com/");
    EXPECT_EQ(parse_url("http://example.com:80/x")->normalised(), "http://example.com/x");
    EXPECT_EQ(parse_url("http://example.com:8080/x")->normalised(), "http://example.com:8080/x");
    EXPECT_EQ(parse_url("http://example.com?q")->normalised(), "http://example.com/?q");
    EXPECT_EQ(parse_url("http://example.com/../../etc")->normalised(), "http://example.com/etc");
    EXPECT_EQ(parse_url("http://[2001:DB8::1]:8443/")->normalised(), "http://[2001:db8::1]:8443/");
    // Non-ASCII path bytes are encoded, not refused.
    EXPECT_EQ(parse_url("https://example.com/caf\xc3\xa9")->normalised(),
              "https://example.com/caf%C3%A9");
}

TEST(UrlPreviewUrl, BackslashEndsTheAuthorityLikeABrowser) {
    auto u = parse_url("http://good.example\\@evil.example/");
    ASSERT_TRUE(u);
    EXPECT_EQ(u->host, "good.example");
    EXPECT_EQ(u->path_query.rfind("/%5C@evil.example", 0), 0u);
}

TEST(UrlPreviewUrl, Refusals) {
    const std::string long_url = "https://example.com/" + std::string(kMaxUrlLength, 'a');
    for (const std::string& bad : std::vector<std::string>{
             "", "example.com", "ftp://example.com/", "file:///etc/passwd", "javascript:alert(1)",
             "gopher://example.com/", "http:/example.com", "http://",
             "http://user:pw@example.com/", "http://user@example.com/", "http://@example.com/",
             "http://example.com@127.0.0.1/", "http://localhost/", "http://LOCALHOST./",
             "http://foo.localhost/", "http://printer.local/", "http://db/", "http://intranet",
             "http://metadata.google.internal/", "http://nas.home.arpa/", "http://x.localdomain/",
             "http://exa mple.com/", "http://example.com/\n", "http://example.com:0/",
             "http://example.com:65536/", "http://example.com:8a/", "http://example.com:1:2/",
             "http://[::1", "http://[fe80::1%25eth0]/", "http://[nothex]/", "http://ex%61mple.com/",
             "http://b\xc3\xbc" "cher.de/", "http://a..b.com/", "http://.example.com/",
             long_url}) {
        EXPECT_FALSE(parse_url(bad).has_value()) << bad;
    }
    // Literal addresses parse; the ADDRESS check is what refuses them.
    EXPECT_TRUE(parse_url("http://127.0.0.1/"));
    EXPECT_TRUE(parse_url("http://[::1]/"));
    std::string why;
    EXPECT_FALSE(parse_url("http://u:p@example.com/", &why));
    EXPECT_FALSE(why.empty());
}

TEST(UrlPreviewUrl, ResolvesReferences) {
    auto base = *parse_url("https://example.com/a/b/page.html?q=1");
    EXPECT_EQ(*resolve_reference(base, "https://cdn.example/x.png"), "https://cdn.example/x.png");
    EXPECT_EQ(*resolve_reference(base, "//cdn.example/x.png"), "https://cdn.example/x.png");
    EXPECT_EQ(*resolve_reference(base, "/img/x.png"), "https://example.com/img/x.png");
    EXPECT_EQ(*resolve_reference(base, "x.png"), "https://example.com/a/b/x.png");
    EXPECT_EQ(parse_url(*resolve_reference(base, "../x.png"))->normalised(),
              "https://example.com/a/x.png");
    EXPECT_EQ(*resolve_reference(base, "?r=2"), "https://example.com/a/b/page.html?r=2");
    EXPECT_EQ(*resolve_reference(base, "  /t\n.png "), "https://example.com/t.png");
    EXPECT_FALSE(resolve_reference(base, "   ").has_value());
    // Resolution does not judge the result; parse_url does.
    EXPECT_FALSE(parse_url(*resolve_reference(base, "javascript:alert(1)")));
    auto v6 = *parse_url("http://[2001:db8::1]:8080/p");
    EXPECT_EQ(*resolve_reference(v6, "/q"), "http://[2001:db8::1]:8080/q");
}

// ── 3. Open Graph extraction ───────────────────────────────────────────────

TEST(UrlPreviewHtml, ExtractsOpenGraph) {
    const std::string html = R"(<!doctype html><html><head>
        <title>Fallback title</title>
        <META PROPERTY="og:title" CONTENT="Real &amp; true &#39;title&#x27;">
        <meta property='og:description' content='A description'>
        <meta property=og:site_name content=Example>
        <meta property="og:url" content="/canonical">
        <meta property="og:image" content="https://cdn.example/i.png">
        <meta property="og:image:width" content="640"><meta property="og:image:height" content="480">
        <meta name="description" content="ignored, og wins">
        </head><body></body></html>)";
    auto t = parse_html(html);
    ASSERT_TRUE(t.title && t.description && t.site_name && t.url && t.image);
    EXPECT_EQ(*clean_text(*t.title, "utf-8", kMaxTitle), "Real & true 'title'");
    EXPECT_EQ(*t.description, "A description");
    EXPECT_EQ(*t.site_name, "Example");
    EXPECT_EQ(*t.url, "/canonical");
    EXPECT_EQ(*t.image, "https://cdn.example/i.png");
    EXPECT_EQ(*t.image_width, "640");
    EXPECT_EQ(*t.image_height, "480");
}

TEST(UrlPreviewHtml, FallsBackToTitleAndMetaDescription) {
    auto t = parse_html("<html><head><title>\n  Plain   page\n</title>"
                        "<meta name=\"Description\" content=\"About it\"></head></html>");
    ASSERT_TRUE(t.title && t.description);
    EXPECT_EQ(*clean_text(*t.title, "", kMaxTitle), "Plain page");
    EXPECT_EQ(*t.description, "About it");
    EXPECT_FALSE(t.image);

    auto tw = parse_html("<meta name=twitter:title content=TW><meta name=twitter:image content=/t.png>");
    EXPECT_EQ(*tw.title, "TW");
    EXPECT_EQ(*tw.image, "/t.png");
}

TEST(UrlPreviewHtml, MissingTagsAndIgnoredContexts) {
    auto none = parse_html("<html><body><p>No metadata here</p></body></html>");
    EXPECT_FALSE(none.title || none.description || none.site_name || none.url || none.image);
    EXPECT_FALSE(parse_html("").title);

    auto t = parse_html(R"(<!-- <meta property="og:title" content="in a comment"> -->
        <script>document.write('<meta property="og:title" content="in script">')</script>
        <style>/* <title>in style</title> */</style>
        <meta property="og:title" content="real">)");
    EXPECT_EQ(*t.title, "real");

    // An attribute value containing '>' does not end the tag.
    auto q = parse_html(R"(<meta content="a > b" property="og:description">)");
    EXPECT_EQ(*q.description, "a > b");
}

TEST(UrlPreviewHtml, HostileInputTerminatesQuickly) {
    const auto start = std::chrono::steady_clock::now();
    std::string junk;
    for (int i = 0; i < 200000; ++i) junk += "<a b=\"<meta";
    junk += std::string(1 << 20, '<');
    auto t = parse_html(junk);
    EXPECT_FALSE(t.title);
    auto unterminated = parse_html("<meta property=\"og:title\" content=\"never closed" +
                                   std::string(1 << 20, 'x'));
    // Raw values are capped as copied.
    ASSERT_TRUE(unterminated.title);
    EXPECT_LE(unterminated.title->size(), 16u * 1024);
    EXPECT_FALSE(parse_html("<title>never closed").title);
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST(UrlPreviewHtml, EntitiesAndCleanup) {
    EXPECT_EQ(decode_entities("&lt;b&gt; &quot;q&quot; &apos;a&apos; &nbsp;"),
              "<b> \"q\" 'a' \xc2\xa0");
    EXPECT_EQ(decode_entities("&#233;&#xE9;&eacute;&#x1F600;"),
              "\xc3\xa9\xc3\xa9\xc3\xa9\xf0\x9f\x98\x80");
    EXPECT_EQ(decode_entities("&#0;&#xD800;&#x110000;"), "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd");
    EXPECT_EQ(decode_entities("&#150;"), "\xe2\x80\x93");  // windows-1252 en dash
    EXPECT_EQ(decode_entities("AT&T &unknown; & &#;"), "AT&T &unknown; & &#;");
    EXPECT_EQ(decode_entities("&mdash;&hellip;&rsquo;"), "\xe2\x80\x94\xe2\x80\xa6\xe2\x80\x99");

    // Bidi overrides and controls are dropped; whitespace collapses.
    EXPECT_EQ(*clean_text("a\xe2\x80\xae" "b\x01\tc  \n d", "utf-8", 100), "ab c d");
    EXPECT_FALSE(clean_text("   \n\t ", "utf-8", 100));
    // Invalid UTF-8 is replaced, not passed through.
    auto bad = clean_text("ok\xff\xfe", "utf-8", 100);
    ASSERT_TRUE(bad);
    EXPECT_EQ(*bad, "ok\xef\xbf\xbd\xef\xbf\xbd");
    // ISO-8859-1 / windows-1252 are transcoded before entity decoding.
    EXPECT_EQ(*clean_text("caf\xe9 \x93q\x94 &amp;", "ISO-8859-1", 100),
              "caf\xc3\xa9 \xe2\x80\x9cq\xe2\x80\x9d &");
    EXPECT_EQ(charset_from_content_type("text/html; Charset=\"Windows-1252\""), "windows-1252");
    EXPECT_EQ(*parse_html("<meta charset=iso-8859-1>").charset, "iso-8859-1");
    EXPECT_EQ(*parse_html("<meta http-equiv=Content-Type content='text/html; charset=latin1'>").charset,
              "latin1");
}

TEST(UrlPreviewHtml, TruncatesToCodepointLimits) {
    std::string title;
    for (int i = 0; i < 400; ++i) title += "\xc3\xa9";  // 400 code points, 800 bytes
    auto t = clean_text(title, "utf-8", kMaxTitle);
    ASSERT_TRUE(t);
    EXPECT_EQ(t->size(), 2 * kMaxTitle);
    auto d = clean_text(std::string(5000, 'x'), "utf-8", kMaxDescription);
    EXPECT_EQ(d->size(), kMaxDescription);
}

// ── 4. Image dimensions ────────────────────────────────────────────────────

namespace {

std::string be32(uint32_t v) {
    return {static_cast<char>(v >> 24), static_cast<char>(v >> 16), static_cast<char>(v >> 8),
            static_cast<char>(v)};
}

std::string png(uint32_t w, uint32_t h, std::size_t pad = 0) {
    std::string d("\x89PNG\r\n\x1a\n", 8);
    d += be32(13) + "IHDR" + be32(w) + be32(h);
    d += std::string("\x08\x06\x00\x00\x00", 5) + be32(0);
    d += std::string(pad, '\0');
    return d;
}

}  // namespace

TEST(UrlPreviewImage, Png) {
    EXPECT_EQ(image_dimensions(png(640, 480)), std::make_pair(640, 480));
    EXPECT_FALSE(image_dimensions(png(0, 480)));
    EXPECT_FALSE(image_dimensions(png(640, 480).substr(0, 20)));
}

TEST(UrlPreviewImage, Gif) {
    std::string g = std::string("GIF89a") + std::string("\x40\x01\xf0\x00", 4) + std::string(8, '\0');
    EXPECT_EQ(image_dimensions(g), std::make_pair(320, 240));
    EXPECT_FALSE(image_dimensions(std::string("GIF89a\x40", 7)));
}

TEST(UrlPreviewImage, JpegSkipsSegmentsToSof) {
    std::string j("\xff\xd8", 2);
    j += std::string("\xff\xe0\x00\x10", 4) + std::string("JFIF\0", 5) + std::string(9, '\0');  // APP0
    j += std::string("\xff\xdb\x00\x04\x00\x00", 6);                                          // DQT
    j += std::string("\xff\xff", 2);  // fill byte before the next marker
    j += std::string("\xff\xc2\x00\x11\x08\x01\xe0\x02\x80\x03", 10) + std::string(9, '\0');   // SOF2
    EXPECT_EQ(image_dimensions(j.substr(0, j.size())), std::make_pair(640, 480));
    // SOS before any SOF: no dimensions, not a guess.
    EXPECT_FALSE(image_dimensions(std::string("\xff\xd8\xff\xda\x00\x02", 6)));
    // DHT (C4) is not a frame header.
    std::string dht("\xff\xd8\xff\xc4\x00\x04\x00\x00", 8);
    EXPECT_FALSE(image_dimensions(dht));
    // A segment length running past the end.
    EXPECT_FALSE(image_dimensions(std::string("\xff\xd8\xff\xe0\xff\xff", 6)));
}

TEST(UrlPreviewImage, WebP) {
    auto riff = [](const std::string& chunk, const std::string& payload) {
        std::string d = "RIFF" + std::string(4, '\0') + "WEBP" + chunk + std::string(4, '\0') + payload;
        d.resize(std::max<std::size_t>(d.size(), 40), '\0');
        return d;
    };
    // VP8X: canvas width-1 / height-1, 24-bit LE at payload+4.
    EXPECT_EQ(image_dimensions(riff("VP8X", std::string("\0\0\0\0\x7f\x02\x00\xdf\x01\x00", 10))),
              std::make_pair(640, 480));
    // VP8L: 14-bit width-1 / height-1 packed after the 0x2f signature.
    {
        const uint32_t w = 640 - 1, h = 480 - 1;
        const uint32_t bits = w | (h << 14);
        std::string p("\x2f", 1);
        p += static_cast<char>(bits & 0xff);
        p += static_cast<char>((bits >> 8) & 0xff);
        p += static_cast<char>((bits >> 16) & 0xff);
        p += static_cast<char>((bits >> 24) & 0xff);
        EXPECT_EQ(image_dimensions(riff("VP8L", p)), std::make_pair(640, 480));
    }
    // VP8 (lossy): start code then 14-bit LE width/height.
    EXPECT_EQ(image_dimensions(riff("VP8 ", std::string("\0\0\0\x9d\x01\x2a\x80\x02\xe0\x01", 10))),
              std::make_pair(640, 480));
    EXPECT_FALSE(image_dimensions(riff("VP8 ", std::string("\0\0\0\x00\x00\x00\x80\x02\xe0\x01", 10))));
}

TEST(UrlPreviewImage, GarbageAndSvgHaveNoDimensions) {
    EXPECT_FALSE(image_dimensions(""));
    EXPECT_FALSE(image_dimensions("<svg width=\"10\" height=\"10\"></svg>"));
    EXPECT_FALSE(image_dimensions(std::string(100, '\xff')));
}

// ── 5. Cache freshness ─────────────────────────────────────────────────────

TEST(UrlPreviewCache, TtlLogic) {
    const int64_t t0 = 1'700'000'000'000;
    EXPECT_TRUE(cache_fresh(t0, t0, false));
    EXPECT_TRUE(cache_fresh(t0, t0 + kPositiveTtlMs - 1, false));
    EXPECT_FALSE(cache_fresh(t0, t0 + kPositiveTtlMs, false));
    EXPECT_TRUE(cache_fresh(t0, t0 + kNegativeTtlMs - 1, true));
    EXPECT_FALSE(cache_fresh(t0, t0 + kNegativeTtlMs, true));
    EXPECT_FALSE(cache_fresh(t0 + 1000, t0, false));  // from the future
    EXPECT_EQ(kPositiveTtlMs, 24LL * 3600 * 1000);
    EXPECT_EQ(kNegativeTtlMs, 3600LL * 1000);
}

TEST(UrlPreviewCache, StoreRoundTripAndPrune) {
    SqliteStore store(":memory:");
    store.initialize();
    EXPECT_FALSE(store.get_url_preview("https://a.example/"));
    store.put_url_preview("https://a.example/", std::string(R"({"og:title":"A"})"), "", 1000);
    store.put_url_preview("https://b.example/", std::nullopt, "", 2000);
    auto a = store.get_url_preview("https://a.example/");
    ASSERT_TRUE(a && a->response_json);
    EXPECT_EQ(*a->response_json, R"({"og:title":"A"})");
    EXPECT_EQ(a->fetched_at_ms, 1000);
    auto b = store.get_url_preview("https://b.example/");
    ASSERT_TRUE(b);
    EXPECT_FALSE(b->response_json);
    // Upsert replaces.
    store.put_url_preview("https://b.example/", std::string("{}"), "", 3000);
    EXPECT_EQ(store.get_url_preview("https://b.example/")->fetched_at_ms, 3000);
    EXPECT_EQ(store.prune_url_previews(2500), 1);
    EXPECT_FALSE(store.get_url_preview("https://a.example/"));
    EXPECT_TRUE(store.get_url_preview("https://b.example/"));
}

TEST(UrlPreviewCache, ReaperSparesAnImageWhileItsCacheRowLives) {
    SqliteStore store(":memory:");
    store.initialize();
    store.insert_media("aaaa", kUrlPreviewUploader, "image/png", "", 10, "aaaa");
    store.insert_media("bbbb", kUrlPreviewUploader, "image/png", "", 10, "bbbb");
    store.put_url_preview("https://a.example/", std::string("{}"), "mxc://test/aaaa", 1000);
    const int64_t future = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count() + 3600 * 1000;
    auto orphans = store.find_orphaned_media("test", future, 100);
    ASSERT_EQ(orphans.size(), 1u);
    EXPECT_EQ(orphans[0].media_id, "bbbb");
    store.prune_url_previews(2000);
    EXPECT_EQ(store.find_orphaned_media("test", future, 100).size(), 2u);
}

// ── 6. The handler against a local server ──────────────────────────────────

namespace {

std::filesystem::path unique_dir(const std::string& prefix) {
    static std::atomic<unsigned> counter{0};
    auto path = std::filesystem::temp_directory_path() /
                (prefix + "-" + std::to_string(static_cast<long>(::getpid())) + "-" +
                 std::to_string(counter.fetch_add(1)));
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    return path;
}

struct Origin {
    httplib::Server svr;
    std::thread thread;
    int port = 0;
    std::atomic<int> hits{0};
    std::string last_user_agent;
    std::string last_cookie;

    Origin() {
        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response&) {
            ++hits;
            last_user_agent = req.get_header_value("User-Agent");
            last_cookie = req.get_header_value("Cookie") + req.get_header_value("Authorization");
            return httplib::Server::HandlerResponse::Unhandled;
        });
        svr.Get("/page", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"(<html><head><title>T</title>
                <meta property="og:title" content="Hello &amp; welcome">
                <meta property="og:description" content="Desc">
                <meta property="og:image" content="/img.png">
                <meta property="og:url" content="/page#x">
                </head></html>)",
                            "text/html; charset=utf-8");
        });
        svr.Get("/img.png", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(png(64, 32), "image/png");
        });
        svr.Get("/big.png", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(png(64, 32, 200 * 1024), "image/png");
        });
        svr.Get("/bigimg", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("<meta property=og:title content=Big><meta property=og:image content=/big.png>",
                            "text/html");
        });
        svr.Get("/huge", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("<meta property=og:title content=Huge>" + std::string(2 << 20, 'x'),
                            "text/html");
        });
        svr.Get("/pdf", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("%PDF-1.4", "application/pdf");
        });
        svr.Get("/fake.png", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("<html>not an image</html>", "image/png");
        });
        svr.Get("/direct.png", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(png(7, 9), "image/png");
        });
        svr.Get(R"(/r(\d))", [](const httplib::Request& req, httplib::Response& res) {
            const int n = std::stoi(req.matches[1]);
            res.status = 302;
            res.set_header("Location", n <= 1 ? "/page" : "/r" + std::to_string(n - 1));
        });
        svr.Get("/to-private", [](const httplib::Request&, httplib::Response& res) {
            res.status = 301;
            res.set_header("Location", "http://10.0.0.1/");
        });
        port = svr.bind_to_any_port("127.0.0.1");
        thread = std::thread([this] { svr.listen_after_bind(); });
        svr.wait_until_ready();
    }
    ~Origin() {
        svr.stop();
        thread.join();
    }
};

struct PreviewFixture {
    std::filesystem::path dir;
    Config config;
    std::shared_ptr<LocalStorage> storage;
    std::unique_ptr<SqliteStore> store;
    Origin origin;

    PreviewFixture() {
        dir = unique_dir("bsfchat-urlpreview");
        std::filesystem::create_directories(dir);
        storage = std::make_shared<LocalStorage>(dir.string());
        config = Config::defaults();
        config.server_name = "test";
        config.url_preview_allowed_ports = {80, 443, origin.port};
        config.url_preview_max_bytes = 64 * 1024;
        config.url_preview_image_max_bytes = 64 * 1024;
        config.url_preview_timeout_seconds = 5;
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        for (const char* lp : {"alice", "bob"}) {
            const std::string uid = std::string("@") + lp + ":test";
            store->create_user(uid, hash_password("password", 10));
            store->store_access_token(std::string("token-") + lp, uid, "dev");
        }
    }
    ~PreviewFixture() { std::filesystem::remove_all(dir); }

    // "preview.test" -> 127.0.0.1, and the loopback relaxation. Everything
    // else in the policy is the production one.
    std::unique_ptr<UrlPreviewHandler> seamed(
        UrlPreviewHandler::Resolver resolver = [](const std::string& host) {
            if (host == "preview.test")
                return std::vector<outbound::IpAddress>{*outbound::IpAddress::parse("127.0.0.1")};
            return UrlPreviewHandler::system_resolve(host);  // numeric only in these tests
        }) {
        UrlPreviewHandler::TestSeams seams;
        seams.resolver = std::move(resolver);
        seams.allow_loopback = true;
        return std::make_unique<UrlPreviewHandler>(*store, config, storage, limiter_steady_now_ms,
                                                   std::move(seams));
    }

    std::string url(const std::string& path) const {
        return "http://preview.test:" + std::to_string(origin.port) + path;
    }

    httplib::Response get(UrlPreviewHandler& h, const std::string& u,
                          const std::string& user = "alice") {
        httplib::Request req;
        if (!user.empty()) req.set_header("Authorization", "Bearer token-" + user);
        req.params.emplace("url", u);
        httplib::Response res;
        h.handle_preview(req, res);
        return res;
    }
};

std::string errcode(const httplib::Response& res) {
    return json::parse(res.body).value("errcode", "");
}

}  // namespace

TEST(UrlPreviewHandlerTest, RealFilterRefusesLoopbackWithoutConnecting) {
    PreviewFixture f;
    UrlPreviewHandler real(*f.store, f.config, f.storage);
    auto res = f.get(real, "http://127.0.0.1:" + std::to_string(f.origin.port) + "/page");
    EXPECT_EQ(res.status, 400);
    EXPECT_EQ(errcode(res), "M_INVALID_PARAM");
    res = f.get(real, "http://[::1]:" + std::to_string(f.origin.port) + "/page");
    EXPECT_EQ(res.status, 400);
    EXPECT_EQ(f.origin.hits.load(), 0);
}

TEST(UrlPreviewHandlerTest, AnyForbiddenAddressRefusesTheHost) {
    PreviewFixture f;
    // DNS answers with the real origin AND an internal address: refused, and
    // nothing is fetched even though one answer would have been allowed here.
    auto h = f.seamed([](const std::string&) {
        return std::vector<outbound::IpAddress>{*outbound::IpAddress::parse("127.0.0.1"),
                                                *outbound::IpAddress::parse("10.0.0.5")};
    });
    auto res = f.get(*h, f.url("/page"));
    EXPECT_EQ(res.status, 400);
    EXPECT_EQ(f.origin.hits.load(), 0);

    auto meta = f.seamed([](const std::string&) {
        return std::vector<outbound::IpAddress>{*outbound::IpAddress::parse("169.254.169.254")};
    });
    EXPECT_EQ(f.get(*meta, f.url("/page")).status, 400);
    auto mapped = f.seamed([](const std::string&) {
        return std::vector<outbound::IpAddress>{*outbound::IpAddress::parse("::ffff:127.0.0.1")};
    });
    EXPECT_EQ(f.get(*mapped, f.url("/page")).status, 400);
    EXPECT_EQ(f.origin.hits.load(), 0);
}

TEST(UrlPreviewHandlerTest, OperatorDenylistAppliesEvenUnderTheSeam) {
    PreviewFixture f;
    f.config.url_preview_ip_denylist = {"127.0.0.0/8"};
    auto h = f.seamed();
    EXPECT_EQ(f.get(*h, f.url("/page")).status, 400);
    EXPECT_EQ(f.origin.hits.load(), 0);

    f.config.url_preview_ip_denylist = {"not-a-cidr"};
    EXPECT_THROW(f.seamed(), std::runtime_error);
}

TEST(UrlPreviewHandlerTest, PreviewsPageAndStoresImageAsServerOwned) {
    PreviewFixture f;
    auto h = f.seamed();
    auto res = f.get(*h, f.url("/page"));
    ASSERT_EQ(res.status, 200) << res.body;
    auto j = json::parse(res.body);
    EXPECT_EQ(j["og:title"], "Hello & welcome");
    EXPECT_EQ(j["og:description"], "Desc");
    EXPECT_EQ(j["og:url"], f.url("/page"));
    EXPECT_EQ(j["og:image:width"], 64);
    EXPECT_EQ(j["og:image:height"], 32);
    EXPECT_EQ(j["matrix:image:size"], static_cast<int64_t>(png(64, 32).size()));
    const std::string mxc = j["og:image"];
    ASSERT_EQ(mxc.rfind("mxc://test/", 0), 0u);

    auto meta = f.store->get_media(mxc.substr(std::string("mxc://test/").size()));
    ASSERT_TRUE(meta);
    EXPECT_EQ(meta->uploader, kUrlPreviewUploader);
    EXPECT_EQ(meta->content_type, "image/png");
    // Readable by any account, not just whoever asked first.
    MediaAccess access(*f.store, f.config);
    EXPECT_TRUE(access.may_read_uri("@bob:test", mxc));

    // UA set, no cookies/credentials forwarded.
    EXPECT_EQ(f.origin.last_user_agent.rfind("BSFChat-URL-Preview/", 0), 0u);
    EXPECT_TRUE(f.origin.last_cookie.empty());

    // Second request — from another account, different spelling — is a cache hit.
    const int hits = f.origin.hits.load();
    auto again = f.get(*h, "HTTP://Preview.Test:" + std::to_string(f.origin.port) + "/page#frag", "bob");
    EXPECT_EQ(again.status, 200);
    EXPECT_EQ(again.body, res.body);
    EXPECT_EQ(f.origin.hits.load(), hits);
}

TEST(UrlPreviewHandlerTest, DirectImageUrl) {
    PreviewFixture f;
    auto h = f.seamed();
    auto res = f.get(*h, f.url("/direct.png"));
    ASSERT_EQ(res.status, 200) << res.body;
    auto j = json::parse(res.body);
    EXPECT_EQ(j["og:image:width"], 7);
    EXPECT_EQ(j["og:image:height"], 9);
    EXPECT_FALSE(j.contains("og:title"));
}

TEST(UrlPreviewHandlerTest, RedirectsAreBoundedAndRechecked) {
    PreviewFixture f;
    auto h = f.seamed();
    EXPECT_EQ(f.get(*h, f.url("/r3")).status, 200);  // three hops: allowed
    auto res = f.get(*h, f.url("/r4"));             // four: refused
    EXPECT_EQ(res.status, 404);
    EXPECT_EQ(errcode(res), "M_NOT_FOUND");
    EXPECT_EQ(f.get(*h, f.url("/to-private")).status, 400);
}

TEST(UrlPreviewHandlerTest, SizeAndTypeLimits) {
    PreviewFixture f;
    auto h = f.seamed();
    // HTML past the cap is truncated, and the head still yields a title.
    auto huge = f.get(*h, f.url("/huge"));
    ASSERT_EQ(huge.status, 200);
    EXPECT_EQ(json::parse(huge.body)["og:title"], "Huge");
    // An image past its cap is dropped; the rest of the preview survives.
    auto big = f.get(*h, f.url("/bigimg"));
    ASSERT_EQ(big.status, 200);
    EXPECT_FALSE(json::parse(big.body).contains("og:image"));
    // Not HTML, not an image: nothing to preview, cached negative.
    EXPECT_EQ(f.get(*h, f.url("/pdf")).status, 404);
    const int hits = f.origin.hits.load();
    EXPECT_EQ(f.get(*h, f.url("/pdf")).status, 404);
    EXPECT_EQ(f.origin.hits.load(), hits);
    // Claims image/png, is HTML: not stored.
    EXPECT_EQ(f.get(*h, f.url("/fake.png")).status, 404);
}

TEST(UrlPreviewHandlerTest, AuthDisabledBadUrlAndRateLimit) {
    PreviewFixture f;
    auto h = f.seamed();
    EXPECT_EQ(f.get(*h, f.url("/page"), "").status, 401);
    EXPECT_EQ(f.get(*h, "ftp://example.com/").status, 400);
    EXPECT_EQ(f.get(*h, "http://user:pw@preview.test/").status, 400);
    EXPECT_EQ(f.get(*h, "http://preview.test:22/").status, 400);  // port not allowed

    f.config.url_preview_enabled = false;
    auto off = f.get(*h, f.url("/page"));
    EXPECT_EQ(off.status, 403);
    EXPECT_EQ(errcode(off), "M_FORBIDDEN");
    f.config.url_preview_enabled = true;

    f.config.url_preview_rate_per_minute = 1;
    auto limited = f.seamed();
    EXPECT_EQ(f.get(*limited, f.url("/page")).status, 200);
    auto res = f.get(*limited, f.url("/direct.png"));
    EXPECT_EQ(res.status, 429);
    EXPECT_EQ(errcode(res), "M_LIMIT_EXCEEDED");
    // A cache hit is not charged.
    EXPECT_EQ(f.get(*limited, f.url("/page")).status, 200);
}

// The client loads og:image through the ticket path (POST /ticket, then
// download). A preview image must be ticketable and downloadable by any
// signed-in account; an ordinary unattached upload must stay private.
TEST(UrlPreviewHandlerTest, SecondUserCanTicketAndDownloadPreviewImage) {
    PreviewFixture f;
    auto h = f.seamed();
    auto res = f.get(*h, f.url("/page"), "alice");
    ASSERT_EQ(res.status, 200) << res.body;
    const std::string mxc = json::parse(res.body)["og:image"];
    const std::string media_id = mxc.substr(std::string("mxc://test/").size());

    // An ordinary upload by alice, attached to nothing: the control.
    f.storage->upload("cafe0000cafe0000cafe0000cafe0000", png(1, 1), "image/png", "");
    f.store->insert_media("cafe0000cafe0000cafe0000cafe0000", "@alice:test", "image/png", "",
                          static_cast<int64_t>(png(1, 1).size()),
                          "cafe0000cafe0000cafe0000cafe0000");

    MediaHandler media(*f.store, f.config, f.storage);
    auto mint = [&](const std::string& uri, const std::string& user) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/_matrix/media/v3/ticket";
        req.body = json{{"mxc_uri", uri}}.dump();
        req.set_header("Authorization", "Bearer token-" + user);
        httplib::Response r;
        media.handle_ticket(req, r);
        return r;
    };
    auto ticket = mint(mxc, "bob");
    ASSERT_EQ(ticket.status, 200) << ticket.body;
    auto t = json::parse(ticket.body);

    httplib::Request dl;
    dl.path = "/_matrix/media/v3/download/test/" + media_id;
    static const std::regex pattern(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))");
    std::regex_match(dl.path, dl.matches, pattern);
    dl.params.emplace("mt", t.at("mt").get<std::string>());
    dl.params.emplace("exp", std::to_string(t.at("exp").get<int64_t>()));
    httplib::Response dres;
    media.handle_download(dl, dres);
    EXPECT_EQ(dres.status == -1 ? 200 : dres.status, 200);

    // Not opened up: bob still cannot ticket alice's unattached upload.
    EXPECT_EQ(mint("mxc://test/cafe0000cafe0000cafe0000cafe0000", "bob").status, 404);
    EXPECT_EQ(mint("mxc://test/cafe0000cafe0000cafe0000cafe0000", "alice").status, 200);
}
