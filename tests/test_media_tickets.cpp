// Signed media tickets — the last link of the takeover chain (audit A1).
//
// The September 2026 media hardening cut the server-side links: an uploader can
// no longer choose the type their bytes are served as, and nothing that is not
// inline-safe renders in place. What it deliberately left was the credential
// itself — `?access_token=<the viewer's 90-day session token>` on every media
// URL, handed to Qt.openUrlExternally by the file card, written to nginx's
// access log, and kept in the browser's history and the user's clipboard.
//
// A ticket replaces it: `?mt=<b64url(user)>.<b64url(mac)>&exp=<ts>`, minted by
// POST /_matrix/media/v3/ticket after the SAME may_download() check the download
// path runs, valid for five minutes, scoped to one object and one user.
//
// The property every test below exists to pin down is that a ticket is a
// POINTER TO AN AUTHORIZATION, NOT A REPLACEMENT FOR ONE. It resolves who the
// caller is; may_download() still decides what they may have, at fetch time.
// TicketIsNotAGrant is the test that would catch a regression turning it into a
// bearer capability.
//
// Grouped as:
//   1. The primitive — what the signature covers.
//   2. The mint endpoint — who gets one, and for what.
//   3. The download path — what a ticket does and does not buy.
//   4. The legacy ?access_token= branch, kept for one release.

#include <gtest/gtest.h>

#include "api/MediaHandler.h"
#include "api/MediaTicket.h"
#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "storage/LocalStorage.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <regex>
#include <string>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::filesystem::path unique_dir(const std::string& prefix) {
    static std::atomic<unsigned> counter{0};
    auto path = std::filesystem::temp_directory_path()
              / (prefix + "-" + std::to_string(static_cast<long>(::getpid()))
                 + "-" + std::to_string(counter.fetch_add(1)));
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    return path;
}

const std::string kPng = std::string("\x89PNG\r\n\x1a\n", 8) + "....IHDR";

ServerRole make_role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

int64_t now_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Same shape as test_media_security.cpp's AclFixture — a server with roles, a
// channel, and the reference index behind may_download() — plus the two ticket
// entry points.
struct TicketFixture {
    std::filesystem::path dir;
    Config config;
    std::shared_ptr<LocalStorage> storage;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<MediaHandler> handler;

    TicketFixture() {
        dir = unique_dir("bsfchat-mediaticket");
        std::filesystem::create_directories(dir);
        storage = std::make_shared<LocalStorage>(dir.string());
        config = Config::defaults();
        config.server_name = "test";
        config.require_media_auth = true;
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();

        ServerRolesContent roles;
        roles.roles.push_back(make_role(std::string(permission::role_id::kEveryone), 0,
                                        permission::kEveryoneDefault));
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());

        handler = std::make_unique<MediaHandler>(*store, config, storage);
    }

    ~TicketFixture() { std::filesystem::remove_all(dir); }

    std::string add_user(const std::string& localpart) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev");
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    std::string add_channel(const std::string& creator) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "text"}}.dump(), 1001);
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
    }

    void deny_view(const std::string& room_id, const std::string& target) {
        ChannelPermissionOverride ov;
        ov.allow = 0;
        ov.deny = permission::kViewChannel;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), "user:" + target,
                            j.dump(), 1003);
    }

    std::string upload(const std::string& uploader) {
        static std::atomic<unsigned> n{0};
        char buf[33];
        std::snprintf(buf, sizeof(buf), "%032x", n.fetch_add(1) + 1);
        std::string id(buf);
        storage->upload(id, kPng, "image/png", "p.png");
        store->insert_media(id, uploader, "image/png", "p.png",
                            static_cast<int64_t>(kPng.size()), "/x/" + id);
        return id;
    }

    void post(const std::string& room_id, const std::string& sender,
              const std::string& mxc_uri) {
        store->insert_event(generate_event_id("test"), room_id, sender,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.image"}, {"body", "p.png"},
                                 {"url", mxc_uri}}.dump(),
                            2000);
    }

    std::string mxc(const std::string& id) const { return "mxc://test/" + id; }

    struct TicketResult {
        int status = 0;
        std::string mt;
        int64_t exp = 0;
    };

    // POST /_matrix/media/v3/ticket as `localpart`.
    TicketResult mint(const std::string& mxc_uri, const std::string& localpart,
                      bool with_auth = true) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/_matrix/media/v3/ticket";
        req.body = json{{"mxc_uri", mxc_uri}}.dump();
        if (with_auth) req.set_header("Authorization", "Bearer token-" + localpart);
        httplib::Response res;
        handler->handle_ticket(req, res);

        TicketResult out;
        out.status = res.status;
        if (res.status == 200) {
            auto body = json::parse(res.body);
            out.mt = body.at("mt").get<std::string>();
            out.exp = body.at("exp").get<int64_t>();
        }
        return out;
    }

    // GET the object with an arbitrary query string and no Authorization header
    // — which is the whole point: this is what Image.source can send.
    int download_with_query(const std::string& media_id, const std::string& query) {
        httplib::Request req;
        req.path = "/_matrix/media/v3/download/test/" + media_id;
        static const std::regex pattern(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))");
        std::regex_match(req.path, req.matches, pattern);
        // httplib::Request exposes params directly; parse the pairs ourselves so
        // the test drives the same structure the server sees off the wire.
        size_t pos = 0;
        while (pos < query.size()) {
            auto amp = query.find('&', pos);
            auto pair = query.substr(pos, amp == std::string::npos ? std::string::npos
                                                                   : amp - pos);
            auto eq = pair.find('=');
            if (eq != std::string::npos) {
                req.params.emplace(pair.substr(0, eq), pair.substr(eq + 1));
            }
            if (amp == std::string::npos) break;
            pos = amp + 1;
        }
        httplib::Response res;
        handler->handle_download(req, res);
        return res.status == -1 ? 200 : res.status;
    }

    int download_with_ticket(const std::string& media_id, const TicketResult& t) {
        return download_with_query(media_id, "mt=" + t.mt + "&exp=" + std::to_string(t.exp));
    }

    // The key the handler is actually using, so a test can forge over the real
    // one rather than a parallel one that would pass for the wrong reason.
    std::vector<unsigned char> key() {
        auto secret = store->get_meta("server.instance_secret");
        EXPECT_TRUE(secret.has_value())
            << "the instance secret should exist once a ticket has been minted";
        return media_ticket::derive_key(secret.value_or(""), "test");
    }
};

} // namespace

// ── 1. The primitive ──────────────────────────────────────────────────────

TEST(MediaTicketPrimitive, RoundTripsAndNamesTheUser) {
    auto k = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    const int64_t exp = now_s() + 300;
    auto mt = media_ticket::mint(k, "test", "abc123", "@alice:test", exp);

    auto got = media_ticket::verify(k, "test", "abc123", mt, exp, now_s());
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, "@alice:test");
}

TEST(MediaTicketPrimitive, ATicketForOneObjectIsNotATicketForAnother) {
    // The failure this rules out: one ticket, obtained legitimately for a file
    // the attacker CAN see, replayed against every other media id on the server.
    auto k = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    const int64_t exp = now_s() + 300;
    auto mt = media_ticket::mint(k, "test", "mine", "@alice:test", exp);

    EXPECT_FALSE(media_ticket::verify(k, "test", "yours", mt, exp, now_s()).has_value());
}

TEST(MediaTicketPrimitive, TheUserIdIsSignedAndCannotBeSwapped) {
    // The user id travels in the clear (the fetch-time re-check needs it), so
    // the only thing stopping a caller rewriting it to someone with more access
    // is that it is inside the MAC.
    auto k = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    const int64_t exp = now_s() + 300;
    auto mt = media_ticket::mint(k, "test", "abc123", "@mallory:test", exp);

    const auto dot = mt.find('.');
    ASSERT_NE(dot, std::string::npos);
    auto forged = media_ticket::mint(k, "test", "abc123", "@admin:test", exp);
    const auto forged_dot = forged.find('.');
    // Mallory's signature under the admin's name.
    auto spliced = forged.substr(0, forged_dot) + mt.substr(dot);

    EXPECT_FALSE(media_ticket::verify(k, "test", "abc123", spliced, exp, now_s()).has_value());
}

TEST(MediaTicketPrimitive, ExpiryIsSignedNotMerelyCarried) {
    // `exp` is a separate query parameter, so the obvious attack is to edit it.
    // It is covered by the MAC, so moving it invalidates the ticket rather than
    // extending it.
    auto k = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    const int64_t exp = now_s() + 60;
    auto mt = media_ticket::mint(k, "test", "abc123", "@alice:test", exp);

    EXPECT_TRUE(media_ticket::verify(k, "test", "abc123", mt, exp, now_s()).has_value());
    EXPECT_FALSE(
        media_ticket::verify(k, "test", "abc123", mt, exp + 3600, now_s()).has_value());
}

TEST(MediaTicketPrimitive, AnExpiredTicketIsRefused) {
    auto k = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    const int64_t exp = now_s() - 1;
    auto mt = media_ticket::mint(k, "test", "abc123", "@alice:test", exp);

    EXPECT_FALSE(media_ticket::verify(k, "test", "abc123", mt, exp, now_s()).has_value());
}

TEST(MediaTicketPrimitive, AnAbsurdlyDistantExpiryIsRefusedEvenWhenSigned) {
    // A correctly signed ticket good for a year means the clock that minted it
    // was wrong, or the TTL clamp was bypassed. Either way it is not the
    // short-lived capability the design rests on.
    auto k = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    const int64_t exp = now_s() + 365 * 24 * 3600;
    auto mt = media_ticket::mint(k, "test", "abc123", "@alice:test", exp);

    EXPECT_FALSE(media_ticket::verify(k, "test", "abc123", mt, exp, now_s()).has_value());
}

TEST(MediaTicketPrimitive, AnotherDeploymentsKeyDoesNotVerifyHere) {
    auto mine = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    auto theirs = media_ticket::derive_key("fedcba9876543210fedcba9876543210", "test");
    const int64_t exp = now_s() + 300;
    auto mt = media_ticket::mint(theirs, "test", "abc123", "@alice:test", exp);

    EXPECT_FALSE(media_ticket::verify(mine, "test", "abc123", mt, exp, now_s()).has_value());
}

TEST(MediaTicketPrimitive, TheSameSecretOnTwoServerNamesGivesUnrelatedKeys) {
    auto a = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "one.example");
    auto b = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "two.example");
    EXPECT_NE(a, b);
}

TEST(MediaTicketPrimitive, AnEmptySecretIsRefusedRatherThanSilentlyShared) {
    EXPECT_THROW(media_ticket::derive_key("", "test"), std::runtime_error);
}

TEST(MediaTicketPrimitive, ASignatureHasExactlyOneSpelling) {
    // The trailing-bit check in b64url_decode. Without it the last character of
    // a 43-character MAC has four values that all decode identically, so one
    // ticket has four wire forms — and a tamper that only touches that
    // character is not a tamper at all.
    auto k = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    const int64_t exp = now_s() + 300;
    auto mt = media_ticket::mint(k, "test", "abc123", "@alice:test", exp);
    ASSERT_TRUE(media_ticket::verify(k, "test", "abc123", mt, exp, now_s()).has_value());

    int accepted = 0;
    for (char c : std::string("ABCD")) {
        auto variant = mt;
        variant.back() = c;
        if (media_ticket::verify(k, "test", "abc123", variant, exp, now_s())) ++accepted;
    }
    EXPECT_LE(accepted, 1);
}

TEST(MediaTicketPrimitive, GarbageDoesNotVerifyAndDoesNotCrash) {
    auto k = media_ticket::derive_key("0123456789abcdef0123456789abcdef", "test");
    const int64_t exp = now_s() + 300;
    for (const char* junk : {"", ".", "a.", ".a", "no-dot", "@@@.@@@", "QWxpY2U",
                             "QWxpY2U.!!!!"}) {
        EXPECT_FALSE(media_ticket::verify(k, "test", "abc123", junk, exp, now_s()).has_value())
            << junk;
    }
}

TEST(MediaTicketPrimitive, ExpParsingIsStrict) {
    EXPECT_EQ(media_ticket::parse_exp("1700000000"), std::optional<int64_t>(1700000000));
    EXPECT_FALSE(media_ticket::parse_exp("").has_value());
    EXPECT_FALSE(media_ticket::parse_exp("-1").has_value());
    EXPECT_FALSE(media_ticket::parse_exp(" 12").has_value());
    EXPECT_FALSE(media_ticket::parse_exp("12abc").has_value());
    EXPECT_FALSE(media_ticket::parse_exp("99999999999999999999").has_value());
}

// ── 2. The mint endpoint ──────────────────────────────────────────────────

TEST(MediaTicketMint, AMemberOfTheChannelGetsOne) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);
    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));

    auto t = f.mint(f.mxc(id), "bob");
    EXPECT_EQ(t.status, 200);
    EXPECT_FALSE(t.mt.empty());
    EXPECT_GT(t.exp, now_s());
    EXPECT_LE(t.exp, now_s() + media_ticket::kMaxTtlSeconds);
}

TEST(MediaTicketMint, RunsTheSameCheckAsDownloadAndRefusesWithTheSame404) {
    // The mint endpoint must not be an easier door than the download it stands
    // in front of, and must not become an existence oracle for media ids: "not
    // yours" and "no such object" are byte-identical.
    TicketFixture f;
    auto alice = f.add_user("alice");
    f.add_user("mallory");
    auto room = f.add_channel(alice);
    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));

    EXPECT_EQ(f.mint(f.mxc(id), "mallory").status, 404);
    EXPECT_EQ(f.mint("mxc://test/00000000000000000000000000000000", "mallory").status, 404);
}

TEST(MediaTicketMint, LosingViewChannelStopsNewTicketsBeingIssued) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);
    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));

    ASSERT_EQ(f.mint(f.mxc(id), "bob").status, 200);
    f.deny_view(room, bob);
    EXPECT_EQ(f.mint(f.mxc(id), "bob").status, 404);
}

TEST(MediaTicketMint, NeedsAnAuthorizationHeader) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);
    EXPECT_EQ(f.mint(f.mxc(id), "alice", /*with_auth=*/false).status, 401);
}

TEST(MediaTicketMint, ATicketCannotMintAnotherTicket) {
    // The TTL is only a bound if a ticket cannot renew itself. handle_ticket
    // authenticates on the header alone, so presenting `mt`/`exp` here buys
    // nothing — otherwise a five-minute capability for one object would be a
    // permanent one for everything the holder could ever see.
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);
    auto t = f.mint(f.mxc(id), "alice");
    ASSERT_EQ(t.status, 200);

    httplib::Request req;
    req.method = "POST";
    req.path = "/_matrix/media/v3/ticket";
    req.body = json{{"mxc_uri", f.mxc(id)}}.dump();
    req.params.emplace("mt", t.mt);
    req.params.emplace("exp", std::to_string(t.exp));
    httplib::Response res;
    f.handler->handle_ticket(req, res);

    EXPECT_EQ(res.status, 401);
}

TEST(MediaTicketMint, AForeignHostUriGetsNothing) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);
    EXPECT_EQ(f.mint("mxc://evil.example/" + id, "alice").status, 404);
}

TEST(MediaTicketMint, AMediaIdThatCouldSmuggleAPathSegmentIsRefused) {
    TicketFixture f;
    f.add_user("alice");
    EXPECT_EQ(f.mint("mxc://test/../../etc/passwd", "alice").status, 404);
    EXPECT_EQ(f.mint("mxc://test/abc?x=1", "alice").status, 404);
    EXPECT_EQ(f.mint("mxc://test/", "alice").status, 404);
}

TEST(MediaTicketMint, ABadBodyIs400) {
    TicketFixture f;
    f.add_user("alice");
    httplib::Request req;
    req.method = "POST";
    req.path = "/_matrix/media/v3/ticket";
    req.body = "not json";
    req.set_header("Authorization", "Bearer token-alice");
    httplib::Response res;
    f.handler->handle_ticket(req, res);
    EXPECT_EQ(res.status, 400);
}

TEST(MediaTicketMint, TheInstanceSecretIsGeneratedOnceAndReused) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);

    ASSERT_EQ(f.mint(f.mxc(id), "alice").status, 200);
    auto first = f.store->get_meta("server.instance_secret");
    ASSERT_TRUE(first.has_value());
    EXPECT_GE(first->size(), 32u);

    // A second handler over the same database must sign compatibly, which is
    // what makes a ticket survive a server restart.
    MediaHandler other(*f.store, f.config, f.storage);
    httplib::Request req;
    req.method = "POST";
    req.path = "/_matrix/media/v3/ticket";
    req.body = json{{"mxc_uri", f.mxc(id)}}.dump();
    req.set_header("Authorization", "Bearer token-alice");
    httplib::Response res;
    other.handle_ticket(req, res);
    ASSERT_EQ(res.status, 200);

    EXPECT_EQ(f.store->get_meta("server.instance_secret"), first);

    auto body = json::parse(res.body);
    TicketFixture::TicketResult t;
    t.mt = body.at("mt").get<std::string>();
    t.exp = body.at("exp").get<int64_t>();
    EXPECT_EQ(f.download_with_ticket(id, t), 200);
}

// ── 3. The download path ──────────────────────────────────────────────────

TEST(MediaTicketDownload, ATicketFetchesTheObjectWithNoTokenInTheUrl) {
    // The point of the whole change: a URL an Image.source can load, carrying no
    // session credential.
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);
    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));

    auto t = f.mint(f.mxc(id), "bob");
    ASSERT_EQ(t.status, 200);
    EXPECT_EQ(f.download_with_ticket(id, t), 200);
}

TEST(MediaTicketDownload, TicketIsNotAGrant) {
    // THE test. A ticket resolves an identity; may_download() still decides.
    //
    // Bob legitimately mints a ticket, then loses VIEW_CHANNEL before spending
    // it. If the ticket were treated as the authorization — the obvious
    // "optimisation", since the check already ran at mint time — the lockdown
    // would not take effect for the life of the ticket, and a moderator locking
    // a channel would have no way to know that.
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);
    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));

    auto t = f.mint(f.mxc(id), "bob");
    ASSERT_EQ(t.status, 200);
    ASSERT_EQ(f.download_with_ticket(id, t), 200);

    f.deny_view(room, bob);

    EXPECT_EQ(f.download_with_ticket(id, t), 404);
}

TEST(MediaTicketDownload, ATicketForOneObjectDoesNotFetchAnother) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);
    auto mine = f.upload(alice);
    auto secret = f.upload(alice); // never posted anywhere: uploader-only
    f.post(room, alice, f.mxc(mine));

    auto t = f.mint(f.mxc(mine), "bob");
    ASSERT_EQ(t.status, 200);

    EXPECT_EQ(f.download_with_ticket(secret, t), 401);
}

TEST(MediaTicketDownload, AForgedOrTamperedTicketIsRefused) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);
    auto t = f.mint(f.mxc(id), "alice");
    ASSERT_EQ(t.status, 200);

    // Flip a signature character. NOT the last one: 32 MAC bytes are 43
    // base64url characters and the final character carries only two significant
    // bits, so changing it need not change the decoded signature at all. (It
    // does now — verify() rejects a non-canonical encoding — but a tamper test
    // that depends on that is testing the wrong thing.)
    auto tampered = t;
    const auto dot = tampered.mt.find('.');
    ASSERT_NE(dot, std::string::npos);
    const auto mid = dot + 1 + (tampered.mt.size() - dot - 1) / 2;
    tampered.mt[mid] = (tampered.mt[mid] == 'A' ? 'B' : 'A');
    EXPECT_EQ(f.download_with_ticket(id, tampered), 401);

    // Push the expiry out without re-signing.
    auto extended = t;
    extended.exp += 86400;
    EXPECT_EQ(f.download_with_ticket(id, extended), 401);

    // Drop the expiry entirely.
    EXPECT_EQ(f.download_with_query(id, "mt=" + t.mt), 401);
}

TEST(MediaTicketDownload, AnExpiredTicketStopsWorking) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);
    ASSERT_EQ(f.mint(f.mxc(id), "alice").status, 200); // forces the key into existence

    // Sign a ticket in the past with the server's real key rather than sleeping
    // out a five-minute TTL.
    const int64_t exp = now_s() - 1;
    TicketFixture::TicketResult stale;
    stale.exp = exp;
    stale.mt = media_ticket::mint(f.key(), "test", id, "@alice:test", exp);

    EXPECT_EQ(f.download_with_ticket(id, stale), 401);
}

TEST(MediaTicketDownload, ATicketNamingANonexistentUserIsRefused) {
    // Not reachable by forgery — the name is signed — but it is reachable by
    // time: the account can be deleted while a ticket is still live.
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);
    ASSERT_EQ(f.mint(f.mxc(id), "alice").status, 200);

    const int64_t exp = now_s() + 300;
    TicketFixture::TicketResult ghost;
    ghost.exp = exp;
    ghost.mt = media_ticket::mint(f.key(), "test", id, "@ghost:test", exp);

    EXPECT_EQ(f.download_with_ticket(id, ghost), 401);
}

TEST(MediaTicketDownload, AnAuthorizationHeaderStillWins) {
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);

    httplib::Request req;
    req.path = "/_matrix/media/v3/download/test/" + id;
    static const std::regex pattern(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))");
    std::regex_match(req.path, req.matches, pattern);
    req.set_header("Authorization", "Bearer token-alice");
    httplib::Response res;
    f.handler->handle_download(req, res);
    EXPECT_EQ(res.status == -1 ? 200 : res.status, 200);
}

// ── 4. The legacy branch ──────────────────────────────────────────────────

TEST(MediaTicketLegacy, AccessTokenInTheQueryStringStillWorksForOneRelease) {
    // Kept ONLY so that upgrading the server does not blank every image in an
    // older client that has no ticket cache. Delete this test together with the
    // branch in authenticate_media() in the release after the one that ships
    // tickets; when it goes, this expectation becomes 401.
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);

    EXPECT_EQ(f.download_with_query(id, "access_token=token-alice"), 200);
}

TEST(MediaTicketLegacy, AStaleTicketFallsThroughToTheTokenRatherThanFailing) {
    // Transitional belt and braces: a client that sends both does not break the
    // moment its cached ticket ages out.
    TicketFixture f;
    auto alice = f.add_user("alice");
    auto id = f.upload(alice);
    ASSERT_EQ(f.mint(f.mxc(id), "alice").status, 200);

    const int64_t exp = now_s() - 1;
    auto stale = media_ticket::mint(f.key(), "test", id, "@alice:test", exp);

    EXPECT_EQ(f.download_with_query(id, "mt=" + stale + "&exp=" + std::to_string(exp)
                                            + "&access_token=token-alice"),
              200);
}
