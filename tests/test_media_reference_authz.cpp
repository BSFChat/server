// The write side of the media ACL: who may create a media reference.
//
// `media_refs` is the table MediaHandler::may_download reads to decide who may
// have an object's bytes. Finding F5 of docs/audit-permissions-2026-09.md is
// that the table was written by the caller: SqliteStore::insert_event indexed
// every `mxc://` string at every depth of every event with no check of any
// kind, so mentioning an id was the act that granted access to it.
//
// The first test here is the audit's own proof, brought over and enabled. It is
// strengthened rather than relaxed — it now asserts the precondition the audit
// described in prose (that the object really is bound to the channel Mallory
// was thrown out of) instead of taking it on trust.
//
// The rest of the file is what the fix has to NOT break, because a fix that
// stops a forward from working is not a fix, and what it has to hold in the
// other direction: `media_refs` is also the reaper's liveness test, so a bogus
// reference was a way to pin an object on disk forever and a fix that drops
// legitimate references would delete live media.
//
// The fixture is a near-copy of the ones in test_media_security.cpp and
// test_permission_scope.cpp rather than a shared header, for the reason the
// audit gives for its own: a proof should not be able to go green because
// somebody changed a helper somewhere else.

#include <gtest/gtest.h>

#include "api/EventHandler.h"
#include "api/MediaHandler.h"
#include "api/ProfileHandler.h"
#include "api/RoomHandler.h"
#include "auth/AutoJoin.h"
#include "auth/LocalAuth.h"
#include "auth/MediaAccess.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "identity/Nickname.h"
#include "storage/LocalStorage.h"
#include "storage/MediaReaper.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <regex>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

const std::string kRoomsPrefix = "/_matrix/client/v3/rooms/";

std::filesystem::path unique_media_dir() {
    static std::atomic<unsigned> n{0};
    return std::filesystem::temp_directory_path() /
           ("bsfchat-mediarefs-" + std::to_string(::getpid()) + "-" +
            std::to_string(n.fetch_add(1)));
}

httplib::Request make_request(const std::string& path, const std::string& token,
                              const std::string& body = "") {
    httplib::Request req;
    req.path = path;
    req.body = body;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

::testing::AssertionResult IsOk(const httplib::Response& res) {
    if (res.status == -1 || res.status == 200) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "status " << res.status << ", body: " << res.body;
}

template <typename Handler, typename Method>
httplib::Response call(Handler& handler, Method method, const std::string& path,
                       const std::string& token, const std::string& body = "") {
    auto req = make_request(path, token, body);
    httplib::Response res;
    (handler.*method)(req, res);
    return res;
}

ServerRole role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

// Smallest thing LocalStorage will accept as an image body; the bytes are never
// inspected by anything these tests assert on.
const std::string kPng =
    std::string("\x89PNG\r\n\x1a\n", 8) + std::string(64, '\0');

struct Fixture {
    std::filesystem::path dir;
    Config config;
    std::shared_ptr<LocalStorage> storage;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    std::unique_ptr<MediaHandler> media;

    Fixture() {
        dir = unique_media_dir();
        std::filesystem::create_directories(dir);
        config = Config::defaults();
        config.server_name = "test";
        config.require_media_auth = true;
        storage = std::make_shared<LocalStorage>(dir.string());
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        media = std::make_unique<MediaHandler>(*store, config, storage);

        ServerRolesContent roles;
        roles.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        // A delegated channel builder: MANAGE_CHANNELS and nothing else beyond
        // @everyone. Deliberately not an administrator, because ADMINISTRATOR
        // short-circuits every flag including VIEW_CHANNEL and would dissolve
        // the very deny these tests are built on.
        roles.roles.push_back(role("builder", 10,
                                   permission::kEveryoneDefault | permission::kManageChannels));
        roles.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        json j;
        to_json(j, roles);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    ~Fixture() { std::filesystem::remove_all(dir); }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev");
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    std::string add_channel(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomName), std::string(""),
                            json{{"name", name}}.dump(), 1000);
        store->insert_event(generate_event_id("test"), room_id, creator,
                            std::string(event_type::kRoomType), std::string(""),
                            json{{"type", "text"}}.dump(), 1001);
        return room_id;
    }

    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
    }

    // An ALLOW override, the ordinary way a member is handed one channel.
    void grant(const std::string& room_id, const std::string& target,
               permission::Flags flags) {
        ChannelPermissionOverride ov;
        ov.allow = flags;
        ov.deny = 0;
        json j;
        to_json(j, ov);
        store->insert_event(generate_event_id("test"), room_id, "@server:test",
                            std::string(event_type::kChannelPermissions), "user:" + target,
                            j.dump(), 1004);
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

    // An uploaded object, owned by `uploader`, attached to nothing yet. Hex,
    // like MediaHandler::generate_media_id — the reference index only ever
    // extracts hex ids.
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

    std::string mxc(const std::string& id) const { return "mxc://test/" + id; }

    bool bound_to(const std::string& mxc_uri, const std::string& room_id) {
        auto rooms = store->get_media_rooms(mxc_uri);
        return std::find(rooms.begin(), rooms.end(), room_id) != rooms.end();
    }

    // Post an attachment the way the server itself would: through the vetted
    // ingest every production send path uses.
    std::string post(const std::string& room_id, const std::string& sender,
                     const std::string& mxc_uri, int64_t ts = 2000) {
        auto event_id = generate_event_id("test");
        insert_event_vetted(*store, config, event_id, room_id, sender,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.image"}, {"body", "p.png"},
                                 {"url", mxc_uri}}.dump(),
                            ts);
        return event_id;
    }

    int download_status(const std::string& media_id, const std::string& localpart) {
        httplib::Request req;
        req.path = "/_matrix/media/v3/download/test/" + media_id;
        static const std::regex pattern(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))");
        std::regex_match(req.path, req.matches, pattern);
        req.set_header("Authorization", "Bearer " + localpart);
        httplib::Response res;
        media->handle_download(req, res);
        // httplib leaves status at -1 when a handler only installs a content
        // provider, which is what a successful streamed download does.
        return res.status == -1 ? 200 : res.status;
    }
};

std::string send_path(const std::string& room, const std::string& txn) {
    return kRoomsPrefix + room + "/send/m.room.message/" + txn;
}

std::string avatar_path(const std::string& user) {
    return "/_matrix/client/v3/profile/" + user + "/avatar_url";
}

// Far enough past every fixture object's created_at that the grace period is
// satisfied, without touching the clock.
int64_t past_grace(const Config& config) {
    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return now + static_cast<int64_t>(config.media_orphan_grace_hours) * 3600 * 1000 + 60000;
}

} // namespace

// ═════ 1. The audit's proof ══════════════════════════════════════════════════

// PermissionAudit2026_09.DISABLED_F5_ASenderCanRebindMediaItMayNotRead,
// enabled. The audit's wording, because it is the statement of the defect:
//
//   a user who merely KNOWS a media id — because they saw it while permitted,
//   or before it was redacted — re-attaches it to a channel they can still see
//   and restores their own access, and grants it to everyone else in that
//   channel.
//
// The id is 128 bits of CSPRNG, so this was never blind enumeration. It is a
// revocation bypass available to whoever already held the id, and what it
// defeats is every mechanism meant to take access away afterwards.
TEST(MediaReferenceAuthz, F5_ASenderCanRebindMediaItMayNotRead) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("mallory");

    auto secret = f.add_channel(alice, "leadership");
    auto open = f.add_channel(alice, "general");
    f.join(secret, mallory);
    f.join(open, mallory);

    auto id = f.upload(alice);
    f.post(secret, alice, f.mxc(id));

    // The precondition the audit stated in prose. Asserted here so the test
    // cannot go green by the object never having been bound to anything.
    ASSERT_TRUE(f.bound_to(f.mxc(id), secret));
    ASSERT_EQ(f.download_status(id, "token-mallory"), 200)
        << "precondition: Mallory could see it while she was in #leadership";

    // Mallory is then denied the channel. The attachment is supposed to go with
    // it — that is MediaAcl.LosingViewChannelRevokesTheAttachmentsToo.
    f.deny_view(secret, mallory);
    {
        PermissionsEngine perms(*f.store, f.config);
        ASSERT_FALSE(perms.can(mallory, secret, permission::kViewChannel))
            << "precondition: Mallory is out of #leadership";
    }
    ASSERT_EQ(f.download_status(id, "token-mallory"), 404);

    // Mallory sends a message into #general through the REAL send handler.
    //
    // msgtype is m.text, so EventHandler's `has_attachment` is false and the
    // ATTACH_FILES gate never runs: this needs nothing beyond the @everyone
    // default. The uri rides in an unrecognised key, which the send path stores
    // verbatim and no client renders — the reference walk covers every string
    // at every depth, so the key it sits under is irrelevant.
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    auto sent = call(events, &EventHandler::handle_send_event, send_path(open, "txn-f5"),
                     "token-mallory",
                     json{{"msgtype", "m.text"}, {"body", "hi"},
                          {"com.example.note", f.mxc(id)}}.dump());
    ASSERT_TRUE(IsOk(sent)) << "the send itself is legitimate and must succeed";

    // THE ASSERTION THAT FAILED BEFORE THE FIX. #general must not become a room
    // in which this object is readable, because the person who put the
    // reference there was not allowed to read it.
    EXPECT_FALSE(f.bound_to(f.mxc(id), open))
        << "a sender who may not read an object bound it to a channel of their "
           "choosing, restoring their own access and publishing it to everyone "
           "who can see that channel";

    // ...and the consequence, end to end, which is what the binding was for.
    EXPECT_EQ(f.download_status(id, "token-mallory"), 404);
}

// The same mention by somebody who CAN still read it. This is the control that
// says the test above is about authorisation and not about m.text messages, or
// unrecognised keys, or mentions in general.
TEST(MediaReferenceAuthz, AMentionByAReaderStillBinds) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto source = f.add_channel(alice, "leadership");
    auto open = f.add_channel(alice, "general");
    f.join(source, bob);
    f.join(open, bob);

    auto id = f.upload(alice);
    f.post(source, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "token-bob"), 200);

    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_send_event,
                          send_path(open, "txn-ok"), "token-bob",
                          json{{"msgtype", "m.text"}, {"body", "look"},
                               {"com.example.note", f.mxc(id)}}.dump())));

    EXPECT_TRUE(f.bound_to(f.mxc(id), open));
}

// ═════ 2. The URI-carrying paths that must keep working ══════════════════════

// A forward is the case the whole fix is shaped around: the sender did not
// upload the object, and must still be able to carry it into another room,
// where it becomes readable to that room's members. Rule 2 of the ACL — "access
// to any one of the rooms that names it is access to the bytes" — is what makes
// this legitimate, and it is the same rule the vetting asks.
TEST(MediaReferenceAuthz, AForwardByAMemberOfTheSourceRoomWidensAccess) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto carol = f.add_user("carol");

    auto source = f.add_channel(alice, "design");
    auto target = f.add_channel(alice, "general");
    f.join(source, bob);
    f.join(target, bob);
    f.join(target, carol);
    f.deny_view(source, carol);

    auto id = f.upload(alice);
    f.post(source, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "token-carol"), 404)
        << "precondition: Carol cannot see #design";

    // Bob forwards it. m.image with an ATTACH_FILES-bearing default role, the
    // ordinary shape.
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_send_event,
                          send_path(target, "txn-fwd"), "token-bob",
                          json{{"msgtype", "m.image"}, {"body", "p.png"},
                               {"url", f.mxc(id)}}.dump())));

    EXPECT_TRUE(f.bound_to(f.mxc(id), target)) << "a forward must still bind";
    EXPECT_EQ(f.download_status(id, "token-carol"), 200)
        << "Carol can see the room the forward landed in, so she may see what it shows";
}

// A reply quoting an image, and an edit of a message that carries one. Both
// re-state a URI the sender did not upload; both are performed by somebody who
// can read the room it is already in.
TEST(MediaReferenceAuthz, AReplyQuotingAnImageCarriesItsOwnBinding) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join(room, bob);

    auto id = f.upload(alice);
    auto original = f.post(room, alice, f.mxc(id));

    // Bob replies, quoting the attachment in the fallback the way a client does.
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_send_event,
                          send_path(room, "txn-reply"), "token-bob",
                          json{{"msgtype", "m.text"}, {"body", "> p.png\n\nnice"},
                               {"m.relates_to", {{"m.in_reply_to", {{"event_id", original}}}}},
                               {"com.example.quoted_url", f.mxc(id)}}.dump())));

    // Redacting the ORIGINAL is what makes this test about the reply. Without
    // it, the binding the original created answers the assertion and the reply
    // could have created nothing at all.
    ASSERT_TRUE(f.store->redact_event(original, alice));

    EXPECT_TRUE(f.bound_to(f.mxc(id), room))
        << "the quote in a surviving reply still shows the image, so it still grants it";
    EXPECT_EQ(f.download_status(id, "token-bob"), 200);
}

// An edit that swaps the attachment. The replacement names an object the
// original never did, so the binding it needs can only come from the edit.
TEST(MediaReferenceAuthz, AnEditThatSwapsTheAttachmentBindsTheNewOne) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join(room, bob);

    auto first = f.upload(alice);
    auto second = f.upload(alice);
    auto original = f.post(room, alice, f.mxc(first));
    ASSERT_FALSE(f.bound_to(f.mxc(second), room));

    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_send_event,
                          send_path(room, "txn-edit"), "token-alice",
                          json{{"msgtype", "m.image"}, {"body", "* p.png"},
                               {"url", f.mxc(second)},
                               {"m.new_content", {{"msgtype", "m.image"}, {"body", "p.png"},
                                                  {"url", f.mxc(second)}}},
                               {"m.relates_to", {{"rel_type", "m.replace"},
                                                 {"event_id", original}}}}.dump())));

    EXPECT_TRUE(f.bound_to(f.mxc(second), room));
    EXPECT_EQ(f.download_status(second, "token-bob"), 200);
}

// A channel icon written through PUT /state. Same rule, different door: the
// writer may name an object they can read and not one they cannot.
TEST(MediaReferenceAuthz, AChannelIconIsVettedLikeAnyOtherReference) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("mallory");
    auto secret = f.add_channel(alice, "leadership");
    auto mine = f.add_channel(mallory, "mallory-corner");
    f.join(secret, mallory);
    f.join(mine, alice);

    auto id = f.upload(alice);
    f.post(secret, alice, f.mxc(id));
    f.deny_view(secret, mallory);

    // Both of them hold MANAGE_CHANNELS here, so the permission to write the
    // icon is not the missing ingredient; the object is.
    f.grant(mine, mallory, permission::kManageChannels);
    f.grant(mine, alice, permission::kManageChannels);

    RoomHandler rooms(*f.store, *f.sync, f.config);
    // The write SUCCEEDS — an unreadable reference is dropped, not refused, so
    // that this endpoint does not become an oracle for which media ids exist
    // (see MediaAccess::vet). What must not happen is the binding.
    ASSERT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          kRoomsPrefix + mine + "/state/m.room.avatar", "token-mallory",
                          json{{"url", f.mxc(id)}}.dump())));
    EXPECT_FALSE(f.bound_to(f.mxc(id), mine));
    EXPECT_EQ(f.download_status(id, "token-mallory"), 404);

    // Alice, who can read it, may use it as an icon in a channel she is in.
    ASSERT_TRUE(IsOk(call(rooms, &RoomHandler::handle_set_state,
                          kRoomsPrefix + mine + "/state/m.room.avatar", "token-alice",
                          json{{"url", f.mxc(id)}}.dump())));
    EXPECT_TRUE(f.bound_to(f.mxc(id), mine));
}

// ═════ 3. Redaction is not undoable ══════════════════════════════════════════

// The half of F5 that matters most: `redact_event` deletes the object's rows
// from `media_refs` precisely so a deleted attachment stops being fetchable,
// and a later mention put them back.
TEST(MediaReferenceAuthz, ARedactionCannotBeUndoneByALaterMention) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join(room, bob);

    auto id = f.upload(alice);
    auto event_id = f.post(room, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "token-bob"), 200)
        << "precondition: Bob saw it, so he has the id";

    ASSERT_TRUE(f.store->redact_event(event_id, alice));
    ASSERT_TRUE(f.store->get_media_rooms(f.mxc(id)).empty());
    ASSERT_EQ(f.download_status(id, "token-bob"), 404);

    // Bob, still a perfectly ordinary member of the room the image was deleted
    // from, names it again.
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_send_event,
                          send_path(room, "txn-undo"), "token-bob",
                          json{{"msgtype", "m.text"}, {"body", "remember this?"},
                               {"com.example.note", f.mxc(id)}}.dump())));

    EXPECT_TRUE(f.store->get_media_rooms(f.mxc(id)).empty())
        << "a redaction was reversed by naming the object in a new event";
    EXPECT_EQ(f.download_status(id, "token-bob"), 404);
    // The uploader keeps it, as they always did: nothing deletes the blob on
    // redaction, and pretending otherwise would be a claim this package does
    // not make.
    EXPECT_EQ(f.download_status(id, "token-alice"), 200);
}

// The same reversal through the redaction event's own `reason` field, which is
// free text and would otherwise be vetted against the redactor — who, when they
// are the uploader, passes rule 1 every time. The redaction would have undone
// itself in one request.
TEST(MediaReferenceAuthz, ARedactionReasonCannotRebindTheObjectItDeletes) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join(room, bob);

    auto id = f.upload(alice);
    auto event_id = f.post(room, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "token-bob"), 200);

    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    auto res = call(events, &EventHandler::handle_redact,
                    kRoomsPrefix + room + "/redact/" + event_id + "/txn-redact",
                    // The reason is the URI and nothing else. A string that merely
                    // CONTAINS one is not extracted — media_uris_in_content takes
                    // strings that ARE a uri — so a "oops <uri>" reason would have
                    // made this test pass without exercising anything.
                    "token-alice", json{{"reason", f.mxc(id)}}.dump());
    ASSERT_TRUE(IsOk(res)) << "the redaction itself must succeed";

    EXPECT_TRUE(f.store->get_media_rooms(f.mxc(id)).empty())
        << "the redaction event's reason re-created the binding it had just deleted";
    EXPECT_EQ(f.download_status(id, "token-bob"), 404);
}

// ═════ 4. The avatar fall-through ════════════════════════════════════════════

// MediaAccess rule 3 makes a room-less object readable by every authenticated
// account when it is somebody's avatar. Rule 3 is reached only when media_refs
// is EMPTY — and emptying media_refs is exactly what a redaction does. So an
// unvalidated avatar write turned "a moderator deleted that image" into "that
// image is now readable by the entire server", which is the worst variant the
// audit records.
TEST(MediaReferenceAuthz, ARedactedObjectCannotBeMadeServerPublicByWearingIt) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("mallory");
    auto stranger = f.add_user("stranger");
    auto room = f.add_channel(alice, "general");
    f.join(room, mallory);

    auto id = f.upload(alice);
    auto event_id = f.post(room, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "token-mallory"), 200);

    ASSERT_TRUE(f.store->redact_event(event_id, alice));
    ASSERT_TRUE(f.store->get_media_rooms(f.mxc(id)).empty())
        << "precondition: redaction is what makes the avatar rule reachable";

    ProfileHandler profiles(*f.store, *f.sync, f.config);
    auto res = call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(mallory),
                    "token-mallory", json{{"avatar_url", f.mxc(id)}}.dump());
    EXPECT_EQ(res.status, 403)
        << "an account wore an object it did not upload and made it server-public";

    EXPECT_FALSE(f.store->is_avatar_of(f.mxc(id), mallory));
    EXPECT_EQ(f.download_status(id, "token-mallory"), 404);
    EXPECT_EQ(f.download_status(id, "token-stranger"), 404)
        << "a redacted attachment became readable by every account on the server";
}

// The control, and the behaviour the narrowing has to preserve: your own upload
// is your avatar, and an avatar stays readable by everyone, which is the point
// of rule 3.
TEST(MediaReferenceAuthz, YourOwnUploadIsStillAValidAvatar) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto id = f.upload(alice);
    ASSERT_EQ(f.download_status(id, "token-bob"), 404) << "precondition: not yet an avatar";

    ProfileHandler profiles(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(alice),
                          "token-alice", json{{"avatar_url", f.mxc(id)}}.dump())));

    EXPECT_TRUE(f.store->is_avatar_of(f.mxc(id), alice));
    EXPECT_EQ(f.download_status(id, "token-bob"), 200);

    // And clearing it is always allowed — the empty string is not a URI and
    // must not be refused by the ownership test.
    EXPECT_TRUE(IsOk(call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(alice),
                          "token-alice", json{{"avatar_url", ""}}.dump())));
    EXPECT_FALSE(f.store->is_avatar_of(f.mxc(id), alice));
}

// Why the test is ownership and not "may you read it". Bob can see the channel
// Alice posted in, so he can read her attachment — and if that were enough, he
// could adopt it as his avatar and it would become readable by the whole server
// the moment her message was redacted. Laundering channel-scoped media into
// server-public media is the act being refused, and only ownership refuses it.
TEST(MediaReferenceAuthz, AnAttachmentYouCanSeeIsStillNotYoursToWear) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(alice, "general");
    f.join(room, bob);

    auto id = f.upload(alice);
    f.post(room, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "token-bob"), 200)
        << "precondition: Bob can read it, which is exactly what must not be enough";

    ProfileHandler profiles(*f.store, *f.sync, f.config);
    auto res = call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(bob),
                    "token-bob", json{{"avatar_url", f.mxc(id)}}.dump());
    EXPECT_EQ(res.status, 403);
    EXPECT_FALSE(f.store->is_avatar_of(f.mxc(id), bob));
}

// The second gate, and the one that matters to a deployment that has been
// running: a laundered avatar row already in the database — written before
// handle_put_avatar_url refused it — must stop granting anything. Simulated by
// writing it through the store directly, which is what the old handler did.
TEST(MediaReferenceAuthz, AnAlreadyLaunderedAvatarRowGrantsNothing) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("mallory");
    auto stranger = f.add_user("stranger");
    auto room = f.add_channel(alice, "general");
    f.join(room, mallory);

    auto id = f.upload(alice);
    auto event_id = f.post(room, alice, f.mxc(id));
    ASSERT_TRUE(f.store->redact_event(event_id, alice));
    ASSERT_TRUE(f.store->get_media_rooms(f.mxc(id)).empty());

    // The row the old handler would have written.
    f.store->set_avatar_url(mallory, f.mxc(id));

    EXPECT_FALSE(f.store->is_avatar_of(f.mxc(id), alice))
        << "the object's uploader is not the one wearing it";
    EXPECT_EQ(f.download_status(id, "token-stranger"), 404);
    EXPECT_EQ(f.download_status(id, "token-mallory"), 404);
    EXPECT_EQ(f.download_status(id, "token-alice"), 200) << "the uploader keeps it";

    // ...and it does not protect the bytes either. A reference that grants
    // nothing must not keep an object off the orphan list, or "wear somebody
    // else's redacted image" becomes a way to make deletion never happen.
    f.config.media_reaper_dry_run = false;
    MediaReaper reaper(*f.store, f.config, f.storage);
    EXPECT_EQ(reaper.sweep_once(past_grace(f.config)), 1u);
}

// The same refusal for an id that is not on this server and for one that does
// not exist, byte for byte with "not yours", so this endpoint is not an oracle
// for which media ids are real.
TEST(MediaReferenceAuthz, AnAvatarThatIsNotAnObjectHereIsRefusedIdentically) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto theirs = f.upload(bob);

    ProfileHandler profiles(*f.store, *f.sync, f.config);
    auto not_mine = call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(alice),
                         "token-alice", json{{"avatar_url", f.mxc(theirs)}}.dump());
    auto no_such = call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(alice),
                        "token-alice",
                        json{{"avatar_url", "mxc://test/deadbeefdeadbeefdeadbeefdeadbeef"}}.dump());
    auto foreign = call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(alice),
                        "token-alice",
                        json{{"avatar_url", "mxc://evil.example/" + theirs}}.dump());

    EXPECT_EQ(not_mine.status, 403);
    EXPECT_EQ(no_such.status, 403);
    EXPECT_EQ(foreign.status, 403);
    EXPECT_EQ(not_mine.body, no_such.body);
    EXPECT_EQ(not_mine.body, foreign.body);
}

// A member event is vouched for by its SUBJECT, not by whoever wrote it.
//
// Member content is a projection of an account's own profile — including its
// avatar — and it is written by whoever happens to be performing the membership
// change. Vetting it against the sender makes an avatar's reachability depend
// on who last touched the membership: a moderator who cannot see any of the
// rooms the avatar is already bound to would emit a member event that binds
// nothing, and the invitee would render with a broken picture for everyone in
// the new channel.
//
// It is safe to name the subject only because member content is never taken
// from a request body — every writer builds it with member_event_content() from
// the server's own records. See MediaAccess::vet.
TEST(MediaReferenceAuthz, AMemberEventBindsTheSubjectsAvatarNotTheSendersReach) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("builder", {"builder"});

    auto alices_room = f.add_channel(alice, "alices-room");
    f.deny_view(alices_room, mallory);

    // Alice's avatar, worn, and therefore bound to the one room she is in.
    auto avatar = f.upload(alice);
    ProfileHandler profiles(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(alice),
                          "token-alice", json{{"avatar_url", f.mxc(avatar)}}.dump())));
    ASSERT_TRUE(f.bound_to(f.mxc(avatar), alices_room))
        << "precondition: the avatar is bound, so the room-less avatar rule is NOT "
           "what keeps it readable";
    {
        MediaAccess access(*f.store, f.config);
        ASSERT_FALSE(access.may_read_uri(mallory, f.mxc(avatar)))
            << "precondition: the builder cannot read Alice's avatar in her own right";
    }

    // The builder makes a channel and invites Alice into it. The member event
    // it writes carries Alice's avatar_url.
    RoomHandler rooms(*f.store, *f.sync, f.config);
    auto created = call(rooms, &RoomHandler::handle_create_room,
                        "/_matrix/client/v3/createRoom", "token-builder",
                        json{{"name", "new-channel"},
                             {"invite", json::array({alice})}}.dump());
    ASSERT_TRUE(IsOk(created)) << created.body;
    const auto new_room = json::parse(created.body).at("room_id").get<std::string>();

    EXPECT_TRUE(f.bound_to(f.mxc(avatar), new_room))
        << "an invited member's avatar stopped being readable in the channel they "
           "were invited to, because the person who invited them could not see it";
}

// The same rule on the force-join path. Every account on this server is joined
// into every public channel, and that join is what binds their avatar in it —
// so an unvetted auto-join would leave a new member rendering with a broken
// picture in every channel they were put into.
TEST(MediaReferenceAuthz, AutoJoinBindsTheJoinersAvatarInEveryChannel) {
    Fixture f;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_channel(bob, "general");

    auto avatar = f.upload(alice);
    ProfileHandler profiles(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(alice),
                          "token-alice", json{{"avatar_url", f.mxc(avatar)}}.dump())));
    ASSERT_FALSE(f.bound_to(f.mxc(avatar), room))
        << "precondition: Alice is not in the channel yet";

    // auto_join_all_users rather than auto_join_public_rooms: both funnel
    // through the same join_user_to_room, and this one does not need the
    // fixture to fabricate an m.room.join_rules event.
    auto_join_all_users(*f.store, *f.sync, f.config, room, bob);

    ASSERT_TRUE(f.store->is_room_member(room, alice)) << "precondition: the join happened";
    EXPECT_TRUE(f.bound_to(f.mxc(avatar), room));
}

// ═════ 5. The reaper, in both directions ═════════════════════════════════════

// `media_refs` is not only the ACL: find_orphaned_media() reads it to decide
// what is unreferenced, so it is also what keeps an object's bytes on disk.
// That makes a fix that drops legitimate references a way to DELETE live media,
// which is the failure mode to check first and the one dry run would not save
// anybody from once the reaper is armed.
TEST(MediaReferenceAuthz, TheReaperLeavesLegitimatelyReferencedMediaAlone) {
    Fixture f;
    f.config.media_reaper_dry_run = false;
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto source = f.add_channel(alice, "design");
    auto target = f.add_channel(alice, "general");
    f.join(source, bob);
    f.join(target, bob);

    auto posted = f.upload(alice);         // an ordinary attachment
    auto forwarded = f.upload(alice);      // posted once, then forwarded by Bob
    auto worn = f.upload(bob);             // Bob's avatar, referenced by nothing

    f.post(source, alice, f.mxc(posted));
    const auto forwarded_original = f.post(source, alice, f.mxc(forwarded));

    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_send_event,
                          send_path(target, "txn-fwd"), "token-bob",
                          json{{"msgtype", "m.image"}, {"body", "p.png"},
                               {"url", f.mxc(forwarded)}}.dump())));

    ProfileHandler profiles(*f.store, *f.sync, f.config);
    ASSERT_TRUE(IsOk(call(profiles, &ProfileHandler::handle_put_avatar_url, avatar_path(bob),
                          "token-bob", json{{"avatar_url", f.mxc(worn)}}.dump())));

    // The forwarded object's ORIGINAL is deleted, so the only thing standing
    // between it and the reaper is the reference Bob's forward created. That is
    // the case this test exists for: a fix that drops a legitimate reference
    // does not merely break an image, it destroys the bytes.
    ASSERT_TRUE(f.store->redact_event(forwarded_original, alice));
    ASSERT_FALSE(f.store->get_media_rooms(f.mxc(forwarded)).empty())
        << "precondition: the forward is now the only reference";

    MediaReaper reaper(*f.store, f.config, f.storage);
    EXPECT_EQ(reaper.sweep_once(past_grace(f.config)), 0u)
        << "the reaper collected an object that is still referenced";

    EXPECT_TRUE(f.store->get_media(posted).has_value());
    EXPECT_TRUE(f.store->get_media(forwarded).has_value());
    EXPECT_TRUE(f.store->get_media(worn).has_value());
    EXPECT_EQ(f.download_status(forwarded, "token-bob"), 200);
}

// The other direction, which the audit does not spell out and which the fix
// closes as a side effect worth pinning: because a reference kept an object off
// the orphan list, ANY account that knew an id could keep those bytes on disk
// indefinitely by mentioning it — including bytes it was never allowed to read,
// and including an object whose every legitimate reference had been redacted.
// Retention is a promise a self-hosted deployment makes to its users, and it
// was a promise any member could quietly break.
TEST(MediaReferenceAuthz, AnUnauthorisedMentionCannotKeepAnObjectOffTheOrphanList) {
    Fixture f;
    f.config.media_reaper_dry_run = false;
    auto alice = f.add_user("alice");
    auto mallory = f.add_user("mallory");
    auto room = f.add_channel(alice, "general");
    auto mine = f.add_channel(mallory, "mallory-corner");
    f.join(room, mallory);

    auto id = f.upload(alice);
    auto event_id = f.post(room, alice, f.mxc(id));
    ASSERT_EQ(f.download_status(id, "token-mallory"), 200);

    // Alice deletes it. Every legitimate reference is gone; the bytes are now
    // an orphan and the reaper's job is to destroy them.
    ASSERT_TRUE(f.store->redact_event(event_id, alice));
    ASSERT_TRUE(f.store->get_media_rooms(f.mxc(id)).empty());

    // Mallory, who noted the id, names it in a channel of her own.
    EventHandler events(*f.store, *f.sync, f.config, nullptr);
    ASSERT_TRUE(IsOk(call(events, &EventHandler::handle_send_event,
                          send_path(mine, "txn-pin"), "token-mallory",
                          json{{"msgtype", "m.text"}, {"body", "keeping this"},
                               {"com.example.note", f.mxc(id)}}.dump())));

    MediaReaper reaper(*f.store, f.config, f.storage);
    EXPECT_EQ(reaper.sweep_once(past_grace(f.config)), 1u)
        << "a mention by somebody with no right to the object kept it on disk";
    EXPECT_FALSE(f.store->get_media(id).has_value());
    EXPECT_FALSE(std::filesystem::exists(f.dir / id));
}
