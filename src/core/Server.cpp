#include "core/Server.h"
#include "core/Logger.h"
#include "auth/AutoJoin.h"
#include "auth/RoleBootstrap.h"
#include "api/AuditHandler.h"
#include "api/AuthHandler.h"
#include "api/BotHandler.h"
#include "api/PermissionsHandler.h"
#include "api/RoleHandler.h"
#include "api/RoomHandler.h"
#include "api/EventHandler.h"
#include "api/SyncHandler.h"
#include "api/MediaHandler.h"
#include "api/ProfileHandler.h"
#include "api/TypingHandler.h"
#include "api/PresenceHandler.h"
#include "api/VoiceHandler.h"
#include "api/PushHandler.h"
#include "api/SearchHandler.h"
#include "push/PushService.h"
#include "http/Router.h"
#include "storage/LocalStorage.h"
#include "storage/MediaReaper.h"
#include "storage/S3Storage.h"

#include <bsfchat/Constants.h>

#include <filesystem>

namespace bsfchat {

Server::Server(Config config)
    : config_(std::move(config)) {

    // Ensure data directories exist
    auto db_dir = std::filesystem::path(config_.database_path).parent_path();
    if (!db_dir.empty()) std::filesystem::create_directories(db_dir);
    std::filesystem::create_directories(config_.media_path);

    store_ = std::make_unique<SqliteStore>(config_.database_path);
    store_->initialize();

    // Create media storage backend
    if (config_.storage.type == "s3") {
        S3Config s3cfg;
        s3cfg.endpoint = config_.storage.s3.endpoint;
        s3cfg.access_key = config_.storage.s3.access_key;
        s3cfg.secret_key = config_.storage.s3.secret_key;
        s3cfg.bucket = config_.storage.s3.bucket;
        s3cfg.region = config_.storage.s3.region;
        s3cfg.use_path_style = config_.storage.s3.use_path_style;
        media_storage_ = std::make_shared<S3Storage>(std::move(s3cfg));
    } else {
        media_storage_ = std::make_shared<LocalStorage>(config_.media_path);
    }

    sync_engine_ = std::make_unique<SyncEngine>(*store_, config_);
    push_service_ = std::make_unique<PushService>(*store_, config_);

    // Initialize OIDC auth if identity provider is configured
    if (config_.identity) {
        oidc_auth_ = std::make_unique<OidcAuth>(config_.identity->provider_url);
        if (oidc_auth_->refresh_keys()) {
            get_logger()->info("OIDC keys loaded from {}", config_.identity->provider_url);
        } else {
            // Not an error, and not the end of the attempt. In a compose
            // deployment the server almost always finishes starting before
            // the identity container is answering, and a single try here
            // used to leave every later token validation to re-fetch the
            // JWKS inline on an httplib worker thread.
            get_logger()->info("OIDC keys not available from {} yet; retrying in "
                               "the background. Identity login starts working as "
                               "soon as the provider answers.",
                               config_.identity->provider_url);
            oidc_auth_->start_background_refresh();
        }
    }

    http_server_ = std::make_unique<HttpServer>(config_);

    register_routes();
}

Server::~Server() {
    stop();
}

void Server::register_routes() {
    auto& svr = http_server_->server();

    // Set CORS headers for all responses
    svr.set_pre_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type");
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Handle CORS preflight
    svr.Options(R"(.*)", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type");
        res.set_content("", "text/plain");
    });

    auto auth_handler = std::make_shared<AuthHandler>(*store_, *sync_engine_, config_, oidc_auth_.get());
    auto room_handler = std::make_shared<RoomHandler>(*store_, *sync_engine_, config_);
    auto event_handler =
        std::make_shared<EventHandler>(*store_, *sync_engine_, config_, push_service_.get());
    auto sync_handler = std::make_shared<SyncHandler>(*store_, *sync_engine_, config_);

    // Auth routes
    svr.Get(std::string(api_path::kVersions),
            [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_versions(req, res); });
    svr.Get(std::string(api_path::kLogin),
            [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_login_flows(req, res); });
    svr.Post(std::string(api_path::kLogin),
             [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_login(req, res); });
    svr.Post(std::string(api_path::kRegister),
             [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_register(req, res); });
    svr.Post(std::string(api_path::kLogout),
             [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_logout(req, res); });
    svr.Post(std::string(api_path::kLogoutAll),
             [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_logout_all(req, res); });
    // Authenticated password change. Local-auth users previously had no way to
    // change their password at all, which is also why token invalidation had
    // nowhere to hook.
    svr.Post(std::string(api_path::kPasswordChange),
             [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_password_change(req, res); });
    // Renewal path for clients that opt in with `refresh_token: true`, so a
    // finite access-token lifetime doesn't mean a forced re-login.
    svr.Post(std::string(api_path::kRefresh),
             [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_refresh(req, res); });
    // Token-identity introspection. Clients restoring a persisted
    // session use this to reconcile their stored user id with the
    // server's canonical one (stale/corrupt stored ids otherwise break
    // every self-identity comparison client-side).
    // Account linking: one human, one account. POST proves control of the
    // account (bearer token) and of the identity (id_token in the body) in the
    // same request — see handle_link_identity for why both halves are
    // mandatory. GET lists the caller's own links and nobody else's.
    svr.Post(std::string(api_path::kLinkIdentity),
             [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_link_identity(req, res); });
    svr.Get(std::string(api_path::kLinkedIdentities),
            [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_linked_identities(req, res); });
    svr.Get(std::string(api_path::kWhoami),
            [h = auth_handler](const httplib::Request& req, httplib::Response& res) { h->handle_whoami(req, res); });

    // Room routes
    svr.Post(std::string(api_path::kCreateRoom),
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_create_room(req, res); });
    svr.Get(std::string(api_path::kJoinedRooms),
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_joined_rooms(req, res); });

    // Parameterized room routes — use regex patterns
    svr.Post(R"(/_matrix/client/v3/join/(.+))",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_join(req, res); });
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/join)",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_join(req, res); });
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/leave)",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_leave(req, res); });
    svr.Delete(R"(/_matrix/client/v3/rooms/([^/]+)$)",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_delete_room(req, res); });
    svr.Get(R"(/_matrix/client/v3/rooms/([^/]+)/state$)",
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_room_state(req, res); });
    svr.Get(R"(/_matrix/client/v3/rooms/([^/]+)/state/(.+))",
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_room_state_event(req, res); });
    svr.Get(R"(/_matrix/client/v3/rooms/([^/]+)/members)",
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_room_members(req, res); });

    // Room moderation routes
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/kick)",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_kick(req, res); });
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/ban)",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_ban(req, res); });
    // Unban. The client has always called this path (MatrixClient::unbanUser);
    // the server never served it, so unbanning silently 404'd and every ban was
    // effectively permanent.
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/unban)",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_unban(req, res); });
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/invite)",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_invite(req, res); });

    // The server-wide ban list. Read-only: bans are placed and lifted through the
    // /rooms/{id}/ban and /unban routes above, which is where the rank check lives.
    // SqliteStore::list_server_bans previously had no route and no caller, so the
    // client could only rebuild the list from the membership rows its own sync had
    // surfaced — and a user banned while holding no membership row anywhere was
    // invisible in the bans tab and could not be unbanned from it. Permission is
    // evaluated at SERVER scope inside the handler, so a per-channel override
    // cannot unlock it.
    svr.Get(std::string(api_path::kServerBans),
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_server_bans(req, res); });

    // Category and order routes (must be before state PUT to avoid conflict)
    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/category)",
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_move_channel(req, res); });
    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/order)",
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_set_order(req, res); });

    // State event PUT (must be before Event routes to avoid conflict)
    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/state/([^/]+)/(.*))",
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_set_state(req, res); });
    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/state/([^/]+)$)",
            [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_set_state(req, res); });

    // Event routes
    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/send/([^/]+)/([^/]+))",
            [h = event_handler](const httplib::Request& req, httplib::Response& res) { h->handle_send_event(req, res); });
    svr.Get(R"(/_matrix/client/v3/rooms/([^/]+)/messages)",
            [h = event_handler](const httplib::Request& req, httplib::Response& res) { h->handle_room_messages(req, res); });
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/read_marker)",
            [h = event_handler](const httplib::Request& req, httplib::Response& res) { h->handle_read_marker(req, res); });
    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/redact/([^/]+)/([^/]+))",
            [h = event_handler](const httplib::Request& req, httplib::Response& res) { h->handle_redact(req, res); });

    // Typing route (must be before generic room PUT patterns)
    auto typing_handler = std::make_shared<TypingHandler>(*store_, *sync_engine_, config_);
    sync_handler->set_typing_handler(typing_handler.get());

    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/typing/([^/]+))",
            [h = typing_handler](const httplib::Request& req, httplib::Response& res) { h->handle_typing(req, res); });

    // Presence — same pattern as typing. PUT updates the in-memory
    // entry; sync_handler picks the entries up at delivery time.
    auto presence_handler = std::make_shared<PresenceHandler>(*store_, *sync_engine_, config_);
    sync_handler->set_presence_handler(presence_handler.get());

    svr.Put(R"(/_matrix/client/v3/presence/([^/]+)/status)",
            [h = presence_handler](const httplib::Request& req, httplib::Response& res) { h->handle_put_presence(req, res); });

    // Sync
    svr.Get(std::string(api_path::kSync),
            [h = sync_handler](const httplib::Request& req, httplib::Response& res) { h->handle_sync(req, res); });

    // Media routes
    auto media_handler = std::make_shared<MediaHandler>(*store_, config_, media_storage_);
    // Same storage object the upload and download paths use, so the reaper can
    // never be pointed at a different backend than the one holding the bytes.
    media_reaper_ = std::make_unique<MediaReaper>(*store_, config_, media_storage_);

    svr.Post(std::string(api_path::kMediaUpload),
             [h = media_handler](const httplib::Request& req, httplib::Response& res) { h->handle_upload(req, res); });
    // Mints a short-lived signed ticket for one object, so the client no longer
    // has to put the viewer's session token in a media URL. Authorization
    // header only, and the same may_download() check the download path runs.
    // Path literal rather than api_path:: because adding a constant would move
    // this change into the protocol repo, which has to merge first; fold it in
    // the next time protocol changes for another reason. The client's mirror of
    // this string is in client/src/util/MediaUrl.h.
    svr.Post("/_matrix/media/v3/ticket",
             [h = media_handler](const httplib::Request& req, httplib::Response& res) { h->handle_ticket(req, res); });
    svr.Get(R"(/_matrix/media/v3/download/([^/]+)/([^/]+)/([^/]+))",
            [h = media_handler](const httplib::Request& req, httplib::Response& res) { h->handle_download(req, res); });
    svr.Get(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))",
            [h = media_handler](const httplib::Request& req, httplib::Response& res) { h->handle_download(req, res); });

    // Profile routes
    auto profile_handler = std::make_shared<ProfileHandler>(*store_, *sync_engine_, config_);

    svr.Get(R"(/_matrix/client/v3/profile/([^/]+)$)",
            [h = profile_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_profile(req, res); });
    svr.Get(R"(/_matrix/client/v3/profile/([^/]+)/displayname)",
            [h = profile_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_displayname(req, res); });
    svr.Put(R"(/_matrix/client/v3/profile/([^/]+)/displayname)",
            [h = profile_handler](const httplib::Request& req, httplib::Response& res) { h->handle_put_displayname(req, res); });
    svr.Get(R"(/_matrix/client/v3/profile/([^/]+)/avatar_url)",
            [h = profile_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_avatar_url(req, res); });
    svr.Put(R"(/_matrix/client/v3/profile/([^/]+)/avatar_url)",
            [h = profile_handler](const httplib::Request& req, httplib::Response& res) { h->handle_put_avatar_url(req, res); });
    // Per-server nickname. Not a Matrix-spec path (the spec has no nickname), so
    // it sits under profile/ rather than being namespaced elsewhere: it is a
    // profile field, just one whose write is permission-gated instead of
    // self-service. PUT accepts a target other than the caller — CHANGE_NICKNAME
    // for your own, MANAGE_NICKNAMES plus a rank check for anyone else's, both at
    // server scope.
    svr.Get(R"(/_matrix/client/v3/profile/([^/]+)/nickname)",
            [h = profile_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_nickname(req, res); });
    svr.Put(R"(/_matrix/client/v3/profile/([^/]+)/nickname)",
            [h = profile_handler](const httplib::Request& req, httplib::Response& res) { h->handle_put_nickname(req, res); });

    // Push routes. Registration + listing are spec-shaped; the per-room
    // notification level is namespaced bsfchat.* because it is an enum per room,
    // not Matrix's full push-rules model.
    auto push_handler = std::make_shared<PushHandler>(*store_, *push_service_, config_);

    svr.Post("/_matrix/client/v3/pushers/set",
             [h = push_handler](const httplib::Request& req, httplib::Response& res) { h->handle_set_pusher(req, res); });
    svr.Get("/_matrix/client/v3/pushers",
            [h = push_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_pushers(req, res); });
    svr.Get(R"(/_matrix/client/v3/bsfchat/rooms/([^/]+)/notify_level)",
            [h = push_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_notify_level(req, res); });
    svr.Put(R"(/_matrix/client/v3/bsfchat/rooms/([^/]+)/notify_level)",
            [h = push_handler](const httplib::Request& req, httplib::Response& res) { h->handle_put_notify_level(req, res); });

    // Search. Spec-shaped POST /search; permission filtering happens inside the
    // query rather than over its output (see SearchHandler).
    auto search_handler = std::make_shared<SearchHandler>(*store_, config_);
    svr.Post("/_matrix/client/v3/search",
             [h = search_handler](const httplib::Request& req, httplib::Response& res) { h->handle_search(req, res); });

    // Moderation audit log. Read-only — there is no write endpoint, because
    // records are written at the action sites and nothing may inject one.
    // Permission is evaluated at SERVER scope inside the handler, so a
    // per-channel override cannot unlock it.
    auto audit_handler = std::make_shared<AuditHandler>(*store_, config_);
    svr.Get(std::string(api_path::kAuditLog),
            [h = audit_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_audit_log(req, res); });

    // Bot accounts. bsfchat.* namespaced because Matrix has no bot concept —
    // same precedent as the push notify_level and audit_log routes above.
    //
    // These four are the whole bot-specific surface. Everything else a bot does
    // arrives at the routes already registered above, authenticated by the same
    // bearer-token middleware, because a bot IS a user account. Permission is
    // MANAGE_BOTS evaluated at SERVER scope inside each handler, so a
    // per-channel override cannot unlock the minting of server-wide accounts.
    //
    // The {userId} routes are registered BEFORE the bare collection route is
    // matched for POST, and the DELETE pattern is anchored with $ so that
    // /bots/{id}/token cannot fall into it.
    auto bot_handler = std::make_shared<BotHandler>(*store_, *sync_engine_, config_);

    svr.Post(std::string(api_path::kBots),
             [h = bot_handler](const httplib::Request& req, httplib::Response& res) { h->handle_create_bot(req, res); });
    svr.Get(std::string(api_path::kBots),
            [h = bot_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_bots(req, res); });
    svr.Post(R"(/_matrix/client/v3/bsfchat/bots/([^/]+)/token$)",
             [h = bot_handler](const httplib::Request& req, httplib::Response& res) { h->handle_rotate_token(req, res); });
    svr.Delete(R"(/_matrix/client/v3/bsfchat/bots/([^/]+)$)",
               [h = bot_handler](const httplib::Request& req, httplib::Response& res) { h->handle_deactivate_bot(req, res); });

    // Server roles. bsfchat.* namespaced for the same reason the bot routes
    // above are: Matrix models permissions with m.room.power_levels, which this
    // server does not use as its authority, so there is no spec path to take.
    //
    // These do not replace the `bsfchat.server.roles` state PUT, and they are
    // not a second authority over it — they hand a DELTA to the server and let
    // it perform the read-modify-write against the one document, through the
    // same PermissionsEngine::may_edit_role_definitions and the same
    // write_server_scoped_state. What they remove is the requirement that the
    // caller assemble a document containing roles it is forbidden to touch,
    // which is what made role management unusable from a delegated MANAGE_ROLES
    // holder such as a bot. See RoleHandler.h.
    //
    // The {roleId} patterns are anchored with $ and registered alongside the
    // bare collection path, which httplib matches by method, so a DELETE on the
    // collection cannot fall into the per-role route.
    //
    // /self_roles is a SEPARATE path rather than a verb on /roles because its
    // authority is different in kind: no MANAGE_ROLES and no rank check at all,
    // paid for by the role having declared itself self-assignable and by a
    // permission-containment rule. Sharing a handler prefix with the admin
    // routes is how that containment rule would eventually be skipped on one
    // branch.
    auto role_handler = std::make_shared<RoleHandler>(*store_, *sync_engine_, config_);

    svr.Get(std::string(api_path::kRoles),
            [h = role_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_roles(req, res); });
    svr.Post(std::string(api_path::kRoles),
             [h = role_handler](const httplib::Request& req, httplib::Response& res) { h->handle_create_role(req, res); });
    svr.Patch(R"(/_matrix/client/v3/bsfchat/roles/([^/]+)$)",
              [h = role_handler](const httplib::Request& req, httplib::Response& res) { h->handle_update_role(req, res); });
    svr.Delete(R"(/_matrix/client/v3/bsfchat/roles/([^/]+)$)",
               [h = role_handler](const httplib::Request& req, httplib::Response& res) { h->handle_delete_role(req, res); });

    svr.Put(R"(/_matrix/client/v3/bsfchat/self_roles/([^/]+)$)",
            [h = role_handler](const httplib::Request& req, httplib::Response& res) { h->handle_add_self_role(req, res); });
    svr.Delete(R"(/_matrix/client/v3/bsfchat/self_roles/([^/]+)$)",
               [h = role_handler](const httplib::Request& req, httplib::Response& res) { h->handle_remove_self_role(req, res); });

    // One member's effective SERVER-SCOPE permission mask. Read-only; there is
    // no write verb here and there must never be one — a permission is changed
    // by editing a role or an assignment, through the routes above, where the
    // hierarchy rules live.
    //
    // Its own handler rather than a fifth verb on RoleHandler, for the reason
    // /self_roles is its own path: the authority is different in kind. The role
    // routes are MANAGE_ROLES plus rank; this is "you already share a channel
    // with this person", which is a visibility rule, not a privilege. Sharing a
    // handler is how the visibility rule eventually gets skipped on one branch.
    //
    // Registered with the {userId} pattern only. There is deliberately no
    // collection route: GET /bsfchat/permissions with no target would be a
    // whole-server dump of who holds power, which is the enumeration oracle this
    // endpoint's authorization rule exists to prevent. httplib has no route
    // here, so it 404s.
    auto permissions_handler = std::make_shared<PermissionsHandler>(*store_, config_);

    svr.Get(R"(/_matrix/client/v3/bsfchat/permissions/([^/]+)$)",
            [h = permissions_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_permissions(req, res); });

    // Voice routes — handler is kept as a member so start()/stop() can
    // manage the ghost-participant reaper thread.
    voice_handler_ = std::make_shared<VoiceHandler>(*store_, *sync_engine_, config_);

    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/voice/join)",
             [h = voice_handler_](const httplib::Request& req, httplib::Response& res) { h->handle_voice_join(req, res); });
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/voice/leave)",
             [h = voice_handler_](const httplib::Request& req, httplib::Response& res) { h->handle_voice_leave(req, res); });
    svr.Get(R"(/_matrix/client/v3/rooms/([^/]+)/voice/members)",
            [h = voice_handler_](const httplib::Request& req, httplib::Response& res) { h->handle_voice_members(req, res); });
    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/voice/state)",
            [h = voice_handler_](const httplib::Request& req, httplib::Response& res) { h->handle_voice_state(req, res); });
    svr.Get("/_matrix/client/v3/voip/turnServer",
            [h = voice_handler_](const httplib::Request& req, httplib::Response& res) { h->handle_turn_server(req, res); });
    // LiveKit SFU join token. 404s when [voice.livekit] is unconfigured, which
    // is how a client detects a mesh-only server.
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/voice/livekit_token)",
             [h = voice_handler_](const httplib::Request& req, httplib::Response& res) { h->handle_livekit_token(req, res); });
    // Rotates a channel's media key. Requires kManageChannels — rotating
    // interrupts everyone still holding the old key. This is the only way to
    // stop a departed member decrypting; see LiveKitConfig::room_encryption.
    // The generation it bumps is persisted (schema v19) and monotonic, so the
    // sentence above survives a restart. It did not always: the generation was
    // an in-memory counter, and every bounce quietly handed the old key back.
    //
    // The generation also names the SFU room, so a rotation moves the channel
    // to a fresh LiveKit room and an already-issued token — a signed JWT this
    // server cannot recall — admits only to the room everyone has left. The
    // rotation reaches each participant when they next fetch a token
    // (reconnect, or token_ttl); it cannot reach one already connected. See
    // VoiceHandler::handle_livekit_rekey for that boundary spelled out.
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/voice/livekit_rekey)",
             [h = voice_handler_](const httplib::Request& req, httplib::Response& res) { h->handle_livekit_rekey(req, res); });
}

void Server::start() {
    auto log = get_logger();
    log->info("BSFChat server v{} starting", "0.1.0");
    log->info("Server name: {}", config_.server_name);
    log->info("Database: {}", config_.database_path);
    log->info("Registration: {}", config_.registration_enabled ? "enabled" : "disabled");
    log->info("Storage: {} (max upload: {} MB)", config_.storage.type, config_.max_upload_size_mb);
    if (config_.identity) {
        log->info("Identity provider: {}", config_.identity->provider_url);
    }

    // Retroactively ensure all existing users are members of all public rooms.
    // Idempotent — skips users already joined.
    log->info("Running auto-join backfill...");
    backfill_auto_join(*store_, *sync_engine_, config_);
    bootstrap_roles(*store_, *sync_engine_, config_);

    voice_handler_->start_reaper();
    media_reaper_->start();
    push_service_->start();

    http_server_->start();
}

void Server::stop() {
    if (voice_handler_) voice_handler_->stop_reaper();
    if (media_reaper_) media_reaper_->stop();
    if (push_service_) push_service_->stop();
    if (http_server_) http_server_->stop();
}

} // namespace bsfchat
