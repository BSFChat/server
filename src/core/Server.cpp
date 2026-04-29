#include "core/Server.h"
#include "core/Logger.h"
#include "auth/AutoJoin.h"
#include "auth/RoleBootstrap.h"
#include "api/AuthHandler.h"
#include "api/RoomHandler.h"
#include "api/EventHandler.h"
#include "api/SyncHandler.h"
#include "api/MediaHandler.h"
#include "api/ProfileHandler.h"
#include "api/TypingHandler.h"
#include "api/PresenceHandler.h"
#include "api/VoiceHandler.h"
#include "http/Router.h"
#include "storage/LocalStorage.h"
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

    // Initialize OIDC auth if identity provider is configured
    if (config_.identity) {
        oidc_auth_ = std::make_unique<OidcAuth>(config_.identity->provider_url);
        if (oidc_auth_->refresh_keys()) {
            get_logger()->info("OIDC keys loaded from {}", config_.identity->provider_url);
        } else {
            get_logger()->warn("Failed to fetch OIDC keys; identity login will not work until keys are available");
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
    auto event_handler = std::make_shared<EventHandler>(*store_, *sync_engine_, config_);
    auto sync_handler = std::make_shared<SyncHandler>(*store_, *sync_engine_);

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
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/invite)",
             [h = room_handler](const httplib::Request& req, httplib::Response& res) { h->handle_invite(req, res); });

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

    svr.Post(std::string(api_path::kMediaUpload),
             [h = media_handler](const httplib::Request& req, httplib::Response& res) { h->handle_upload(req, res); });
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

    // Voice routes
    auto voice_handler = std::make_shared<VoiceHandler>(*store_, *sync_engine_, config_);

    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/voice/join)",
             [h = voice_handler](const httplib::Request& req, httplib::Response& res) { h->handle_voice_join(req, res); });
    svr.Post(R"(/_matrix/client/v3/rooms/([^/]+)/voice/leave)",
             [h = voice_handler](const httplib::Request& req, httplib::Response& res) { h->handle_voice_leave(req, res); });
    svr.Get(R"(/_matrix/client/v3/rooms/([^/]+)/voice/members)",
            [h = voice_handler](const httplib::Request& req, httplib::Response& res) { h->handle_voice_members(req, res); });
    svr.Put(R"(/_matrix/client/v3/rooms/([^/]+)/voice/state)",
            [h = voice_handler](const httplib::Request& req, httplib::Response& res) { h->handle_voice_state(req, res); });
    svr.Get("/_matrix/client/v3/voip/turnServer",
            [h = voice_handler](const httplib::Request& req, httplib::Response& res) { h->handle_turn_server(req, res); });
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

    http_server_->start();
}

void Server::stop() {
    if (http_server_) http_server_->stop();
}

} // namespace bsfchat
