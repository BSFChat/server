#pragma once

#include "auth/OidcAuth.h"
#include "core/Config.h"
#include "http/HttpServer.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <memory>

namespace bsfchat {

class MediaReaper;
class MediaStorage;
class VoiceHandler;
class PushService;

class Server {
public:
    explicit Server(Config config);
    ~Server();

    void start();
    void stop();

    Config& config() { return config_; }
    SqliteStore& store() { return *store_; }
    SyncEngine& sync_engine() { return *sync_engine_; }

private:
    void register_routes();

    Config config_;
    std::unique_ptr<SqliteStore> store_;
    std::unique_ptr<SyncEngine> sync_engine_;
    // Owns the out-of-band push delivery worker; started/stopped with the
    // server, like the voice reaper.
    std::unique_ptr<PushService> push_service_;
    std::unique_ptr<OidcAuth> oidc_auth_;
    std::unique_ptr<HttpServer> http_server_;
    std::shared_ptr<MediaStorage> media_storage_;
    // Collects media nothing references any more. Like the voice reaper and
    // the push worker, it is a member so start()/stop() can own its thread.
    std::unique_ptr<MediaReaper> media_reaper_;
    std::shared_ptr<VoiceHandler> voice_handler_;
};

} // namespace bsfchat
