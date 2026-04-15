#pragma once

#include "auth/OidcAuth.h"
#include "core/Config.h"
#include "http/HttpServer.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <memory>

namespace bsfchat {

class MediaStorage;

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
    std::unique_ptr<OidcAuth> oidc_auth_;
    std::unique_ptr<HttpServer> http_server_;
    std::shared_ptr<MediaStorage> media_storage_;
};

} // namespace bsfchat
