#include "http/HttpServer.h"
#include "core/Config.h"
#include "core/Logger.h"

namespace bsfchat {

HttpServer::HttpServer(const Config& config)
    : bind_address_(config.bind_address)
    , port_(config.port) {
}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::start() {
    auto log = get_logger();
    log->info("Starting HTTP server on {}:{}", bind_address_, port_);
    server_.listen(bind_address_, port_);
}

void HttpServer::stop() {
    if (server_.is_running()) {
        server_.stop();
    }
}

} // namespace bsfchat
