#include "http/HttpServer.h"
#include "core/Config.h"
#include "core/Logger.h"

#include <stdexcept>

namespace bsfchat {

HttpServer::HttpServer(const Config& config)
    : bind_address_(config.bind_address)
    , port_(config.port)
    , workers_(config.workers) {

    // [server].workers used to be parsed into Config and then never consulted —
    // httplib silently ran its default-sized pool. Wire it up for real.
    server_.new_task_queue = [n = workers_] {
        return new httplib::ThreadPool(static_cast<size_t>(n));
    };

    // Cap the request body BEFORE httplib buffers it. Without this,
    // set_payload_max_length was never called anywhere, so httplib happily
    // materialised an arbitrarily large POST in memory and MediaHandler's
    // max_upload_size_mb check only ran afterwards — a large upload could OOM
    // the process before the configured limit was ever consulted.
    //
    // The slack covers multipart/form framing and the JSON endpoints, which
    // are all far smaller than any media upload.
    constexpr size_t kNonMediaSlackBytes = 1024 * 1024;
    server_.set_payload_max_length(config.max_upload_size_mb * 1024 * 1024 + kNonMediaSlackBytes);

    if (config.tls_enabled) {
        // [tls] is parsed but there is no SSLServer path here, so honouring
        // `enabled = true` by carrying on would serve plaintext on a port the
        // operator believes is HTTPS. Fail loudly instead of lying.
        throw std::runtime_error(
            "[tls] enabled = true, but this build has no TLS support. Terminate TLS at a "
            "reverse proxy (nginx/Caddy/Traefik) and set [tls] enabled = false.");
    }
}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::start() {
    auto log = get_logger();
    log->info("Starting HTTP server on {}:{} ({} worker threads)",
              bind_address_, port_, workers_);
    server_.listen(bind_address_, port_);
}

void HttpServer::stop() {
    if (server_.is_running()) {
        server_.stop();
    }
}

} // namespace bsfchat
