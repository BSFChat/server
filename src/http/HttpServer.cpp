#include "http/HttpServer.h"
#include "core/Config.h"
#include "core/Logger.h"

#include <stdexcept>

namespace bsfchat {

HttpServer::HttpServer(const Config& config)
    : bind_address_(config.bind_address)
    , port_(config.port)
    , workers_(config.workers)
    , max_workers_(config.max_workers) {

    // [server].workers used to be parsed into Config and then never consulted —
    // httplib silently ran its default-sized pool. Wire it up for real.
    //
    // The ceiling is not optional. httplib's ThreadPool signature is
    // (base, max_n = 0, ...) and reads max_n == 0 as "max == base", so passing
    // the base alone builds a pool that can never grow. That matters here more
    // than it would for most servers, because httplib runs a whole keep-alive
    // connection on one pool task: a worker is occupied for the lifetime of the
    // SOCKET, not of a request, and /sync deliberately holds its socket open
    // for the length of the long poll. So the base size is a ceiling on
    // concurrent *connections*, and every signed-in client holds more than one.
    //
    // With workers = 4 (what production shipped) and two desktop clients, all
    // four were held by long polls and idle keep-alives, and a message send
    // queued behind them with no thread to run it: 28.4s measured to deliver a
    // message, against 81ms on the same build with an idle pool. Dynamic
    // threads retire after a few seconds idle, so the steady-state footprint is
    // still `workers` — the ceiling only costs anything while it is saving you.
    server_.new_task_queue = [n = workers_, max_n = max_workers_] {
        return new httplib::ThreadPool(static_cast<size_t>(n),
                                       static_cast<size_t>(max_n));
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
    log->info("Starting HTTP server on {}:{} ({} worker threads, growing to {} on demand)",
              bind_address_, port_, workers_, max_workers_);
    server_.listen(bind_address_, port_);
}

void HttpServer::stop() {
    if (server_.is_running()) {
        server_.stop();
    }
}

} // namespace bsfchat
