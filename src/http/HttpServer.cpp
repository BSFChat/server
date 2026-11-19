#include "http/HttpServer.h"
#include "core/Config.h"
#include "core/Logger.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

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

    // SO_REUSEADDR only (audit 3, 2026-11-19). httplib's default socket
    // options set SO_REUSEPORT where the platform has it, so a second server
    // started on a port already in use bound it SILENTLY and the kernel split
    // the traffic between the two — which is how two reviewers' servers, on
    // two different databases, ended up answering for each other. Without it
    // the second bind fails and start() says so. SO_REUSEADDR is still wanted:
    // it is what lets a restart rebind while the old socket sits in TIME_WAIT.
    server_.set_socket_options([](socket_t sock) {
        httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    });

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

void HttpServer::bind() {
    if (bound_) return;
    bool ok = false;
    if (port_ == 0) {
        const int port = server_.bind_to_any_port(bind_address_);
        ok = port > 0;
        if (ok) port_ = port;
    } else {
        ok = server_.bind_to_port(bind_address_, port_);
    }
    if (!ok) {
        const int err = errno;
        throw std::runtime_error(
            "Cannot listen on " + bind_address_ + ":" + std::to_string(port_) + " (" +
            (err ? std::strerror(err) : "bind failed") +
            "). Is another server (or identity service) already running on this port?");
    }
    bound_ = true;
}

void HttpServer::start() {
    auto log = get_logger();
    // Bind first, separately, so a taken port is a startup ERROR with a reason
    // rather than listen() returning false and the process exiting quietly.
    bind();
    log->info("Starting HTTP server on {}:{} ({} worker threads, growing to {} on demand)",
              bind_address_, port_, workers_, max_workers_);
    server_.listen_after_bind();
}

void HttpServer::stop() {
    if (server_.is_running()) {
        server_.stop();
    }
}

} // namespace bsfchat
