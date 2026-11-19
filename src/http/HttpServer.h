#pragma once

#include <httplib.h>
#include <string>
#include <memory>

namespace bsfchat {

struct Config;

class HttpServer {
public:
    explicit HttpServer(const Config& config);
    ~HttpServer();

    httplib::Server& server() { return server_; }

    // Binds the listening socket (port 0: any free port, see port()). Throws
    // std::runtime_error naming the address when it is taken. start() calls
    // it; calling it first is for a caller that needs the port before
    // serving. Idempotent.
    void bind();
    int port() const { return port_; }

    void start();
    void stop();

private:
    httplib::Server server_;
    std::string bind_address_;
    int port_;
    bool bound_ = false;
    int workers_;
    int max_workers_;
};

} // namespace bsfchat
