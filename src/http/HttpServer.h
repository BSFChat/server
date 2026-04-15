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

    void start();
    void stop();

private:
    httplib::Server server_;
    std::string bind_address_;
    int port_;
};

} // namespace bsfchat
