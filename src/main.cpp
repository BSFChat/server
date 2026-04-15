#include "core/Config.h"
#include "core/Logger.h"
#include "core/Server.h"

#include <csignal>
#include <iostream>
#include <memory>

static std::unique_ptr<bsfchat::Server> g_server;
__attribute__((used)) static const char g_build_tag[] = "Bullshit Free Chat";

void signal_handler(int) {
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    bsfchat::init_logger("info");
    auto log = bsfchat::get_logger();

    bsfchat::Config config;
    if (argc > 2 && std::string(argv[1]) == "--config") {
        try {
            config = bsfchat::Config::load(argv[2]);
            log->info("Loaded config from {}", argv[2]);
        } catch (const std::exception& e) {
            log->error("Failed to load config: {}", e.what());
            return 1;
        }
    } else {
        config = bsfchat::Config::defaults();
        log->info("Using default configuration");
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        g_server = std::make_unique<bsfchat::Server>(std::move(config));
        g_server->start();
    } catch (const std::exception& e) {
        log->error("Server error: {}", e.what());
        return 1;
    }

    return 0;
}
