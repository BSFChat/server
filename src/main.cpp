#include "cli/AdminCli.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "core/Server.h"
#include "core/Version.h"

#include <csignal>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

static std::unique_ptr<bsfchat::Server> g_server;
__attribute__((used)) static const char g_build_tag[] = "Bullshit Free Chat";

void signal_handler(int) {
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    bsfchat::init_logger("info");
    auto log = bsfchat::get_logger();

    // First line in the log, before config loading can fail: when someone
    // pastes a log excerpt asking why their server is misbehaving, the
    // build that produced it is the first thing worth knowing, and a
    // config error must not swallow it.
    log->info("BSFChat server {}", bsfchat::build::describe());

    // ARGUMENT HANDLING, AND WHY IT REFUSES RATHER THAN GUESSES.
    //
    // This used to accept `--config <path>` and silently ignore everything
    // else, falling through to defaults. Defaults mean the database path is
    // relative, so `bsfchat-server --help` from a checkout root started a
    // server and migrated ./data/bsfchat.db — forward-only, no down path.
    // That has now happened twice to the same developer database, once via a
    // misparsed config and once via a flag that does not exist. The e2e
    // scripts already carry elaborate guards because of the first occurrence.
    //
    // An unrecognised argument is a mistake, and the safe response to a
    // mistake is to stop. Starting a server with a database nobody named is
    // the one outcome an operator never wants from a typo.
    const auto usage = [&log](int code) {
        log->info("usage: bsfchat-server [--config <path>]");
        log->info("       bsfchat-server <admin-subcommand> --config <path> [...]");
        log->info("  --config <path>   TOML configuration file");
        log->info("  --help, -h        this message");
        log->info("");
        log->info("With no --config the server uses built-in defaults, whose");
        log->info("database path is RELATIVE to the working directory. That is");
        log->info("convenient for a throwaway instance and dangerous anywhere");
        log->info("else, so prefer an explicit --config.");
        log->info("");
        bsfchat::print_admin_usage(std::cout);
        return code;
    };

    // OFFLINE ADMIN SUBCOMMANDS, AND WHY THEY LIVE IN THIS BINARY.
    //
    // `bsfchat-server grant-admin --config ... --user @me:example.org` is the
    // supported way to hand out the first (or a replacement) admin role when
    // nobody who holds MANAGE_ROLES can reach the client — the lockout that
    // put hand-written SQL into a production database. See src/cli/AdminCli.h
    // for the full incident, the stopped-server requirement, and the argument
    // that this is not a privilege-escalation path.
    //
    // A separate binary would have been the tidier shape and was rejected: it
    // would have to be built, shipped, and put on the host alongside the
    // server, and the one moment an operator needs it is the moment they are
    // least inclined to go fetch a second tool. The server binary is already
    // there, already the right version for the database next to it.
    //
    // Dispatched BEFORE the flag loop below, so the subcommand owns its own
    // argument grammar and an unrecognised flag is refused by the command that
    // was actually asked for.
    if (argc > 1 && bsfchat::is_admin_subcommand(argv[1])) {
        std::vector<std::string> args;
        for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
        return bsfchat::run_admin_cli(args, std::cout);
    }

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") return usage(0);
        if (arg == "--config") {
            if (i + 1 >= argc) {
                log->error("--config requires a path");
                return usage(2);
            }
            ++i;  // consumed
            continue;
        }
        log->error("unrecognised argument: {}", arg);
        return usage(2);
    }

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
        // Run the same validation/warning pass the file path gets, so a
        // default-configured server still reports unusable combinations
        // (e.g. voice enabled with no STUN/TURN) instead of failing silently.
        bsfchat::Config::validate(config);
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
