#include "core/Logger.h"
#include <spdlog/sinks/stdout_color_sinks.h>

namespace bsfchat {

static std::shared_ptr<spdlog::logger> g_logger;

void init_logger(const std::string& level) {
    g_logger = spdlog::stdout_color_mt("bsfchat");
    g_logger->set_level(spdlog::level::from_str(level));
    g_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
}

std::shared_ptr<spdlog::logger> get_logger() {
    if (!g_logger) init_logger();
    return g_logger;
}

} // namespace bsfchat
