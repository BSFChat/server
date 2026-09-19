#include "core/Logger.h"
#include <spdlog/sinks/stdout_color_sinks.h>

#include <algorithm>

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

std::string log_safe(std::string_view value, std::size_t max_len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(std::min(value.size(), max_len) + 8);

    std::size_t consumed = 0;
    for (char ch : value) {
        if (consumed >= max_len) break;
        const auto c = static_cast<unsigned char>(ch);
        // Backslash is escaped too: without it "\x0a" typed by a user would be
        // indistinguishable from a newline this function escaped.
        if (c < 0x20 || c == 0x7f || c == '\\') {
            out += "\\x";
            out += kHex[c >> 4];
            out += kHex[c & 0x0f];
        } else {
            out += ch;
        }
        ++consumed;
    }
    if (consumed < value.size()) out += "...(truncated)";
    return out;
}

} // namespace bsfchat
