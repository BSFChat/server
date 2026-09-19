#pragma once

#include <spdlog/spdlog.h>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace bsfchat {

void init_logger(const std::string& level = "info");
std::shared_ptr<spdlog::logger> get_logger();

// Renders an untrusted string safe to put in a log line.
//
// The log pattern is one record per line ("[ts] [level] msg"), so any
// user-controlled string reaching it unescaped lets that user write whole
// fabricated records: a newline plus a convincing "[2026-09-19 ...] [warning]
// Auth lockout engaged for ip:..." is indistinguishable from the real thing.
// That matters here beyond tidiness because the server log IS the
// security-event record for auth — registration, logins, lockouts, password
// changes are recorded there and nowhere else — so anyone who can forge lines
// can bury a real event in a hundred fakes or manufacture one against another
// account.
//
// C0 controls, DEL and backslash become \xNN so the escaping is unambiguous and
// itself unforgeable; the result is truncated to `max_len` with a trailing
// marker, because a diagnostic never needs more and an unbounded field is its
// own flood primitive.
std::string log_safe(std::string_view value, std::size_t max_len = 128);

} // namespace bsfchat
