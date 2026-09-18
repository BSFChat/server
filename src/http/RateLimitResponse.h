#pragma once

#include <bsfchat/ErrorCodes.h>
#include <httplib.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>

namespace bsfchat {

// The one 429 shape this server emits, shared so every limiter answers
// identically. A client that learns to back off from /login must not meet a
// differently-shaped refusal from /send and fail to recognise it.
//
// The wait goes in both places a client might look: the Matrix body field
// (milliseconds) and the HTTP header (whole seconds, rounded UP — telling a
// client to come back a fraction early just earns it a second 429).
inline void send_rate_limited(httplib::Response& res, int64_t retry_ms,
                              const std::string& message) {
    retry_ms = std::clamp<int64_t>(retry_ms, 1, std::numeric_limits<int>::max());
    res.set_header("Retry-After", std::to_string((retry_ms + 999) / 1000));
    res.status = 429;
    res.set_content(
        MatrixError::limit_exceeded(message, static_cast<int>(retry_ms)).to_json().dump(),
        "application/json");
}

} // namespace bsfchat
