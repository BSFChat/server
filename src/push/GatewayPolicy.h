#pragma once

#include <string>

namespace bsfchat {

struct PushConfig;

// Whether `url` is a push gateway this server may POST notifications to under
// `cfg`: absolute http(s), on the operator's allowlist (scheme + host + port +
// path boundary), with the path exactly /_matrix/push/v1/notify (audit 3), no
// dot-segments or encoded separators, and not an internal
// address unless the operator opted in. On refusal `why` says which rule.
//
// Defined in api/PushHandler.cpp, next to the parsing it depends on. Called at
// REGISTRATION (/pushers/set) and again at DELIVERY (PushService::drain_once):
// a pusher stored by an older build, or before the operator narrowed the
// allowlist, must not keep receiving message data because it was once allowed.
bool gateway_url_allowed(const std::string& url, const PushConfig& cfg, std::string& why);

} // namespace bsfchat
