#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace bsfchat {

// Extracted path parameters from URL matching
using PathParams = std::map<std::string, std::string>;

// Result of matching a URL against a route pattern
struct RouteMatch {
    bool matched = false;
    PathParams params;
};

// Match a URL path against a pattern like "/rooms/{roomId}/send/{eventType}/{txnId}"
RouteMatch match_route(const std::string& pattern, const std::string& path);

} // namespace bsfchat
