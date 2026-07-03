#include "http/Router.h"
#include <httplib.h>
#include <sstream>

namespace bsfchat {

namespace {
// Percent-decode a single path segment. httplib::decode_uri_component is
// the public replacement for the old detail::decode_url(s, false): pure
// %XX decoding, no plus-to-space conversion (which is form-encoding, not
// path semantics — a literal '+' in a state_key must survive).
std::string pct_decode(const std::string& s) {
    return httplib::decode_uri_component(s);
}
} // namespace

RouteMatch match_route(const std::string& pattern, const std::string& path) {
    RouteMatch result;

    // Split both into segments
    auto split = [](const std::string& s) -> std::vector<std::string> {
        std::vector<std::string> parts;
        std::istringstream stream(s);
        std::string part;
        while (std::getline(stream, part, '/')) {
            if (!part.empty()) parts.push_back(part);
        }
        return parts;
    };

    auto pattern_parts = split(pattern);
    auto path_parts = split(path);

    if (pattern_parts.size() != path_parts.size()) {
        return result;
    }

    PathParams params;
    for (size_t i = 0; i < pattern_parts.size(); ++i) {
        const auto& pp = pattern_parts[i];
        const auto& pathp = path_parts[i];

        if (pp.size() >= 3 && pp.front() == '{' && pp.back() == '}') {
            // Parameter segment. Clients percent-encode user-controlled
            // segments (state_key can be "@user:host", "role:<id>" etc.);
            // decode here so handlers see the original characters.
            std::string name = pp.substr(1, pp.size() - 2);
            params[name] = pct_decode(pathp);
        } else if (pp != pathp) {
            return result;
        }
    }

    result.matched = true;
    result.params = std::move(params);
    return result;
}

} // namespace bsfchat
