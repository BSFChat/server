#include "http/JsonIo.h"

namespace bsfchat {

using json = nlohmann::json;

bool json_nesting_exceeds(std::string_view body, std::size_t max_depth) {
    std::size_t depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (char c : body) {
        if (in_string) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_string = false;
            continue;
        }
        switch (c) {
            case '"': in_string = true; break;
            case '[':
            case '{':
                if (++depth > max_depth) return true;
                break;
            case ']':
            case '}':
                // Unbalanced closers are the parser's problem, not ours; just
                // do not wrap around.
                if (depth > 0) --depth;
                break;
            default: break;
        }
    }
    return false;
}

json parse_request_json(std::string_view body) {
    if (json_nesting_exceeds(body)) {
        throw JsonTooDeep("request body is nested more than " +
                          std::to_string(kMaxJsonNestingDepth) + " levels deep");
    }
    return json::parse(body);
}

json parse_request_json_or_discarded(std::string_view body) {
    if (json_nesting_exceeds(body)) return json(json::value_t::discarded);
    return json::parse(body, nullptr, /*allow_exceptions=*/false);
}

std::string dump_response_json(const json& j) {
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

} // namespace bsfchat
