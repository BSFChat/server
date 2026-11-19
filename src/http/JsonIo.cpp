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

namespace {
struct BodyMark {
    const char* data = nullptr;
    std::size_t size = 0;
};
thread_local BodyMark t_body_mark;
} // namespace

void mark_request_body_parsed(std::string_view body) noexcept {
    t_body_mark = {body.data(), body.size()};
}

bool request_body_was_parsed(std::string_view body) noexcept {
    return !body.empty() && t_body_mark.data == body.data() && t_body_mark.size == body.size();
}

void clear_request_body_mark() noexcept { t_body_mark = {}; }

bool type_error_is_bad_request_body(int type_error_id, std::string_view body) noexcept {
    // 302 "type must be", 304/305/306 "cannot use ... with". 316 (invalid
    // UTF-8 on dump) and the rest are never the caller's input.
    const bool ill_typed = type_error_id == 302 || type_error_id == 304 ||
                           type_error_id == 305 || type_error_id == 306;
    return ill_typed && request_body_was_parsed(body);
}

json parse_request_json(std::string_view body) {
    mark_request_body_parsed(body);
    if (json_nesting_exceeds(body)) {
        throw JsonTooDeep("request body is nested more than " +
                          std::to_string(kMaxJsonNestingDepth) + " levels deep");
    }
    return json::parse(body);
}

json parse_request_json_or_discarded(std::string_view body) {
    mark_request_body_parsed(body);
    if (json_nesting_exceeds(body)) return json(json::value_t::discarded);
    return json::parse(body, nullptr, /*allow_exceptions=*/false);
}

std::string dump_response_json(const json& j) {
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

} // namespace bsfchat
