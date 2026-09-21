#include "store/MediaReferences.h"

#include <nlohmann/json.hpp>

#include <algorithm>

namespace bsfchat {

std::vector<std::string> media_uris_in_content(const std::string& content_json) {
    std::vector<std::string> uris;
    auto j = nlohmann::json::parse(content_json, nullptr, false);
    if (j.is_discarded()) return uris;

    // Iterative rather than recursive: content is attacker-supplied, and
    // nlohmann will happily parse a few thousand levels of nesting, which a
    // recursive walker would turn into a stack overflow — a remote crash from
    // one PUT /send. A worklist has no such ceiling.
    std::vector<const nlohmann::json*> todo{&j};
    while (!todo.empty()) {
        const nlohmann::json* node = todo.back();
        todo.pop_back();
        if (node->is_string()) {
            const auto& s = node->get_ref<const std::string&>();
            if (s.rfind("mxc://", 0) != 0 || s.size() > 512) continue;
            auto slash = s.find('/', 6);
            if (slash == std::string::npos || slash == 6) continue; // no host
            auto id = s.substr(slash + 1);
            // A media id is lowercase hex (MediaHandler::generate_media_id).
            // Refusing anything else keeps a crafted `mxc://host/../..` out of
            // the table entirely rather than relying on downstream checks.
            if (id.empty() || id.size() > 128 ||
                id.find_first_not_of("0123456789abcdef") != std::string::npos) {
                continue;
            }
            uris.push_back(s);
        } else if (node->is_object() || node->is_array()) {
            for (const auto& child : *node) todo.push_back(&child);
        }
    }

    std::sort(uris.begin(), uris.end());
    uris.erase(std::unique(uris.begin(), uris.end()), uris.end());
    return uris;
}

MediaReferences::MediaReferences(std::vector<std::string> uris) : uris_(std::move(uris)) {
    std::sort(uris_.begin(), uris_.end());
    uris_.erase(std::unique(uris_.begin(), uris_.end()), uris_.end());
}

MediaReferences MediaReferences::none() { return MediaReferences(); }

bool MediaReferences::permits(const std::string& mxc_uri) const {
    return std::binary_search(uris_.begin(), uris_.end(), mxc_uri);
}

} // namespace bsfchat
