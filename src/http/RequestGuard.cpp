#include "http/RequestGuard.h"

#include "core/Config.h"

#include <bsfchat/Constants.h>

#include <algorithm>
#include <cctype>
#include <charconv>

namespace bsfchat {

namespace {

std::string ascii_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

bool is_media_upload(const httplib::Request& req) {
    return req.path == api_path::kMediaUpload;
}

} // namespace

std::size_t max_json_body_bytes(const Config& config) {
    return config.send_limits.max_event_bytes;
}

std::optional<RequestRefusal> refuse_before_body(const httplib::Request& req,
                                                 const Config& config) {
    if (is_media_upload(req)) return std::nullopt;

    // Any Content-Encoding at all except the explicit no-op. "gzip, identity"
    // is still gzip, so the whole value must be identity, not merely contain it.
    if (req.has_header("Content-Encoding")) {
        const auto enc = ascii_lower(trim(req.get_header_value("Content-Encoding")));
        if (!enc.empty() && enc != "identity") {
            return RequestRefusal{
                415, MatrixError::unrecognized(
                         "Compressed request bodies are not accepted on this endpoint; send "
                         "the JSON uncompressed")};
        }
    }

    // Checked BEFORE Content-Length, not only in its absence: a request that
    // carries both is read as chunked by httplib (as HTTP requires), so a small
    // Content-Length alongside Transfer-Encoding would pass the length check
    // below while the chunked body streamed in unbounded.
    if (req.has_header("Transfer-Encoding")) {
        return RequestRefusal{
            411, MatrixError::unrecognized(
                     "A Content-Length is required for request bodies on this endpoint")};
    }

    const auto cap = max_json_body_bytes(config);
    if (req.has_header("Content-Length")) {
        const auto raw = trim(req.get_header_value("Content-Length"));
        std::size_t len = 0;
        const auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), len);
        // An unparseable length is httplib's to reject; an overflowing one is
        // certainly over the cap.
        if (ec == std::errc::result_out_of_range || (ec == std::errc{} && len > cap)) {
            return RequestRefusal{
                413, MatrixError::too_large("Request body is larger than the " +
                                            std::to_string(cap) + "-byte limit for this endpoint")};
        }
        return std::nullopt;
    }

    return std::nullopt;
}

void apply_cors_headers(const httplib::Request& req, httplib::Response& res,
                        const std::vector<std::string>& allowed_origins) {
    if (allowed_origins.empty()) return;
    // Whatever happens below, the response now depends on Origin; say so, or a
    // shared cache could serve one origin's allowance to another.
    res.set_header("Vary", "Origin");
    if (!req.has_header("Origin")) return;
    const auto origin = req.get_header_value("Origin");
    // Exact match, case-insensitive on the scheme/host (origins are
    // serialised lowercase by browsers; the operator's list may not be).
    const auto want = ascii_lower(origin);
    const bool allowed = std::any_of(allowed_origins.begin(), allowed_origins.end(),
                                     [&](const std::string& o) { return ascii_lower(o) == want; });
    if (!allowed) return;
    res.set_header("Access-Control-Allow-Origin", origin);
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type");
}

} // namespace bsfchat
