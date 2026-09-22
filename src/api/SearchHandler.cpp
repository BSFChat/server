#include "api/SearchHandler.h"

#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/JsonIo.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <set>

namespace bsfchat {

using json = nlohmann::json;

namespace {

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// Category the spec puts message search under.
constexpr const char* kRoomEvents = "room_events";

} // namespace

SearchHandler::SearchHandler(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {}

std::vector<std::string> SearchHandler::tokenize(const std::string& search_term) {
    std::vector<std::string> terms;
    std::string current;
    // Any run of characters that isn't whitespace or an FTS5 metacharacter is a
    // term. Everything else is a separator, which is what makes the result
    // syntax-free by construction: there is no input that produces a MATCH
    // expression the caller chose.
    auto is_separator = [](unsigned char c) {
        if (std::isspace(c)) return true;
        static const std::string meta = "\"'(){}[]*^:-+,.!?/\\|&<>=~;`$#@%";
        return meta.find(static_cast<char>(c)) != std::string::npos;
    };
    for (unsigned char c : search_term) {
        if (is_separator(c)) {
            if (!current.empty()) terms.push_back(std::move(current));
            current.clear();
        } else {
            current.push_back(static_cast<char>(c));
        }
    }
    if (!current.empty()) terms.push_back(std::move(current));

    // Dedupe while preserving order, and bound the term count: each term is
    // another posting-list intersection, and a 200-term query is not a search.
    std::vector<std::string> out;
    for (auto& t : terms) {
        if (std::find(out.begin(), out.end(), t) != out.end()) continue;
        out.push_back(std::move(t));
        if (out.size() >= 16) break;
    }
    return out;
}

void SearchHandler::handle_search(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    if (!store_.search_index_available()) {
        // Honest failure rather than an empty result set that looks like "no
        // matches". See migrate_v12: the index is skipped when the SQLite build
        // has no FTS5 module.
        return send_error(res, 501, MatrixError::unrecognized(
            "Message search is unavailable: this server's SQLite build has no FTS5 module"));
    }

    json body;
    try {
        body = parse_request_json(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }

    auto cats = body.find("search_categories");
    if (cats == body.end() || !cats->is_object()) {
        return send_error(res, 400,
            MatrixError::bad_json("search_categories.room_events is required"));
    }
    auto room_events = cats->find(kRoomEvents);
    if (room_events == cats->end() || !room_events->is_object()) {
        return send_error(res, 400,
            MatrixError::bad_json("search_categories.room_events is required"));
    }

    const std::string search_term = room_events->value("search_term", "");
    if (search_term.empty()) {
        return send_error(res, 400, MatrixError::invalid_param("search_term is required"));
    }
    if (search_term.size() > limits::kMaxSearchTermLength) {
        return send_error(res, 400, MatrixError::invalid_param("search_term is too long"));
    }
    auto terms = tokenize(search_term);
    if (terms.empty()) {
        // Punctuation only. Nothing to match, and matching "everything" would be
        // both useless and the most expensive query the endpoint can run.
        json out;
        out["search_categories"][kRoomEvents] = {
            {"count", 0}, {"results", json::array()}, {"highlights", json::array()}};
        res.set_content(dump_response_json(out), "application/json");
        return;
    }

    // ── Permission filtering ──────────────────────────────────────────────
    //
    // Computed BEFORE the query and used as the query's room restriction, so an
    // inaccessible channel is never searched rather than searched-then-filtered.
    // Fail-closed at every step: the set starts from the caller's own joined
    // rooms (which is also what keeps DMs private — you are only ever a member of
    // your own), and a room only survives if VIEW_CHANNEL is affirmatively
    // granted.
    PermissionsEngine perms(store_, config_);
    std::vector<std::string> searchable;
    for (const auto& room_id : store_.get_joined_rooms(*user_id)) {
        if (!perms.can(*user_id, room_id, permission::kViewChannel)) continue;
        searchable.push_back(room_id);
    }

    int limit = limits::kDefaultSearchLimit;
    std::vector<std::string> senders;
    if (auto filter = room_events->find("filter");
        filter != room_events->end() && filter->is_object()) {
        if (auto l = filter->find("limit"); l != filter->end() && l->is_number_integer()) {
            limit = std::clamp(l->get<int>(), 1, limits::kMaxSearchLimit);
        }
        // A client-supplied room list can only ever NARROW the set the
        // permission pass produced — it is an intersection, never a substitution.
        if (auto rooms = filter->find("rooms"); rooms != filter->end() && rooms->is_array()) {
            std::set<std::string> requested;
            for (const auto& entry : *rooms) {
                if (entry.is_string()) requested.insert(entry.get<std::string>());
            }
            std::vector<std::string> narrowed;
            for (const auto& room_id : searchable) {
                if (requested.count(room_id)) narrowed.push_back(room_id);
            }
            searchable = std::move(narrowed);
        }
        if (auto s = filter->find("senders"); s != filter->end() && s->is_array()) {
            for (const auto& entry : *s) {
                if (entry.is_string() && senders.size() < 32) {
                    senders.push_back(entry.get<std::string>());
                }
            }
        }
    }

    // "recent" orders by stream position, "rank" (the default) by bm25.
    const bool order_recent = room_events->value("order_by", "rank") == "recent";

    // `next_batch` is an opaque offset into the ordered result set.
    int offset = 0;
    if (auto nb = body.find("next_batch"); nb != body.end() && nb->is_string()) {
        try {
            offset = std::max(0, std::stoi(nb->get<std::string>()));
        } catch (const std::exception&) {
            offset = 0;
        }
    } else if (req.has_param("next_batch")) {
        try {
            offset = std::max(0, std::stoi(req.get_param_value("next_batch")));
        } catch (const std::exception&) {
            offset = 0;
        }
    }

    json results = json::array();
    int count = 0;
    if (!searchable.empty()) {
        SqliteStore::SearchResult found;
        try {
            found = store_.search_messages(searchable, terms, senders, limit, offset,
                                           order_recent);
        } catch (const std::exception& e) {
            // The store quotes every term as a literal phrase, so a well-formed
            // request cannot reach here. Answer 400 rather than 500 anyway: if
            // some input ever does slip through, the honest response is "that
            // query was not usable", not a silent empty result set that looks
            // like "nothing matched".
            // log_safe on the exception text: a SQLite error can quote the
            // offending expression back, and the offending expression is the
            // caller's search terms. Same sweep as the auth lockout key and the
            // rejected pusher URL — see docs/audit-requests-2026-09.md 17.
            get_logger()->warn("Search query failed for {}: {}", log_safe(*user_id),
                               log_safe(e.what(), 256));
            return send_error(res, 400, MatrixError::invalid_param("Search term is not usable"));
        }
        count = found.total;
        for (const auto& hit : found.hits) {
            // Fetched through the shared read path, so an edited message comes
            // back as its CURRENT content with the same bundled-edit metadata the
            // timeline returns — search results and the timeline can never
            // disagree about what a message says.
            auto event = store_.get_event_by_id(hit.event_id);
            if (!event) continue;
            json ev;
            to_json(ev, *event);
            // bm25() is negative with better matches more negative; flip it so a
            // higher `rank` is a better result, which is what clients expect.
            results.push_back(json{{"rank", -hit.rank}, {"result", std::move(ev)}});
        }
        if (found.more) {
            json out;
            out["search_categories"][kRoomEvents] = {
                {"count", count},
                {"results", std::move(results)},
                {"highlights", terms},
                {"next_batch", std::to_string(offset + limit)},
            };
            res.set_content(dump_response_json(out), "application/json");
            return;
        }
    }

    json out;
    out["search_categories"][kRoomEvents] = {
        {"count", count},
        {"results", std::move(results)},
        // The terms the client should highlight in the rendered results.
        {"highlights", terms},
    };
    res.set_content(dump_response_json(out), "application/json");
}

} // namespace bsfchat
