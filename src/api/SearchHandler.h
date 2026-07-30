#pragma once

#include <httplib.h>

#include <string>
#include <vector>

namespace bsfchat {

class SqliteStore;
struct Config;

// POST /_matrix/client/v3/search — full-text search over message bodies.
//
// Spec-shaped (search_categories.room_events), because the client already speaks
// Matrix everywhere else and a bespoke endpoint would be one more thing to
// special-case. The subset implemented is search_term, order_by, and
// filter.{limit,rooms,senders}; anything else in the request is ignored rather
// than rejected, so a fuller client does not break.
//
// The result set is permission-filtered before the query runs, not after: the
// room set is computed from the caller's own joined rooms intersected with
// VIEW_CHANNEL, so a channel they cannot see is not merely hidden from the
// output — it is never searched, and neither its content nor its existence can
// be inferred from counts or timing.
class SearchHandler {
public:
    SearchHandler(SqliteStore& store, const Config& config);

    void handle_search(const httplib::Request& req, httplib::Response& res);

    // Splits a user's search string into bare terms. Exposed for tests.
    //
    // Deliberately throws away FTS5 query syntax rather than passing it through.
    // MATCH expressions are a hostile surface: unbalanced quotes and stray
    // operators make sqlite3_prepare fail (turning a typo into a 500), `NEAR`
    // and nested boolean groups are a cheap way to make the engine do a lot of
    // work, and a bare `*` matches the entire index. Users get substring-free
    // term matching; power syntax is not worth the blast radius.
    static std::vector<std::string> tokenize(const std::string& search_term);

private:
    SqliteStore& store_;
    const Config& config_;
};

} // namespace bsfchat
