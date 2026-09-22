#include "api/AccountDataHandler.h"
#include "api/InputLimits.h"

#include "core/Config.h"
#include "http/JsonIo.h"
#include "http/Middleware.h"
#include "http/RateLimitResponse.h"
#include "http/Router.h"
#include "store/SqliteStore.h"

#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>

#include <nlohmann/json.hpp>

#include <chrono>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace bsfchat {

using json = nlohmann::json;

namespace {

constexpr const char* kAccountDataRoute =
    "/_matrix/client/v3/user/{userId}/account_data/{type}";

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// The ignore list, parsed out of an m.ignored_user_list document.
//
// `error` is set when the document is not one this server will act on. It is a
// 400 and not a silent acceptance, which is the decision worth recording here:
// every other account-data type is stored verbatim because the server does not
// read it, so a client is free to put whatever it likes in one. This type the
// server DOES read, and an entry it cannot enforce is worse than a refusal —
// the client shows the user a block that exists only in their own UI, and the
// person they blocked keeps arriving. A 400 is visible; an unenforceable block
// is not.
struct IgnoreList {
    std::vector<std::string> users;
    std::optional<MatrixError> error;
};

IgnoreList parse_ignore_list(const json& content, const std::string& self) {
    IgnoreList out;

    auto it = content.find(account_data_type::kIgnoredUsersKey);
    if (it == content.end()) {
        // A document with no `ignored_users` key at all is an empty list, not an
        // error: it is what a client sends to clear the list, and Matrix's own
        // shape for "nobody is ignored".
        return out;
    }
    if (!it->is_object()) {
        out.error = MatrixError::invalid_param(
            std::string(account_data_type::kIgnoredUsersKey) + " must be an object");
        return out;
    }

    if (it->size() > input_limits::kMaxIgnoredUsers) {
        out.error = MatrixError::invalid_param(
            "ignore list holds " + std::to_string(it->size()) + " entries; the limit is " +
            std::to_string(input_limits::kMaxIgnoredUsers));
        return out;
    }

    // A set, so a document that somehow names the same id twice (different
    // escaping, a client bug) still produces one row per account and the
    // projection cannot depend on JSON key ordering.
    std::set<std::string> unique;
    for (const auto& [target, value] : it->items()) {
        // The VALUE is unconstrained on purpose. The spec says it is an empty
        // object reserved for future use, and a server that refused anything
        // else would break a client that had adopted the future use — while a
        // server that stores it loses nothing, because the document is returned
        // byte-for-byte and only the KEYS are projected.
        (void)value;

        if (!UserId::is_valid(target)) {
            // Named rather than counted. The client put this string in the
            // document, so telling it which one is malformed is the difference
            // between a bug it can fix and a block list that will not save.
            out.error = MatrixError::invalid_param(
                "'" + target.substr(0, input_limits::kMaxDisplayNameBytes) +
                "' is not a valid user id");
            return out;
        }
        // Ignoring yourself would filter your own messages out of your own
        // timeline — a state a client cannot get back out of, because the
        // document it would PUT to fix it is delivered over a /sync that is
        // hiding the evidence. Refused rather than dropped, so the client knows
        // the list it holds is not the list the server holds.
        if (target == self) {
            out.error = MatrixError::invalid_param("You cannot ignore yourself");
            return out;
        }
        unique.insert(target);
    }

    out.users.assign(unique.begin(), unique.end());
    return out;
}

} // namespace

AccountDataHandler::AccountDataHandler(SqliteStore& store, const Config& config,
                                       LimiterClock clock)
    : store_(store), config_(config), limits_(config.send_limits, std::move(clock)) {}

void AccountDataHandler::handle_get_account_data(const httplib::Request& req,
                                                 httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto match = match_route(kAccountDataRoute, req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    // Somebody else's account data is not readable, by anybody, at any
    // permission level — see the header for why this one matters more than it
    // looks. The refusal is identical for "that account does not exist" and
    // "that account exists and is not you", because distinguishing them would
    // make this an account-existence oracle for free.
    if (match.params["userId"] != *user_id) {
        return send_error(res, 403, MatrixError::forbidden(
            "You can only read your own account data"));
    }

    const auto& type = match.params["type"];
    if (type.empty()) {
        return send_error(res, 400, MatrixError::invalid_param("type must not be empty"));
    }

    auto stored = store_.get_account_data(*user_id, type);
    if (!stored) {
        // The spec's answer for a document that was never written, and the one
        // a client needs: "I have no block list" and "my block list is empty"
        // are different states, and a client that cannot tell them apart cannot
        // decide whether to upload its local one.
        return send_error(res, 404, MatrixError::not_found("Account data not found"));
    }

    // Returned as JSON, not as a quoted string. It went in as an object and a
    // client must not have to parse a document out of a document.
    auto parsed = json::parse(*stored, nullptr, false);
    if (parsed.is_discarded()) {
        // Only reachable if something wrote a non-JSON row underneath this
        // class. Answer with an empty object rather than a 500: the client's
        // next PUT then overwrites it, which is a recoverable state, whereas a
        // 500 on every read of one document is not.
        parsed = json::object();
    }
    res.set_content(dump_response_json(parsed), "application/json");
}

void AccountDataHandler::handle_put_account_data(const httplib::Request& req,
                                                 httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto match = match_route(kAccountDataRoute, req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    if (match.params["userId"] != *user_id) {
        return send_error(res, 403, MatrixError::forbidden(
            "You can only write your own account data"));
    }

    // Charged BEFORE the body is parsed, like every other limiter in this
    // server: the point of the budget is to bound work, and parsing is work.
    if (const auto wait = limits_.acquire(SendLimiter::Bucket::kAccountData, *user_id)) {
        return send_rate_limited(res, wait,
                                 SendLimiter::message_for(SendLimiter::Bucket::kAccountData));
    }

    const auto& type = match.params["type"];
    if (type.empty()) {
        return send_error(res, 400, MatrixError::invalid_param("type must not be empty"));
    }
    if (auto err = oversize_field("type", type, input_limits::kMaxAccountDataTypeBytes)) {
        return send_error(res, 400, *err);
    }

    json body;
    try {
        body = parse_request_json(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }
    // Matrix account data is a JSON OBJECT. Refusing an array or a scalar is
    // not pedantry: every reader of this store — this server's ignore-list
    // projection today, a client's merge tomorrow — expects to index into it,
    // and a stored `[]` turns that into a type error at every one of them.
    if (!body.is_object()) {
        return send_error(res, 400, MatrixError::bad_json("Account data must be a JSON object"));
    }

    const std::string content = body.dump();
    if (auto err = oversize_field("content", content, input_limits::kMaxAccountDataBytes)) {
        return send_error(res, 400, *err);
    }

    std::optional<std::vector<std::string>> ignored;
    if (type == std::string(account_data_type::kIgnoredUserList)) {
        auto parsed = parse_ignore_list(body, *user_id);
        if (parsed.error) {
            return send_error(res, 400, *parsed.error);
        }
        ignored = std::move(parsed.users);
    }

    // The document and its index go down together; see set_account_data.
    store_.set_account_data(*user_id, type, content, ignored, now_ms());

    // NO SYNC WAKE, and no account-data section in /sync.
    //
    // Matrix delivers account data through /sync, and this server does not —
    // the client that reads its block list reads it from this endpoint, which
    // is where it just wrote it. Waking every parked poll on the server for a
    // change only one account can see, which that account already knows about
    // because it is the one that made it, would be cost with nothing on the
    // other side.
    //
    // The enforcement does not wait for a sync either: the filter is a SQL
    // clause evaluated on the next scan, so the very next poll — including one
    // already parked, when it re-scans — is already filtered. Blocking takes
    // effect at the moment of the PUT, not at the moment of a delivery.
    //
    // A /sync account_data section is the thing to add when a second device
    // needs to learn about the first one's change without asking. That is a
    // real gap and it is stated here rather than left to be discovered.
    res.set_content("{}", "application/json");
}

} // namespace bsfchat
