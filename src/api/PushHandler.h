#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class PushService;
struct Config;

// Matrix pusher API plus the per-room notification level that push evaluation
// reads.
//
//   POST /_matrix/client/v3/pushers/set
//   GET  /_matrix/client/v3/pushers
//   GET  /_matrix/client/v3/bsfchat/rooms/{roomId}/notify_level
//   PUT  /_matrix/client/v3/bsfchat/rooms/{roomId}/notify_level
//
// The notify_level pair is deliberately in the bsfchat.* namespace rather than
// pretending to be Matrix's /pushrules: it is a single enum per room, not the
// spec's rule/condition/action model, and claiming the spec path for a partial
// implementation would mislead any real Matrix client that found it.
class PushHandler {
public:
    PushHandler(SqliteStore& store, PushService& push, const Config& config);

    void handle_set_pusher(const httplib::Request& req, httplib::Response& res);
    void handle_get_pushers(const httplib::Request& req, httplib::Response& res);
    void handle_get_notify_level(const httplib::Request& req, httplib::Response& res);
    void handle_put_notify_level(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    PushService& push_;
    const Config& config_;
};

} // namespace bsfchat
