#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
struct Config;

// Bot account administration: create, list, rotate, deactivate.
//
// These four endpoints are the ENTIRE bot-specific request surface. There is no
// bot-flavoured /sync, no bot variant of /rooms/{id}/send, no parallel
// authentication path — because a bot is a user account, so everything else it
// does goes through the routes that already exist and the bearer-token
// middleware that already guards them. If this file ever grows a fifth endpoint
// that duplicates something a human account can already do, that is the signal
// that the "a bot is a user" property has been broken somewhere else.
//
// Every endpoint here requires MANAGE_BOTS at SERVER scope. Server scope is not
// incidental: with a room id, PermissionsEngine::compute applies that channel's
// allow/deny overrides, so a MANAGE_BOTS override granted inside one channel
// would otherwise unlock the ability to mint server-wide accounts. That
// escalation shape has been a real bug in this codebase twice (the role-write
// path, and nearly the audit log), and minting credentials is the worst place
// for it to happen a third time. ADMINISTRATOR still passes, because compute()
// short-circuits it from the role base before any override is considered.
class BotHandler {
public:
    BotHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

    // POST /_matrix/client/v3/bsfchat/bots
    // {localpart, display_name, description} -> 201 {user_id, display_name, token}
    // The token is shown HERE and never again; nothing stores the plaintext.
    void handle_create_bot(const httplib::Request& req, httplib::Response& res);

    // GET /_matrix/client/v3/bsfchat/bots -> {bots: [...]}
    // Never returns token material, in any field, for any bot.
    void handle_list_bots(const httplib::Request& req, httplib::Response& res);

    // POST /_matrix/client/v3/bsfchat/bots/{userId}/token -> {token}
    // Every prior token for that bot is invalidated in the same transaction.
    void handle_rotate_token(const httplib::Request& req, httplib::Response& res);

    // DELETE /_matrix/client/v3/bsfchat/bots/{userId} -> {}
    // Revokes every token, leaves every room, marks the bot deactivated.
    // Idempotent: a second call is a 200 that changes nothing.
    void handle_deactivate_bot(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
