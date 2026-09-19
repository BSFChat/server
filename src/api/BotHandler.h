#pragma once

#include "store/SqliteStore.h"

#include <httplib.h>

#include <optional>
#include <string>

namespace bsfchat {

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
    // Everything an authorized operation on an existing bot needs.
    struct BotAdminContext {
        std::string actor;
        SqliteStore::BotRecord bot;
    };

    // THE gate for any operation on an EXISTING bot. Authentication, MANAGE_BOTS
    // at server scope, the bot lookup, and the hierarchy check — in that order,
    // in one call. On refusal it writes the response and returns nullopt.
    //
    // It returns the BotRecord because that is what makes it hard to misuse: a
    // handler cannot act on a bot without having come through here, so a future
    // endpoint cannot acquire a bot and forget half the gate. The original hole
    // was exactly that shape — two handlers each doing their own permission
    // check, both doing only the easy half.
    //
    // THE HIERARCHY CHECK, AND WHY IT IS NOT OPTIONAL. A bot token is a bearer
    // credential for an account that holds roles. Handing one to a human is
    // therefore equivalent to granting that human the bot's roles, and it is
    // worse than a role grant in two ways: it leaves no bsfchat.member.roles
    // event naming the new principal, and the credential never expires. Without
    // a rank check, a delegated MANAGE_BOTS holder at position 10 could rotate
    // the token of a bot holding Administrator and walk away with permanent
    // ownership of the server.
    //
    // This is the same hole, in the same codebase, that may_assign_roles was
    // written for — see the long comment in auth/Permissions.h about MANAGE_ROLES
    // not being "a one-request path to owning the server". MANAGE_BOTS has
    // exactly that property, so it gets exactly that treatment, reusing
    // outranks() rather than inventing a parallel notion of rank.
    //
    // Exemptions match may_assign_roles: the synthetic @server actor and holders
    // of ADMINISTRATOR pass. The ADMINISTRATOR exemption is load-bearing rather
    // than a convenience — an admin bot sits at the admin role's position, so a
    // strict outranks() would leave a bot that no human could ever rotate.
    //
    // Deliberately NOT applied to creation or listing. A newly created bot holds
    // no roles, so it sits at position 0 and everyone outranks it; the escalation
    // "create a bot, then grant it Administrator" is already refused by
    // may_assign_roles, which will not assign a role at or above the actor's own
    // position. A rank check on creation would be noise that implied a
    // protection living somewhere else. Listing discloses no credential.
    std::optional<BotAdminContext> authorize_bot_admin(const httplib::Request& req,
                                                       httplib::Response& res,
                                                       const std::string& bot_user_id,
                                                       const char* action);

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
