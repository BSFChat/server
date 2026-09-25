#pragma once

#include "store/SqliteStore.h"

#include <httplib.h>

#include <optional>
#include <string>

namespace bsfchat {

class SyncEngine;
struct Config;

// Bot account administration: create, list, rotate, deactivate, and read scope.
//
// These five endpoints are the ENTIRE bot-specific request surface. There is no
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
    // {localpart, display_name, description}
    //   -> 201 {user_id, display_name, token, role_ids, bsfchat.warning}
    // The token is shown HERE and never again; nothing stores the plaintext.
    //
    // `role_ids` and the warning are the scope this call just wrote, said out
    // loud. They are not decoration: the account it creates holds nothing
    // anywhere, that is the least Matrix-shaped thing about this server, and
    // until they existed the first mention of it in the whole onboarding
    // sequence was a 403 four requests later that named a channel. See
    // docs/bot-scoping.md §10.
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

    // GET /_matrix/client/v3/bsfchat/bots/{userId}/access
    //   -> 200 {user_id, deactivated, role_ids, server_permissions,
    //           can_view_any_listed_channel,
    //           channels: [{room_id, name, type, category_id?, joined,
    //                       permissions, override?: {allow, deny}}]}
    //
    // WHERE CAN THIS BOT GO — the read side of bot scoping, and READ ONLY.
    //
    // THE FIFTH ENDPOINT, against the rule three paragraphs up. It earns its
    // place because it duplicates no authority: everything in the answer is
    // something the caller could already obtain, and the endpoint is purely the
    // aggregation. A caller holding MANAGE_BOTS can already list bots; a caller
    // who can view a channel can already read its overrides out of /state and
    // its own effective permissions out of GET /bsfchat/permissions/{userId}.
    // What does not exist is a way to ask that question about ANOTHER account
    // across every channel at once, and without it a bots tab would have to
    // issue one /state request per channel and then compute the answer itself —
    // which is a second implementation of the permission algorithm, in a client,
    // for a security decision. That has already drifted once here
    // (client/src/util/PermissionMath.cpp). PermissionsEngine answers instead.
    //
    // THERE IS NO WRITE SIBLING, deliberately. Granting a bot a channel is
    // writing `bsfchat.channel.permissions` with state_key `user:<bot id>`, and
    // granting it a server-wide permission is writing `bsfchat.member.roles` —
    // both of which already exist, are already audited, and already carry the
    // rank and containment rules. A bot-flavoured write route would be a second
    // way to author the same state, and the second way is the one that ends up
    // missing a rule. A consequence worth stating plainly: MANAGE_BOTS alone
    // cannot grant a bot access to anything. Letting a bot into a channel needs
    // MANAGE_ROLES in that channel, which is the same authority it takes to let
    // a person in, and that is the intended answer rather than a gap.
    //
    // WHAT WAS A GAP was that nothing said so. The design above is unchanged;
    // what changed is that creation, the join and the refusal now each state
    // it at the moment it applies. docs/bot-scoping.md §10 is the record, and
    // src/api/ChannelAccessRefusal.h is the refusal half.
    //
    // `can_view_any_listed_channel` is the reduction of that array that every
    // reader was going to perform anyway: does this bot hold VIEW_CHANNEL
    // anywhere the caller can see? It is one field because the audience for
    // this endpoint is somebody whose bot has gone quiet, and making them scan
    // hex masks to find out that the answer is "nowhere" is the same failure,
    // one layer up, as the refusal that named the channel.
    //
    // GATED BY authorize_bot_admin, so it carries the rank rule too. Reading
    // where a credential may go is reconnaissance for rotating it, and rotation
    // is already refused for a bot that outranks the caller.
    //
    // FILTERED BY WHAT THE CALLER MAY BE TOLD ABOUT. The channel list is the
    // caller's own visible_channel_directory(), not the server's room list.
    // MANAGE_BOTS is a licence to manufacture accounts, not to enumerate the
    // server: without this, a delegated bot administrator who cannot see
    // #leadership would learn that it exists, what it is called and how its
    // overrides are shaped, by asking about an unrelated bot. The BOT's
    // permissions inside those channels are then computed for the bot, which is
    // the whole point — the caller's visibility decides which channels are
    // listed, and the bot's decides what each entry says.
    void handle_get_bot_access(const httplib::Request& req, httplib::Response& res);

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
    // THAT REUSE WAS RIGHT AND THE THING IT REUSED WAS NOT. F6 of
    // docs/audit-permissions-2026-09.md: outranks() measured ROLE POSITION
    // ONLY, and the paragraph below about there being no write sibling is
    // exactly why that made it inert here. A bot is scoped with a per-channel
    // override and `handle_create_bot` writes it an empty role assignment, so
    // a correctly scoped bot sat at position 0 forever and every delegated
    // MANAGE_BOTS holder at position >= 1 "outranked" it — buying them a
    // non-expiring credential for an account that reads channels they are
    // themselves denied, with `handle_list_bots` supplying the ids to try.
    // The rank check was a comparison of 0 against 0 for precisely the
    // configuration this file documents.
    //
    // The fix is in outranks(), not here, and that is the point: rank now has
    // a channel half as well as a role half (auth/Permissions.h, "THE
    // CONTAINMENT RULE"). This file goes on asking the one question it should
    // ask — "is this principal below me?" — and the answer has stopped being
    // wrong. A second, bot-shaped notion of containment living in this handler
    // is what the paragraph above about write siblings warns against.
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
