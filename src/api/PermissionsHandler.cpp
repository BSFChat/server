#include "api/PermissionsHandler.h"

#include "auth/Permissions.h"
#include "auth/RoomVisibility.h"
#include "core/Config.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <unordered_set>
#include <vector>

namespace bsfchat {

using json = nlohmann::json;

namespace {

// Server scope for PermissionsEngine — the empty room id. See PermissionsHandler.h
// for why this file has no other kind.
const std::string kServerScope;

// ONE refusal for every reason this endpoint can refuse: not a member of
// anything you share, not visible to you, never existed. Differencing the
// responses is how a read endpoint becomes an account-existence oracle, which
// is precisely what GET /profile/{userId} was before it was made to require
// authentication — and it still answers 404 vs 200, so this one is not going to
// add a second way to walk the namespace.
//
// A single const so the three call sites cannot drift into three wordings.
const char* const kRefusal = "You are not permitted to read that member's permissions";

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

void send_json(httplib::Response& res, const json& body, int status = 200) {
    res.status = status;
    res.set_content(body.dump(), "application/json");
}

} // namespace

PermissionsHandler::PermissionsHandler(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {}

bool PermissionsHandler::may_read_permissions_of(PermissionsEngine& perms,
                                                  const std::string& caller,
                                                  const std::string& target) {
    // Asking about yourself is always allowed and discloses nothing: the caller
    // can already establish every bit of this by attempting the action and
    // reading the 403. It is also the case a shared library will exercise on
    // startup, so it must not depend on the bot being in a channel yet.
    if (caller == target) return true;

    // A caller who can rewrite the assignment graph may read it. Server scope,
    // not channel scope, and that distinction is not cosmetic: with a room id
    // compute() applies that channel's overrides, so MANAGE_ROLES handed out
    // inside one unimportant channel would otherwise unlock a server-wide read.
    // That exact shape has been a real hole here before — it is what
    // RoleHandler and BotHandler both say at length, and this endpoint is one
    // more place that must not be the exception.
    if (perms.can(caller, kServerScope, permission::kManageRoles)) return true;

    // Otherwise: a channel they are both joined to, that the CALLER may view.
    //
    // Membership is not visibility on this server — every channel is created
    // public and force-joined, and a "private" channel is one where @everyone is
    // denied VIEW_CHANNEL afterwards, so "joined but not permitted to see"
    // is the normal steady state (docs/membership-vs-visibility.md). A rule
    // written on membership alone would therefore let a member of a channel they
    // cannot see read the permissions of everybody else force-joined into it,
    // i.e. everybody on the server. The VIEW_CHANNEL term is the whole rule.
    //
    // can_view_room() from RoomVisibility.h is deliberately NOT used here. It
    // grants categories the benefit of the doubt so the sidebar can draw a
    // container whose children are hidden — and that header says in as many
    // words that the exemption belongs to LISTING a room, not to a request that
    // acts. Every account is joined to the categories, so importing the
    // exemption would quietly turn this rule back into "any account may ask
    // about any account".
    auto target_rooms = store_.get_joined_rooms(target);
    if (target_rooms.empty()) return false;
    std::unordered_set<std::string> shared(target_rooms.begin(), target_rooms.end());

    // Intersect first, permission-check second. The permission check is the
    // expensive term (a channel-override read per room under the store's global
    // mutex); the intersection is a hash lookup. On a server with a hundred
    // channels the other order pays for ninety-nine rooms the target is not even
    // in. One engine spans the loop, so the roles read is memoised across it.
    for (const auto& room_id : store_.get_joined_rooms(caller)) {
        if (!shared.count(room_id)) continue;
        if (perms.can(caller, room_id, permission::kViewChannel)) return true;
    }
    return false;
}

void PermissionsHandler::handle_get_permissions(const httplib::Request& req,
                                                 httplib::Response& res) {
    auto caller = authenticate(store_, req.get_header_value("Authorization"));
    if (!caller) {
        send_error(res, 401, auth_error(req.get_header_value("Authorization")));
        return;
    }

    // A banned identity is told nothing, whatever its membership rows say. The
    // ban projection already rewrites those rows to "ban", so get_joined_rooms
    // returns nothing and the shared-channel rule refuses on its own — but this
    // also closes the MANAGE_ROLES branch, which a ban does not touch, and it
    // fails closed for any room whose projection was missed. /sync leads with
    // the same lookup for the same reason.
    if (store_.is_server_banned(*caller)) {
        send_error(res, 403, MatrixError::forbidden(kRefusal));
        return;
    }

    auto match = match_route(std::string(api_path::kPermissions) + "/{userId}", req.path);
    if (!match.matched) {
        send_error(res, 404, MatrixError::not_found("Unknown endpoint"));
        return;
    }
    const std::string target = match.params.at("userId");

    // Existence BEFORE visibility, and the same refusal for both — see kRefusal.
    //
    // This is also what keeps the synthetic @server actor out of the answer.
    // PermissionsEngine::compute() short-circuits it to kAllFlags, so without
    // this an operator-shaped id like "@server:chat.example.com" would come back
    // as a full administrator and a bot would cheerfully obey anything wearing
    // that sender. It is not a row in `users`, so it stops here — and it stops
    // here on the MANAGE_ROLES branch too, which the shared-channel rule alone
    // would not have covered.
    if (!store_.user_exists(target)) {
        send_error(res, 403, MatrixError::forbidden(kRefusal));
        return;
    }

    // One engine for the authorization decision and the answer, so the server
    // role document and the caller's own assignment are read once between them.
    PermissionsEngine perms(store_, config_);
    if (!may_read_permissions_of(perms, *caller, target)) {
        send_error(res, 403, MatrixError::forbidden(kRefusal));
        return;
    }

    // THE authority. Not a reimplementation of it, not a cached copy of it, and
    // not a different engine instance seeded from anything the request said.
    const permission::Flags flags = perms.compute(target, kServerScope);

    send_json(res, json{
        {"user_id", target},
        // Stated rather than implied. A future reader adding a channel variant
        // has to decide what this says, instead of a bot discovering the change
        // by mis-authorizing somebody.
        {"scope", "server"},
        // Hex, like every other permission field on the wire. An ADMINISTRATOR
        // holder reads back kAllFlags, not just bit 15, because compute()
        // short-circuits — which is what makes `mask & MANAGE_BOTS` the whole of
        // a bot's check, with no special case for admins.
        {"permissions", permission::flags_to_hex(flags)},
    });
}

} // namespace bsfchat
