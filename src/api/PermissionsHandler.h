#pragma once

#include "store/SqliteStore.h"

#include <httplib.h>

#include <optional>
#include <string>

namespace bsfchat {

class PermissionsEngine;
struct Config;

// "What may this member do, server-wide?" — the read side of the permission
// model, and the only one there is.
//
// WHY THIS EXISTS.
//
// An integration that wants to gate its own privileged commands ("may this
// person restart me / reconfigure me / make me leave?") has to answer that
// question about the SENDER of a message. Until this endpoint it could not, and
// the two things it could do instead were both wrong:
//
//   1. Keep an allowlist of user ids in the bot's own configuration. That is a
//      second permission model, maintained by hand, that goes stale the moment
//      somebody is promoted or — much worse — demoted. A server that has an
//      answer to "who is an admin" should not make every integration invent a
//      worse one.
//   2. Reconstruct the answer client-side from state events. A bot cannot: role
//      definitions and per-member assignments live in the `server_state` table,
//      and clients only ever saw them because RoleBootstrap MIRRORS those
//      events into a single room — list_all_non_category_rooms().front(). /sync
//      reads server_state for nothing. A bot invited into one channel that is
//      not that room receives no role state at all, so it has nothing to
//      compute from. And a bot that DID receive it would have to reimplement
//      the OR-the-roles / ADMINISTRATOR-short-circuit algorithm, which is
//      exactly what client/src/util/PermissionMath.cpp does and exactly what
//      has silently drifted from this repo before.
//
// So the answer is computed HERE, by PermissionsEngine — the same object every
// enforcing endpoint asks — and handed over as a number. There is deliberately
// no second implementation of the algorithm in this file; if you find yourself
// wanting to OR some role bits together here, you are writing the bug this
// endpoint exists to delete.
//
// SERVER SCOPE, ALWAYS.
//
// compute() is called with an empty room id. That is not a default, it is the
// contract: the flags an integration gates on (MANAGE_BOTS, MANAGE_SERVER,
// ADMINISTRATOR) are all evaluated at server scope by the endpoints that
// enforce them, so a channel-scoped answer here would confidently predict the
// wrong verdict. A per-channel variant is also a disclosure this read has no
// business making — it would report which channels exist and how their
// overrides are shaped.
//
// WHO MAY ASK ABOUT WHOM.
//
// Three ways in, and nothing else:
//
//   * yourself — tells you nothing you could not already infer by trying
//     something and reading the 403;
//   * a member you share at least one channel with, where you hold
//     VIEW_CHANNEL in that channel;
//   * a caller holding MANAGE_ROLES at server scope.
//
// The reasoning, because "role assignments are already broadcast" is a true
// statement that does not by itself justify an endpoint:
//
// Role assignments ARE already broadcast — `bsfchat.member.roles` for every
// member is mirrored into the mirror room, and ordinary accounts are
// force-joined to every public channel, so in practice every human on the
// server already receives every assignment. Not secret. But "not secret" is
// not "any account may enumerate the server". An unrestricted version of this
// endpoint would be a machine-readable directory of who holds power, walkable
// at line rate by any account that can hold a token — including a bot created
// for some unrelated integration, and including an attacker who has phished one
// low-value credential and now wants a target list. Two audits on this codebase
// have turned up privilege escalations; handing out the escalation map is the
// same class of mistake one step earlier.
//
// The shared-channel rule keeps the answer inside a boundary the caller is
// ALREADY on the inside of: they can call GET /rooms/{id}/members on that
// channel and get the same list of people. It adds no name to anybody's world.
// It is also the boundary a bot naturally satisfies — it was invited into the
// channel it is being commanded from — so the legitimate case needs no
// privilege at all.
//
// MANAGE_ROLES is included because a caller holding it can already REWRITE the
// assignment graph through RoleHandler; a write authority that cannot read back
// what it wrote is an invitation to go and read the mirror room instead.
//
// WHAT IS DELIBERATELY NOT IN THE ANSWER: the member's role ids. The question is
// "what may they do", and the role list is strictly more than that — it would
// name private roles ("mods-in-training", "trust-level-3") to a caller whose
// only claim is sharing one channel. Minimum disclosure that answers the
// question asked.
//
// NOT AN EXISTENCE ORACLE. A user who does not exist and a user who exists but
// shares nothing with the caller get the SAME 403 with the SAME message. The
// ordering in may_read_permissions_of() is what enforces that, and it is the
// reason existence is checked before visibility rather than after.
//
// NOT SPOOFABLE. The only caller-controlled input is the target's user id in the
// path. Nothing in the request influences the computation — no room id, no
// claimed roles, no flags to check against. The caller cannot even choose the
// scope. The worst a caller can do with a forged path segment is name somebody
// they are not allowed to ask about, which is the refusal above.
class PermissionsHandler {
public:
    PermissionsHandler(SqliteStore& store, const Config& config);

    // GET /_matrix/client/v3/bsfchat/permissions/{userId}
    //   -> 200 {"user_id": "...", "scope": "server", "permissions": "0x..."}
    //
    // `permissions` is the same lowercase hex spelling every other permission
    // field on the wire uses (permission::flags_to_hex), for the same reason:
    // JSON numbers cannot carry 64 bits safely, and a client that parses one
    // field's spelling should not have to learn a second.
    //
    // Computed fresh on every call and cached NOWHERE on the server. That is the
    // whole answer to "does it stay correct when a role is edited or reassigned
    // while the bot is running": there is no state to invalidate, so the call
    // after the change is already right. The corresponding obligation lands on
    // the caller and is written down in docs/bots.md — ask at the moment you
    // authorize an action, do not cache a verdict.
    void handle_get_permissions(const httplib::Request& req, httplib::Response& res);

private:
    // The authorization rule from the class comment. Returns false having
    // decided nothing about WHY, on purpose: the caller writes one refusal for
    // every reason, so the endpoint cannot be differenced.
    bool may_read_permissions_of(PermissionsEngine& perms, const std::string& caller,
                                 const std::string& target);

    SqliteStore& store_;
    const Config& config_;
};

} // namespace bsfchat
