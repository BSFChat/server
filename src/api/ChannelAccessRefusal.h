#pragma once

#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace bsfchat {

// ONE refusal, built in one place, for "you are in this room and may not see
// it" — and the one case where that sentence is actively misleading.
//
// ── what went wrong ──────────────────────────────────────────────────────
//
// An operator created a bot, minted its token, joined it to a public channel
// and watched it post. Four requests: 201, 200, 200 (joined), then 403
// "No access to this channel", forever. Every step reported success until the
// last one, and the last one blamed the channel.
//
// The channel was not the problem. `handle_create_bot` writes a new bot an
// EMPTY role assignment and a bot does not inherit @everyone
// (permission::inherits_everyone_role), so that account held 0x0 in every
// channel on the server — which is the design, deliberately, and is why the
// join succeeded: membership is not a permission here. See
// docs/bot-scoping.md §3 and §4. What was missing was not a grant, it was any
// statement of the fact at the moment it mattered.
//
// ── the rule ─────────────────────────────────────────────────────────────
//
// The sentence a handler produces STARTS with the exact string it has always
// produced, so a client matching substrings of it keeps matching (the
// substring habit is real — client/src/model/ChannelInviteModel.cpp — and
// ErrorCodes.h's standing rule 1 is that a reason never replaces the prose).
// Where the cause is an unscoped bot the sentence continues, because that
// continuation is the only thing that would have saved the operator an hour,
// and because the client currently throws `bsfchat.errcode` away entirely
// (MatrixFailure.h) while it does show `error`.
//
// ── why the predicate is what it is ──────────────────────────────────────
//
// "The account holds no roles" is NOT the predicate, and must not be: a human
// whose assignment document is empty still has @everyone, implicitly, so
// telling them they hold no roles would be false and would send them looking
// at role assignments for a deny override. The predicate is the conjunction —
// an account that does not inherit @everyone AND has nothing assigned — which
// is exactly and only a bot nobody has granted anything, and it is cheap: one
// server_state read, on a path that is already refusing the request.
//
// It is stated in terms of the permission rule rather than of users.kind on
// purpose. inherits_everyone_role is the rule the engine itself applies; a
// second, differently-spelled notion of "is this a bot" living beside it is
// how the two drift.
inline bool is_unscoped_bot(SqliteStore& store, const std::string& user_id) {
    if (permission::inherits_everyone_role(user_id)) return false;
    return store.get_member_role_ids(user_id).empty();
}

// The refusal body for a member who lacks VIEW_CHANNEL in a room they are in.
//
// Used by every handler that answers that situation — send, redact,
// /messages, /state, /state/{type}, /members, self-membership and room-type
// changes — so the classification cannot be right at some of them and stale at
// the rest.
//
// Callers have already checked and separately refused non-membership ("Not a
// member of this room"), so nothing here says anything about a room the caller
// is not in.
inline MatrixError no_channel_access(SqliteStore& store, const std::string& user_id) {
    if (!is_unscoped_bot(store, user_id)) {
        return MatrixError::forbidden("No access to this channel", refusal::kNoViewChannel);
    }
    return MatrixError::forbidden(
        "No access to this channel: this bot holds no roles and no channel grant, so it "
        "has no access to any channel on this server. Joining a channel does not grant "
        "access. An operator must grant it a role or a channel override first — see "
        "GET /_matrix/client/v3/bsfchat/bots/{userId}/access.",
        refusal::kBotNotScoped);
}

// The advisory a SUCCESS response carries when the caller is an unscoped bot,
// or nullopt when it is not. Empty for every human and for every bot that has
// been granted something, so an ordinary response is byte-identical to what it
// always was.
//
// The join is the one success worth annotating: it is the step the operator
// reads as "the bot is in", and on this server it is not. Deliberately a
// sentence rather than a flag — see bot::kWarningKey.
inline std::optional<std::string> unscoped_bot_warning(SqliteStore& store,
                                                       const std::string& user_id) {
    if (!is_unscoped_bot(store, user_id)) return std::nullopt;
    return std::string(
        "Joined, but this bot holds no roles and no channel grant, so it cannot see or "
        "post in this channel — or any other. Membership is not access on this server. "
        "An operator must grant it a role or a channel override.");
}

} // namespace bsfchat
