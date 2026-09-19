#pragma once

#include "core/RateLimiter.h"

#include <string>

namespace bsfchat {

struct SendLimitsConfig;

// Per-IDENTITY limits on the endpoints that write to a room.
//
// The auth limiter (AuthHandler) covers /login, /register, /refresh and
// /account/password, and keys on the client ADDRESS because those endpoints
// have no authenticated identity yet. Everything past authentication had no
// limit at all: a looping client or a bug in a bot could push events into a
// channel as fast as the socket allowed, and nothing server-side stopped it.
// Media upload had the same shape with a much larger unit of work attached.
//
// Keyed on the account, not the connection and not the address, for two
// reasons. Opening ten connections must not buy ten budgets, which is what a
// per-connection limit would hand out for free. And an address key would put
// everyone behind one NAT or one corporate proxy in a single bucket, so the
// first bot to misbehave would throttle its colleagues — the auth limiter can
// live with that because a shared login attempt budget is itself a defence,
// but a shared MESSAGE budget would just be an outage.
//
// Buckets are separate counters, so a client that has exhausted its edits can
// still delete, and neither starves the other.
//
// Layering a tighter per-bot limit on top of this needs no change to any call
// site: the identity string is whatever the caller hands over, so a bot's
// stable identity can be passed here instead of (or as well as) the user id,
// and a bot-specific bucket is one more enum entry and one more configured
// size. That is the shape the bot-accounts work on `feat/bots` will want.
class SendLimiter {
public:
    enum class Bucket {
        kSend,        // PUT /rooms/{id}/send/{type}/{txn}
        kRedact,      // PUT /rooms/{id}/redact/{event}/{txn}
        kMediaUpload, // POST /_matrix/media/v3/upload
        // PUT /profile/{me}/displayname, /avatar_url, /nickname.
        //
        // ONE bucket for all three on purpose. They are not three costs, they
        // are three doors onto one: each calls broadcastMemberUpdate, which
        // re-emits an m.room.member event in every channel the account is
        // joined to and then wakes every parked /sync on the server. Separate
        // buckets would just triple the ceiling on the same amplifier.
        kProfile,
    };

    SendLimiter(const SendLimitsConfig& config, LimiterClock clock = limiter_steady_now_ms);

    // Records an attempt against `identity`'s budget for `bucket`. Returns 0
    // when it is within the limit, otherwise the milliseconds to wait. An empty
    // identity, or a disabled limiter, always returns 0 — the caller has
    // already authenticated, so an empty identity here is a programming error
    // and failing OPEN is the right direction for one: dropping legitimate
    // messages is worse than not limiting them.
    int64_t acquire(Bucket bucket, const std::string& identity);

    // The message a 429 from `bucket` carries. Phrased for the human who will
    // see it in a client, not for the operator.
    static const char* message_for(Bucket bucket);

private:
    bool enabled_;
    RateLimiter send_;
    RateLimiter redact_;
    RateLimiter media_upload_;
    RateLimiter profile_;
};

} // namespace bsfchat
