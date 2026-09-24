#include "api/EventHandler.h"
#include "api/InputLimits.h"
#include "api/ChannelAccessRefusal.h"
#include "auth/MediaAccess.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/JsonIo.h"
#include "http/RateLimitResponse.h"
#include "http/Router.h"
#include "push/PushService.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <regex>
#include <string>
#include <vector>

namespace bsfchat {

using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Very permissive URL detector used for the EMBED_LINKS gate. Matches any
// http(s) URL token; we intentionally don't try to parse Markdown or HTML
// — a single URL anywhere in the body triggers the check.
bool body_contains_url(const std::string& body) {
    static const std::regex re(R"(https?://[^\s<>"']+)", std::regex::icase);
    return std::regex_search(body, re);
}

bool body_mentions_everyone(const std::string& body) {
    return body.find("@everyone") != std::string::npos || body.find("@here") != std::string::npos;
}

// Every field of an m.room.message whose text a client will put in front of a
// human, gathered once.
//
// EMBED_LINKS and MENTION_EVERYONE used to be tested against `body` alone, so
// the permission was decorative: `formatted_body` is the HTML a client actually
// renders, and
//
//     {"body": "see attached",
//      "format": "org.matrix.custom.html",
//      "formatted_body": "<a href=\"https://phish.example/login\">host login</a>"}
//
// has no URL in `body`, sails past the gate, and renders as a live link with a
// preview card. `m.new_content` is the same hole one level down: an edit's
// replacement text was never examined at all, so a permitted message could be
// rewritten into a forbidden one afterwards.
//
// Collected rather than checked inline so a text field added later is caught by
// changing one list, which is the part that kept going wrong.
//
// Each entry carries where it came from and whether it is the HTML variant,
// because the SIZE ceiling is per-field and the two variants have different
// ceilings (see the size check in handle_send_event). That is deliberately a
// third consumer of THIS list rather than a second collector beside it: a
// separate "fields to measure" list would drift from the "fields to inspect"
// list on the first message field anybody adds, and the whole reason this
// function exists is that the drift had already happened once.
struct RenderableField {
    std::string_view name; // for the error message: "body", "m.new_content.body", …
    bool formatted;        // the HTML variant, which gets the larger ceiling
    std::string text;
};

std::vector<RenderableField> renderable_text(const json& content) {
    std::vector<RenderableField> out;
    const auto take = [&out](const json& obj, const char* key, std::string_view name,
                             bool formatted) {
        if (!obj.is_object()) return;
        auto it = obj.find(key);
        if (it == obj.end() || !it->is_string()) return;
        auto value = it->get<std::string>();
        if (!value.empty()) out.push_back(RenderableField{name, formatted, std::move(value)});
    };
    take(content, "body", "body", false);
    take(content, "formatted_body", "formatted_body", true);
    if (auto it = content.find("m.new_content"); it != content.end()) {
        take(*it, "body", "m.new_content.body", false);
        take(*it, "formatted_body", "m.new_content.formatted_body", true);
    }
    return out;
}

bool any_text(const std::vector<RenderableField>& fields, bool (*pred)(const std::string&)) {
    return std::any_of(fields.begin(), fields.end(),
                       [pred](const RenderableField& f) { return pred(f.text); });
}

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// What may be PUT to /rooms/{id}/send/{eventType}, and what it takes.
//
// This used to be decided by one `if (evt_type == "m.room.message")`, with
// SEND_MESSAGES, ATTACH_FILES and EMBED_LINKS all nested inside it. Everything
// else in the universe passed on VIEW_CHANNEL alone. That was not a gap in
// coverage of a few event types — it meant a member with SEND_MESSAGES
// explicitly DENIED could still write an event of any type at all, with
// arbitrary content, into the room timeline, where it is stored and delivered
// to every member through /sync. Reactions were the visible case (a muted user
// could still react); an undefined type nobody has ever heard of was the
// general one.
//
// A table, and an unrecognised type is REFUSED. Allowing by default is what
// produced the hole: the safe direction is that adding a new sendable event
// type is a deliberate edit here, not something that works by accident.
//
// State events are not in this table because they do not belong on this
// endpoint at all — PUT /rooms/{id}/state/... is where they go, with its own
// per-type authorisation in RoomHandler.
struct SendGate {
    bool allowed = false;
    // Required IN ADDITION to VIEW_CHANNEL, which every send already checks.
    permission::Flags required = 0;
};

SendGate send_gate_for(std::string_view evt_type) {
    if (evt_type == event_type::kRoomMessage) {
        return {true, permission::kSendMessages};
    }
    // Its own permission, not SEND_MESSAGES. "Everyone may react, only a few
    // may post" is an ordinary read-mostly channel, and folding reactions into
    // SEND_MESSAGES would take that arrangement away in the course of fixing a
    // different problem. ADD_REACTIONS is in kEveryoneDefault and is backfilled
    // onto existing roles, so nobody loses the ability to react on upgrade —
    // what changes is that denying it now works at all.
    if (evt_type == event_type::kReaction) {
        return {true, permission::kAddReactions};
    }
    // Call signalling. VIEW_CHANNEL only, which is the same gate
    // VoiceHandler::handle_voice_join applies — these are the events an
    // in-call client exchanges, and a participant who may be in the channel may
    // signal in it. They are addressed events (see the signal_to handling in
    // SqliteStore::insert_event), not room-wide chatter.
    //
    // bsfchat.call.negotiate is in this list on purpose, and its absence would
    // be a field break rather than a tightening: VoiceEngine.cpp sends it
    // mid-call to add RTP video m-lines to an established call, so refusing it
    // would leave video renegotiation failing on a call that had already
    // connected. m.call.member is a state event the server writes itself
    // (VoiceHandler), never one a client PUTs here, so it is listed for
    // completeness rather than because anything sends it.
    if (evt_type == event_type::kCallInvite || evt_type == event_type::kCallAnswer ||
        evt_type == event_type::kCallCandidates || evt_type == event_type::kCallHangup ||
        evt_type == event_type::kCallNegotiate || evt_type == event_type::kCallMember) {
        return {true, 0};
    }
    return {};
}

// ── @mentions (MSC3952 `m.mentions`) ──────────────────────────────────────
//
// The shape on the wire is
//     "m.mentions": { "user_ids": ["@alice:host", ...], "room": true }
// and it is the ONLY source of mentions. Deliberately not scraped out of the
// body: the body is display text, so a body scrape would have to guess how a
// display name maps back to a user id, and would fire on any literal "@foo"
// somebody typed inside a code block.
//
// Non-forgeability rests on three things, all enforced below:
//   1. The recorded mention is always "the AUTHENTICATED sender mentioned X".
//      Nothing in the request body names the mentioner, so a client cannot make
//      a badge claim that some third party mentioned somebody.
//   2. A target is only recorded if it is a joined member of the room WITH
//      VIEW_CHANNEL, so a mention cannot be used to poke somebody who has no
//      business being reachable in that channel, nor to probe membership.
//   3. `room` is gated on MENTION_EVERYONE, so a room-wide ping is a permission,
//      not a client-side choice.
//
// ── Role mentions (`m.mentions["bsfchat.role_ids"]`) ──────────────────────
//
// Same three rules, plus a fourth gate of their own. THE PERMISSION RULE IS
// DISCORD'S, deliberately:
//
//     a role may be mentioned if the role is `mentionable`,
//     OR the sender holds MENTION_EVERYONE.
//
// Three alternatives were on the table and this one is the only one that leaves
// `mentionable` meaning what the switch in the role editor says it means.
//
//   * Reusing MENTION_EVERYONE as the whole gate would make `mentionable` dead
//     UI a second time — a role would be pingable by exactly the people who can
//     already ping the entire server, so the flag would change nothing. It also
//     gets the blast radius backwards: "@Raiders" is a much smaller interruption
//     than "@everyone", and requiring the bigger permission for the smaller
//     action means servers hand out the bigger permission.
//
//   * A new MENTION_ROLES flag would need a bit, and a bit allocated here
//     collides with the role-CRUD work in flight. More to the point it would be
//     a second switch controlling the same thing as `mentionable`, and an
//     operator would have to reason about both to answer "can people ping the
//     mods?". Discord has no such flag.
//
//   * `mentionable` alone, with no override, is nearly right and is what the
//     flag reads like on its face. It is rejected because it leaves no way to
//     reach a locked role in the case the lock exists for: @Admins is set
//     non-mentionable so that members cannot ping it, not so that a moderator
//     cannot. Without the override an admin who needs to raise the other admins
//     has to flip the switch, post, and flip it back — during which window
//     everyone can ping it. MENTION_EVERYONE is the right key for that door:
//     anyone holding it can already ping strictly more people with @room.
//
// The flag is the gate for ordinary members; the permission is the override.
// Neither is a body scrape: as with @room's MENTION_EVERYONE check, what a
// message SAYS is never rewritten or rejected over a role name in it. A role
// that may not be mentioned simply records nothing and notifies nobody, and the
// text stays exactly as typed (the client then renders it as plain text — see
// MentionRenderer — so a blocked ping reads as words rather than vanishing).
//
// Fan-out: a role mention is stored as ONE sentinel row, never one row per
// holder, exactly like @room. See SqliteStore::mention_match_keys().
struct MentionSet {
    std::vector<std::string> user_ids; // validated, deduped, sender removed
    std::vector<std::string> role_ids; // validated against the roles list + gate
    bool room_wide = false;

    [[nodiscard]] bool empty() const {
        return user_ids.empty() && role_ids.empty() && !room_wide;
    }

    // Flattened for storage: room-wide and each role become sentinel rows.
    [[nodiscard]] std::vector<std::string> to_rows() const {
        auto rows = user_ids;
        if (room_wide) rows.emplace_back(kRoomMentionSentinel);
        for (const auto& role_id : role_ids) {
            rows.push_back(role_mention_sentinel(role_id));
        }
        return rows;
    }
};

// Result of validating the `m.mentions` block. `error` set => reject the send.
struct MentionParse {
    MentionSet mentions;
    std::optional<std::pair<int, MatrixError>> error;
};

MentionParse parse_mentions(const json& content, const std::string& sender,
                            const std::string& room_id, permission::Flags user_perms,
                            SqliteStore& store, PermissionsEngine& perms) {
    MentionParse out;

    auto it = content.find("m.mentions");
    if (it == content.end() || !it->is_object()) return out;
    const auto& m = *it;

    // Room-wide ping. Gated even when the send is an edit (which records no
    // mentions at all), so the permission is never bypassable and a client
    // without it is told rather than silently ignored.
    auto room_it = m.find("room");
    if (room_it != m.end() && !room_it->is_null()) {
        if (!room_it->is_boolean()) {
            out.error = {400, MatrixError::invalid_param("m.mentions.room must be a boolean")};
            return out;
        }
        if (room_it->get<bool>()) {
            if (!permission::has(user_perms, permission::kMentionEveryone)) {
                out.error = {403, MatrixError::forbidden(
                    "You don't have permission to mention everyone")};
                return out;
            }
            out.mentions.room_wide = true;
        }
    }

    // Role mentions. Dropped rather than rejected when the gate says no — see
    // the block comment above the MentionSet for the rule and why. A 403 was
    // considered and rejected for the same reason a stale user mention does not
    // fail the send: the sender's idea of which roles are mentionable comes from
    // a state event that can change between their last sync and this send, and
    // losing the message over it is worse than not lighting the ping. It is also
    // what Discord does — the message posts, nobody is notified.
    //
    // Unlike `room`, dropping opens no bypass: there is no second, scrape-based
    // path to a role mention that this one could be played off against.
    if (auto roles_it = m.find(std::string(mention::kRoleIdsKey));
        roles_it != m.end() && !roles_it->is_null()) {
        if (!roles_it->is_array()) {
            out.error = {400, MatrixError::invalid_param(
                std::string(mention::kRoleIdsKey) + " must be an array")};
            return out;
        }
        if (roles_it->size() > limits::kMaxRoleMentionsPerEvent) {
            out.error = {400, MatrixError::invalid_param(
                std::string(mention::kRoleIdsKey) + " exceeds " +
                std::to_string(limits::kMaxRoleMentionsPerEvent) + " entries")};
            return out;
        }
        // The override half of the rule, evaluated once.
        const bool may_mention_any =
            permission::has(user_perms, permission::kMentionEveryone);
        const auto& defined = perms.roles();

        std::vector<std::string> accepted;
        for (const auto& entry : *roles_it) {
            if (!entry.is_string()) continue;
            auto role_id = entry.get<std::string>();
            if (role_id.empty()) continue;
            // @everyone is not a role you mention — it is every member of the
            // server, which is what `room: true` is for and what MENTION_EVERYONE
            // gates. Accepting it here would be a route around that gate for
            // anyone who could get `mentionable` set on it, which the role-CRUD
            // surface makes an ordinary edit rather than an impossibility.
            if (role_id == permission::role_id::kEveryone) continue;
            // A colon would make the stored sentinel "@role/<id>" parse as a
            // Matrix user id and stop being unspellable. Role ids are opaque
            // and ours; one containing a colon is refused rather than escaped.
            if (role_id.find(':') != std::string::npos) continue;
            if (std::find(accepted.begin(), accepted.end(), role_id) != accepted.end()) continue;

            auto def = std::find_if(defined.begin(), defined.end(),
                                    [&](const ServerRole& r) { return r.id == role_id; });
            if (def == defined.end()) continue;           // no such role
            if (!def->mentionable && !may_mention_any) continue; // the gate
            accepted.push_back(std::move(role_id));
        }
        out.mentions.role_ids = std::move(accepted);
    }

    auto users_it = m.find("user_ids");
    if (users_it == m.end() || users_it->is_null()) return out;
    if (!users_it->is_array()) {
        out.error = {400, MatrixError::invalid_param("m.mentions.user_ids must be an array")};
        return out;
    }
    if (users_it->size() > limits::kMaxMentionsPerEvent) {
        out.error = {400, MatrixError::invalid_param(
            "m.mentions.user_ids exceeds " + std::to_string(limits::kMaxMentionsPerEvent) +
            " entries")};
        return out;
    }

    // Entries that fail the membership/visibility checks are DROPPED rather than
    // rejected: a client working from a slightly stale member list mentioning
    // somebody who just left is ordinary, and failing the whole send over it
    // would lose the message. The content itself is left exactly as the client
    // sent it — the server decides who gets badged, not what the message says.
    std::vector<std::string> seen;
    for (const auto& entry : *users_it) {
        if (!entry.is_string()) continue;
        auto target = entry.get<std::string>();
        if (target.empty()) continue;
        // Blocks a client from claiming a room-wide mention by "mentioning" a
        // user literally named "@room" — belt and braces on top of the sentinel
        // being unspellable as a real Matrix id.
        if (target == kRoomMentionSentinel) continue;
        // Same belt-and-braces for role sentinels: a client must not be able to
        // ping a role — least of all a non-mentionable one — by spelling its
        // storage key into user_ids.
        //
        // REDUNDANT TODAY, and knowingly so: UserId::is_valid() on the next line
        // already rejects "@role/..." because it carries no colon, so deleting
        // this line changes no behaviour and no test (mutate.py says as much,
        // and says the same about the @room guard above). It is here because the
        // thing making it redundant is a property of the SENTINEL SPELLING, and
        // this loop should not silently depend on that: if the prefix ever gains
        // a colon, or UserId ever accepts a colonless id, the hole opens here
        // and nothing else in this function would notice.
        if (target.rfind(kRoleMentionPrefix, 0) == 0) continue;
        if (!UserId::is_valid(target)) continue;
        // Self-mentions must not badge your own room.
        if (target == sender) continue;
        if (std::find(seen.begin(), seen.end(), target) != seen.end()) continue;
        if (!store.is_room_member(room_id, target)) continue;
        if (!perms.can(target, room_id, permission::kViewChannel)) continue;
        seen.push_back(std::move(target));
    }
    out.mentions.user_ids = std::move(seen);
    return out;
}

} // namespace

EventHandler::EventHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config,
                           PushService* push, LimiterClock clock)
    : store_(store), sync_engine_(sync_engine), config_(config), push_(push)
    , limits_(config.send_limits, std::move(clock)) {}

void EventHandler::handle_send_event(const httplib::Request& req, httplib::Response& res) {
    const auto auth_header = req.get_header_value("Authorization");
    auto user_id = authenticate(store_, auth_header);
    if (!user_id) {
        return send_error(res, 401, auth_error(auth_header));
    }
    // The DEVICE, not just the identity: it is half the transaction-id key
    // below. authenticate() above is what validates the token and slides its
    // expiry; this is a second probe of the same indexed row for the device
    // the now-validated token belongs to.
    std::string device_id;
    if (auto token = extract_access_token(auth_header)) {
        if (auto session = store_.get_session_by_token(*token)) device_id = session->device_id;
    }

    // Match: PUT /rooms/{roomId}/send/{eventType}/{txnId}
    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    auto& evt_type = match.params["eventType"];
    auto& txn_id = match.params["txnId"];

    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    // Transaction-id idempotency. txnId was parsed out of the path and then
    // never used, so any client retry — a flaky connection, a resend after a
    // timeout — silently duplicated the message.
    const SqliteStore::TransactionKey txn_key{*user_id, device_id, room_id, txn_id};
    if (!txn_id.empty()) {
        if (auto existing = store_.get_transaction_event(txn_key)) {
            res.set_content(json{{"event_id", *existing}}.dump(), "application/json");
            return;
        }
    }

    // Per-account send ceiling, checked AFTER the idempotency short-circuit
    // above and BEFORE the permission computation below.
    //
    // After, because a retry of a request the server has already accepted is
    // the behaviour we asked clients for; charging it to the budget would
    // punish a client on a bad connection for doing exactly the right thing,
    // and a flood is made of DISTINCT transactions by definition.
    //
    // Before, because everything past this point — resolving every role and
    // override for the caller, then writing the event, its mentions and its
    // push rows — is the work worth refusing to do.
    if (const auto wait = limits_.acquire(SendLimiter::Bucket::kSend, *user_id)) {
        return send_rate_limited(res, wait,
                                 SendLimiter::message_for(SendLimiter::Bucket::kSend));
    }

    PermissionsEngine perms(store_, config_);
    auto user_perms = perms.compute(*user_id, room_id);

    // VIEW_CHANNEL is a prerequisite for anything happening in the room.
    if (!permission::has(user_perms, permission::kViewChannel)) {
        return send_error(res, 403, no_channel_access(store_, *user_id));
    }

    // Then the per-type gate. Refusing an unrecognised type is the point: the
    // previous shape allowed every type except m.room.message through on
    // VIEW_CHANNEL alone, so a muted member could still write arbitrary events
    // into the timeline. See send_gate_for().
    const auto gate = send_gate_for(evt_type);
    if (!gate.allowed) {
        return send_error(res, 403, MatrixError::forbidden(
            "Events of type '" + evt_type + "' cannot be sent to a room"));
    }
    if (gate.required != 0 && !permission::has(user_perms, gate.required)) {
        return send_error(res, 403, MatrixError::forbidden(
            "You don't have permission to send this here"));
    }

    // Outer size ceiling, on the REQUEST and before the parse.
    //
    // Before the parse for two reasons: a hostile payload never reaches the
    // parser, and this is the only check that can cover event types whose
    // content nothing here reads. The per-field ceilings below cover
    // m.room.message, which is the type the gap was found on, but the send
    // allowlist also admits m.reaction and the call-signalling types, and
    // `content` on any of them is stored, delivered through /sync and
    // paginated exactly like a message. A limit on the fields we happen to
    // parse would leave the amplifier available under a key nobody parses —
    // a well-formed 8-byte reaction with 4 MB bolted onto `com.evil.payload`.
    //
    // Measured on the raw body rather than on content.dump(): it is free, it
    // runs before the allocation it is protecting against, and it is the
    // conservative direction (the raw form is never smaller than the reparse
    // for any payload a client actually sends).
    //
    // Note this is NOT the same bound as HttpServer's set_payload_max_length,
    // which is sized for media uploads (tens of megabytes) and applies to every
    // route. This is the send route saying that a timeline event is not a file.
    if (req.body.size() > config_.send_limits.max_event_bytes) {
        res.status = 413;
        return res.set_content(
            MatrixError::too_large(
                "Event content is " + std::to_string(req.body.size()) + " bytes; the limit is " +
                std::to_string(config_.send_limits.max_event_bytes))
                .to_json()
                .dump(),
            "application/json");
    }

    json content;
    try {
        content = parse_request_json(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }

    // Set when this send is an m.replace edit, to the id of the event the
    // replacement should be reconciled onto once it has been stored.
    std::optional<std::string> edit_target;

    // Validated mention set, recorded after the event is stored. Stays empty for
    // an edit — see the comment at the record_mentions() call below.
    MentionSet mentions;

    // Content-dependent gates, on top of the per-type one above. These cannot
    // live in the table because they depend on what is IN the event.
    //
    // (The comment that used to sit here claimed non-message types "use
    // separate permission semantics not worth spelling out". For reactions
    // that was simply untrue — there were none — and the sentence is what kept
    // anyone from noticing that this `if` was the only authorisation in the
    // handler.)
    if (evt_type == std::string(event_type::kReaction)) {
        // A reaction names an event it annotates, and that was taken entirely
        // on trust: any string was accepted as a target, including the id of an
        // event in a room the sender cannot see. The reaction is then delivered
        // to THIS room referring to an event that is not in it — at best a
        // dangling reference, at worst a way to confirm an event id exists
        // somewhere else.
        //
        // The accepted shape is unchanged: this validates the fields the client
        // already sends, and rejects nothing it has ever sent.
        const auto* rel = content.contains("m.relates_to") && content["m.relates_to"].is_object()
                              ? &content["m.relates_to"] : nullptr;
        if (!rel || rel->value("rel_type", "") != std::string(event_type::kRelAnnotation)) {
            return send_error(res, 400, MatrixError::bad_json(
                "A reaction must carry m.relates_to with rel_type m.annotation"));
        }
        const std::string target_id = rel->value("event_id", "");
        if (target_id.empty()) {
            return send_error(res, 400, MatrixError::bad_json("Reaction missing target event_id"));
        }
        // The key is the emoji, and it is what a client groups and counts by.
        // An empty one aggregates into a bubble with no label; an unbounded one
        // is an arbitrary attacker-chosen string stored per reaction and sent to
        // every member of the room on every sync. The ceiling is generous —
        // a long ZWJ emoji sequence with skin-tone modifiers runs to tens of
        // bytes — and this is a storage bound, not an emoji validator: deciding
        // what counts as an emoji is a client concern and a moving target.
        const std::string key = rel->value("key", "");
        if (key.empty()) {
            return send_error(res, 400, MatrixError::bad_json("Reaction missing key"));
        }
        if (key.size() > limits::kMaxReactionKeyLength) {
            return send_error(res, 400, MatrixError::invalid_param(
                "Reaction key must be at most " +
                std::to_string(limits::kMaxReactionKeyLength) + " bytes"));
        }
        auto target = store_.get_event_by_id(target_id);
        if (!target) {
            return send_error(res, 404, MatrixError::not_found("Reaction target does not exist"));
        }
        if (target->room_id != room_id) {
            // Deliberately the same answer as "does not exist": telling the
            // caller that the id is real but lives elsewhere is the confirmation
            // the check exists to withhold.
            return send_error(res, 404, MatrixError::not_found("Reaction target does not exist"));
        }
        // Consistent with edits, which already refuse a redacted target: a
        // deleted message must not acquire new reactions.
        if (store_.is_event_redacted(target_id)) {
            return send_error(res, 404, MatrixError::not_found(
                "Reaction target has been deleted"));
        }

        // Reacting twice with the same emoji is idempotent, not an error.
        //
        // 200 with the existing event id, exactly like the transaction-id
        // replay above, because that is what the situation actually is: a
        // second request for a state the server is already in. A 403 or a 409
        // would put an error in front of a user who double-tapped, and the
        // client has nowhere sensible to put it. Storing a second event instead
        // — which is what happened before — rendered the same person twice in
        // the same reaction bubble.
        //
        // Un-reacting is a redaction of the reaction event, and a redacted
        // reaction is not a duplicate (see find_reaction_event), so react →
        // unreact → react still works.
        if (auto existing = store_.find_reaction_event(room_id, *user_id, target_id, key)) {
            res.set_content(json{{"event_id", *existing}}.dump(), "application/json");
            return;
        }
    }

    if (evt_type == std::string(event_type::kRoomMessage)) {
        const std::string msgtype = content.value("msgtype", "m.text");
        const bool has_attachment = msgtype != std::string(msg_type::kText) && msgtype != std::string(msg_type::kEmote) && msgtype != std::string(msg_type::kNotice);

        if (has_attachment && !permission::has(user_perms, permission::kAttachFiles)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to attach files here"));
        }

        // Both content gates run over EVERY text-bearing field, not just `body`
        // — see renderable_text() for what that list is and what walked past the
        // old one-field check.
        const auto text_fields = renderable_text(content);

        // Size, before the two content gates below — a regex scan over a
        // hostile body is itself work worth refusing, and a message that is
        // going to be rejected for its size should not be told about a
        // permission it does not have instead.
        //
        // Per field, not on the sum. `body` is what the user typed and
        // `formatted_body` is the same message after markup, so a sum would
        // make the plain-text budget depend on how much HTML the sending
        // client chose to generate: the identical paste would be accepted from
        // a client that sends no formatting and refused from one that does,
        // and the composer — which can only count what the user typed — could
        // not tell them in advance which it would be. Separate ceilings keep
        // "how long a message may be" answerable by the thing typing it.
        //
        // The HTML ceiling is derived, not configured, precisely so that the
        // relation between them cannot be misconfigured; see Constants.h.
        //
        // This covers edits without a word about edits, because
        // m.new_content.body is on the list renderable_text() already returns.
        // An oversize edit is therefore refused exactly like an oversize send,
        // and the message everyone already has stays as it was — which is the
        // right outcome: an edit that is too big to accept must not half-apply.
        const size_t body_cap = config_.send_limits.max_message_bytes;
        const size_t html_cap = body_cap * limits::kFormattedBodyMultiplier;
        for (const auto& field : text_fields) {
            const size_t cap = field.formatted ? html_cap : body_cap;
            if (field.text.size() <= cap) continue;
            res.status = 413;
            return res.set_content(
                MatrixError::too_large(std::string(field.name) + " is " +
                                       std::to_string(field.text.size()) +
                                       " bytes; the limit is " + std::to_string(cap))
                    .to_json()
                    .dump(),
                "application/json");
        }

        if (any_text(text_fields, body_contains_url) &&
            !permission::has(user_perms, permission::kEmbedLinks)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to post links here"));
        }
        if (any_text(text_fields, body_mentions_everyone) &&
            !permission::has(user_perms, permission::kMentionEveryone)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to mention everyone"));
        }

        // Structured mentions. Validated before the edit handling below so the
        // MENTION_EVERYONE gate applies to every message send, edit included.
        auto parsed = parse_mentions(content, *user_id, room_id, user_perms, store_, perms);
        if (parsed.error) {
            return send_error(res, parsed.error->first, parsed.error->second);
        }
        mentions = std::move(parsed.mentions);

        // Edits: m.relates_to { rel_type: "m.replace", event_id: "$..." }.
        // Only the original sender can edit their own message. MANAGE_MESSAGES
        // is for deletion (redaction), not rewriting — matches Discord: mods
        // can delete but not edit someone else's text.
        if (content.contains("m.relates_to") && content["m.relates_to"].is_object()) {
            const auto& rel = content["m.relates_to"];
            if (rel.value("rel_type", "") == "m.replace") {
                std::string target_id = rel.value("event_id", "");
                if (target_id.empty()) {
                    return send_error(res, 400, MatrixError::bad_json(
                        "Edit missing target event_id"));
                }
                // ONE answer for "there is no such message here", covering all
                // three ways that can be true: no such event anywhere, an event
                // that exists in another room, and an event that has been
                // redacted. Distinguishing them made this endpoint a global
                // event-existence oracle — `get_event_by_id` is a bare
                // primary-key lookup with no room scoping, so a member could
                // replay ids cached from a channel they have since been removed
                // from and read "still exists" / "deleted" off the status code,
                // from a DM of their own. Event ids are CSPRNG-random, so this
                // is not blind enumeration; it is a live feed of moderation
                // activity to someone who kept their client's cache.
                //
                // This is the answer handle_redact already gives (one shared 404
                // for missing-or-elsewhere) and the one the reaction path above
                // gives, with the same comment. The edit path was the last copy
                // of the old shape.
                //
                // The redacted case is checked HERE rather than after the sender
                // and type tests below, because reaching those means answering
                // questions about an event, and a redacted event is one the
                // caller must be told nothing about beyond "not found".
                const auto not_here = [&] {
                    return send_error(res, 404, MatrixError::not_found(
                        "Target message not found"));
                };

                auto target = store_.get_event_by_id(target_id);
                if (!target || target->room_id != room_id) return not_here();
                if (store_.is_event_redacted(target_id)) return not_here();

                // An edit aimed at a previous edit resolves to the original.
                // Matrix says clients must always target the original, but a
                // client that chains them would otherwise pin the replacement
                // pointer to an event nothing resolves through, making the
                // second edit invisible. Bounded so a malformed cycle can't
                // spin here.
                //
                // Every hop is confined to THIS room, and the room check above
                // now runs before the loop rather than after it. Previously the
                // loop followed m.relates_to pointers through the same unscoped
                // lookup, so it walked into another room's event to find a
                // parent and only then discovered it had left — reading across a
                // boundary it should not have known about, and reporting the
                // crossing when it failed. A pointer that leaves the room is
                // treated as the end of the chain: the event we already hold is
                // in this room and is the caller's to edit.
                for (int hops = 0; hops < 10; ++hops) {
                    if (!target->content.data.is_object()) break;
                    auto it = target->content.data.find("m.relates_to");
                    if (it == target->content.data.end() || !it->is_object()) break;
                    if (it->value("rel_type", "") != "m.replace") break;
                    auto parent_id = it->value("event_id", "");
                    if (parent_id.empty() || parent_id == target->event_id) break;
                    auto parent = store_.get_event_by_id(parent_id);
                    if (!parent || parent->room_id != room_id) break;
                    target = std::move(parent);
                    target_id = target->event_id;
                }

                // Re-checked after resolution: a chain can only end on an event
                // in this room now, but the redaction state of the ORIGINAL is a
                // separate fact from that of the replacement we started at.
                if (store_.is_event_redacted(target_id)) return not_here();

                if (target->sender != *user_id) {
                    return send_error(res, 403, MatrixError::forbidden(
                        "You can only edit your own messages"));
                }
                if (target->type != std::string(event_type::kRoomMessage)) {
                    return send_error(res, 400, MatrixError::bad_json(
                        "Can only edit message events"));
                }
                // (The "target message has been deleted" 404 that used to sit
                // here has moved up, above the sender and type tests. A deleted
                // message must still not be editable back into existence; it
                // must also not be distinguishable from one that was never
                // there, which is why it now shares the not_here() answer.)
                edit_target = target_id;
            }
        }

        // Slowmode: users with MANAGE_MESSAGES bypass it (matches Discord).
        if (!permission::has(user_perms, permission::kManageMessages)) {
            int slow = store_.get_channel_slowmode(room_id);
            if (slow > 0) {
                int64_t last = store_.get_last_message_ts(*user_id, room_id);
                int64_t now = now_ms();
                int64_t window_ms = static_cast<int64_t>(slow) * 1000;
                if (last > 0 && (now - last) < window_ms) {
                    int retry = static_cast<int>(window_ms - (now - last));
                    return send_error(res, 429,
                        MatrixError::limit_exceeded("Slowmode is enabled in this channel", retry));
                }
            }
        }
    }

    auto event_id = generate_event_id(config_.server_name);
    // insert_event_vetted, not insert_event: this is the path audit finding F5
    // was proven against. `content` is whatever the caller sent, at any depth,
    // and the ATTACH_FILES gate above does not stand in the way of a media URI
    // because it keys off `msgtype` — an `m.text` message with an `mxc://` in
    // an unrecognised key passes it. Vetting binds only the objects this sender
    // could already read, so quoting, replying and forwarding still work and
    // naming a revoked or redacted id grants nothing.
    int64_t stream_pos = insert_event_vetted(store_, config_, event_id, room_id, *user_id,
                                             evt_type, std::nullopt, content.dump(), now_ms());

    // Record mentions — but NEVER for an edit.
    //
    // This is the anti-forgery rule that matters most in practice. A replacement
    // is an ordinary m.room.message in the timeline, so extracting its mentions
    // like any other message would give it mention rows at a BRAND NEW stream
    // position, i.e. past everyone's read marker: editing "hi" into "hi @alice"
    // would fire a fresh mention badge for Alice on a message she had already
    // read. Worse, it would let somebody edit an old, long-since-read message to
    // ping people out of nowhere with no visible new message to explain it.
    //
    // So the mention set is fixed at the moment of the original send and an edit
    // can neither add to it nor move it.
    //
    // Removal-on-edit is intentionally NOT implemented either, and the reason is
    // NOT the one this comment used to give. It used to say the shipped client
    // stripped `m.mentions` from its edit payload; that is no longer true —
    // MatrixClient::editMessage now sends it deliberately in BOTH places, inside
    // `m.new_content` (so the folded-in content keeps it) and at the top level
    // (because that is the copy this handler validates `room: true` against).
    //
    // The reason that still stands is that `m.mentions` is OPTIONAL in the
    // protocol and always will be. Our client sending it does not make its
    // absence meaningful: a third-party or older client that edits a message
    // without the field would have "absent" read as "deliberately cleared", and
    // every mention badge on that message would vanish because somebody fixed a
    // typo. There is no way to distinguish the two on the wire, so narrowing an
    // existing mention set would require a positive signal the protocol does not
    // have — an explicit empty `user_ids`, say, which our own client also does not
    // emit (applyMentions omits the key entirely when there are no mentions).
    //
    // Adding is unsafe (forgery, see above) and removing is ambiguous, so the set
    // is immutable. The skip below is load-bearing for the forgery half and must
    // not be relaxed.
    if (!edit_target && !mentions.empty()) {
        store_.record_mentions(event_id, room_id, *user_id, stream_pos, mentions.to_rows());
    }

    // Reconcile the edit server-side. The replacement was previously stored as
    // a sibling event and nothing more, so /messages and /sync kept returning
    // the pre-edit text and the edit was only "real" for clients that chose to
    // apply it. The original keeps its identity; this just records which
    // replacement wins. Idempotent with the txnId short-circuit above: a retry
    // returns the first event id and never reaches here.
    if (edit_target && !store_.apply_edit(*edit_target, event_id)) {
        get_logger()->warn("Edit {} could not be applied to {} (redacted or missing)",
                           event_id, *edit_target);
    }

    // Push evaluation. Enqueue-only: this writes push_queue rows and returns, so
    // the response below is never waiting on a push gateway. Skipped for edits
    // for the same reason mentions are — a replacement must not fire a second
    // notification for a message that already generated one.
    if (push_ && !edit_target && evt_type == std::string(event_type::kRoomMessage)) {
        PushService::MessageNotification notification;
        notification.event_id = event_id;
        notification.room_id = room_id;
        notification.sender = *user_id;
        notification.event_type = evt_type;
        notification.mentioned = mentions.user_ids;
        notification.mentioned_role_ids = mentions.role_ids;
        notification.room_wide_mention = mentions.room_wide;
        notification.content = content;
        try {
            push_->evaluate_message(notification, perms);
        } catch (const std::exception& e) {
            // A message must still be delivered if push bookkeeping fails.
            get_logger()->error("Push evaluation failed for {}: {}", event_id, e.what());
        }
    }

    if (!txn_id.empty()) {
        store_.record_transaction(txn_key, event_id);
    }
    sync_engine_.notify_new_event();

    res.set_content(json{{"event_id", event_id}}.dump(), "application/json");
}

void EventHandler::handle_room_messages(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/messages", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, room_id, permission::kViewChannel)) {
        return send_error(res, 403, no_channel_access(store_, *user_id));
    }

    // Parse query params
    std::string dir = "b";
    if (req.has_param("dir")) dir = req.get_param_value("dir");

    int limit = limits::kDefaultMessagesLimit;
    if (req.has_param("limit")) {
        // Unguarded std::stoi threw out of the handler on a malformed param.
        try {
            limit = std::stoi(req.get_param_value("limit"));
        } catch (const std::exception&) {
            limit = limits::kDefaultMessagesLimit;
        }
        limit = std::clamp(limit, 1, limits::kMaxMessagesLimit);
    }

    std::optional<std::string> from;
    if (req.has_param("from")) from = req.get_param_value("from");

    // No `viewer`, deliberately — this is the HISTORY path, and addressed call
    // signalling is not pageable months later (store/CallSignalling.h).
    //
    // But the caller IS passed as the ignoring user, and the two are separate
    // arguments precisely so that one can be absent while the other is present.
    // An ignore that held on /sync and not on back-pagination would be undone
    // by scrolling up: the blocked account's messages would reappear the moment
    // the client asked for history, which is the first thing it does when a
    // channel is opened.
    auto [events, next_pos] = store_.get_room_events_paginated(
        room_id, limit, dir, from, std::nullopt, *user_id);

    MessagesResponse msg_resp;
    msg_resp.chunk = std::move(events);
    if (from) msg_resp.start = *from;
    if (next_pos) {
        // Token format is "s<stream_position>" — same as what /sync emits
        // for `next_batch` and what the /messages handler expects back as
        // the `from` param.
        msg_resp.end = "s" + std::to_string(*next_pos);
    }

    json resp;
    to_json(resp, msg_resp);
    res.set_content(dump_response_json(resp), "application/json");
}

void EventHandler::handle_read_marker(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/read_marker", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    // Membership AND VIEW_CHANNEL. Membership alone is not an access check on
    // this server: every user is force-joined into every channel, private ones
    // included, so "is a member" was letting a denied user write a read position
    // into a channel they cannot read. Finding 4 of
    // docs/membership-vs-visibility.md.
    //
    // kViewChannel asked directly, NOT through can_view_room(): that helper
    // exempts categories because the sidebar has to render a container it
    // cannot open, which is a rule about LISTING. This is a write into a room,
    // so it gets the reading/acting rule — see the comment above can_read_room
    // in RoomHandler.cpp.
    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }
    {
        PermissionsEngine perms(store_, config_);
        if (!perms.can(*user_id, room_id, permission::kViewChannel)) {
            // The same status and the same message as the membership refusal
            // above, deliberately: telling the two apart would say "this room
            // exists and you are in it", which is the oracle the sibling
            // finding is about.
            return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
        }
    }

    json body;
    try {
        body = parse_request_json(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }

    int64_t pos = 0;
    if (body.contains("last_read_pos") && body["last_read_pos"].is_number_integer()) {
        pos = body["last_read_pos"].get<int64_t>();
    } else if (body.contains("m.fully_read") && body["m.fully_read"].is_string()) {
        pos = store_.get_room_max_stream_position(room_id);
    } else {
        pos = store_.get_room_max_stream_position(room_id);
    }

    // Nothing moved: the marker is already at or past `pos`. The client posts
    // one for every batch of messages that arrives in the open room, so this is
    // the ordinary case, and there is nothing to tell anybody about. Answering
    // 200 either way is deliberate — a read marker is idempotent, and the
    // client has no use for the distinction.
    if (!store_.set_read_marker(*user_id, room_id, pos)) {
        res.set_content("{}", "application/json");
        return;
    }

    // notify_ephemeral, NOT notify_new_event.
    //
    // A read marker writes no event row, so the stream head does not move —
    // and notify_new_event's predicate is "has the head passed what I have
    // already examined". Waking every parked poll with a head that has not
    // changed satisfies nobody's predicate, so the call was a pure no-op:
    // the unread and highlight counts this changes did not reach a parked
    // client until some unrelated event happened along, or until its poll
    // timed out 30 seconds later. Reading a channel on one device left the
    // badge lit on the other for exactly that long.
    //
    // The ephemeral counter is the mechanism for "something changed that is
    // not a timeline event" — it is what typing and presence already use.
    //
    // Since schema v30 the write also claims a stream position, so the wake is
    // no longer all that a second device has: the marker travels in that
    // poll's `m.fully_read` room account data, and a device that missed the
    // wake still finds it against its own token on the next poll. The wake is
    // when, not whether — see docs/read-state.md.
    sync_engine_.notify_ephemeral();

    res.set_content("{}", "application/json");
}

void EventHandler::handle_redact(const httplib::Request& req, httplib::Response& res) {
    const auto auth_header = req.get_header_value("Authorization");
    auto user_id = authenticate(store_, auth_header);
    if (!user_id) {
        return send_error(res, 401, auth_error(auth_header));
    }
    // The DEVICE, not just the identity: it is part of the transaction-id key
    // below, because a txn id is scoped to the access token and two clients
    // signed in as the same user each start their counters at 1. authenticate()
    // above is what validated the token; this is a second read of the same
    // indexed row for the device it belongs to.
    std::string device_id;
    if (auto token = extract_access_token(auth_header)) {
        if (auto session = store_.get_session_by_token(*token)) device_id = session->device_id;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    auto& target_event_id = match.params["eventId"];
    auto& txn_id = match.params["txnId"];

    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    // Transaction-id idempotency. This endpoint matched {txnId} out of its path
    // and then ignored it, so a retry after a timeout redacted the target a
    // second time and appended a second m.room.redaction to the timeline. The
    // end state was right and the history was not.
    //
    // The key is the whole request, not just the sender — see
    // SqliteStore::RedactionKey for why the room and the target are in it, and
    // migrate_v19 for why this is a different namespace from /send's.
    //
    // Checked before the rate limiter on purpose: a retry is the same request,
    // and charging a client for the network's failure to deliver the first
    // answer would make a flaky connection look like abuse.
    //
    // The empty-id guard mirrors /send. It cannot fire here — match_route drops
    // empty path segments, so a trailing slash fails the route outright — which
    // is what makes "every redaction is recorded" true rather than hopeful.
    const SqliteStore::RedactionKey txn_key{*user_id, device_id, room_id, target_event_id, txn_id};
    if (!txn_id.empty()) {
        if (auto existing = store_.get_redaction_transaction_event(txn_key)) {
            res.set_content(json{{"event_id", *existing}}.dump(), "application/json");
            return;
        }
    }

    // Its own budget, separate from sending: a client that has exhausted one
    // can still do the other, and a deletion loop is the more destructive of
    // the two.
    //
    // Charged AFTER the idempotency check above, so a retry of a request whose
    // answer was lost costs nothing: it is the same redaction, already
    // recorded. Before harden/redact-homoglyphs there was no such record — this
    // endpoint parsed a txnId out of its path and ignored it — and a retry did
    // cost a slot here.
    if (const auto wait = limits_.acquire(SendLimiter::Bucket::kRedact, *user_id)) {
        return send_rate_limited(res, wait,
                                 SendLimiter::message_for(SendLimiter::Bucket::kRedact));
    }

    PermissionsEngine perms(store_, config_);
    auto user_perms = perms.compute(*user_id, room_id);
    if (!permission::has(user_perms, permission::kViewChannel)) {
        return send_error(res, 403, no_channel_access(store_, *user_id));
    }

    // Self-redact always allowed; redacting others requires MANAGE_MESSAGES.
    auto target = store_.get_event_by_id(target_event_id);
    if (!target || target->room_id != room_id) {
        return send_error(res, 404, MatrixError::not_found("Target event not found in this room"));
    }
    const bool is_self = target->sender == *user_id;
    if (!is_self && !permission::has(user_perms, permission::kManageMessages)) {
        return send_error(res, 403, MatrixError::forbidden("You can only redact your own messages"));
    }

    json body = json::object();
    if (!req.body.empty()) {
        try { body = parse_request_json(req.body); } catch (...) {
            return send_error(res, 400, MatrixError::bad_json());
        }
    }

    json content = json::object();
    content["redacts"] = target_event_id;
    if (body.contains("reason") && body["reason"].is_string()) {
        // Checked here, BEFORE redact_event() below strips the target: an
        // oversize reason must be refused with nothing done, not after the
        // message is already gone. The redaction event is delivered to every
        // member and kept forever, and nothing bounded this but the 51 MiB
        // transport cap (audit S2). See api/InputLimits.h.
        const auto& reason = body["reason"].get_ref<const std::string&>();
        if (auto err = oversize_field("reason", reason, input_limits::kMaxReasonBytes)) {
            return send_error(res, 400, *err);
        }
        content["reason"] = reason;
    }

    // Actually strip the target's content. Previously redaction only appended
    // an m.room.redaction event and left the original untouched, so a
    // "deleted" message was still fully retrievable from
    // /rooms/{id}/messages — enforcement relied entirely on the client
    // choosing to hide it.
    if (!store_.redact_event(target_event_id, *user_id)) {
        return send_error(res, 404, MatrixError::not_found("Target event not found in this room"));
    }

    auto event_id = generate_event_id(config_.server_name);
    // Bare insert_event, so this event binds NOTHING — and here that is the
    // stricter choice, not the lazier one. `reason` is free text, and vetting
    // it would let the redactor re-create the very binding redact_event() just
    // deleted by naming the id in the reason: the uploader redacting their own
    // message passes rule 1 every time. A redaction is the one event whose
    // whole purpose is to REMOVE a media grant, so it must never be able to
    // create one.
    store_.insert_event(event_id, room_id, *user_id,
                        std::string(event_type::kRoomRedaction),
                        std::nullopt, content.dump(), now_ms());
    if (!txn_id.empty()) {
        store_.record_redaction_transaction(txn_key, event_id);
    }
    sync_engine_.notify_new_event();

    res.set_content(json{{"event_id", event_id}}.dump(), "application/json");
}

} // namespace bsfchat
