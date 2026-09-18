#include "api/EventHandler.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
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
    // A reaction is a message the user is putting in the room, so it answers to
    // the same permission. Discord has a separate ADD_REACTIONS bit and this
    // server has no equivalent; inventing one is a permissions-model change,
    // not a fix for this defect, and SEND_MESSAGES is the conservative reading
    // in the meantime — nobody who can post text is newly blocked, and everyone
    // who was muted now actually is.
    if (evt_type == event_type::kReaction) {
        return {true, permission::kSendMessages};
    }
    // Call signalling. VIEW_CHANNEL only, which is the same gate
    // VoiceHandler::handle_voice_join applies — these are the events an
    // in-call client exchanges, and a participant who may be in the channel may
    // signal in it. They are addressed events (see the signal_to handling in
    // SqliteStore::insert_event), not room-wide chatter.
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
struct MentionSet {
    std::vector<std::string> user_ids; // validated, deduped, sender removed
    bool room_wide = false;

    [[nodiscard]] bool empty() const { return user_ids.empty() && !room_wide; }

    // Flattened for storage: room-wide becomes the sentinel row.
    [[nodiscard]] std::vector<std::string> to_rows() const {
        auto rows = user_ids;
        if (room_wide) rows.emplace_back(kRoomMentionSentinel);
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
                           PushService* push)
    : store_(store), sync_engine_(sync_engine), config_(config), push_(push) {}

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

    PermissionsEngine perms(store_, config_);
    auto user_perms = perms.compute(*user_id, room_id);

    // VIEW_CHANNEL is a prerequisite for anything happening in the room.
    if (!permission::has(user_perms, permission::kViewChannel)) {
        return send_error(res, 403, MatrixError::forbidden("No access to this channel"));
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

    json content;
    try {
        content = json::parse(req.body);
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
    }

    if (evt_type == std::string(event_type::kRoomMessage)) {
        const std::string msgtype = content.value("msgtype", "m.text");
        const std::string body = content.value("body", "");
        const bool has_attachment = msgtype != std::string(msg_type::kText) && msgtype != std::string(msg_type::kEmote) && msgtype != std::string(msg_type::kNotice);

        if (has_attachment && !permission::has(user_perms, permission::kAttachFiles)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to attach files here"));
        }
        if (!body.empty() && body_contains_url(body) &&
            !permission::has(user_perms, permission::kEmbedLinks)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to post links here"));
        }
        if (!body.empty() && body_mentions_everyone(body) &&
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
                auto target = store_.get_event_by_id(target_id);
                if (!target) {
                    return send_error(res, 404, MatrixError::not_found(
                        "Target message not found"));
                }

                // An edit aimed at a previous edit resolves to the original.
                // Matrix says clients must always target the original, but a
                // client that chains them would otherwise pin the replacement
                // pointer to an event nothing resolves through, making the
                // second edit invisible. Bounded so a malformed cycle can't
                // spin here.
                for (int hops = 0; hops < 10; ++hops) {
                    if (!target->content.data.is_object()) break;
                    auto it = target->content.data.find("m.relates_to");
                    if (it == target->content.data.end() || !it->is_object()) break;
                    if (it->value("rel_type", "") != "m.replace") break;
                    auto parent_id = it->value("event_id", "");
                    if (parent_id.empty() || parent_id == target->event_id) break;
                    auto parent = store_.get_event_by_id(parent_id);
                    if (!parent) break;
                    target = std::move(parent);
                    target_id = target->event_id;
                }

                if (target->room_id != room_id) {
                    return send_error(res, 400, MatrixError::bad_json(
                        "Edit target is in a different room"));
                }
                if (target->sender != *user_id) {
                    return send_error(res, 403, MatrixError::forbidden(
                        "You can only edit your own messages"));
                }
                if (target->type != std::string(event_type::kRoomMessage)) {
                    return send_error(res, 400, MatrixError::bad_json(
                        "Can only edit message events"));
                }
                // A deleted message must not be editable back into existence.
                if (store_.is_event_redacted(target_id)) {
                    return send_error(res, 404, MatrixError::not_found(
                        "Target message has been deleted"));
                }
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
    int64_t stream_pos = store_.insert_event(event_id, room_id, *user_id, evt_type,
                                             std::nullopt, content.dump(), now_ms());

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
        return send_error(res, 403, MatrixError::forbidden("No access to this channel"));
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

    auto [events, next_pos] =
        store_.get_room_events_paginated(room_id, limit, dir, from);

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
    res.set_content(resp.dump(), "application/json");
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
    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    json body;
    try {
        body = json::parse(req.body);
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

    store_.set_read_marker(*user_id, room_id, pos);
    sync_engine_.notify_new_event();

    res.set_content("{}", "application/json");
}

void EventHandler::handle_redact(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    auto& target_event_id = match.params["eventId"];

    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    PermissionsEngine perms(store_, config_);
    auto user_perms = perms.compute(*user_id, room_id);
    if (!permission::has(user_perms, permission::kViewChannel)) {
        return send_error(res, 403, MatrixError::forbidden("No access to this channel"));
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
        try { body = json::parse(req.body); } catch (...) {
            return send_error(res, 400, MatrixError::bad_json());
        }
    }

    json content = json::object();
    content["redacts"] = target_event_id;
    if (body.contains("reason") && body["reason"].is_string()) {
        content["reason"] = body["reason"];
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
    store_.insert_event(event_id, room_id, *user_id,
                        std::string(event_type::kRoomRedaction),
                        std::nullopt, content.dump(), now_ms());
    sync_engine_.notify_new_event();

    res.set_content(json{{"event_id", event_id}}.dump(), "application/json");
}

} // namespace bsfchat
