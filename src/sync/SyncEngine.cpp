#include "sync/SyncEngine.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/InstanceSecret.h"
#include "core/Logger.h"
#include "store/SqliteStore.h"
#include "sync/SyncToken.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Permissions.h>

#include <optional>
#include <set>
#include <unordered_map>

namespace bsfchat {

namespace {

bool is_category_room(SqliteStore& store, const std::string& room_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kRoomType), "");
    if (!ev) return false;
    return ev->content.data.value("type", "") == room_type::kCategory;
}

// How much of a room a user may be shown. Three answers, not two, because a
// category is genuinely a third case and collapsing it into `true` is what
// made it a hole: `is_category_room(...) || perms.can(..., kViewChannel)`
// exempted a category from VIEW_CHANNEL ENTIRELY, so its full state, member
// list and timeline went to every joined user regardless of any deny override.
// Every account is force-joined into every channel on this data model (see
// auth/AutoJoin.cpp and the membership-vs-visibility audit), so "joined" is
// not a filter, and one MANAGE_CHANNELS write retyping a private channel as a
// category published its history to the whole server.
//
// `kCategoryStub` is the exemption the sidebar actually needs, and nothing
// more. /messages and /search never carried the exemption at all, which is the
// tell that the blanket version was an accident rather than a policy.
enum class RoomView {
    kNone,          // not shown at all
    kCategoryStub,  // named and ordered in the sidebar; no contents
    kFull,          // ordinary VIEW_CHANNEL access
};

// The only state a category contributes to a viewer without VIEW_CHANNEL.
//
// Derived from what the client actually consumes for a category node, not from
// what seemed safe: RoomListModel::getCategoriesWithChannels() reads exactly
// roomId, displayName, roomType and sortOrder, which come from m.room.name,
// bsfchat.room.type and bsfchat.room.category (parent_id + order). It reads no
// topic, no members, no timeline and no unread counts for a category header,
// so none of those are sent. Adding a type here widens the exemption — do it
// only with a client change that needs it.
bool is_category_stub_state(const RoomEvent& event) {
    if (!event.state_key.has_value() || !event.state_key->empty()) return false;
    return event.type == event_type::kRoomName ||
           event.type == event_type::kRoomType ||
           event.type == event_type::kRoomCategory;
}

RoomView room_view(SqliteStore& store, PermissionsEngine& perms, const std::string& user_id,
                   const std::string& room_id) {
    if (perms.can(user_id, room_id, permission::kViewChannel)) return RoomView::kFull;
    // A category the user cannot view is still named to them: the sidebar has
    // to render the container node even when every channel inside it is
    // hidden, and a category that vanished would re-file its visible children
    // under "Uncategorized".
    //
    // Judgement call recorded deliberately: the stub is emitted whether or not
    // the user can see any child. Making it conditional would need a
    // VIEW_CHANNEL evaluation per child, which build_incremental_sync — which
    // walks events, not rooms — cannot do without a full room walk on every
    // poll. The two sync paths would then disagree and the node would flicker
    // in and out of the sidebar. What the stub discloses is a name and a sort
    // order; the history, roster and state that made this a HIGH finding are
    // gone either way.
    if (is_category_room(store, room_id)) return RoomView::kCategoryStub;
    return RoomView::kNone;
}

// The sidebar node, and only the sidebar node. No timeline, so no prev_batch
// and no `limited`; no member list; no unread or highlight counts (a count is
// a message-volume oracle on a channel you cannot read).
JoinedRoom category_stub(SqliteStore& store, const std::string& room_id) {
    JoinedRoom stub;
    for (auto& event : store.get_state_events(room_id)) {
        if (is_category_stub_state(event)) stub.state.events.push_back(std::move(event));
    }
    return stub;
}

// m.direct for `user_id`, derived from rooms.is_direct. It is a full
// replacement by Matrix convention, so it always lists every DM, never a delta
// — which is what makes restating it on a delivered response harmless.
//
// The room marks itself direct too (is_direct on both participants'
// m.room.member content, see RoomHandler), but only for DMs opened by a server
// that writes it. For every DM that already existed when such a server was
// installed, this is still the only thing in /sync that says the room is one.
void attach_direct_rooms(SqliteStore& store, const std::string& user_id,
                         SyncResponse& response) {
    auto direct = store.get_direct_rooms(user_id);
    if (direct.empty()) return;
    auto& out = response.direct_rooms.emplace();
    for (auto& [room_id, peer] : direct) out[peer].push_back(std::move(room_id));
}

// Categories bypass VIEW_CHANNEL so the sidebar can still show the container
// node even when individual child channels are hidden.
bool can_view_room(SqliteStore& store, PermissionsEngine& perms, const std::string& user_id,
                   const std::string& room_id) {
    return is_category_room(store, room_id) ||
           perms.can(user_id, room_id, permission::kViewChannel);
}

// One room's invite section: the stripped state and nothing else. Already
// stated wins, so a delta that found the invite is never overwritten by the
// restatement below.
void attach_invite(SqliteStore& store, const std::string& user_id, const std::string& room_id,
                   SyncResponse& response) {
    if (response.rooms.invite.count(room_id)) return;
    InvitedRoom invited;
    invited.invite_state.events = store.get_invite_state(room_id, user_id);
    response.rooms.invite[room_id] = std::move(invited);
}

// Whether an invite into `room_id` was sent by somebody `user_id` ignores.
//
// A block has to cover invites or it does not cover the thing people are
// actually blocking for: the whole point of a DM invite from a stranger is that
// it arrives whether or not you want it, and a block that silenced their
// messages but still delivered their invitations would leave the harassment
// route open and the feature looking broken.
//
// SUPPRESSED AT DELIVERY, NOT REFUSED AT THE INVITE. The inviter's POST
// succeeds and returns exactly what it returned before; the membership row is
// written; the invite simply never appears in the ignoring user's /sync. That
// asymmetry is the requirement, not a shortcut around one — a block whose
// subject can detect it by watching their own invite fail is a block that tells
// them they have been blocked and by whom, which is what makes a second account
// worth registering. Nothing else about the room changes: if the invite is
// later accepted by some other route, or the block is lifted, the row is still
// there and the room appears.
bool invite_is_from_ignored_user(SqliteStore& store, const std::string& user_id,
                                 const std::string& room_id) {
    auto inviter = store.get_invite_sender(room_id, user_id);
    // No inviter found means no m.room.member invite event to read a sender
    // from — a membership row written by some path that does not emit one. Fail
    // OPEN (deliver the invite): a block is a filter over a known sender, and
    // silently swallowing invites whose origin cannot be established would be a
    // far stranger failure than showing one.
    if (!inviter) return false;
    return store.is_ignoring(user_id, *inviter);
}

// Every invite this user currently has pending, whether or not it arrived in
// this delta — the same restatement m.direct gets, for the same reason.
//
// The delta path alone is enough for an invite sent from now on and nothing at
// all for one that is already pending: a client resumes from a persisted sync
// token, so it never asks for an initial sync again, and the member event
// announcing an older invite sits below that token forever. Upgrading the
// server would therefore have fixed nothing for the invites an owner actually
// has outstanding. Restating them fixes that within one poll.
//
// Safe for the long poll, and structurally so: this runs from deliver(), on
// the response AFTER the decision to keep waiting has been taken on it. A
// pending invite can therefore never make an empty response look non-empty —
// which would return instantly, poll again with an advanced token, find the
// same invite still pending, and spin.
//
// It is also what makes a delivered response's invite set authoritative: it is
// read from current membership, so an invite accepted or declined elsewhere is
// simply absent next poll and the client drops it. That is the whole of
// rooms.leave's job here, without the section.
void attach_pending_invites(SqliteStore& store, const Config& config,
                            const std::string& user_id, SyncResponse& response) {
    auto invited = store.get_invited_rooms(user_id);
    if (invited.empty()) return;  // the common case: one indexed lookup, no rows
    PermissionsEngine perms(store, config);
    for (const auto& room_id : invited) {
        // Ahead of the visibility gate below, and it does not matter which
        // order these two run in — both end in `continue` and neither is
        // observable — but a blocked inviter is the cheaper question (one
        // primary-key probe against an almost always empty table) and asking it
        // first keeps the permission engine off the path for the case that has
        // already been decided.
        if (invite_is_from_ignored_user(store, user_id, room_id)) continue;
        // The same gate every other room in the response passes. An invite into
        // a channel this user's roles cannot view would be an invitation to
        // accept and still see nothing, and it would surface a channel the
        // server has decided they cannot see.
        if (!can_view_room(store, perms, user_id, room_id)) continue;
        attach_invite(store, user_id, room_id, response);
    }
}

// ── Account data ─────────────────────────────────────────────────────────
//
// The section that was missing: /sync carried no account data at all, so a
// document written on one device — a block list, a read marker — reached the
// account's other devices never. See docs/read-state.md.
//
// Stored content is text this server hands back as it was PUT, so it is parsed
// here rather than trusted. A row that will not parse is SKIPPED, not thrown
// on: the alternative is one malformed document taking out /sync for that
// account entirely, on the endpoint a client cannot work without.
std::optional<AccountDataEvent> account_data_event(const std::string& type,
                                                   const std::string& content_json) {
    auto content = nlohmann::json::parse(content_json, nullptr, /*allow_exceptions=*/false);
    if (content.is_discarded() || !content.is_object()) {
        get_logger()->warn("account data for type '{}' is not a JSON object; not delivered",
                           type);
        return std::nullopt;
    }
    return AccountDataEvent{type, std::move(content)};
}

// `m.fully_read` for one room: the Matrix room account-data document naming
// how far its owner has read.
//
// The marker is STORED as a stream position, which is meaningless to a client
// — it is this server's internal ordering. What goes on the wire is the event
// that position points at: its id, which is the spec's field, and its
// origin_server_ts, which is what this client's unread dot compares against
// (client/src/core/ReadState.h). Resolving it here costs one indexed lookup
// per CHANGED marker, which is the reason the section is a delta.
//
// nullopt when the position resolves to no surviving event — an empty room, or
// a marker below everything left after a purge. There is nothing truthful to
// say then, and saying "read up to timestamp 0" would be a marker that moves
// the client's own backwards.
std::optional<AccountDataEvent> fully_read_event(SqliteStore& store,
                                                 const SqliteStore::ReadMarker& marker) {
    auto marked = store.resolve_read_marker(marker.room_id, marker.last_read_pos);
    if (!marked) return std::nullopt;
    return AccountDataEvent{
        std::string(event_type::kFullyRead),
        nlohmann::json{{std::string(fully_read::kEventId), marked->event_id},
                       {std::string(fully_read::kOriginServerTs), marked->origin_server_ts}}};
}

} // namespace

SyncEngine::SyncEngine(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {
    current_position_ = store_.get_current_stream_position();
}

const std::vector<unsigned char>& SyncEngine::token_key() {
    // If the derivation throws — an empty secret, an OpenSSL failure, a CSPRNG
    // that will not produce 256 bits — call_once leaves the flag clear, so the
    // next request retries rather than caching a broken key. It also means
    // /sync answers 500 while the condition lasts, which is correct: there is
    // no safe degraded token, and handing out a predictable one would restore
    // the oracle silently.
    std::call_once(token_key_once_, [this] {
        token_key_ = sync_token::derive_key(get_or_create_instance_secret(store_),
                                            config_.server_name);
    });
    return token_key_;
}

std::string SyncEngine::mint_token(const std::string& user_id, int64_t position) {
    return sync_token::mint(token_key(), user_id, position);
}

int64_t SyncEngine::parse_token(const std::string& user_id, const std::string& token) {
    auto pos = sync_token::parse(token_key(), user_id, token);
    if (!pos || *pos < 0) return 0;
    return *pos;
}

void SyncEngine::notify_new_event() {
    auto pos = store_.get_current_stream_position();
    {
        // Must be held while publishing the new position: a waiter evaluates
        // its predicate under this same lock, and a notify slipping in between
        // that evaluation and the wait would otherwise be lost entirely.
        std::lock_guard lock(wait_mutex_);
        // Monotonic, never a plain assignment. The head is read after the
        // insert's transaction has committed and released the store mutex, so
        // two writers can reach here in the opposite order to their commits:
        // B commits position 6 and publishes 6, then A — which committed 5 and
        // sampled the head as 5 before B got there — would drag the published
        // head back to 5. A waiter that had already examined 6 then parks
        // against a head that no longer exceeds it and sits out its timeout
        // holding an event that is committed and visible.
        if (pos > current_position_.load()) {
            current_position_ = pos;
        }
    }
    new_event_cv_.notify_all();
}

void SyncEngine::notify_ephemeral() {
    {
        std::lock_guard lock(wait_mutex_);
        ++ephemeral_seq_;
    }
    new_event_cv_.notify_all();
}

void SyncEngine::set_post_scan_hook_for_test(std::function<void()> hook) {
    post_scan_hook_for_test_ = std::move(hook);
}

SyncResponse SyncEngine::handle_sync(const std::string& user_id,
                                      const std::string& since_token,
                                      int timeout_ms) {
    // A banned user sees nothing, whatever their membership rows say.
    //
    // The ban projection already sets every room_members row to "ban", so this is
    // belt and braces — but it is the cheap kind: one primary-key lookup at the
    // top of the one endpoint a client polls continuously, and it fails closed for
    // any room whose projection was missed (a crash between the ban-list write and
    // the projection, or a row written by some future code path). It also returns
    // immediately rather than long-polling, so a banned client stops holding a
    // request thread open.
    if (store_.is_server_banned(user_id)) {
        SyncResponse response;
        response.next_batch = mint_token(user_id, store_.get_current_stream_position());
        return response;
    }

    if (since_token.empty()) {
        return build_initial_sync(user_id);
    }

    // Every response this function DELIVERS restates m.direct; the ones it
    // discards inside the long poll below do not.
    //
    // It used to be attached only on an initial sync and on the one
    // incremental sync where the user newly joined a direct room. That is
    // enough for a DM opened from now on, and nothing at all for a DM that
    // already exists: a client resumes from a persisted sync token, so it
    // never asks for an initial sync again, and it joined its existing DMs
    // long ago. Upgrading the server therefore changed nothing for the rooms
    // the complaint is actually about — they stay filed under channels until
    // the client is reinstalled. Restating it fixes that within one poll.
    //
    // Safe for the long poll, and structurally so: the decision to keep
    // waiting is `response.rooms.join.empty()`, taken on the response BEFORE
    // deliver() ever sees it. m.direct can therefore never make an empty
    // response look non-empty, and the wait's own re-scans never call this at
    // all — so the cost is one indexed lookup per response actually returned
    // (once per poll cycle), not one per spurious wake.
    //
    // Safe for the client, too: m.direct is a full replacement, the client's
    // merge is idempotent and reports only what changed, and next_batch is
    // untouched — so a restatement on an idle timeout cannot be mistaken for
    // progress, and cannot churn the sidebar.
    //
    // Pending invites ride along for the same reasons, argued in full at
    // attach_pending_invites: they are read from current membership, so the
    // set on a delivered response is the complete one, and an invite that was
    // already outstanding when the client's token was minted is learned within
    // one poll instead of never.
    auto deliver = [this, &user_id](SyncResponse&& r) {
        if (!r.direct_rooms) attach_direct_rooms(store_, user_id, r);
        attach_pending_invites(store_, config_, user_id, r);
        return std::move(r);
    };

    // What counts as "something for this user", i.e. worth returning now
    // rather than parking on. An invite is content: the whole complaint is
    // that an invitee learned nothing until they were told out of band.
    //
    // This deliberately reads the response BUILT BY build_incremental_sync,
    // never one that deliver() has touched — see attach_pending_invites.
    //
    // Global account data counts too, and has to: a block list written on
    // another device belongs to no room, so it puts nothing in rooms.join, and
    // a response carrying only that would otherwise be judged empty, discarded
    // by the wait, and the change held back until the poll timed out. Room
    // account data needs no clause of its own — a read marker is attached to
    // its room, so the room is in rooms.join by the time this is asked.
    //
    // It cannot spin: the delta is bounded above by the same position
    // next_batch is built from, so the very token this response hands back
    // puts those documents below the next poll's range.
    auto has_payload = [](const SyncResponse& r) {
        return !r.rooms.join.empty() || !r.rooms.invite.empty() ||
               !r.account_data.empty();
    };

    // Opaque on the way out, opaque or legacy-numeric on the way in — see
    // sync/SyncToken.h. Anything unrecognised is position 0, which is a full
    // replay of what THIS caller may see and never anyone else's events: the
    // scan below is membership-joined to `user_id` in SQL and re-filtered
    // through VIEW_CHANNEL per event. That is also why the token only has to be
    // opaque and not unforgeable — a forged position buys nothing.
    //
    // A malformed token used to throw std::invalid_argument / std::out_of_range
    // straight out of the handler; the parser is strict and total instead.
    const int64_t since_pos = parse_token(user_id, since_token);

    // Snapshot the ephemeral counter BEFORE building, so typing/presence
    // changes that land while we're querying still count as "something
    // happened" and don't get swallowed by the wait.
    const uint64_t edu_at_entry = ephemeral_seq_.load();

    // The position this scan covered — NOT the head as it stands now. An event
    // persisted while the scan was running has a position above this, so the
    // wait below still treats it as unseen and wakes on it at once.
    int64_t covered_pos = since_pos;
    auto response = build_incremental_sync(user_id, since_pos, &covered_pos);
    if (has_payload(response)) {
        return deliver(std::move(response));
    }

    if (timeout_ms > 0) {
        timeout_ms = std::min(timeout_ms, limits::kMaxSyncTimeoutMs);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

        // The condition variable is global: notify_new_event() wakes every
        // waiter on the server, whatever room the event landed in. Returning
        // straight after the first wake therefore ended a client's poll because
        // somebody else posted in a channel it cannot even see.
        //
        // That is not just wasted work. Such a reply carries no timeline events
        // AND no advance in next_batch, and the desktop client reads a fast
        // reply that did not move next_batch as a broken endpoint: it answers
        // with SyncBackoff's escalating no-progress delay, 1s then 2s, 4s, 8s,
        // up to a minute. So a busy unrelated channel could walk an idle
        // client's poll interval out to 60s, and the next message genuinely
        // addressed to it then waited that long with no request even in flight.
        //
        // Re-check instead, and go back to sleep on a wake that turned out to
        // hold nothing for this user. `checked_pos` is what makes that
        // terminate: the raw predicate stays true forever once the global head
        // has passed since_pos, so it has to advance past what we have already
        // looked at.
        //
        // It advances to the position each SCAN COVERED, never to the head as
        // read afterwards. Sampling the head here instead marked an event that
        // landed between the scan and this line as already examined: the
        // predicate was false for it, and the client sat out the whole 30s
        // timeout — or until some unrelated event happened along — holding a
        // message that was committed and readable the entire time.
        int64_t checked_pos = covered_pos;
        for (;;) {
            bool signalled = false;
            {
                std::unique_lock lock(wait_mutex_);
                signalled = new_event_cv_.wait_until(lock, deadline, [&] {
                    return current_position_.load() > checked_pos ||
                           ephemeral_seq_.load() != edu_at_entry;
                });
            }
            if (!signalled) break; // deadline passed with nothing for us

            // Sampled BEFORE the re-scan, for the livelock fallback at the
            // bottom of this loop. Sampling it after would be the same
            // mistake this whole block was rewritten to remove: an event
            // that commits while the re-scan runs would raise the head, the
            // fallback would mark that head as examined, and the poll would
            // sleep out its deadline holding an event it never looked at.
            // Taken here, the value can only describe rows that already
            // existed when the scan started.
            const int64_t head_before_rescan = current_position_.load();

            response = build_incremental_sync(user_id, since_pos, &covered_pos);
            // Real events, or an ephemeral change the caller injects typing and
            // presence from — either is worth returning immediately.
            if (has_payload(response) ||
                ephemeral_seq_.load() != edu_at_entry) {
                return deliver(std::move(response));
            }
            // Woken for an event this user cannot see. Keep the poll parked,
            // now against the position that re-scan reached.
            if (covered_pos > checked_pos) {
                checked_pos = covered_pos;
                continue;
            }
            // The re-scan covered no new ground. That means it was cut short by
            // its limit on rows this user cannot read, so re-scanning returns
            // the same rows forever and covered_pos will never move. Park
            // against the head AS IT WAS WHEN THIS PASS BEGAN rather than
            // spinning until the deadline; next_batch carries the client past
            // those rows on its next poll.
            //
            // `head_before_rescan`, never a fresh load. Re-reading the head
            // here would let an event that committed DURING the re-scan be
            // written off as examined — the exact defect that
            // EventDuringTheInitialScanWakesThePollAtOnce and
            // AnEphemeralWakeDoesNotHandBackATokenPastAnUnscannedEvent exist
            // for, surviving in the one branch neither of them reaches.
            checked_pos = std::max(checked_pos, head_before_rescan);
        }

        response = build_incremental_sync(user_id, since_pos, &covered_pos);
    }

    // The idle-timeout reply, and the timeout_ms == 0 poll. Both are delivered
    // responses, so both restate it — which is what lets a client whose server
    // is completely quiet still learn its existing DMs are DMs, within one
    // poll rather than never.
    return deliver(std::move(response));
}

SyncResponse SyncEngine::build_initial_sync(const std::string& user_id) {
    SyncResponse response;
    PermissionsEngine perms(store_, config_);

    // Sampled BEFORE a single room is read, and next_batch is built from it
    // below. Reading it at the end instead skips every event that landed while
    // this sync was walking the room list: such an event is not in any
    // timeline here, yet sits at or below the token the client goes on to poll
    // with, so nothing ever asks for it again. Taken first, the worst case is
    // that the client is offered an event twice — which it deduplicates by
    // event_id — instead of never.
    const int64_t head_before_scan = store_.get_current_stream_position();

    auto rooms = store_.get_joined_rooms(user_id);

    // Stands in for an event committing while the walk below is in progress.
    if (post_scan_hook_for_test_) post_scan_hook_for_test_();
    // Rooms present in the response as a sidebar node only. Tracked so the
    // counts pass below skips them: it walks response.rooms.join, so a stub
    // left in that map would be handed an unread and a highlight count for a
    // channel its viewer is not allowed to read.
    std::set<std::string> stubbed;

    for (const auto& room_id : rooms) {
        const RoomView view = room_view(store_, perms, user_id, room_id);
        if (view == RoomView::kNone) continue;
        if (view == RoomView::kCategoryStub) {
            response.rooms.join[room_id] = category_stub(store_, room_id);
            stubbed.insert(room_id);
            continue;
        }

        JoinedRoom joined;
        joined.state.events = store_.get_state_events(room_id);
        // Use the paginated variant so we can set `prev_batch` to the
        // token the client needs for back-pagination. `next_pos` here is
        // the stream_position of the oldest row in the returned batch; the
        // client passes it back as `from` to /rooms/{id}/messages to fetch
        // events strictly older than this batch.
        // `user_id` as the viewer: an initial sync is a DELIVERY path, not a
        // history one. Without it a client that restarts mid-call — or that
        // reconnects after a network blip — silently loses the invite or
        // candidate batch addressed to it, and the call never establishes. With
        // it, this user sees their own signalling and no one else's; /messages
        // passes no viewer and so shows none of it to anybody. See
        // store/CallSignalling.h.
        //
        // `user_id` twice, for two unrelated rules that happen to take the same
        // argument: as the VIEWER, which admits this account's own addressed
        // call signalling (see store/CallSignalling.h), and as the IGNORING
        // USER, which drops non-state events sent by anyone they have blocked.
        // Both belong here rather than in a filter over the result — see
        // SqliteStore::get_room_events_paginated.
        auto [timeline_events, next_pos] = store_.get_room_events_paginated(
            room_id, limits::kDefaultTimelineLimit, "b", std::nullopt, user_id, user_id);
        joined.timeline.events = std::move(timeline_events);
        std::reverse(joined.timeline.events.begin(), joined.timeline.events.end());
        // `limited` is true when more history exists beyond this batch; the
        // probe-row trick in get_room_events_paginated sets next_pos iff so.
        joined.timeline.limited = next_pos.has_value();
        if (next_pos) {
            joined.timeline.prev_batch = "s" + std::to_string(*next_pos);
        }

        response.rooms.join[room_id] = std::move(joined);
    }

    // One grouped query for mentions across every room, rather than one per
    // room inside the loop — each store call serialises behind the store's
    // single global mutex, and an initial sync visits every joined channel.
    auto mentions = store_.get_unread_mention_counts(user_id);
    for (auto& [room_id, joined] : response.rooms.join) {
        if (stubbed.count(room_id)) continue;
        joined.unread_count = store_.count_unread(user_id, room_id);
        auto it = mentions.find(room_id);
        joined.highlight_count = it == mentions.end() ? 0 : it->second;
    }

    // Account data, complete rather than a delta: this caller has no token, so
    // there is nothing to take a delta against, and everything they have is
    // new to them.
    for (auto& doc : store_.get_all_account_data(user_id)) {
        if (auto event = account_data_event(doc.type, doc.content_json)) {
            response.account_data.push_back(std::move(*event));
        }
    }
    // Read markers, for the rooms this response actually contains — which is
    // the visibility gate, already applied above. A marker for a room that is
    // absent from rooms.join is DROPPED rather than attached: the account may
    // have read a channel it can no longer view, and hanging its room id off
    // the response would say the channel exists to somebody the rest of this
    // function has just decided must not be told. `stubbed` is excluded for
    // the same reason it is excluded from the counts: a category stub is a
    // name and an ordering, and a read position inside it is contents.
    for (const auto& marker : store_.get_read_markers(user_id)) {
        auto it = response.rooms.join.find(marker.room_id);
        if (it == response.rooms.join.end()) continue;
        if (stubbed.count(marker.room_id)) continue;
        if (auto event = fully_read_event(store_, marker)) {
            it->second.account_data.push_back(std::move(*event));
        }
    }

    attach_direct_rooms(store_, user_id, response);
    // A fresh client learns its pending invites here; an established one is
    // told again on every delivered incremental response (see deliver()).
    attach_pending_invites(store_, config_, user_id, response);

    response.next_batch = mint_token(user_id, head_before_scan);
    return response;
}

SyncResponse SyncEngine::build_incremental_sync(const std::string& user_id, int64_t since_pos,
                                                int64_t* out_covered_pos) {
    SyncResponse response;
    PermissionsEngine perms(store_, config_);

    // `delivered_max` is the highest stream position actually scanned. It is
    // what next_batch must be built from: the old code fetched at most `limit`
    // events and then set next_batch to the GLOBAL stream head, so anything
    // past the limit — or anything inserted between the fetch and the head
    // read — was skipped permanently.
    int64_t delivered_max = since_pos;
    constexpr int kScanLimit = 1000;
    // `scan_head` is the stream head as of the scan's own snapshot, taken under
    // the store lock that serialises writes. Reading the head separately after
    // the scan — as this did — leaves a window in which an insert commits with
    // a position at or below the head we then read but above anything the scan
    // returned. next_batch jumped over it and no later sync ever asked for it:
    // that event was lost to this client for good.
    int64_t scan_head = since_pos;
    auto events =
        store_.get_events_since(user_id, since_pos, delivered_max, scan_head, kScanLimit);

    if (post_scan_hook_for_test_) post_scan_hook_for_test_();

    // When the scan was not cut short by the limit, this user has been offered
    // everything on the stream, so their token can jump to the global head even
    // though most of those rows were other people's rooms. Leaving it pinned to
    // the highest VISIBLE row meant a client in a quiet channel re-scanned the
    // same widening range on every poll, and — worse — came back from any
    // spurious wake with next_batch unchanged, which the desktop client treats
    // as a no-progress reply and punishes with an escalating backoff.
    //
    // Only safe when the scan was complete: if it hit the limit there are
    // certainly rows past `delivered_max` this user still needs, and skipping
    // to the head would drop them permanently.
    if (static_cast<int>(events.size()) < kScanLimit) {
        delivered_max = std::max(delivered_max, scan_head);
    }

    std::set<std::string> newly_joined_rooms;
    std::set<std::string> invited_rooms;
    // Cache visibility decisions so we don't recompute for every event in
    // the same room (hot path during bursts).
    std::unordered_map<std::string, RoomView> view_cache;
    auto view_of = [&](const std::string& room_id) -> RoomView {
        auto it = view_cache.find(room_id);
        if (it != view_cache.end()) return it->second;
        RoomView view = room_view(store_, perms, user_id, room_id);
        view_cache.emplace(room_id, view);
        return view;
    };
    // "May this user be told the room exists" — the LISTING rule, used by the
    // invite trigger below. Equal to the free can_view_room() above
    // (is_category_room || VIEW_CHANNEL) and therefore to `!= kNone`; if you
    // ever change one, change both, or invites and the sidebar will disagree
    // about which rooms are namable.
    auto can_view = [&](const std::string& room_id) {
        return view_of(room_id) != RoomView::kNone;
    };
    // Same caching, for the same reason: the scan can return many rows per
    // room and this is one query each.
    std::unordered_map<std::string, std::string> membership_cache;
    auto membership_of = [&](const std::string& room_id) -> const std::string& {
        auto it = membership_cache.find(room_id);
        if (it == membership_cache.end()) {
            it = membership_cache.emplace(room_id, store_.get_membership(room_id, user_id))
                     .first;
        }
        return it->second;
    };

    for (auto& event : events) {
        // feat/sync-invites' invite trigger, kept AHEAD of the view switch: a
        // room this user has only been invited to contributes no timeline and
        // no state, so it must not fall through to the join-section handling
        // below.
        //
        // can_view() is `view_of() != kNone`, deliberately not `== kFull`. The
        // old predicate this replaced was `VIEW_CHANNEL || is_category`, and
        // `!= kNone` is exactly that set — so invite delivery is unchanged by
        // the category work. Requiring kFull would silently drop an invite into
        // a category the invitee cannot view yet, which is precisely the case
        // an invite exists to resolve.
        const bool own_member_event =
            event.type == std::string(event_type::kRoomMember) &&
            event.state_key.has_value() && *event.state_key == user_id;
        if (own_member_event &&
            membership_of(event.room_id) == std::string(membership::kInvite)) {
            // The ignore filter in get_events_since exempts STATE events, and
            // an invite IS one — this user's own m.room.member — so the scan
            // hands it over however the invite arrived. That exemption is right
            // (dropping member events empties the reader's member list) and it
            // is why the block has to be applied here, on the sender of the
            // invite rather than on the sender of the row.
            //
            // `event.sender` rather than a fresh get_invite_sender() lookup:
            // this IS the invite event, so its sender is the inviter by
            // definition, and a second read would only introduce a way for the
            // delta path and the restatement path to disagree about the same
            // invite. attach_pending_invites has no event in hand and so has to
            // ask the store; both end up on the same answer.
            if (store_.is_ignoring(user_id, event.sender)) continue;
            if (can_view(event.room_id)) invited_rooms.insert(event.room_id);
            continue;
        }

        const RoomView view = view_of(event.room_id);
        if (view == RoomView::kNone) continue;

        if (view == RoomView::kCategoryStub) {
            // Name and ordering changes keep the sidebar node correct. Nothing
            // else: in particular the event never reaches `timeline`, so a
            // message sent into a category — which EventHandler permits, it
            // has no notion of categories at all — is not delivered to anyone
            // who lacks VIEW_CHANNEL on it. That is the incremental half of
            // the same rule build_initial_sync applies with category_stub().
            if (!is_category_stub_state(event)) continue;
            auto& joined = response.rooms.join[event.room_id];
            joined.state.events.push_back(std::move(event));
            continue;
        }

        if (event.type == std::string(event_type::kRoomMember)
            && event.state_key.has_value()
            && *event.state_key == user_id) {
            auto membership = event.content.data.value("membership", "");
            if (membership == "join") {
                newly_joined_rooms.insert(event.room_id);
            }
        }

        auto& joined = response.rooms.join[event.room_id];
        if (event.state_key.has_value()) {
            joined.state.events.push_back(event);
        }
        joined.timeline.events.push_back(std::move(event));
    }

    for (const auto& room_id : invited_rooms) {
        attach_invite(store_, user_id, room_id, response);
    }

    bool joined_direct_room = false;
    for (const auto& room_id : newly_joined_rooms) {
        // Re-checked rather than assumed: only kFull gets the whole state
        // dump. `newly_joined_rooms` is only populated on the kFull path, so
        // this cannot currently be a stub — the guard is here so that stays
        // true if the population above ever moves.
        if (view_of(room_id) != RoomView::kFull) continue;
        auto state = store_.get_state_events(room_id);
        auto& joined = response.rooms.join[room_id];
        joined.state.events = std::move(state);
        joined_direct_room = joined_direct_room || store_.is_direct_room(room_id);
    }
    // The DM set only changes when this user lands in a direct room, so that is
    // the only incremental sync that needs to restate it.
    if (joined_direct_room) attach_direct_rooms(store_, user_id, response);

    // ── Account data, as a delta ─────────────────────────────────────────
    //
    // Bounded by `delivered_max`, the same position next_batch is built from,
    // and not by the head: a document written after this scan sits above the
    // token this response hands back, so it is picked up by the next poll —
    // which its own wake has already scheduled — instead of being delivered
    // under a token that does not cover it. That is the identical rule the
    // event scan follows two screens up, and for the identical reason.
    //
    // AHEAD of the counts pass below, deliberately. A read marker set on
    // another device puts its room into rooms.join with nothing else in it,
    // and that room's unread count is the number the other device's badge is
    // wrong about. Attaching after the counts would deliver the marker and
    // leave the count stale for another poll.
    for (auto& doc : store_.get_account_data_changed(user_id, since_pos, delivered_max)) {
        if (auto event = account_data_event(doc.type, doc.content_json)) {
            response.account_data.push_back(std::move(*event));
        }
    }
    for (const auto& marker : store_.get_read_markers_changed(user_id, since_pos, delivered_max)) {
        // kFull, not `!= kNone`. The listing exemption that lets a category
        // appear in the sidebar is not permission to see what happens inside
        // one, and a read position is inside one. A marker for a room this
        // account can no longer view is dropped entirely — it is their own
        // row, but delivering it would name a room the visibility rules have
        // stopped naming, which is how a "per-user" section becomes a channel
        // oracle. See docs/membership-vs-visibility.md.
        if (view_of(marker.room_id) != RoomView::kFull) continue;
        // And a member, which the initial-sync path gets for free by walking
        // get_joined_rooms(). A marker is only writable by a member — the
        // handler checks — but a membership can END after one is written, and
        // a room this account has left must not reappear in its sidebar
        // because a row about it moved.
        if (membership_of(marker.room_id) != std::string(membership::kJoin)) continue;
        if (auto event = fully_read_event(store_, marker)) {
            response.rooms.join[marker.room_id].account_data.push_back(std::move(*event));
        }
    }

    auto mentions = store_.get_unread_mention_counts(user_id);
    for (auto& [room_id, joined] : response.rooms.join) {
        // A sidebar stub carries no counts — see category_stub().
        if (view_of(room_id) != RoomView::kFull) continue;
        joined.unread_count = store_.count_unread(user_id, room_id);
        auto it = mentions.find(room_id);
        joined.highlight_count = it == mentions.end() ? 0 : it->second;
    }

    response.next_batch = mint_token(user_id, delivered_max);
    // Same POSITION as next_batch by construction, and that is the point: what
    // the client is told it has seen and what a wait treats as seen must be the
    // one number, or one of the two is wrong. next_batch is now that number put
    // through a keyed permutation — the wait keeps the raw value, because it is
    // internal and is compared as an ordering, which the token deliberately is
    // not.
    if (out_covered_pos) *out_covered_pos = delivered_max;
    return response;
}

} // namespace bsfchat
