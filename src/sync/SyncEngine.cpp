#include "sync/SyncEngine.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Permissions.h>

#include <set>
#include <unordered_map>

namespace bsfchat {

namespace {

bool is_category_room(SqliteStore& store, const std::string& room_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kRoomType), "");
    if (!ev) return false;
    return ev->content.data.value("type", "") == "category";
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
        // The same gate every other room in the response passes. An invite into
        // a channel this user's roles cannot view would be an invitation to
        // accept and still see nothing, and it would surface a channel the
        // server has decided they cannot see.
        if (!can_view_room(store, perms, user_id, room_id)) continue;
        attach_invite(store, user_id, room_id, response);
    }
}

} // namespace

SyncEngine::SyncEngine(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {
    current_position_ = store_.get_current_stream_position();
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
        response.next_batch = "s" + std::to_string(store_.get_current_stream_position());
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
    auto has_payload = [](const SyncResponse& r) {
        return !r.rooms.join.empty() || !r.rooms.invite.empty();
    };

    int64_t since_pos = 0;
    if (since_token.size() > 1 && since_token[0] == 's') {
        // A malformed token used to throw std::invalid_argument /
        // std::out_of_range straight out of the handler.
        try {
            since_pos = std::stoll(since_token.substr(1));
        } catch (const std::exception&) {
            since_pos = 0;
        }
        if (since_pos < 0) since_pos = 0;
    }

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
            // against the current head rather than spinning until the deadline;
            // next_batch carries the client past those rows on its next poll.
            checked_pos = std::max(checked_pos, current_position_.load());
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
    for (const auto& room_id : rooms) {
        // Categories bypass VIEW_CHANNEL so the sidebar can still show the
        // container node even when individual child channels are hidden.
        if (!is_category_room(store_, room_id) &&
            !perms.can(user_id, room_id, permission::kViewChannel)) {
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
        auto [timeline_events, next_pos] = store_.get_room_events_paginated(
            room_id, limits::kDefaultTimelineLimit, "b", std::nullopt, user_id);
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
        joined.unread_count = store_.count_unread(user_id, room_id);
        auto it = mentions.find(room_id);
        joined.highlight_count = it == mentions.end() ? 0 : it->second;
    }

    attach_direct_rooms(store_, user_id, response);
    // A fresh client learns its pending invites here; an established one is
    // told again on every delivered incremental response (see deliver()).
    attach_pending_invites(store_, config_, user_id, response);

    response.next_batch = "s" + std::to_string(head_before_scan);
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
    // Cache VIEW_CHANNEL decisions so we don't recompute for every event in
    // the same room (hot path during bursts).
    std::unordered_map<std::string, bool> view_cache;
    auto can_view = [&](const std::string& room_id) -> bool {
        auto it = view_cache.find(room_id);
        if (it != view_cache.end()) return it->second;
        bool ok = can_view_room(store_, perms, user_id, room_id);
        view_cache.emplace(room_id, ok);
        return ok;
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
        // A room this user has only been invited to contributes NO timeline and
        // no state to the join section. The query hands us exactly one kind of
        // row for such a room — this user's own m.room.member — and it is a
        // trigger to state the invite, not history to deliver.
        //
        // Keyed on current membership rather than on the event's own
        // `membership` field: an account invited back into a room it used to be
        // in has older member events of its own in that room, and any of them
        // can land in the same delta as the invite. What decides where the room
        // goes is where the user stands now.
        //
        // Only this user's own member event can have come from a room they
        // have merely been invited to — the query admits nothing else out of
        // one — so every other row is from a joined room by construction. That
        // is what confines the membership lookup, which is a store call behind
        // the global mutex, to a rare row instead of one per room per delta.
        const bool own_member_event =
            event.type == std::string(event_type::kRoomMember) &&
            event.state_key.has_value() && *event.state_key == user_id;
        if (own_member_event &&
            membership_of(event.room_id) == std::string(membership::kInvite)) {
            if (can_view(event.room_id)) invited_rooms.insert(event.room_id);
            continue;
        }
        if (!can_view(event.room_id)) continue;

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
        if (!can_view(room_id)) continue;
        auto state = store_.get_state_events(room_id);
        auto& joined = response.rooms.join[room_id];
        joined.state.events = std::move(state);
        joined_direct_room = joined_direct_room || store_.is_direct_room(room_id);
    }
    // The DM set only changes when this user lands in a direct room, so that is
    // the only incremental sync that needs to restate it.
    if (joined_direct_room) attach_direct_rooms(store_, user_id, response);

    auto mentions = store_.get_unread_mention_counts(user_id);
    for (auto& [room_id, joined] : response.rooms.join) {
        joined.unread_count = store_.count_unread(user_id, room_id);
        auto it = mentions.find(room_id);
        joined.highlight_count = it == mentions.end() ? 0 : it->second;
    }

    response.next_batch = "s" + std::to_string(delivered_max);
    // Same value as next_batch by construction, and that is the point: what the
    // client is told it has seen and what a wait treats as seen must be the one
    // number, or one of the two is wrong.
    if (out_covered_pos) *out_covered_pos = delivered_max;
    return response;
}

} // namespace bsfchat
