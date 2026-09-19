// Call signalling must not publish anybody's IP address to the room.
//
// The defect these tests pin is described in full in src/store/CallSignalling.h.
// The short version: m.call.invite / answer / candidates / hangup and
// bsfchat.call.negotiate carry ICE candidates, and ICE candidates are LAN and
// public IP addresses in plain text. The server delivered them to every member
// syncing the room and kept them in the timeline forever, so a silent bystander
// could read the addresses of every pair in a call, and anybody who joined the
// channel months later could page /messages back and harvest the lot.
//
// Every assertion below is about one of two things — WHO a signalling event
// reaches, and HOW LONG it survives — plus the negative space around them: the
// paths that must NOT have changed. The sync engine had two subtle
// stream-position bugs fixed just before this work (5cbbe78, c40ef93), and a
// recipient filter is exactly the kind of change that can quietly reintroduce
// them, so the token and long-poll behaviour is asserted here too rather than
// left to test_sync_latency.cpp alone.

#include <gtest/gtest.h>

#include "auth/LocalAuth.h"
#include "core/Config.h"
#include "core/InstanceSecret.h"
#include "store/CallSignalling.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "sync/SyncToken.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#include <sqlite3.h>

#include <nlohmann/json.hpp>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// A candidate batch shaped like the one the client actually sends
// (client/src/voice/CallSignalCodec.h::buildCandidates), addresses and all. The
// literal IPs are what the tests search for: an assertion that some event is
// absent is weaker than an assertion that this specific string never reaches
// that user.
json candidates_content(const std::string& to, const std::string& host_ip,
                        const std::string& public_ip) {
    return json{
        {"call_id", "call-1"},
        {"to", to},
        {"version", 1},
        {"candidates", json::array({
            json{{"candidate", "candidate:1 1 udp 2130706431 " + host_ip +
                               " 54321 typ host"},
                 {"sdpMid", "0"},
                 {"sdpMLineIndex", 0}},
            json{{"candidate", "candidate:2 1 udp 1694498815 " + public_ip +
                               " 54321 typ srflx"},
                 {"sdpMid", "0"},
                 {"sdpMLineIndex", 0}},
        })},
    };
}

class CallPrivacyTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        config.server_name = "test";
        sync = std::make_unique<SyncEngine>(*store, config);

        for (const auto* u : {"@alice:test", "@bob:test", "@carol:test"}) {
            store->create_user(u, hash_password("pass", 10));
        }

        room_id = generate_room_id("test");
        store->create_room(room_id, "@alice:test");
        store->set_membership(room_id, "@alice:test", "join");
        store->set_membership(room_id, "@bob:test", "join");
        store->set_membership(room_id, "@carol:test", "join");
    }

    // `ts` defaults to now so the retention sweep does not eat the fixture out
    // from under a delivery test.
    std::string send_signal(const std::string& sender, const std::string& type,
                            const json& content, int64_t ts = 0) {
        auto id = generate_event_id("test");
        store->insert_event(id, room_id, sender, type, std::nullopt, content.dump(),
                            ts ? ts : now_ms());
        return id;
    }

    std::string send_message(const std::string& sender, const std::string& body) {
        auto id = generate_event_id("test");
        store->insert_event(id, room_id, sender, std::string(event_type::kRoomMessage),
                            std::nullopt, json{{"msgtype", "m.text"}, {"body", body}}.dump(),
                            now_ms());
        return id;
    }

    // Everything `user` is offered in the timeline of an incremental sync.
    std::vector<RoomEvent> timeline_since(const std::string& user,
                                          const std::string& since) {
        auto resp = sync->handle_sync(user, since, 0);
        auto it = resp.rooms.join.find(room_id);
        if (it == resp.rooms.join.end()) return {};
        return it->second.timeline.events;
    }

    static bool contains_event(const std::vector<RoomEvent>& events,
                               const std::string& event_id) {
        for (const auto& e : events) {
            if (e.event_id == event_id) return true;
        }
        return false;
    }

    // Does any event in this batch mention `needle` anywhere in its content?
    // Deliberately blunt: the question is "did this address reach this user",
    // not "did it reach them through the field I was thinking of".
    static bool leaks(const std::vector<RoomEvent>& events, const std::string& needle) {
        for (const auto& e : events) {
            if (e.content.data.dump().find(needle) != std::string::npos) return true;
        }
        return false;
    }

    // The stream position inside an opaque next_batch.
    //
    // next_batch stopped being "s<N>" because that integer was the global
    // stream head and therefore an activity oracle over every room on the
    // server (finding 10, docs/audit-data-2026-09.md). The token-monotonicity
    // assertions below are still about the POSITION, so they re-open the token
    // with the same key the engine used rather than being weakened into
    // string comparisons. Nothing outside a test may do this.
    int64_t token_pos(const std::string& user_id, const std::string& token) {
        auto key = sync_token::derive_key(get_or_create_instance_secret(*store),
                                          config.server_name);
        auto pos = sync_token::parse(key, user_id, token);
        EXPECT_TRUE(pos.has_value()) << "not a token this server minted: " << token;
        return pos.value_or(-1);
    }

    std::unique_ptr<SqliteStore> store;
    Config config;
    std::unique_ptr<SyncEngine> sync;
    std::string room_id;
};

} // namespace

// ── The classification rule ──────────────────────────────────────────────

TEST(CallSignallingRule, TheFiveSignallingTypesAreRecognised) {
    EXPECT_TRUE(is_call_signalling_type(event_type::kCallInvite));
    EXPECT_TRUE(is_call_signalling_type(event_type::kCallAnswer));
    EXPECT_TRUE(is_call_signalling_type(event_type::kCallCandidates));
    EXPECT_TRUE(is_call_signalling_type(event_type::kCallHangup));
    EXPECT_TRUE(is_call_signalling_type(event_type::kCallNegotiate));
}

// The voice ROSTER is not signalling. It says who is in the call, it carries no
// address, and the member list cannot be drawn without it — hiding it from the
// room would break the feature while protecting nothing.
TEST(CallSignallingRule, TheRosterStateEventIsNotSignalling) {
    EXPECT_FALSE(is_call_signalling_type(event_type::kCallMember));
    EXPECT_FALSE(is_call_signalling_type(event_type::kRoomMessage));
    EXPECT_FALSE(is_call_signalling_type(event_type::kRoomMember));
}

TEST(CallSignallingRule, AnAddresseeIsOnlyReadFromSignalling) {
    const auto content = json{{"to", "@bob:test"}}.dump();
    EXPECT_EQ(call_signal_addressee(event_type::kCallInvite, content), "@bob:test");
    // A message with a stray `to` key is still a message.
    EXPECT_FALSE(call_signal_addressee(event_type::kRoomMessage, content).has_value());
    EXPECT_FALSE(call_signal_addressee(event_type::kCallMember, content).has_value());
}

// Every doubtful case answers "not addressed", which downstream means "behave
// exactly as before". Getting this backwards would drop signalling on the floor
// and leave calls that never connect, with nothing in a log to explain it.
TEST(CallSignallingRule, AnythingUnparseableIsTreatedAsUnaddressed) {
    EXPECT_FALSE(call_signal_addressee(event_type::kCallInvite, "{not json").has_value());
    EXPECT_FALSE(call_signal_addressee(event_type::kCallInvite, "[]").has_value());
    EXPECT_FALSE(call_signal_addressee(event_type::kCallInvite, "{}").has_value());
    EXPECT_FALSE(call_signal_addressee(event_type::kCallInvite,
                                       json{{"to", 42}}.dump()).has_value());
    EXPECT_FALSE(call_signal_addressee(event_type::kCallInvite,
                                       json{{"to", ""}}.dump()).has_value());
}

// ── Delivery: /sync ──────────────────────────────────────────────────────

// The headline. Alice and Bob negotiate; Carol is in the channel and must never
// see either of their addresses.
TEST_F(CallPrivacyTest, AThirdMembersSyncNeverContainsAnotherPairsCandidates) {
    const std::string carol_since = sync->handle_sync("@carol:test", "", 0).next_batch;
    const std::string bob_since = sync->handle_sync("@bob:test", "", 0).next_batch;

    const auto ev = send_signal("@alice:test", std::string(event_type::kCallCandidates),
                                candidates_content("@bob:test", "192.168.7.31", "203.0.113.9"));

    const auto carol = timeline_since("@carol:test", carol_since);
    EXPECT_FALSE(contains_event(carol, ev));
    EXPECT_FALSE(leaks(carol, "192.168.7.31")) << "Carol was handed Alice's LAN address";
    EXPECT_FALSE(leaks(carol, "203.0.113.9")) << "Carol was handed Alice's public address";

    // ...and the addressee still gets it, which is the whole point of the event.
    const auto bob = timeline_since("@bob:test", bob_since);
    EXPECT_TRUE(contains_event(bob, ev));
    EXPECT_TRUE(leaks(bob, "203.0.113.9"));
}

TEST_F(CallPrivacyTest, TheSenderStillSeesItsOwnSignalling) {
    const std::string since = sync->handle_sync("@alice:test", "", 0).next_batch;
    const auto ev = send_signal("@alice:test", std::string(event_type::kCallInvite),
                                json{{"call_id", "c"}, {"to", "@bob:test"},
                                     {"offer", {{"type", "offer"}, {"sdp", "v=0"}}}});
    EXPECT_TRUE(contains_event(timeline_since("@alice:test", since), ev));
}

TEST_F(CallPrivacyTest, EveryOneOfTheFiveTypesIsScopedToThePair) {
    const std::string carol_since = sync->handle_sync("@carol:test", "", 0).next_batch;
    const std::string bob_since = sync->handle_sync("@bob:test", "", 0).next_batch;

    std::vector<std::string> ids;
    for (auto type : {event_type::kCallInvite, event_type::kCallAnswer,
                      event_type::kCallCandidates, event_type::kCallHangup,
                      event_type::kCallNegotiate}) {
        ids.push_back(send_signal("@alice:test", std::string(type),
                                  json{{"call_id", "c"}, {"to", "@bob:test"},
                                       {"secret", "10.1.2.3"}}));
    }

    const auto carol = timeline_since("@carol:test", carol_since);
    const auto bob = timeline_since("@bob:test", bob_since);
    for (const auto& id : ids) {
        EXPECT_FALSE(contains_event(carol, id));
        EXPECT_TRUE(contains_event(bob, id));
    }
    EXPECT_FALSE(leaks(carol, "10.1.2.3"));
}

// m.call.member is the roster, and the roster is for the room. Losing this is
// how a "privacy fix" turns into "nobody can see who is in the call".
TEST_F(CallPrivacyTest, TheRosterStateEventStillReachesTheWholeRoom) {
    const std::string since = sync->handle_sync("@carol:test", "", 0).next_batch;
    auto id = generate_event_id("test");
    store->insert_event(id, room_id, "@alice:test", std::string(event_type::kCallMember),
                        "@alice:test", json{{"active", true}}.dump(), now_ms());
    EXPECT_TRUE(contains_event(timeline_since("@carol:test", since), id));
}

// A client too old to name a recipient cannot be delivered to selectively — the
// server would have to guess, and a wrong guess is a call that silently never
// connects. So it keeps exactly today's behaviour, including today's exposure.
TEST_F(CallPrivacyTest, UnaddressedSignallingKeepsTheOldBehaviour) {
    const std::string since = sync->handle_sync("@carol:test", "", 0).next_batch;
    const auto ev = send_signal("@alice:test", std::string(event_type::kCallCandidates),
                                json{{"call_id", "c"}, {"candidates", json::array()}});
    EXPECT_TRUE(contains_event(timeline_since("@carol:test", since), ev));
}

// The gap case the TTL exists for: Bob's client is between polls when the
// invite is sent, and must still receive it when it comes back — on an
// incremental sync and on a fresh initial one, because a client that restarted
// has no `since` token to offer.
TEST_F(CallPrivacyTest, TheAddresseeReceivesAnInviteSentWhileItWasBetweenSyncs) {
    const std::string bob_since = sync->handle_sync("@bob:test", "", 0).next_batch;

    // Bob is not polling. Two candidate batches and an invite land.
    const auto invite = send_signal("@alice:test", std::string(event_type::kCallInvite),
                                    json{{"call_id", "c"}, {"to", "@bob:test"},
                                         {"offer", {{"type", "offer"}, {"sdp", "v=0"}}}});
    const auto cands = send_signal("@alice:test", std::string(event_type::kCallCandidates),
                                   candidates_content("@bob:test", "10.0.0.5", "198.51.100.2"));

    const auto resumed = timeline_since("@bob:test", bob_since);
    EXPECT_TRUE(contains_event(resumed, invite));
    EXPECT_TRUE(contains_event(resumed, cands));

    // And for a client that came back with no token at all.
    auto fresh = sync->handle_sync("@bob:test", "", 0);
    ASSERT_EQ(fresh.rooms.join.count(room_id), 1u);
    EXPECT_TRUE(contains_event(fresh.rooms.join[room_id].timeline.events, invite));

    // Carol's initial sync is the paging-back attack in its simplest form.
    auto carol = sync->handle_sync("@carol:test", "", 0);
    ASSERT_EQ(carol.rooms.join.count(room_id), 1u);
    EXPECT_FALSE(contains_event(carol.rooms.join[room_id].timeline.events, invite));
    EXPECT_FALSE(leaks(carol.rooms.join[room_id].timeline.events, "198.51.100.2"));
}

// ── Delivery: /messages history ──────────────────────────────────────────

// The other half of the leak, and the worse half: production held 4,518 of
// these going back to April, so a member who joined in September could page the
// channel's history and read addresses from calls they were never part of.
// History is excluded for EVERYBODY — including the two participants, who have
// no use for a five-month-old candidate batch.
TEST_F(CallPrivacyTest, SignallingIsAbsentFromMessageHistoryForEveryone) {
    send_message("@alice:test", "before");
    const auto ev = send_signal("@alice:test", std::string(event_type::kCallCandidates),
                                candidates_content("@bob:test", "172.16.4.9", "192.0.2.77"));
    send_message("@alice:test", "after");

    auto [events, next] = store->get_room_events_paginated(room_id, 50, "b");
    EXPECT_FALSE(contains_event(events, ev));
    EXPECT_FALSE(leaks(events, "172.16.4.9"));
    EXPECT_FALSE(leaks(events, "192.0.2.77"));
    // The messages around it are untouched — this is a filter, not a purge of
    // the timeline.
    EXPECT_EQ(events.size(), 2u) << "the two ordinary messages should remain";
}

TEST_F(CallPrivacyTest, UnaddressedSignallingRemainsInHistory) {
    const auto ev = send_signal("@alice:test", std::string(event_type::kCallHangup),
                                json{{"call_id", "c"}, {"reason", "user_hangup"}});
    auto [events, next] = store->get_room_events_paginated(room_id, 50, "b");
    EXPECT_TRUE(contains_event(events, ev));
}

// The viewer-scoped variant is the initial-sync path. Same pair rule as /sync.
TEST_F(CallPrivacyTest, TheViewerScopedPageShowsOnlyTheViewersOwnSignalling) {
    const auto to_bob = send_signal("@alice:test", std::string(event_type::kCallInvite),
                                    json{{"call_id", "c"}, {"to", "@bob:test"}});
    const auto to_carol = send_signal("@bob:test", std::string(event_type::kCallInvite),
                                      json{{"call_id", "d"}, {"to", "@carol:test"}});

    auto bob = store->get_room_events_paginated(room_id, 50, "b", std::nullopt,
                                                std::string("@bob:test")).first;
    EXPECT_TRUE(contains_event(bob, to_bob));   // addressed to Bob
    EXPECT_TRUE(contains_event(bob, to_carol)); // sent by Bob
    auto carol = store->get_room_events_paginated(room_id, 50, "b", std::nullopt,
                                                  std::string("@carol:test")).first;
    EXPECT_FALSE(contains_event(carol, to_bob));
    EXPECT_TRUE(contains_event(carol, to_carol));
}

// ── Search, unread and notification counts ───────────────────────────────

// These are all "it was already true, keep it true". Signalling has never been
// indexed or counted, because every one of those paths keys off m.room.message
// — but that is an accident of where the filters happen to sit, and the next
// person to widen one of them needs a test that says no.
TEST_F(CallPrivacyTest, SignallingIsNeverSearchIndexed) {
    send_signal("@alice:test", std::string(event_type::kCallCandidates),
                candidates_content("@bob:test", "192.168.1.55", "203.0.113.200"));
    // Search the address itself, and a word from the wire format. A hit on
    // either would mean a bystander could find a call by searching for an IP.
    // Control first: the index is live in this build, so an empty result below
    // means "not indexed" rather than "search is switched off".
    send_message("@alice:test", "a findable message");
    ASSERT_TRUE(store->search_index_available());
    EXPECT_FALSE(store->search_messages({room_id}, {"findable"}, {}, 20, 0, true)
                     .hits.empty());

    for (const char* term : {"192.168.1.55", "203.0.113.200", "candidate", "srflx"}) {
        auto r = store->search_messages({room_id}, {term}, {}, 20, 0, true);
        EXPECT_TRUE(r.hits.empty()) << "signalling is searchable for '" << term << "'";
        EXPECT_EQ(r.total, 0);
    }
}

TEST_F(CallPrivacyTest, SignallingDoesNotRaiseAnUnreadCount) {
    store->set_read_marker("@carol:test", room_id, store->get_current_stream_position());
    const int before = store->count_unread("@carol:test", room_id);

    for (auto type : {event_type::kCallInvite, event_type::kCallCandidates,
                      event_type::kCallHangup}) {
        send_signal("@alice:test", std::string(type),
                    json{{"call_id", "c"}, {"to", "@bob:test"}});
    }
    EXPECT_EQ(store->count_unread("@carol:test", room_id), before);
    EXPECT_EQ(store->count_unread_mentions("@carol:test", room_id), 0);

    // Control: a real message still counts, so the assertion above is not
    // passing because counting is broken outright.
    send_message("@alice:test", "hello");
    EXPECT_EQ(store->count_unread("@carol:test", room_id), before + 1);
}

// ── Retention ────────────────────────────────────────────────────────────

TEST_F(CallPrivacyTest, ExpiredSignallingIsDeletedAndFreshSignallingIsNot) {
    const int64_t now = now_ms();
    const auto old_ev = send_signal("@alice:test", std::string(event_type::kCallCandidates),
                                    candidates_content("@bob:test", "10.9.9.9", "203.0.113.4"),
                                    now - limits::kCallSignallingTtlMs - 1000);
    const auto fresh_ev = send_signal("@alice:test", std::string(event_type::kCallCandidates),
                                      candidates_content("@bob:test", "10.9.9.8", "203.0.113.5"),
                                      now);
    const auto msg = send_message("@alice:test", "an old message is not swept");

    EXPECT_EQ(store->prune_expired_call_signalling(now), 1);

    EXPECT_FALSE(store->get_event_by_id(old_ev).has_value());
    EXPECT_TRUE(store->get_event_by_id(fresh_ev).has_value());
    EXPECT_TRUE(store->get_event_by_id(msg).has_value());

    // Idempotent: a second sweep with nothing newly expired removes nothing.
    EXPECT_EQ(store->prune_expired_call_signalling(now), 0);
}

// Unaddressed signalling is left alone here too. It is visible to the room
// either way, so deleting it would be a behaviour change with no privacy gain
// — and it is the one case where the server cannot be sure what it is holding.
TEST_F(CallPrivacyTest, UnaddressedSignallingIsNotSwept) {
    const int64_t now = now_ms();
    const auto ev = send_signal("@alice:test", std::string(event_type::kCallCandidates),
                                json{{"call_id", "c"}},
                                now - limits::kCallSignallingTtlMs - 60000);
    EXPECT_EQ(store->prune_expired_call_signalling(now), 0);
    EXPECT_TRUE(store->get_event_by_id(ev).has_value());
}

// A sweep must not rewind the stream. The head lives in server_meta and is
// never re-derived from MAX(stream_position) — if that ever changes, every
// client holding a token above the deleted row stops receiving anything, which
// is precisely the defect migration v4 exists to prevent.
TEST_F(CallPrivacyTest, SweepingDoesNotRewindTheStreamHead) {
    const int64_t now = now_ms();
    send_signal("@alice:test", std::string(event_type::kCallCandidates),
                candidates_content("@bob:test", "10.0.0.1", "203.0.113.1"),
                now - limits::kCallSignallingTtlMs - 1000);
    const int64_t head = store->get_current_stream_position();

    // Minted BEFORE the sweep — that is the token whose survival is the point.
    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;
    ASSERT_EQ(token_pos("@bob:test", since), head);

    ASSERT_EQ(store->prune_expired_call_signalling(now), 1);
    EXPECT_EQ(store->get_current_stream_position(), head);

    auto resp = sync->handle_sync("@bob:test", since, 0);
    EXPECT_EQ(resp.next_batch, since);
    EXPECT_EQ(token_pos("@bob:test", resp.next_batch), head);
}

// ── Sync-token and long-poll semantics ───────────────────────────────────
//
// The filter drops rows from the scan, and the scan's result is what next_batch
// is built from. Get this wrong and a bystander's token stops advancing, which
// the desktop client reads as a broken endpoint and answers with an escalating
// backoff — up to a minute of added latency on the NEXT real message. That is
// the failure 5cbbe78 / c40ef93 fixed, so it gets its own assertions here.

TEST_F(CallPrivacyTest, ABystandersTokenStillAdvancesPastFilteredSignalling) {
    const std::string before = sync->handle_sync("@carol:test", "", 0).next_batch;
    for (int i = 0; i < 5; ++i) {
        send_signal("@alice:test", std::string(event_type::kCallCandidates),
                    candidates_content("@bob:test", "10.0.0.1", "203.0.113.1"));
    }
    auto resp = sync->handle_sync("@carol:test", before, 0);
    EXPECT_TRUE(resp.rooms.join.empty()) << "Carol was shown a pair's signalling";
    EXPECT_NE(resp.next_batch, before)
        << "Carol's sync token stalled on events she cannot see; the desktop "
           "client treats an unmoved next_batch as no progress and backs off";
    EXPECT_GT(token_pos("@carol:test", resp.next_batch),
              token_pos("@carol:test", before));
}

// Monotonic, and never past an event the scan did not offer. This is the
// invariant c40ef93 restored; the filter must not chip at it.
TEST_F(CallPrivacyTest, TheAddresseesTokenNeverPassesAnUndeliveredEvent) {
    std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;
    int64_t last = token_pos("@bob:test", since);

    for (int i = 0; i < 4; ++i) {
        send_signal("@alice:test", std::string(event_type::kCallCandidates),
                    candidates_content("@bob:test", "10.0.0.1", "203.0.113.1"));
        send_message("@alice:test", "chat " + std::to_string(i));

        auto resp = sync->handle_sync("@bob:test", since, 0);
        const int64_t pos = token_pos("@bob:test", resp.next_batch);
        EXPECT_GE(pos, last) << "next_batch went backwards";
        last = pos;
        since = resp.next_batch;
        ASSERT_EQ(resp.rooms.join.count(room_id), 1u);
        EXPECT_EQ(resp.rooms.join[room_id].timeline.events.size(), 2u);
    }

    // Nothing left over: a full re-poll at the final token is empty.
    EXPECT_TRUE(sync->handle_sync("@bob:test", since, 0).rooms.join.empty());
}

// A parked poll belonging to the addressee must wake on their invite, not ride
// out its timeout — the filter sits inside the scan the long poll re-runs, so
// this is the path that would break if it were applied after the wait instead.
TEST_F(CallPrivacyTest, AParkedPollWakesOnAnInviteAddressedToIt) {
    const std::string since = sync->handle_sync("@bob:test", "", 0).next_batch;

    std::atomic<bool> got_it{false};
    std::thread bob([&] {
        auto resp = sync->handle_sync("@bob:test", since, 5000);
        auto it = resp.rooms.join.find(room_id);
        got_it = it != resp.rooms.join.end() && !it->second.timeline.events.empty();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    send_signal("@alice:test", std::string(event_type::kCallInvite),
                json{{"call_id", "c"}, {"to", "@bob:test"}});
    sync->notify_new_event();

    const auto t0 = std::chrono::steady_clock::now();
    bob.join();
    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    EXPECT_TRUE(got_it.load());
    EXPECT_LT(waited, 2000) << "the addressee's poll sat out its timeout holding "
                               "an invite that was already committed";
}

// And a bystander's poll must NOT be ended by it. Returning a reply that
// carries nothing is the cheap-looking failure that costs the client a backoff.
TEST_F(CallPrivacyTest, ABystandersPollIsNotEndedByAnotherPairsSignalling) {
    const std::string since = sync->handle_sync("@carol:test", "", 0).next_batch;

    std::atomic<bool> returned_early{false};
    std::thread carol([&] {
        auto resp = sync->handle_sync("@carol:test", since, 700);
        returned_early = !resp.rooms.join.empty();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    send_signal("@alice:test", std::string(event_type::kCallCandidates),
                candidates_content("@bob:test", "10.0.0.1", "203.0.113.1"));
    sync->notify_new_event();

    carol.join();
    EXPECT_FALSE(returned_early.load());
}

// ── Migration ────────────────────────────────────────────────────────────

// The purge that runs on an existing deployment. Built by hand at v16 with
// signalling already in the table, then migrated — because the interesting case
// is a database that predates the column, which is the only kind production has.
// Rewind a real database to the v16 shape — user_version back to 16, the column
// emptied, the index dropped — and let initialize() migrate it. That is exactly
// what production hands this step: rows written before the column existed, and
// therefore rows whose signal_to is NULL until the backfill fills it in.
void rewind_to_v16(const std::string& path) {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
    auto run = [&](const char* sql) {
        char* err = nullptr;
        ASSERT_EQ(sqlite3_exec(db, sql, nullptr, nullptr, &err), SQLITE_OK)
            << (err ? err : "");
        sqlite3_free(err);
    };
    run("UPDATE events SET signal_to = NULL");
    run("DROP INDEX IF EXISTS idx_events_signal_expiry");
    run("PRAGMA user_version = 16");
    sqlite3_close(db);
}

TEST(CallSignallingMigration, V17BackfillsThenPurgesWhatIsAlreadyStored) {
    const std::string path =
        (std::filesystem::temp_directory_path() /
         ("bsfchat-v17-" + std::to_string(now_ms()) + ".db")).string();
    std::filesystem::remove(path);

    const int64_t now = now_ms();
    const int64_t old_ts = now - 90LL * 24 * 3600 * 1000; // ~April, like production
    std::string old_id, fresh_id, legacy_id, message_id;
    std::string room;

    {
        SqliteStore store(path);
        store.initialize();
        // Rewind to v16 is not possible, and faking it would test the fake. What
        // matters is the data half: rows that predate the column are rows whose
        // signal_to is NULL, which is what a v16 database hands v17. The
        // migration's UPDATE is what fills them in, and it is re-run below.
        store.create_user("@alice:test", hash_password("pass", 10));
        store.create_user("@bob:test", hash_password("pass", 10));
        room = generate_room_id("test");
        store.create_room(room, "@alice:test");
        store.set_membership(room, "@alice:test", "join");
        store.set_membership(room, "@bob:test", "join");

        old_id = generate_event_id("test");
        store.insert_event(old_id, room, "@alice:test",
                           std::string(event_type::kCallCandidates), std::nullopt,
                           json{{"call_id", "c"}, {"to", "@bob:test"},
                                {"candidates", json::array()}}.dump(), old_ts);
        fresh_id = generate_event_id("test");
        store.insert_event(fresh_id, room, "@alice:test",
                           std::string(event_type::kCallCandidates), std::nullopt,
                           json{{"call_id", "c"}, {"to", "@bob:test"},
                                {"candidates", json::array()}}.dump(), now);
        legacy_id = generate_event_id("test");
        store.insert_event(legacy_id, room, "@alice:test",
                           std::string(event_type::kCallHangup), std::nullopt,
                           json{{"call_id", "c"}}.dump(), old_ts);
        message_id = generate_event_id("test");
        store.insert_event(message_id, room, "@alice:test",
                           std::string(event_type::kRoomMessage), std::nullopt,
                           json{{"msgtype", "m.text"}, {"body", "hi"}}.dump(), old_ts);
    }

    rewind_to_v16(path);

    {
        SqliteStore store(path);
        store.initialize(); // runs migrations, including v17's sweep
        EXPECT_FALSE(store.get_event_by_id(old_id).has_value())
            << "a five-month-old addressed candidate batch survived the upgrade";
        EXPECT_TRUE(store.get_event_by_id(fresh_id).has_value())
            << "signalling inside the delivery window was deleted";
        EXPECT_TRUE(store.get_event_by_id(legacy_id).has_value())
            << "unaddressed signalling must keep its old behaviour";
        EXPECT_TRUE(store.get_event_by_id(message_id).has_value())
            << "the migration deleted a chat message";
    }

    std::filesystem::remove(path);
}

// ── Audit data-path finding 21: the one read of `events` that forgot the rule ──
//
// Every other read of the table carries the addressee clause. get_state_events
// does not, and its result is broadcast to every joined member through /sync
// and served whole by GET /rooms/{id}/state. A signalling event written WITH a
// state_key therefore escapes the filter that the rest of the table obeys.
//
// Writing one needs kManageChannels (PUT /rooms/{id}/state/...), so this is
// not a plain-member leak, and the prune removes the row within two minutes.
// It is fixed anyway because the value of the rule is that it is uniform: a
// reader checking "can signalling reach a bystander" should be able to answer
// from the table's read paths without having to know which of them is the
// exception.
TEST_F(CallPrivacyTest, AddressedSignallingWithAStateKeyIsNotInRoomState) {
    auto id = generate_event_id("test");
    store->insert_event(id, room_id, "@alice:test", std::string(event_type::kCallCandidates),
                        std::string("somekey"),
                        json{{"to", "@bob:test"}, {"candidate", "192.168.1.50 54321 typ host"}}.dump(),
                        now_ms());

    auto state = store->get_state_events(room_id);
    for (const auto& ev : state) {
        EXPECT_NE(ev.event_id, id)
            << "addressed signalling reached room state, where every member reads it";
        EXPECT_EQ(ev.content.data.dump().find("192.168.1.50"), std::string::npos)
            << "an ICE candidate address reached room state";
    }
}

// The control. Unaddressed signalling keeps today's behaviour everywhere else
// (see UnaddressedSignallingRemainsInHistory), so it must keep it here too —
// otherwise the fix is "drop all signalling from state", which is a different
// and larger change than the one being made.
TEST_F(CallPrivacyTest, UnaddressedSignallingWithAStateKeyStaysInRoomState) {
    auto id = generate_event_id("test");
    store->insert_event(id, room_id, "@alice:test", std::string(event_type::kCallCandidates),
                        std::string("somekey"),
                        json{{"candidate", "192.168.1.50 54321 typ host"}}.dump(), now_ms());

    bool found = false;
    for (const auto& ev : store->get_state_events(room_id)) {
        if (ev.event_id == id) found = true;
    }
    EXPECT_TRUE(found);
}

// And the roster must survive, because it is a state event whose whole job is
// to reach the room. If the filter were written against event TYPE rather than
// against signal_to this test would fail.
TEST_F(CallPrivacyTest, TheRosterStateEventSurvivesTheStateFilter) {
    auto id = generate_event_id("test");
    store->insert_event(id, room_id, "@alice:test", std::string(event_type::kCallMember),
                        std::string("@alice:test"), json{{"active", true}}.dump(), now_ms());

    bool found = false;
    for (const auto& ev : store->get_state_events(room_id)) {
        if (ev.event_id == id) found = true;
    }
    EXPECT_TRUE(found) << "the voice roster was filtered out of room state";
}
