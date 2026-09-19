// The /sync token, and the volume-and-timing oracle it used to be.
//
// `next_batch` was "s" + the RAW GLOBAL stream position — one counter shared by
// every room on the deployment. Any authenticated account could poll
// `GET /sync?timeout=0` on a loop, read the integer, and subtract the events it
// was actually shown; the remainder is the exact count of events that happened
// in rooms it cannot see, timestamped to the second. Finding 10 of
// docs/audit-data-2026-09.md.
//
// The properties under test, in the order they appear below:
//   1. OPACITY. A delivered token carries no readable stream position, and two
//      accounts at the same position get different tokens. This is the finding.
//   2. DETERMINISM. The same (user, position) always mints the same string, so
//      an idle reply still reads as "no progress" to the client's backoff, and
//      a token that advances still reads as progress. Breaking this is the
//      mirror-image regression and would cost every idle client a 60 s poll
//      interval.
//   3. COMPATIBILITY. The legacy "s<N>" form is still accepted on the way in,
//      so the upgrade does not force every client on the deployment into a full
//      initial sync at once.
//   4. THE PRIMITIVE. Round trip, user binding, domain separation from the
//      media-ticket key, and rejection of every malformed spelling.
//
// Section 4 is the only part that names sync_token:: directly; sections 1–3 go
// through SyncEngine, so they compile and can be confirmed FAILING against the
// pre-fix tree.

#include <gtest/gtest.h>

#include "api/MediaTicket.h"
#include "auth/LocalAuth.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/InstanceSecret.h"
#include "identity/Nickname.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "sync/SyncToken.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <cctype>
#include <filesystem>
#include <string>
#include <vector>

using namespace bsfchat;
using json = nlohmann::json;

namespace {

std::string temp_db_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() /
            ("bsfchat-synctoken-" + name + "-" + std::to_string(::getpid()) + ".db")).string();
}

void remove_db(const std::string& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path + "-wal");
    std::filesystem::remove(path + "-shm");
}

ServerRole role(const std::string& id, int position, permission::Flags flags) {
    ServerRole r;
    r.id = id;
    r.name = id;
    r.position = position;
    r.permissions = flags;
    return r;
}

struct Fixture {
    std::string db_path;
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::unique_ptr<SyncEngine> sync;
    int64_t ts = 1000;

    explicit Fixture(const std::string& name) {
        db_path = temp_db_path(name);
        remove_db(db_path);
        config = Config::defaults();
        config.server_name = "test";
        store = std::make_unique<SqliteStore>(db_path);
        store->initialize();
        sync = std::make_unique<SyncEngine>(*store, config);
        seed_roles();
    }

    ~Fixture() {
        sync.reset();
        store.reset();
        remove_db(db_path);
    }

    void seed_roles() {
        ServerRolesContent content;
        content.roles.push_back(
            role(permission::role_id::kEveryone, 0, permission::kEveryoneDefault));
        content.roles.push_back(role(permission::role_id::kAdmin, 100, permission::kAllFlags));
        json j;
        to_json(j, content);
        store->set_server_state(std::string(event_type::kServerRoles), "", "@server:test",
                                j.dump());
    }

    std::string add_user(const std::string& localpart,
                         const std::vector<std::string>& extra_roles = {}) {
        std::string uid = "@" + localpart + ":test";
        store->create_user(uid, hash_password("password", 10));
        store->store_access_token("token-" + localpart, uid, "dev");
        MemberRolesContent c;
        c.role_ids = {std::string(permission::role_id::kEveryone)};
        for (const auto& r : extra_roles) c.role_ids.push_back(r);
        json j;
        to_json(j, c);
        store->set_server_state(std::string(event_type::kMemberRoles), uid, "@server:test",
                                j.dump());
        return uid;
    }

    void state(const std::string& room_id, const std::string& sender, std::string_view type,
               const std::string& state_key, const json& content) {
        store->insert_event(generate_event_id("test"), room_id, sender, std::string(type),
                            state_key, content.dump(), ++ts);
    }

    std::string add_room(const std::string& creator, const std::string& name) {
        auto room_id = generate_room_id("test");
        store->create_room(room_id, creator);
        store->set_membership(room_id, creator, std::string(membership::kJoin));
        state(room_id, creator, event_type::kRoomName, "", json{{"name", name}});
        return room_id;
    }

    // Force-joined, which on this data model is what every account is to every
    // channel — membership carries no privacy meaning, VIEW_CHANNEL does.
    void join(const std::string& room_id, const std::string& user_id) {
        store->set_membership(room_id, user_id, std::string(membership::kJoin));
        state(room_id, user_id, event_type::kRoomMember, user_id,
              member_event_content(*store, user_id, std::string(membership::kJoin)));
    }

    void message(const std::string& room_id, const std::string& sender, const std::string& body) {
        store->insert_event(generate_event_id("test"), room_id, sender,
                            std::string(event_type::kRoomMessage), std::nullopt,
                            json{{"msgtype", "m.text"}, {"body", body}}.dump(), ++ts);
    }

    // A deny override on @everyone is how a private channel is spelled here.
    void hide_from_everyone(const std::string& room_id) {
        ChannelPermissionOverride ov;
        ov.allow = 0;
        ov.deny = permission::kViewChannel;
        json j;
        to_json(j, ov);
        state(room_id, "@server:test", event_type::kChannelPermissions,
              std::string("role:") + permission::role_id::kEveryone, j);
    }

    int64_t head() { return store->get_current_stream_position(); }
};

// Is the whole token an "s<digits>" number a client could do arithmetic on?
// This is the property the finding is about; everything else below pins the
// shape that replaced it.
bool is_numeric_token(const std::string& token) {
    if (token.size() < 2 || token[0] != 's') return false;
    for (size_t i = 1; i < token.size(); ++i) {
        if (token[i] < '0' || token[i] > '9') return false;
    }
    return true;
}

// "t_" + 32 lowercase hex, and nothing else. Fixed width matters on its own:
// a variable-length token leaks the magnitude of what is inside it.
//
// Deliberately NOT "does the token contain the head's decimal digits" — a hex
// string of 32 characters contains any given two-digit decimal about one time
// in eight by chance, which would be a coin-flip test.
::testing::AssertionResult IsOpaque(const std::string& token) {
    if (token.size() != 34 || token.compare(0, 2, "t_") != 0) {
        return ::testing::AssertionFailure() << "not an opaque token: " << token;
    }
    for (size_t i = 2; i < token.size(); ++i) {
        const char c = token[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return ::testing::AssertionFailure() << "not lowercase hex: " << token;
        }
    }
    return ::testing::AssertionSuccess();
}

// Bit distance between two same-width tokens. An additive or XOR encoding of
// the counter moves one or two bits between adjacent positions; a permutation
// moves about half of them.
int token_distance(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return -1;
    auto nib = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    int bits = 0;
    for (size_t i = 2; i < a.size(); ++i) {
        int x = nib(a[i]) ^ nib(b[i]);
        while (x) { bits += x & 1; x >>= 1; }
    }
    return bits;
}

} // namespace

// ══ 1. Opacity — the finding ══════════════════════════════════════════════

// The oracle, stated as directly as it can be: a user who can see ONE room
// polls, and the number they are handed back is the head of a stream that spans
// every room on the server.
TEST(SyncTokenOpacity, ADeliveredTokenDoesNotCarryTheGlobalStreamPosition) {
    Fixture f("opacity-head");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto open_room = f.add_room(admin, "general");
    f.join(open_room, bob);

    auto secret_room = f.add_room(admin, "leadership");
    f.join(secret_room, bob);
    f.hide_from_everyone(secret_room);
    for (int i = 0; i < 5; ++i) f.message(secret_room, admin, "not for bob");

    const auto token = f.sync->handle_sync(bob, "", 0).next_batch;
    ASSERT_GT(f.head(), 0);
    EXPECT_FALSE(is_numeric_token(token))
        << "next_batch is still an integer a client can subtract: " << token;
    EXPECT_TRUE(IsOpaque(token));
}

// The oracle is the DELTA, not the value — which is why every order-preserving
// or delta-preserving encoding fails. Bob polls, five events land in a channel
// he cannot see, Bob polls again: the pair of tokens must not let him count
// them.
TEST(SyncTokenOpacity, TwoConsecutiveTokensDoNotCountInvisibleActivity) {
    Fixture f("opacity-delta");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");

    auto open_room = f.add_room(admin, "general");
    f.join(open_room, bob);
    auto secret_room = f.add_room(admin, "leadership");
    f.join(secret_room, bob);
    f.hide_from_everyone(secret_room);

    const auto before = f.sync->handle_sync(bob, "", 0).next_batch;
    const int64_t head_before = f.head();
    for (int i = 0; i < 5; ++i) f.message(secret_room, admin, "not for bob");
    const auto after = f.sync->handle_sync(bob, before, 0).next_batch;
    ASSERT_EQ(f.head() - head_before, 5) << "the fixture did not produce the invisible events";

    // The token still has to MOVE — a stalled token is read as a broken
    // endpoint by the client's backoff, which is the regression the raw counter
    // was introduced to fix. It just must not move by a readable amount.
    EXPECT_NE(after, before) << "the token stalled on events the caller cannot see";
    ASSERT_TRUE(IsOpaque(before));
    ASSERT_TRUE(IsOpaque(after));
    const int distance = token_distance(before, after);
    EXPECT_GT(distance, 30)
        << "five invisible events moved the token by only " << distance
        << " of 128 bits; the delta is still readable";
}

// Two accounts polling the same quiet server sit at the same stream position.
// If the token is a pure function of that position, their tokens are equal —
// which is an oracle in its own right: it confirms to each of them what the
// other's view of the global stream is, and it makes a token trivially
// transplantable.
TEST(SyncTokenOpacity, TwoUsersAtTheSamePositionGetDifferentTokens) {
    Fixture f("opacity-peruser");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");

    auto room = f.add_room(admin, "general");
    f.join(room, alice);
    f.join(room, bob);
    f.message(room, admin, "hello both");

    const auto alice_token = f.sync->handle_sync(alice, "", 0).next_batch;
    const auto bob_token = f.sync->handle_sync(bob, "", 0).next_batch;
    EXPECT_NE(alice_token, bob_token);
}

// The one /sync reply that does not go through build_incremental_sync at all.
// A server-banned account is answered immediately from the global head, so it
// was handed the oracle in its purest form — the raw counter, with no events to
// subtract from it.
TEST(SyncTokenOpacity, ABannedAccountsReplyIsOpaqueToo) {
    Fixture f("opacity-banned");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto mallory = f.add_user("mallory");

    auto room = f.add_room(admin, "general");
    f.join(room, mallory);
    f.message(room, admin, "chatter");
    f.store->set_server_ban(mallory, admin, "spam");

    auto resp = f.sync->handle_sync(mallory, "", 0);
    ASSERT_TRUE(resp.rooms.join.empty());
    EXPECT_FALSE(is_numeric_token(resp.next_batch)) << resp.next_batch;
    EXPECT_TRUE(IsOpaque(resp.next_batch));
}

// An initial sync's prev_batch is NOT this token and deliberately keeps the
// numeric form: it is the position of an event in ONE room the caller has just
// been shown, and /rooms/{id}/messages?from= consumes it. Pinned here so a
// later sweep does not "fix" it and break back-pagination.
TEST(SyncTokenOpacity, PrevBatchKeepsTheNumericRoomScopedForm) {
    Fixture f("opacity-prevbatch");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(admin, "general");
    f.join(room, bob);
    for (int i = 0; i < 60; ++i) f.message(room, admin, "m" + std::to_string(i));

    auto resp = f.sync->handle_sync(bob, "", 0);
    ASSERT_EQ(resp.rooms.join.count(room), 1u);
    const auto& tl = resp.rooms.join[room].timeline;
    ASSERT_TRUE(tl.limited) << "not enough history to produce a prev_batch";
    ASSERT_TRUE(tl.prev_batch.has_value());
    EXPECT_TRUE(is_numeric_token(*tl.prev_batch)) << *tl.prev_batch;
}

// ══ 2. Determinism — the mirror-image regression ══════════════════════════

// SyncBackoff reads a fast reply whose next_batch did not move as an endpoint
// answering 200 unconditionally, and punishes it with an escalating delay up to
// a minute. A token carrying a nonce or a timestamp would trip that on every
// idle poll.
TEST(SyncTokenStability, AnIdleReplyReturnsTheIdenticalToken) {
    Fixture f("stable-idle");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(admin, "general");
    f.join(room, bob);

    const auto first = f.sync->handle_sync(bob, "", 0).next_batch;
    const auto second = f.sync->handle_sync(bob, first, 0).next_batch;
    const auto third = f.sync->handle_sync(bob, second, 0).next_batch;
    EXPECT_EQ(second, first) << "an idle reply must not look like progress";
    EXPECT_EQ(third, first);
}

TEST(SyncTokenStability, ARealEventStillMovesTheToken) {
    Fixture f("stable-progress");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(admin, "general");
    f.join(room, bob);

    auto token = f.sync->handle_sync(bob, "", 0).next_batch;
    for (int i = 0; i < 4; ++i) {
        f.message(room, admin, "m" + std::to_string(i));
        auto resp = f.sync->handle_sync(bob, token, 0);
        ASSERT_EQ(resp.rooms.join.count(room), 1u);
        EXPECT_EQ(resp.rooms.join[room].timeline.events.size(), 1u)
            << "the token did not resume exactly where it left off";
        EXPECT_NE(resp.next_batch, token);
        token = resp.next_batch;
    }
    EXPECT_TRUE(f.sync->handle_sync(bob, token, 0).rooms.join.empty())
        << "a re-poll at the final token replayed events";
}

// ══ 3. Compatibility — the upgrade path ═══════════════════════════════════

// Every client persists its sync token across restarts. If the upgraded server
// refused the old spelling, every client on every deployment would do a full
// initial sync the moment the operator restarted, which is the one cost an
// opaque token must not have.
TEST(SyncTokenCompat, ALegacyNumericTokenIsStillAccepted) {
    Fixture f("compat-legacy");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(admin, "general");
    f.join(room, bob);
    f.message(room, admin, "before the upgrade");

    // What bob's client persisted against the old server.
    const auto legacy = "s" + std::to_string(f.head());

    f.message(room, admin, "after the upgrade");
    auto resp = f.sync->handle_sync(bob, legacy, 0);
    ASSERT_EQ(resp.rooms.join.count(room), 1u);
    ASSERT_EQ(resp.rooms.join[room].timeline.events.size(), 1u)
        << "a resumed legacy token did not resume — this is a full re-sync for every client";
    EXPECT_EQ(resp.rooms.join[room].timeline.events[0].content.data.value("body", ""),
              "after the upgrade");

    // And the reply hands back the new form, so the client is migrated after
    // exactly one poll.
    EXPECT_FALSE(is_numeric_token(resp.next_batch)) << resp.next_batch;
}

TEST(SyncTokenCompat, AGarbageTokenIsAFullReplayRatherThanAnError) {
    Fixture f("compat-garbage");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(admin, "general");
    f.join(room, bob);
    f.message(room, admin, "hello");

    // Long-standing behaviour, kept: /sync has never answered 400 for a
    // malformed token, and a hardening pass is the wrong place to start.
    for (const auto& junk : {"banana", "t_", "t_zzzz", "s", "s-1", "t_0123"}) {
        auto resp = f.sync->handle_sync(bob, junk, 0);
        EXPECT_EQ(resp.rooms.join.count(room), 1u) << "junk token: " << junk;
    }
}

// A token names the account it was minted for. Presenting someone else's is
// not a way to read their stream — the scan is membership-joined and
// VIEW_CHANNEL-filtered for the CALLER regardless — but it should not be
// honoured as a position either.
TEST(SyncTokenCompat, ATokenMintedForAnotherAccountIsNotHonoured) {
    Fixture f("compat-crossuser");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto alice = f.add_user("alice");
    auto bob = f.add_user("bob");
    auto room = f.add_room(admin, "general");
    f.join(room, alice);
    f.join(room, bob);
    f.message(room, admin, "one");

    const auto alice_token = f.sync->handle_sync(alice, "", 0).next_batch;
    f.message(room, admin, "two");

    // Bob replays his own visible history from the start rather than resuming
    // at Alice's position. Never Alice's events: there are none he cannot
    // already see, and the scan is his either way.
    auto resp = f.sync->handle_sync(bob, alice_token, 0);
    ASSERT_EQ(resp.rooms.join.count(room), 1u);
    EXPECT_GT(resp.rooms.join[room].timeline.events.size(), 1u)
        << "Alice's token resumed Bob's stream at Alice's position";
}

// ══ 4. The primitive ══════════════════════════════════════════════════════

namespace {
// 64 hex characters, the shape get_or_create_instance_secret() produces.
const std::string kSecret = std::string(32, 'a') + std::string(32, 'b');
} // namespace

TEST(SyncTokenPrimitive, RoundTrips) {
    auto k = sync_token::derive_key(kSecret, "test");
    for (int64_t pos : {int64_t(0), int64_t(1), int64_t(42), int64_t(1) << 20,
                        int64_t(1) << 40, int64_t(9007199254740993)}) {
        const auto token = sync_token::mint(k, "@alice:test", pos);
        EXPECT_EQ(token.size(), 34u) << token;
        EXPECT_EQ(token.compare(0, 2, "t_"), 0) << token;
        auto back = sync_token::parse(k, "@alice:test", token);
        ASSERT_TRUE(back.has_value()) << token;
        EXPECT_EQ(*back, pos);
    }
}

TEST(SyncTokenPrimitive, IsDeterministic) {
    auto k = sync_token::derive_key(kSecret, "test");
    EXPECT_EQ(sync_token::mint(k, "@alice:test", 99), sync_token::mint(k, "@alice:test", 99));
}

// The property that rules out `pos + k` and `pos XOR k`: adjacent positions
// must not produce adjacent tokens. A permutation scrambles about half the
// bits; an additive or XOR encoding scrambles one or two.
TEST(SyncTokenPrimitive, AdjacentPositionsAreUnrelated) {
    auto k = sync_token::derive_key(kSecret, "test");
    const auto a = sync_token::mint(k, "@alice:test", 1000);
    const auto b = sync_token::mint(k, "@alice:test", 1001);
    const int distance = token_distance(a, b);
    EXPECT_GT(distance, 30) << "adjacent positions differ in only " << distance
                            << " of 128 bits — the delta is still readable";
    EXPECT_LT(distance, 98) << "suspiciously anti-correlated: " << distance;
}

TEST(SyncTokenPrimitive, BindsToTheUser) {
    auto k = sync_token::derive_key(kSecret, "test");
    const auto token = sync_token::mint(k, "@alice:test", 77);
    EXPECT_NE(token, sync_token::mint(k, "@bob:test", 77));
    EXPECT_FALSE(sync_token::parse(k, "@bob:test", token).has_value());
    EXPECT_TRUE(sync_token::parse(k, "@alice:test", token).has_value());
}

TEST(SyncTokenPrimitive, RejectsMalformedSpellings) {
    auto k = sync_token::derive_key(kSecret, "test");
    const auto good = sync_token::mint(k, "@alice:test", 12345);

    // One flipped hex digit.
    auto flipped = good;
    flipped[10] = (flipped[10] == 'a') ? 'b' : 'a';
    EXPECT_FALSE(sync_token::parse(k, "@alice:test", flipped).has_value());

    // Uppercase: the same bytes, a second spelling. Rejected, because the
    // client's no-progress guard compares tokens as STRINGS.
    std::string upper = good;
    for (size_t i = 2; i < upper.size(); ++i) upper[i] = std::toupper(upper[i]);
    EXPECT_NE(upper, good);
    EXPECT_FALSE(sync_token::parse(k, "@alice:test", upper).has_value());

    EXPECT_FALSE(sync_token::parse(k, "@alice:test", good.substr(0, 33)).has_value());
    EXPECT_FALSE(sync_token::parse(k, "@alice:test", good + "0").has_value());
    EXPECT_FALSE(sync_token::parse(k, "@alice:test", "t_" + std::string(32, 'z')).has_value());
    EXPECT_FALSE(sync_token::parse(k, "@alice:test", "").has_value());

    // A different key is a different permutation.
    auto other = sync_token::derive_key(std::string(64, 'c'), "test");
    EXPECT_FALSE(sync_token::parse(other, "@alice:test", good).has_value());
}

TEST(SyncTokenPrimitive, AcceptsTheLegacyNumericFormAndNothingElseNumeric) {
    auto k = sync_token::derive_key(kSecret, "test");
    EXPECT_EQ(sync_token::parse(k, "@alice:test", "s0").value_or(-1), 0);
    EXPECT_EQ(sync_token::parse(k, "@alice:test", "s12345").value_or(-1), 12345);
    // The legacy form is not user-bound; it never was.
    EXPECT_EQ(sync_token::parse(k, "@bob:test", "s12345").value_or(-1), 12345);

    for (const auto& bad : {"s", "s-1", "s1x", "sabc", "s 1", "s99999999999999999999", "1234"}) {
        EXPECT_FALSE(sync_token::parse(k, "@alice:test", bad).has_value()) << bad;
    }
}

// Same instance secret, same server name, different subsystem: the salts must
// make these unrelated keys. If they were equal, a media ticket's MAC and a
// sync token would be two constructions over one key.
TEST(SyncTokenPrimitive, IsDomainSeparatedFromTheMediaTicketKey) {
    EXPECT_NE(sync_token::derive_key(kSecret, "test"),
              media_ticket::derive_key(kSecret, "test"));
}

TEST(SyncTokenPrimitive, ServerNameIsPartOfTheDerivation) {
    EXPECT_NE(sync_token::derive_key(kSecret, "a.example"),
              sync_token::derive_key(kSecret, "b.example"));
}

TEST(SyncTokenPrimitive, RefusesAnEmptySecret) {
    EXPECT_THROW(sync_token::derive_key("", "test"), std::runtime_error);
}

// ══ The key's home ════════════════════════════════════════════════════════

// One secret per database, shared by every subsystem that derives from it, and
// stable across restarts — which is what makes a token outlive a redeploy.
TEST(InstanceSecret, IsGeneratedOnceAndSharedAcrossSubsystems) {
    Fixture f("secret-shared");
    auto admin = f.add_user("admin", {std::string(permission::role_id::kAdmin)});
    auto bob = f.add_user("bob");
    auto room = f.add_room(admin, "general");
    f.join(room, bob);

    // Minting a sync token is enough to bring the secret into existence.
    const auto token = f.sync->handle_sync(bob, "", 0).next_batch;
    ASSERT_FALSE(is_numeric_token(token));

    auto stored = f.store->get_meta("server.instance_secret");
    ASSERT_TRUE(stored.has_value());
    EXPECT_GE(stored->size(), 32u);
    EXPECT_EQ(get_or_create_instance_secret(*f.store), *stored)
        << "a second caller generated a different secret";

    // A second engine over the same database reads the same token back, which
    // is the restart case.
    SyncEngine other(*f.store, f.config);
    EXPECT_EQ(other.handle_sync(bob, "", 0).next_batch, token);
}

TEST(InstanceSecret, TwoDeploymentsDoNotShareASecret) {
    Fixture a("secret-a");
    Fixture b("secret-b");
    EXPECT_NE(get_or_create_instance_secret(*a.store), get_or_create_instance_secret(*b.store));
}
