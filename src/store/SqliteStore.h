#pragma once

#include "store/MediaReferences.h"

#include <bsfchat/MatrixTypes.h>
#include <sqlite3.h>

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <cstdint>

namespace bsfchat {

// Default access-token lifetime: 90 days.
//
// Deliberately long. The shipped desktop client persists a single access token
// and (as of this change) has no background refresh, so a short lifetime would
// silently log people out mid-session — exactly the failure this must not
// introduce. Every successful authentication slides the expiry forward (see
// get_user_by_token), so an actively-used session never lapses, while a token
// that stops being used dies 90 days later. Admins can shorten it with
// `auth.access_token_lifetime_days`.
inline constexpr int64_t kDefaultAccessTokenLifetimeMs = 90LL * 24 * 60 * 60 * 1000;

// How stale a bot token's `last_used_at` is allowed to get before a request
// refreshes it.
//
// A bot token never expires and therefore never slides, so the expiry-renewal
// write that keeps `last_used_at` current for a human session never fires for
// one. Without a timer of its own, a bot's "last seen" would read as never, and
// the question it answers — which of these integrations is still alive, and
// which has been dead for months — has no other source. A minute is far finer
// than anyone inspecting a bot list needs, and coarse enough that a bot making
// hundreds of requests a second costs one write, not hundreds.
inline constexpr int64_t kBotLastSeenIntervalMs = 60LL * 1000;

// When a session's refresh token stops being redeemable: one further lifetime
// after its access token lapses (180 days idle at the default 90-day lifetime).
//
// Longer than the access token, because refreshing a lapsed access token is
// what a refresh token is for — but FINITE, which it was not before
// security-audit-2026-09 finding S3: redemption never read the expiry at all,
// so a refresh token lifted from an abandoned device worked forever. Derived
// from the row's own expires_at and lifetime_ms rather than stored, so it
// needed no schema change and every existing row got a deadline the moment
// this shipped. Because expires_at slides while the session is used, so does
// this: an active session never meets it.
constexpr int64_t refresh_deadline_ms(int64_t expires_at, int64_t lifetime_ms) {
    return expires_at + lifetime_ms;
}

// Sentinel "user id" a room-wide (`@room`) mention is stored under. Safe as a
// sentinel because every real Matrix user id is "@localpart:server" and so
// always contains a colon — no account can ever collide with it, which means a
// client cannot manufacture a room-wide mention by claiming to mention a user
// literally called "@room".
inline constexpr const char* kRoomMentionSentinel = "@room";

// Sentinel "user id" a ROLE mention is stored under: "@role/" + the role id.
// Safe for the same reason @room is — it carries no colon, so UserId::parse
// rejects it and no account can collide with it. (A role id containing a colon
// would break that, so the send path refuses one; see parse_mentions.)
//
// A role mention is ONE row, exactly like @room, never one row per holder. The
// fan-out happens on the READ side, by widening the set of sentinels a reader
// matches to include the roles they hold. See the mention section in the .cpp.
inline constexpr const char* kRoleMentionPrefix = "@role/";

inline std::string role_mention_sentinel(const std::string& role_id) {
    return std::string(kRoleMentionPrefix) + role_id;
}

// Account-data types this server treats as more than an opaque blob.
//
// Here rather than in the protocol headers for the reason the media-ticket path
// literal in Server.cpp is: adding a constant there moves this change into a
// second repository that has to merge first. Fold it in the next time protocol
// changes for another reason. The string itself is fixed by the Matrix spec,
// which is what makes a local copy safe — it is not this server's to choose.
namespace account_data_type {

// The block list: {"ignored_users": {"@spammer:example": {}}}.
//
// Named here because SqliteStore has to recognise it — it is the one type whose
// write also rewrites an index (see set_account_data). Everything else in
// account_data is stored and returned untouched.
inline constexpr const char* kIgnoredUserList = "m.ignored_user_list";

// The key inside that document holding the map of ignored user ids.
inline constexpr const char* kIgnoredUsersKey = "ignored_users";

} // namespace account_data_type

class SqliteStore {
public:
    explicit SqliteStore(const std::string& db_path);
    ~SqliteStore();

    SqliteStore(const SqliteStore&) = delete;
    SqliteStore& operator=(const SqliteStore&) = delete;

    void initialize();

    // Users
    bool create_user(const std::string& user_id, const std::string& password_hash);
    // The stored password hash for a HUMAN account, or nullopt.
    //
    // The query filters on `users.kind = 'user'`, and that filter is the entire
    // mechanism by which a bot cannot log in with a password. It is deliberately
    // here, in the one place every password path already funnels through
    // (m.login.password, and the re-authentication stage of the password-change
    // endpoint), rather than as an `if (is_bot(...))` at each of those call sites.
    //
    // The difference is what happens to the NEXT password path somebody writes.
    // A check at the call site is a thing to remember; a WHERE clause here is a
    // thing you cannot get past — a future handler that asks this store for a
    // bot's hash in order to verify something against it is handed nullopt, and
    // every existing caller already treats nullopt as "this account cannot
    // authenticate that way" and refuses. "Bots have an empty password_hash" is
    // then a second, independent line of defence rather than the only one.
    // The same clause-you-cannot-get-past argument covers `deactivated_at IS
    // NULL` (schema v29): a deactivated account is handed nullopt here, and
    // every existing caller already reads nullopt as "this account cannot
    // authenticate that way".
    std::optional<std::string> get_password_hash(const std::string& user_id);
    // Replaces the stored hash (used to transparently upgrade a hash that was
    // generated with a weaker cost factor at the next successful login).
    void update_password_hash(const std::string& user_id, const std::string& password_hash);
    bool user_exists(const std::string& user_id);

    // Lookalike-username policy. The user id of an account whose localpart
    // folds to the same confusable skeleton (identity/Localpart.h), or nullopt.
    //
    // Registration consults this; login never does. The rule is enforced at the
    // point a name is CHOSEN, because an account that already exists under a
    // colliding name predates the rule and refusing its owner a login would be
    // a far worse outcome than the impersonation the rule prevents.
    std::optional<std::string> find_user_by_localpart_skeleton(const std::string& skeleton);

    // How many existing accounts would collide if the rule were applied
    // retroactively, and how many distinct lookalike groups they form. Reported
    // by the v20 migration so an operator can see what their server already
    // contains; never acted on.
    struct SkeletonCollisions {
        int groups = 0;
        int accounts = 0;
    };
    SkeletonCollisions count_localpart_skeleton_collisions();
    bool username_exists(const std::string& localpart);

    // ── Linked identity-provider identities ───────────────────────────────
    //
    // One human, one account. See migrate_v28 for the shape of the table and
    // why (issuer, subject) rather than subject alone; see AuthHandler's
    // handle_link_identity for the two-sided proof that must be presented
    // before anything here is written.
    struct LinkedIdentity {
        std::string issuer;
        std::string subject;
        std::string user_id;
        int64_t linked_at = 0;
        std::string linked_by;  // the account that performed the link
    };

    // The account an identity signs in as, or nullopt when it has never been
    // linked. THIS IS THE READ THE LOGIN PATH MAKES, before it derives an
    // `oidc_<sub>` id, and it is the whole of the feature from the outside: a
    // linked identity lands in the account its owner chose, an unlinked one
    // keeps the old behaviour exactly.
    std::optional<std::string> find_linked_user(const std::string& issuer,
                                                const std::string& subject);

    // Records the link. Returns false when this identity is ALREADY linked —
    // to any account, including this one — and writes nothing.
    //
    // The refusal is the table's primary key doing the work rather than a
    // read-then-write in the handler, so two concurrent link attempts for the
    // same identity cannot both believe they succeeded. A link is not an
    // update: re-pointing an identity at a different account is a distinct and
    // much more dangerous operation (it would move an identity off an account
    // its owner may no longer control), and it deliberately has no path here.
    bool link_identity(const std::string& issuer, const std::string& subject,
                       const std::string& user_id, const std::string& linked_by,
                       int64_t when_ms);

    // Every identity linked to one account, oldest first. Used to answer the
    // caller's own GET; never exposed for another user id.
    std::vector<LinkedIdentity> list_linked_identities(const std::string& user_id);

    // Access tokens
    //
    // Tokens are never stored in the clear — only hash_access_token() digests
    // are persisted, so every method here takes the plaintext and hashes it
    // internally. The caller keeps the plaintext only long enough to hand it
    // back to the client.
    //
    // `lifetime_ms` is both the initial validity window and the window the
    // expiry slides forward by while the session stays in use. Pass a
    // `refresh_token` to attach a refresh secret to the session.
    //
    // `family_id` groups a login with every session that later rotates out of
    // it, so a replayed refresh token can revoke the whole chain (see
    // revoke_family_for_replayed_refresh_token). Empty means "a new login":
    // a fresh family id is generated. A refresh MUST pass the family id it got
    // from consume_refresh_token, or the chain is broken and reuse detection
    // silently stops covering everything after that point.
    void store_access_token(const std::string& token, const std::string& user_id,
                            const std::string& device_id,
                            int64_t lifetime_ms = kDefaultAccessTokenLifetimeMs,
                            const std::optional<std::string>& refresh_token = std::nullopt,
                            const std::string& family_id = {});
    // Resolves a token to its user. Returns nullopt when the token is unknown
    // OR expired (an expired row is dropped on the way out). Renews the
    // expiry of a live token that is past the halfway point of its lifetime,
    // so a client that keeps syncing is never logged out.
    std::optional<std::string> get_user_by_token(const std::string& token);
    void delete_access_token(const std::string& token);
    // Revokes every session for the account: /logout/all, and a server-wide ban.
    //
    // This deletes ROWS, and a refresh token is the `refresh_hash` column of the
    // row its access token lives on — so both die together and there is no way to
    // revoke one and leave the other alive. That is the reason a ban reuses this
    // rather than growing a revocation path of its own: a ban that killed the
    // access token but left a refresh token able to mint a replacement would be
    // theatre. Returns the number of sessions revoked; 0 is an ordinary result
    // (an account that never logged in, or is already logged out).
    int delete_all_tokens_for_user(const std::string& user_id);
    // "Log out everywhere but here": used by the password-change flow so the
    // caller isn't logged out of the session they just re-authenticated in.
    // Returns the number of sessions revoked.
    int delete_other_tokens_for_user(const std::string& user_id,
                                     const std::string& keep_token);

    struct TokenSession {
        std::string user_id;
        std::string device_id;
        // The rotation chain this session belongs to. Only populated by
        // consume_refresh_token, which is the one caller that has to pass it on.
        std::string family_id;
    };
    // Single-use redemption of a refresh token: returns the session it belonged
    // to and removes the row, so the caller can issue a fresh access/refresh
    // pair. Rotation-on-use means a stolen refresh token stops working as soon
    // as the legitimate client refreshes. Expiry of the ACCESS token does not
    // block redemption — refreshing an expired access token is the whole point —
    // but the refresh token's own deadline does (refresh_deadline_ms): past it
    // the row is reaped and nothing is returned.
    std::optional<TokenSession> consume_refresh_token(const std::string& refresh_token);
    // Reuse detection, to be called when consume_refresh_token() returned
    // nothing: if this refresh token was one we have ALREADY redeemed, the
    // chain has been copied and every session descended from that login is
    // revoked. Returns the number of sessions revoked, or 0 when the token was
    // simply never ours (a typo, an expired session, a probe).
    //
    // Rotation on its own does not make theft unprofitable: whichever side
    // redeems second is the one that gets logged out, and if that is the real
    // user they will just sign in again while the thief keeps a live session
    // that no longer shares a secret with anyone. Revoking the family is the
    // only response available, because at this point the two branches are
    // indistinguishable — which is also why it is deliberately loud in the log.
    int revoke_family_for_replayed_refresh_token(const std::string& refresh_token);
    // The (user, device) a live access token belongs to. Used where the device
    // matters and not just the identity — e.g. recording which device a pusher
    // was registered from. Does NOT slide the expiry; callers have already
    // authenticated via get_user_by_token().
    std::optional<TokenSession> get_session_by_token(const std::string& token);
    // Expiry timestamp (ms) of a live token, for `expires_in_ms` responses.
    std::optional<int64_t> get_token_expiry(const std::string& token);

    // Users
    //
    // Bots ARE users and are included here, deliberately. RoleBootstrap walks
    // this list to give every account a bsfchat.member.roles row, and a bot that
    // is skipped would hold no role assignment at all — which is the opposite of
    // the contract that a bot goes through the ordinary roles machinery. The
    // place bots are excluded is auto-join, and that exclusion lives in
    // AutoJoin's own funnel where it can be read next to its reasoning, not in a
    // filter here that every unrelated caller would silently inherit.
    std::vector<std::string> list_all_users();

    // ── Account deactivation (schema v29) ───────────────────────────────────
    //
    // Apple App Store guideline 5.1.1(v) requires an app that creates accounts
    // to let a person delete theirs from inside the app, and Matrix spells that
    // as POST /_matrix/client/v3/account/deactivate.
    //
    // DEACTIVATION IS NOT ROW DELETION, and the distinction is the whole design.
    // A user id appears on every message that account ever sent, in every
    // membership row, in the audit log and in anyone else's DM history. Deleting
    // the row would either break those references or mean rewriting other
    // people's conversations, which is not the departing user's to rewrite —
    // the same position Matrix, Element and every other server on the protocol
    // take. What goes is the account's identity and its ability to act:
    //
    //   * every access and refresh token (it can no longer authenticate);
    //   * its password hash (nothing can sign in as it again, and the hash is
    //     the one piece of credential material the account leaves behind);
    //   * display name, avatar and per-server nickname (its personal data);
    //   * account data, including the ignore list, and push registrations;
    //   * linked identity-provider identities, so the identity is free to sign
    //     in as a fresh account rather than being permanently bound to a dead
    //     one;
    //   * membership of every room, left as an ordinary 'leave'.
    //
    // Returns false when the account was already deactivated, so the caller can
    // write exactly one audit record however many times the button is pressed —
    // the same idempotency shape as deactivate_bot, and taken from the UPDATE's
    // own WHERE clause rather than from a read followed by a write.
    //
    // The caller emits the m.room.member leave events and wakes the syncs; this
    // writes the rows. See AuthHandler::handle_deactivate_account.
    bool deactivate_user(const std::string& user_id, int64_t when_ms);

    // When the account was deactivated, or nullopt for a live one (and for an
    // account that does not exist — callers here always have an authenticated
    // user id, and "no such account" and "not deactivated" lead to the same
    // refusal at every site that asks).
    std::optional<int64_t> get_user_deactivated_at(const std::string& user_id);

    // ── Bot accounts ────────────────────────────────────────────────────────
    //
    // A bot is a row in `users` with kind = 'bot' plus a row here holding the
    // metadata that has no home on `users`. See migrate_v19 for why each piece
    // is shaped the way it is.

    struct BotRecord {
        std::string user_id;
        std::string display_name;
        std::string description;
        // ADVISORY. Who to go and ask about this bot — nothing more.
        //
        // It participates in NO authorization decision, deliberately, and this
        // comment exists so nobody has to read BotHandler to find that out. A
        // field that looks like access control but is not is worse than no field,
        // because a reviewer sees "owner" in a listing and assumes something is
        // enforcing it.
        //
        // Why rank and not ownership is the control: the danger in handing out a
        // bot's credential is acquiring the bot's ROLES, which is a question
        // about the actor's rank relative to the bot, not about who filled in a
        // form. Owner-as-a-bypass would reintroduce the escalation outright — a
        // low-ranked owner could rotate a bot that was later granted
        // Administrator. Owner-as-an-extra-restriction would add no security the
        // rank check does not already provide, and would strand every bot whose
        // owner has left the company, unless admins bypassed it, at which point
        // it would be decorative anyway.
        std::string owner_id;
        int64_t created_at = 0;
        std::string created_by;
        // Set once, when the bot is deactivated. A timestamp rather than a flag:
        // "when did this stop being live" is the question an incident actually
        // asks, and a boolean cannot answer it.
        std::optional<int64_t> deactivated_at;
        // Newest last_used_at across the bot's live tokens, or nullopt when it
        // has never authenticated. Only meaningful for a bot, because ordinary
        // access tokens write last_used_at only when the expiry slides (see
        // get_user_by_token) whereas bot tokens refresh it on a coarse timer.
        std::optional<int64_t> last_seen_at;
    };

    // Creates the users row (kind = 'bot', EMPTY password hash) and the bots row
    // in ONE transaction. Both or neither: a users row without its bots row would
    // be an account nobody can list, rotate or deactivate, and a bots row without
    // its users row cannot exist at all (the foreign key forbids it). Returns
    // false when the user id is already taken.
    //
    // No token is minted here — the caller does that with rotate_bot_token(), so
    // there is exactly one code path that issues bot credentials.
    bool create_bot(const BotRecord& bot);

    // True when `user_id` names an existing account with kind = 'bot'. False for
    // a human and for an id that does not exist.
    bool is_bot(const std::string& user_id);

    std::optional<BotRecord> get_bot(const std::string& user_id);
    // Every bot, newest first. Unpaginated: the list is bounded by how many bots
    // an operator has deliberately created, not by traffic, and the endpoint that
    // serves it already requires MANAGE_BOTS.
    std::vector<BotRecord> list_bots();

    // Issues `token` as the bot's credential and invalidates every token it had,
    // in ONE transaction.
    //
    // Delete-then-insert under a single lock and a single transaction, rather
    // than two calls, because a rotation that is not atomic has a window in which
    // the old token and the new one are both live — and the reason an operator
    // rotates is usually that the old one leaked. Returns false when `user_id` is
    // not a bot, so this can never mint a non-expiring credential for a person.
    //
    // The row is written with lifetime_ms = 0 and token_kind = 'bot': never
    // expires, never slides. Only the hash is stored; the caller shows the
    // plaintext to the operator exactly once and then forgets it.
    bool rotate_bot_token(const std::string& user_id, const std::string& token,
                          const std::string& device_id);

    // Marks the bot deactivated and revokes every token it holds, in one
    // transaction. Returns true when this call is what deactivated it, false when
    // it was already deactivated or is not a bot — so the caller can be
    // idempotent without racing a second deactivation.
    //
    // Does NOT delete the account. The user id stays taken (its messages keep
    // resolving to a name) and stays unavailable for reuse, and the record of who
    // created it and when survives — which is the point of an audited lifecycle.
    bool deactivate_bot(const std::string& user_id, int64_t when_ms);

    // Rooms
    // `is_direct` marks a Matrix DM. Direct rooms are permanently excluded
    // from list_public_rooms() and from every auto-join path, so no
    // server-wide sweep can ever make a DM readable by the whole instance.
    std::string create_room(const std::string& room_id, const std::string& creator,
                            bool is_direct = false);
    bool room_exists(const std::string& room_id);
    bool is_direct_room(const std::string& room_id);
    // Every direct room `user_id` is joined to, as (room_id, peer) pairs. The
    // peer is reported whatever their own membership is: a DM the other side
    // has left is still that person's conversation. This is what /sync turns
    // into m.direct.
    std::vector<std::pair<std::string, std::string>> get_direct_rooms(const std::string& user_id);
    // The direct room both users are currently joined to AND WHOSE ONLY TWO
    // JOINED MEMBERS THEY ARE, if any — oldest first, so the answer is stable
    // when legacy duplicates exist. The member count is part of the question,
    // not an optimisation: see the implementation for the confused deputy it
    // closes.
    std::optional<std::string> find_direct_room(const std::string& user_a,
                                                const std::string& user_b);
    // Remove a room and everything that references it (events, members,
    // read markers). Destructive; intended for admin-driven channel deletion.
    void delete_room(const std::string& room_id);
    std::vector<std::string> get_joined_rooms(const std::string& user_id);
    // Rooms the user has been invited to and has not answered. The complement
    // of get_joined_rooms for /sync's purposes: those two together are every
    // room a client should be told about.
    std::vector<std::string> get_invited_rooms(const std::string& user_id);
    bool is_room_member(const std::string& room_id, const std::string& user_id);
    // Public, non-category, non-direct rooms — i.e. rooms every user on the
    // instance is expected to be a member of.
    std::vector<std::string> list_public_rooms();
    // Does this server hold ANY room — channel, category, DM, or a channel
    // everyone has since left?
    //
    // The deliberately widest of the room predicates on this class, and the
    // width is the point: bootstrap_default_channels (core/FirstRun.h) uses it
    // to answer "has this deployment ever been used?", and every narrower
    // question would answer a different one. A server whose only room is a
    // category has had an admin arranging a sidebar; one whose only room is a
    // DM has had two people talking in it. Neither is a new server, and
    // neither should have channels invented underneath it.
    bool has_any_room();
    // Non-category, non-direct rooms.
    std::vector<std::string> list_all_non_category_rooms();
    // Non-category, non-direct rooms that carry no bsfchat.room.type state
    // event. Those predate the Discord-like channel model and are the only
    // rooms the one-time legacy-publicize migration is allowed to touch.
    std::vector<std::string> list_legacy_untyped_rooms();

    // One room as the channel directory needs it: the sidebar fields, resolved
    // from state in the same query that finds the room.
    //
    // `type` is bsfchat.room.type, empty on a legacy room that predates it.
    // `parent_id` and `sort_order` come from bsfchat.room.category; parent_id
    // is empty for an uncategorized channel. NO topic, NO member count, NO
    // creator: this row is built to be rendered in a picker, and every field
    // that is not needed to render one is a field a directory call would
    // otherwise hand to anybody who asks.
    struct RoomDirectoryRow {
        std::string room_id;
        std::string name;
        std::string type;
        std::string parent_id;
        int sort_order = 0;
    };

    // Every non-direct room on the server, CATEGORIES INCLUDED, with the fields
    // above. UNFILTERED — this is the candidate set, not an answer. The caller
    // must run every row past auth/RoomVisibility before showing it to anyone;
    // see list_public_rooms' own history for what happens when a store-level
    // room list is mistaken for an access decision.
    //
    // Direct rooms are excluded IN SQL rather than by the caller, and that is
    // load-bearing rather than tidy: PermissionsEngine::compute() deliberately
    // clears channel overrides on a DM, so a DM that reached a VIEW_CHANNEL
    // filter would PASS it for every user on the server (@everyone carries
    // VIEW_CHANNEL by default) and the directory would publish every private
    // conversation on the instance. Membership is the privacy boundary for a
    // DM and this list cannot express that, so a DM must never enter it.
    //
    // One statement, not one per room: the correlated subqueries ride
    // idx_events_room_type_state exactly as a per-room get_state_event would,
    // but the whole sweep takes the store mutex once instead of 3N times.
    std::vector<RoomDirectoryRow> list_room_directory_rows();

    // Room membership
    void set_membership(const std::string& room_id, const std::string& user_id, const std::string& membership);
    // Note: returns "leave" when there is NO row, so it cannot tell "never a
    // member" from "kicked". Use find_membership when that distinction matters.
    std::string get_membership(const std::string& room_id, const std::string& user_id);
    // The membership row if one exists, nullopt if the user has never had one.
    std::optional<std::string> find_membership(const std::string& room_id,
                                               const std::string& user_id);
    std::vector<std::pair<std::string, std::string>> get_room_members(const std::string& room_id);
    // Every (room_id, membership) row this user has, in any state. This is the
    // list a server-wide ban has to be projected across, and it is deliberately
    // NOT get_joined_rooms(): a ban must also reach rooms where the user is
    // merely invited, and an unban must find the rooms where they are banned.
    // It is also the query the CLIENT could not do — it looped over the rooms its
    // own sync had surfaced, which is why unsynced channels kept the user.
    std::vector<std::pair<std::string, std::string>> get_user_memberships(const std::string& user_id);

    // One phantom membership: a room_members row whose user_id names no account.
    struct OrphanMembership {
        std::string room_id;
        std::string user_id;
        std::string membership;
        int64_t updated_at = 0;
    };
    // Every row in room_members for an account that does not exist.
    //
    // These are not supposed to be possible. They became possible because
    // room_members.user_id has no REFERENCES users(user_id) — unlike
    // access_tokens, bots and linked_identities, which all constrain theirs —
    // and three request paths wrote the column from a caller-supplied id
    // without checking it (see kNoSuchAccount in RoomHandler.cpp). The paths
    // are closed; a database that was running before they were closed can still
    // hold the rows, and nothing on the read side would ever mention them: they
    // are reported in the roster, counted in joined-member counts, and walked by
    // every projection over room_members, as if they were people.
    //
    // A REPORT, deliberately, and there is no matching delete. Removing one
    // correctly is not a DELETE: other members' clients have already rendered
    // the arrival and cached the roster, so the row has to go out as a
    // membership event as well, and deciding that on an operator's behalf is
    // exactly the kind of hand-written repair AdminCli.h exists to stop. The
    // first thing an operator needs is to know whether they have any.
    //
    // Ordered by room then user so a repeated run is diffable.
    std::vector<OrphanMembership> list_orphan_memberships();

    struct MalformedDirectRoom {
        std::string room_id;
        std::string creator;
        size_t joined = 0;
    };
    // Every room marked `is_direct` whose JOINED membership is not exactly two.
    //
    // A direct message is a conversation between exactly two people; that is
    // the sentence PermissionsEngine::compute(), list_room_directory_rows(),
    // handle_delete_room and handle_kick are each written against. Until
    // handle_create_room started checking the `is_direct` claim (finding F3 of
    // docs/audit-permissions-2026-09.md), any account holding nothing but
    // @everyone could send `{"is_direct": true, "invite": [a, b, c]}` and get a
    // room that force-joined all three and was then protected by all four of
    // those rules at once. No such room can be made now, so every row this
    // returns is either manufactured through that hole or left over from a
    // database that ran the vulnerable code.
    //
    // GENUINE DMs ARE NEVER RETURNED, and that is the whole design of this
    // query rather than a side effect. It exists so an operator can find the
    // rooms that need removing without being handed a list of everyone's
    // private conversations — an operator who can enumerate DMs is a different
    // product (docs/membership-vs-visibility.md), and no route exposes this.
    // It is reachable only from the offline admin CLI, which already requires
    // the database file and the server stopped, so it adds no capability an
    // operator did not have with sqlite3.
    //
    // A ONE-MEMBER row is included too: a direct room somebody left is normal
    // and not listed, because the row it left behind still counts the peer —
    // it is a `leave`, not a deletion — so a count of one means the room never
    // had two. A REPORT, with no matching delete: removal goes through
    // DELETE /rooms/{id}, which is audited and wakes the participants' syncs.
    //
    // Ordered by room id so a repeated run is diffable.
    std::vector<MalformedDirectRoom> list_malformed_direct_rooms();

    // ── Server-wide bans (schema v15) ─────────────────────────────────────
    //
    // The single authoritative record of "this identity is banned from this
    // server". Per-room membership='ban' rows are a PROJECTION of this list, not
    // a second source of truth — see RoomHandler::apply_membership_moderation.
    //
    // Lives in its own table rather than in room state or server_state so it
    // survives channel deletion and so "is this user banned" is a primary-key
    // lookup on the hot path of /join, auto-join and /sync. See migrate_v15.
    struct ServerBan {
        std::string user_id;
        std::string actor;     // who placed it; "" for rows recovered by migrate_v15
        std::string reason;    // "" if none given
        int64_t created_at = 0;  // ms; filled with "now" when left at 0
    };

    // Idempotent: re-banning an already-banned user REPLACES the record, so the
    // actor and reason are the most recent ones rather than the first.
    void set_server_ban(const std::string& user_id, const std::string& actor,
                        const std::string& reason, int64_t created_at = 0);
    // True when a ban row existed and was removed. The return value is what lets
    // an unban distinguish "lifted a ban" from "there was nothing to lift".
    bool clear_server_ban(const std::string& user_id);
    bool is_server_banned(const std::string& user_id);
    std::optional<ServerBan> get_server_ban(const std::string& user_id);

    // Every ban, newest first. Convenience for tests and for callers that know the
    // list is small; the HTTP read path uses the paginated overload below.
    std::vector<ServerBan> list_server_bans();

    struct ServerBanPage {
        std::vector<ServerBan> bans;  // ordered by user_id ASC — see below
        // Cursor for the following page: pass it back as `after` to get the bans
        // ordered strictly after the last one returned here. Absent at the end.
        std::optional<std::string> next_from;
        int64_t total = 0;            // rows in the table
    };

    // A page of at most `limit` bans, ordered by user_id ASCENDING, restricted to
    // ids strictly greater than `after` when one is given.
    //
    // WHY user_id AND NOT created_at, even though created_at is what an operator
    // would rather sort by: a cursor has to name something that does not move.
    //   * created_at is not unique — two bans in the same millisecond share it, so
    //     a cursor of "older than T" either repeats or skips whichever of them
    //     falls on the boundary.
    //   * created_at is not even STABLE. set_server_ban is deliberately idempotent
    //     by REPLACE, so re-banning an already-banned user rewrites created_at and
    //     the row MOVES in a created_at ordering. A reader paging through the list
    //     while that happens can be handed the same ban twice or miss one
    //     entirely.
    //   * user_id is the PRIMARY KEY. It is unique, and it never changes for the
    //     lifetime of a row: a re-ban replaces the row in place and keeps the same
    //     key. So a page boundary is a fixed point in the key order.
    // The guarantee this buys is weaker than the audit log's, because unlike
    // audit_log this table is mutable and rows can be deleted, and it is stated
    // rather than implied: a ban that existed when the walk began and still exists
    // when it ends is returned EXACTLY ONCE. A ban lifted mid-walk simply does not
    // appear, and a ban PLACED mid-walk appears only if its user_id happens to
    // sort after the cursor. Neither can corrupt the walk.
    //
    // Ordering by user_id is also the cheaper query: it is served by the table's
    // own primary-key index with no sort step, whereas ORDER BY created_at DESC is
    // a full scan plus a temp b-tree. No new index, and so no migration.
    ServerBanPage list_server_bans(int limit, const std::optional<std::string>& after);

    // Events
    //
    // `media` is the set of media URIs this event's author may bind to this
    // room; see MediaReferences and auth/MediaAccess.h. Only URIs that are BOTH
    // named by `content_json` and permitted by `media` reach `media_refs`, so
    // the extraction rule stays here on the door where no call site can drift
    // from it, and the authorisation rule — which cannot run under this mutex —
    // is supplied by the caller.
    //
    // The default binds NOTHING, which is the right answer for the handful of
    // server-composed events that name no media and the fail-closed answer for
    // anything else. Production paths with a principal behind them call
    // insert_event_vetted() instead of choosing here.
    int64_t insert_event(const std::string& event_id, const std::string& room_id,
                         const std::string& sender, const std::string& event_type,
                         const std::optional<std::string>& state_key,
                         const std::string& content_json, int64_t origin_server_ts,
                         const MediaReferences& media = MediaReferences::none());

    // Returns (events, next_from_token). next_from_token is the stream
    // position of the oldest row in this batch for dir="b" / newest for
    // dir="f"; encode it as "s<pos>" and pass back as `from` on the next
    // page request. nullopt when there are no more rows in that direction.
    //
    // `viewer` decides what happens to ADDRESSED call signalling (see
    // store/CallSignalling.h). Left unset — the history case, /messages — none
    // of it is returned at all: those events carry participants' LAN and public
    // IP addresses and have no business being pageable months later. Set to a
    // user id — the initial-sync case — that user's own signalling (sent by
    // them, or addressed to them) is included and nobody else's is, so a client
    // that reconnects still receives an invite that arrived while it was away.
    //
    // Unaddressed signalling, from a client too old to name a recipient, is
    // NULL in the column and returned on both paths exactly as before.
    //
    // `ignoring_user` applies that account's ignore list (schema v29): NON-STATE
    // events sent by somebody it ignores are dropped from the page. Both
    // /messages and the initial sync pass it; the history case passes it too,
    // because an ignore that held on /sync and not on back-pagination would be
    // undone by scrolling up.
    //
    // STATE EVENTS ARE NEVER DROPPED BY IT, whoever sent them, and that is not
    // an oversight. A room's state is not the sender's content — it is the
    // room's description of itself. Dropping the m.room.member event of a person
    // you ignore takes them out of your member list; dropping an m.room.name
    // they happened to set renames the channel to nothing in your client. Same
    // rule Matrix's own ignore semantics take, and the same one the /sync scan
    // applies in get_events_since.
    std::pair<std::vector<RoomEvent>, std::optional<int64_t>>
    get_room_events_paginated(const std::string& room_id, int limit,
                              const std::string& direction = "b",
                              const std::optional<std::string>& from = std::nullopt,
                              const std::optional<std::string>& viewer = std::nullopt,
                              const std::optional<std::string>& ignoring_user = std::nullopt);

    std::vector<RoomEvent> get_room_events(const std::string& room_id, int limit, const std::string& direction = "b",
                                            const std::optional<std::string>& from = std::nullopt);

    std::vector<RoomEvent> get_state_events(const std::string& room_id);
    // The stripped state for an invite to `room_id` addressed to `invitee`:
    // enough to render "somebody invited you to #channel", and nothing that
    // belongs to people who have accepted.
    //
    // NOT get_state_events() with a filter applied afterwards. The whitelist
    // lives in the SQL, so the set of things an un-joined account can read out
    // of a room is decided in one place that a later caller cannot widen by
    // forgetting to re-apply it:
    //
    //   * the room-level events that name and describe the room —
    //     m.room.create, name, topic, avatar, join_rules, canonical_alias,
    //     and bsfchat.room.type so a client can tell text from voice;
    //   * `invitee`'s own m.room.member event, which IS the invite and whose
    //     sender is the inviter;
    //   * that inviter's m.room.member event, for their display name.
    //
    // Withheld: the timeline, power levels, roles and channel permissions, and
    // every other member event — the membership of a room you are not in is
    // not yours to read. bsfchat.room.category is withheld too: it names a
    // parent room the invitee may have no business knowing about, and sidebar
    // placement means nothing before the invite is accepted.
    std::vector<RoomEvent> get_invite_state(const std::string& room_id,
                                            const std::string& invitee);

    // Who invited `invitee` into `room_id`: the sender of the most recent
    // m.room.member event that put them in 'invite'. nullopt when there is no
    // such event.
    //
    // The MOST RECENT one, not the first: an invite that was declined and
    // re-sent by somebody else must answer with whoever sent the live one, or
    // the ignore filter in SyncEngine would suppress an invite from a person
    // the reader has not blocked because a different person's older invite is
    // still in the table.
    std::optional<std::string> get_invite_sender(const std::string& room_id,
                                                 const std::string& invitee);
    std::optional<RoomEvent> get_state_event(const std::string& room_id, const std::string& event_type, const std::string& state_key);
    std::optional<RoomEvent> get_event_by_id(const std::string& event_id);

    // Redact an event in place: replaces its content with an empty object and
    // records who redacted it. The event row itself (id, type, sender,
    // timestamp) survives as a tombstone, per the Matrix redaction algorithm.
    // Returns false if the event doesn't exist. Idempotent.
    //
    // THE INVARIANT, which every part of this class is here to keep: once this
    // returns, no surface of the server still holds the text of `event_id` or
    // of any edit of it — not the events table, not the FTS index, not the
    // bundled edit history under `unsigned`, not the mention rows, and not the
    // undispatched push queue.
    //
    // "A message" is therefore not a row. It is the original event plus every
    // m.replace of it, transitively, because an edit is stored as its own
    // ordinary m.room.message and /messages returns it with no type and no
    // relation filter. Stripping only the row named in the request left the
    // edit — usually the newest and most sensitive version of the text — fully
    // readable to any member with an access token.
    //
    // Interacts with edits in both directions: redacting an original discards
    // its edit pointer and cascades to its replacements, and redacting a
    // replacement re-resolves its target to the newest surviving replacement,
    // or back to the pristine original if there is none. The cascade runs
    // DOWNWARDS only: deleting one edit still means "undo this edit", not
    // "delete the message".
    bool redact_event(const std::string& event_id, const std::string& redacted_by);

    // Message edits (m.replace).
    //
    // Point `target_event_id` at the replacement that now wins for it. Every
    // read path resolves through this pointer, so the API returns edited
    // content instead of leaving enforcement to client goodwill. The original
    // row is untouched apart from the pointer: same event id, same sender, same
    // origin_server_ts, pristine content still on disk and still exposed under
    // `unsigned`, and the replacement remains an ordinary timeline event.
    //
    // That an edit PRESERVES the text it replaced is a decision, not an
    // accident — see docs/redaction-and-edit-history.md. Editing is revision;
    // redaction is removal, and it is the only removal. The decision is only
    // defensible because redact_event() reaches every version, so the two must
    // be changed together if they are changed at all.
    //
    // Refuses to apply to a redacted event. Returns false if the target does
    // not exist or is redacted.
    bool apply_edit(const std::string& target_event_id, const std::string& replacement_event_id);

    // The replacement currently winning for an event, or nullopt if unedited.
    std::optional<std::string> get_edit_pointer(const std::string& event_id);

    // An existing, un-redacted m.reaction from `sender` in `room_id` annotating
    // `target_event_id` with `key`, if there is one.
    //
    // Exists so a duplicate reaction is idempotent rather than a second event:
    // the client renders one bubble per reaction EVENT, so pressing the same
    // emoji twice used to show the same person twice.
    //
    // Redacted reactions are deliberately excluded, and that exclusion is
    // load-bearing rather than tidiness: un-reacting IS redacting the reaction
    // event (MatrixClient::unreact), so treating a redacted one as a duplicate
    // would make a reaction impossible to take back and put back.
    std::optional<std::string> find_reaction_event(const std::string& room_id,
                                                   const std::string& sender,
                                                   const std::string& target_event_id,
                                                   const std::string& key);

    // True if the event has been redacted. get_event_by_id() cannot answer this
    // — a redacted event and a legitimately contentless one both read as `{}`.
    bool is_event_redacted(const std::string& event_id);

    // Transaction-id idempotency for client sends.
    //
    // All four parts are the key, and each one is load-bearing. It was
    // (user_id, txn_id) alone, which is wider than what a txn id identifies:
    // reusing an id in a different room answered 200 with the FIRST message's
    // event id and posted nothing to the second room, and two clients signed in
    // as the same user — both starting their counters at 1 — swallowed each
    // other's early messages. A txn id is scoped to the sending DEVICE (Matrix
    // scopes it per access token); the room is ours, and makes the key match the
    // request being retried rather than merely the sender.
    struct TransactionKey {
        std::string user_id;
        std::string device_id;
        std::string room_id;
        std::string txn_id;
    };
    std::optional<std::string> get_transaction_event(const TransactionKey& key);
    void record_transaction(const TransactionKey& key, const std::string& event_id);

    // Transaction-id idempotency for /redact, which is a SEPARATE namespace
    // from the one above and not an oversight. See migrate_v19: a shared
    // namespace would let a client that keeps one counter per endpoint have its
    // redaction answered with the event id of a message, having redacted
    // nothing.
    //
    // Every part of the key is load-bearing. A txn id is scoped to the access
    // token, which is the DEVICE; the room and the TARGET are what make the key
    // identify the request being retried rather than merely its sender. Without
    // the target, a client reusing an id for a second deletion in the same room
    // is told it succeeded and handed the first redaction's event id, while the
    // second message stays up — the same silent no-op that made the send path's
    // (sender, txn_id) key wrong.
    //
    // device_id is the one part that could be argued either way, and it is in
    // because it is in /send's key. Dropping it would fold together the only
    // case where it matters — two clients of the SAME user redacting the SAME
    // target with the SAME id, which happens because both counters start at 1 —
    // and that fold would even be harmless here, since (room, target) fully
    // determines the effect of a redaction. It is not worth having redaction's
    // key differ in shape from /send's for it: the cost of keeping it is a
    // second tombstone in that one case, which is exactly what those two
    // clients already produce today whenever their ids do not happen to
    // coincide.
    struct RedactionKey {
        std::string user_id;
        std::string device_id;
        std::string room_id;
        std::string target_event_id;
        std::string txn_id;
    };
    std::optional<std::string> get_redaction_transaction_event(const RedactionKey& key);
    void record_redaction_transaction(const RedactionKey& key, const std::string& event_id);

    // Sync
    // Returns events strictly after `since_position` that the user can see.
    // `out_max_position` receives the highest stream position actually
    // scanned, which is what the caller must use to build `next_batch` —
    // using the global head instead permanently skips anything beyond `limit`.
    // It is left at `since_position` when nothing was returned.
    std::vector<RoomEvent> get_events_since(const std::string& user_id, int64_t since_position,
                                            int64_t& out_max_position, int limit = 1000);
    std::vector<RoomEvent> get_events_since(const std::string& user_id, int64_t since_position,
                                            int limit = 1000);
    // Same scan, plus `out_stream_head`: the global stream head sampled under
    // the SAME lock as the scan, so it is the head of the snapshot the scan
    // actually saw and not a later one.
    //
    // Reading the head afterwards (a second, separate lock acquisition) loses
    // events permanently. An insert landing between the two calls gets a
    // position at or below the head the caller then reads, so the caller's
    // next_batch jumps past a row the scan never returned and no later sync
    // ever asks for it again. Writes are serialised by this same mutex_ and a
    // position is both claimed and committed while it is held, so a head taken
    // inside the lock is a genuine watermark: every position at or below it is
    // committed and was offered to the query.
    std::vector<RoomEvent> get_events_since(const std::string& user_id, int64_t since_position,
                                            int64_t& out_max_position, int64_t& out_stream_head,
                                            int limit);
    // Deletes addressed call-signalling events whose origin_server_ts is more
    // than kCallSignallingTtlMs before `now_ms`, and returns how many went.
    //
    // This is the retention half of the fix, and it is the half that has to keep
    // running: the /sync and /messages filters stop anyone READING another
    // pair's addresses, but an addressed candidate batch still sits on disk in
    // plain text until this removes it, where a database copy, a backup or a
    // future bug can reach it. Two minutes of exposure instead of five months.
    //
    // Cheap enough to call on a timer: served by a partial index over just those
    // rows, and on an idle server it matches nothing.
    int prune_expired_call_signalling(int64_t now_ms);

    int64_t get_current_stream_position();
    int64_t get_room_max_stream_position(const std::string& room_id);

    // Server-wide state (bsfchat.server.roles / bsfchat.member.roles).
    // Deliberately NOT stored as room events: they used to live in an
    // arbitrary channel, so deleting that channel wiped every role on the
    // server. Room events are now only a mirror for client sync.
    //
    // What a caller believes is currently stored under a key, for the optional
    // compare-and-swap below. An engaged optional is "this exact content"; a
    // disengaged one is "no row at all". Passing no expectation (a null
    // pointer) makes the write unconditional, which is what bootstrap and the
    // admin CLI want.
    using ExpectedServerState = std::optional<std::string>;

    // The outcome of one server-scoped state write.
    struct ServerStateWrite {
        // False ONLY when an expectation was supplied and the stored content
        // had already moved. Nothing was written in that case.
        bool applied = true;
        // What was in the row when the write was attempted: the content this
        // write replaced if it applied, or the content that beat it if it did
        // not. nullopt for a key that was unset.
        std::optional<std::string> previous;
    };

    // Returns the content this write REPLACED, or nullopt if the key was unset.
    // Read inside the same lock as the write, which is what lets the audit log
    // record a before/after pair that no concurrent writer can have already
    // superseded — reading it with a separate get_server_state() call first would
    // leave a window where two simultaneous role edits both report the same
    // "before".
    //
    // WITH AN EXPECTATION, the same lock makes it a compare-and-swap, and that
    // is a correctness requirement rather than a nicety. The role document is a
    // single row that every caller read-modify-writes wholesale, so without one
    // a stale proposal silently reverts whatever landed between its read and
    // its write — including a revocation. Worse, the authorisation is computed
    // from a FRESH read (RoleHandler::commit_roles builds a new
    // PermissionsEngine), so a proposal built from document A is approved
    // against document B and then overwrites it: "cannot grant what you do not
    // hold" sees the revoked bit as newly added, the actor does hold it, and
    // the revocation is undone by an unrelated rename. Permissions audit F8,
    // September 2026; RoleHandler.h had claimed this was already safe.
    ServerStateWrite set_server_state(const std::string& event_type,
                                      const std::string& state_key,
                                      const std::string& sender,
                                      const std::string& content_json,
                                      const ExpectedServerState* expected = nullptr);
    std::optional<std::string> get_server_state(const std::string& event_type,
                                                 const std::string& state_key);

    // Server metadata key/value store (migration markers etc.).
    std::optional<std::string> get_meta(const std::string& key);
    void set_meta(const std::string& key, const std::string& value);

    // ── LiveKit media-key generation ──────────────────────────────────────
    //
    // The channel's media key is HKDF(key_material, server_name ‖ room_id ‖
    // generation), so the generation IS the key: rotating it is what stops a
    // departed member decrypting, and reusing one hands their key back. It
    // lives here rather than in VoiceHandler because it was in a std::map
    // there, and every restart quietly undid every rotation ever performed
    // (schema v19).
    //
    // Returns the generation currently in force for `room_id` — the stored
    // value, or this install's baseline for a channel that has never been
    // rotated. Never fabricates 0: 0 is a real, derivable key, and defaulting
    // to it is precisely the bug.
    uint64_t get_voice_key_generation(const std::string& room_id);

    // What a rotation replaced and what it installed. Returned as a pair, and
    // read inside the write's own lock, for the same reason set_server_state
    // returns the content it superseded: a separate read first would leave a
    // window in which two concurrent rotations both report the same "before"
    // to the audit log.
    struct VoiceKeyRotation {
        uint64_t previous = 0;
        uint64_t current = 0;
    };

    // Rotates `room_id` onto a new generation and returns it with its
    // predecessor.
    //
    // MONOTONIC IN TWO DIRECTIONS. The new value is
    // max(current + 1, wall clock in ms), and the write itself takes the MAX of
    // what is already stored, so:
    //   * a generation never decreases within an install, and
    //   * it never decreases ACROSS one either. A database restored from an
    //     older backup loses the record of rotations made since — nothing
    //     stored in that same database can survive its own rollback — but the
    //     wall clock cannot be rolled back with it, so the next rotation lands
    //     above every generation this install ever issued instead of walking
    //     back over keys that were already retired.
    // A backwards jump of the system clock costs nothing either: current + 1
    // still applies. The two floors cover each other.
    //
    // Throws if the new generation cannot be persisted. A rotation that reports
    // success without being durable is the defect this method exists to fix.
    VoiceKeyRotation bump_voice_key_generation(const std::string& room_id);

    // Permissions / roles (reads)
    // Returns the server-wide role definitions, empty if unset.
    std::vector<ServerRole> get_server_roles();
    // Role IDs assigned to the given user, empty if none.
    std::vector<std::string> get_member_role_ids(const std::string& user_id);
    // All per-channel allow/deny overrides for the room, keyed by target ("role:..." / "user:...").
    std::map<std::string, ChannelPermissionOverride> get_channel_overrides(const std::string& room_id);
    // Every room that carries a bsfchat.channel.permissions event, in no
    // particular order.
    //
    // For PermissionsEngine::channel_access_excess, which has to ask "is there
    // a channel where this account can do something the actor cannot" and
    // would otherwise have to walk every room on the server. A room with no
    // override evaluates identically for everybody, so it can never be the
    // answer — see the comment on that function for the full argument.
    //
    // DELIBERATELY A SUPERSET: it names a room whose only override has since
    // been emptied out, because "has ever carried one" is one indexed scan and
    // "carries a non-empty one now" is the same group-by get_channel_overrides
    // already does per room. The caller computes the real answer anyway and an
    // extra room costs it one query and yields nothing.
    std::vector<std::string> rooms_with_channel_overrides();
    // Per-channel slowmode, in seconds. 0 = disabled.
    int get_channel_slowmode(const std::string& room_id);
    // Timestamp (origin_server_ts, ms) of the user's most recent m.room.message in the room, 0 if none.
    int64_t get_last_message_ts(const std::string& user_id, const std::string& room_id);
    // For startup bootstrap: (user_id, created_at) ordered ascending by created_at.
    std::vector<std::pair<std::string, int64_t>> list_users_with_created_at();

    // Mentions (MSC3952 `m.mentions`).
    //
    // Written ONLY by the send path, from the sender's own event content, after
    // it has been validated against room membership and VIEW_CHANNEL. There is
    // deliberately no client-reachable route to this table: a mention records
    // "`sender` mentioned `user_id` in `event_id`", and `sender` is always the
    // authenticated user, so no request body can claim a third party did the
    // mentioning.
    //
    // `mentioned_user_ids` may contain kRoomMentionSentinel for a room-wide
    // (`@room`) mention, and a kRoleMentionPrefix sentinel per mentioned role.
    // Entries equal to `sender` are dropped — mentioning yourself must not badge
    // your own room. Idempotent per (event, user).
    //
    // A sentinel is one row regardless of how many members it reaches; the
    // expansion is on the read side, in mention_match_keys().
    void record_mentions(const std::string& event_id, const std::string& room_id,
                         const std::string& sender, int64_t stream_position,
                         const std::vector<std::string>& mentioned_user_ids);

    // Every event_mentions.user_id value that counts as a mention OF this user:
    // their own id, kRoomMentionSentinel, and a sentinel for each role they
    // hold. The read-side half of the role-mention fan-out; the two count
    // functions below are its only callers, and it is public so a test can
    // assert the expansion directly rather than only through a badge count.
    std::vector<std::string> mention_match_keys(const std::string& user_id);

    // Mentions of `user_id` in `room_id` at a stream position past their read
    // marker, excluding ones they made themselves. This is the number the client
    // needs for a mention badge that is distinct from the plain unread dot.
    int count_unread_mentions(const std::string& user_id, const std::string& room_id);
    // Same, for every room at once — one indexed query instead of one per room,
    // which matters because /sync asks about every joined room on every poll.
    // Rooms with no unread mentions are absent from the map.
    std::map<std::string, int> get_unread_mention_counts(const std::string& user_id);

    // Users mentioned by an event (kRoomMentionSentinel included if room-wide).
    // Used to decide whether an edit is trying to introduce a NEW mention.
    std::vector<std::string> get_event_mentions(const std::string& event_id);
    // Drop mention rows for an event. Used when an edit narrows the mention set
    // and when a message is redacted.
    void delete_mentions_for_event(const std::string& event_id);

    // Read markers
    // Upserts (user_id, room_id) marker. Only moves forward (monotonic).
    //
    // Returns whether it MOVED. A marker that did not move is not a change, so
    // there is nothing for a second device to be told and nothing to wake a
    // parked /sync for — and, since a write that moves the marker claims a
    // stream position (schema v30) so that /sync can deliver it, a no-op write
    // must not claim one either. The client posts a marker on every batch of
    // messages in the open room, so the no-op is the common case.
    bool set_read_marker(const std::string& user_id, const std::string& room_id, int64_t stream_pos);
    int64_t get_read_marker(const std::string& user_id, const std::string& room_id);

    // ── Cross-device read state (schema v30) ─────────────────────────────
    //
    // One user's read markers, for /sync to publish as `m.fully_read` room
    // account data. `since_pos` and `until_pos` bound the range by the position
    // of the WRITE (read_markers.updated_pos), never by the marker's own value:
    // the question is "what has this account changed since its sync token",
    // and the marker value is the answer, not the clock.
    //
    // Half-open at the bottom and closed at the top — (since_pos, until_pos] —
    // to match exactly what the caller's next_batch will name. A row above
    // `until_pos` is left for the next poll rather than delivered under a token
    // that does not cover it.
    //
    // NO VISIBILITY FILTER HERE. These rows are the caller's own, but a room
    // they may no longer view can still have one, and naming it would tell them
    // the room exists. The gate is in SyncEngine, where room_view() lives; this
    // returns what is stored.
    struct ReadMarker {
        std::string room_id;
        int64_t last_read_pos = 0;
    };
    std::vector<ReadMarker> get_read_markers_changed(const std::string& user_id,
                                                     int64_t since_pos, int64_t until_pos);
    // Every read marker this account has, for an initial sync. Same caveat: no
    // visibility filter, and the caller applies one.
    std::vector<ReadMarker> get_read_markers(const std::string& user_id);

    // What a read marker POINTS AT: the newest event in the room at or below
    // `last_read_pos`. The marker is stored as a stream position, and the two
    // things a client can use are the event id (the Matrix spec's field) and
    // its origin_server_ts (what this client's unread dot is arithmetic on) —
    // both of which live on that row.
    //
    // Resolves against ANY event type, not only messages. The position comes
    // from get_room_max_stream_position(), so it is whatever was newest when
    // the room was read; a state event's timestamp is the same server clock as
    // a message's, and picking the newest MESSAGE at or below the marker
    // instead would report the room as read up to an older moment than it was.
    //
    // nullopt for a marker in an empty room, or one pointing below every
    // surviving event (every event before it redacted away and purged).
    struct MarkedEvent {
        std::string event_id;
        int64_t origin_server_ts = 0;
    };
    std::optional<MarkedEvent> resolve_read_marker(const std::string& room_id,
                                                   int64_t last_read_pos);
    // Counts messages in the room past the user's marker that somebody else
    // sent. Excludes m.replace replacements (editing a message used to bump
    // everyone else's badge as if it were a new message) and redacted events (a
    // deleted message must not keep a badge lit for content nobody can read).
    int count_unread(const std::string& user_id, const std::string& room_id);

    // Has anybody ever sent a message in this room? Existence, not a count:
    // the only caller asks "is this a channel with content in it", and that is
    // answered by the first matching row.
    //
    // Redacted messages COUNT. A redaction tombstones the content but leaves
    // the sender, the timestamp and the event id, and the whole point of the
    // caller — refusing to retype a used channel as a category — is that a
    // conversation happened here. "Every message was deleted" is not "this was
    // never a channel".
    bool room_has_messages(const std::string& room_id);

    // ── Push notifications ────────────────────────────────────────────────
    //
    // `url` is a push GATEWAY endpoint, not a provider endpoint: the server
    // speaks only the Matrix push-gateway notify shape and knows nothing about
    // FCM or APNs, whose credentials are a deployment concern living in the
    // gateway.
    struct Pusher {
        std::string user_id;
        std::string app_id;
        std::string pushkey;
        std::string device_id;
        std::string kind;                 // "http"
        std::string app_display_name;
        std::string device_display_name;
        std::string profile_tag;
        std::string lang;
        std::string url;                  // gateway endpoint (data.url)
        std::string format;               // "" or "event_id_only"
        std::string data_json;            // full `data` object, echoed to gateway
    };

    void upsert_pusher(const Pusher& pusher);
    std::vector<Pusher> get_pushers(const std::string& user_id);
    void delete_pusher(const std::string& user_id, const std::string& app_id,
                       const std::string& pushkey);
    // `append: false` semantics: an (app_id, pushkey) pair belongs to exactly
    // one account, so registering it removes other accounts' pushers holding
    // the same pair (a reused device token must not keep delivering the
    // previous account's messages).
    //
    // Scoped to one app_id deliberately. A pushkey is a token issued to one
    // application by APNs or FCM, so it carries no claim over a row with a
    // different app_id — and an unscoped delete made "knows a pushkey" into
    // "may delete other people's rows". There is deliberately no
    // delete-by-pushkey-alone: the gateway rejection path used to call one, and
    // that let any gateway wipe push for the whole server.
    int delete_pushers_by_pushkey_except(const std::string& pushkey,
                                        const std::string& app_id,
                                        const std::string& keep_user_id);

    // Pushers belonging to joined members of `room_id`, excluding
    // `exclude_user`. Restricting to users who actually have a pusher is what
    // keeps room-wide evaluation cheap in a large channel — the pushers table
    // only holds users who registered for push.
    std::vector<Pusher> list_room_pusher_candidates(const std::string& room_id,
                                                    const std::string& exclude_user);

    // Per-(user, room) notification level: "all", "mentions" or "none".
    // Returns only rows that exist; absent means the caller's default applies.
    std::map<std::string, std::string> get_room_notify_levels(const std::string& room_id);
    std::optional<std::string> get_room_notify_level(const std::string& user_id,
                                                     const std::string& room_id);
    void set_room_notify_level(const std::string& user_id, const std::string& room_id,
                               const std::string& level);

    struct QueuedPush {
        int64_t id = 0;
        std::string user_id;
        std::string app_id;
        std::string pushkey;
        std::string url;
        std::string payload;
        int attempts = 0;
        // What the notification is about. The payload is a snapshot taken at
        // enqueue time and is never re-derived, so this id is the only thing
        // that lets a later redaction find the row and destroy it. A push whose
        // event id is empty (a test harness, a future non-event notification)
        // is delivered as before.
        std::string event_id;
    };

    // Enqueue only. Never performs network I/O, so the event-insert path is
    // never blocked on a gateway.
    //
    // Skips any push whose event is already redacted. That is not the main
    // guard — redaction deletes queued rows itself — but enqueue happens after
    // the event is visible to /sync, so a fast redaction can land in between
    // and find nothing to delete.
    void enqueue_pushes(const std::vector<QueuedPush>& pushes);
    // Claims up to `limit` rows that are due at `now`, pushing their
    // next_attempt_at out by `lease_ms` so the same row is not picked up again
    // while it is in flight. Returns with the store mutex RELEASED — the caller
    // must do its HTTP work outside any store call, never holding the store's
    // global lock across network I/O.
    //
    // A claimed row whose event has since been redacted is deleted and not
    // returned. This is the last gate before the payload leaves the process and
    // the only one that cannot be raced: enqueue and redaction both write under
    // this mutex, but the worker POSTs outside it, so "was it redacted?" has to
    // be asked at the moment of claiming. A push already handed to a gateway
    // cannot be recalled.
    std::vector<QueuedPush> claim_due_pushes(int64_t now_ms, int limit, int64_t lease_ms);
    void delete_queued_push(int64_t id);
    // Records a failed attempt and schedules the retry. Returns false when the
    // row was dropped for exceeding `max_attempts`.
    bool reschedule_queued_push(int64_t id, int max_attempts, int64_t next_attempt_at);
    int count_queued_pushes();

    // ── Message search (FTS5) ─────────────────────────────────────────────
    //
    // False when this SQLite build has no FTS5 module; the endpoint then reports
    // search as unavailable rather than returning an empty result set that looks
    // like "no matches". See migrate_v12.
    bool search_index_available();

    struct SearchHit {
        std::string event_id;
        std::string room_id;
        int64_t stream_position = 0;
        double rank = 0.0; // bm25: more negative = better match
    };
    struct SearchResult {
        std::vector<SearchHit> hits;
        int total = 0;      // total matches across the permitted rooms
        bool more = false;  // another page exists after this one
    };

    // Full-text search restricted to `room_ids`.
    //
    // `room_ids` is the authorisation boundary and it is applied INSIDE the
    // query, not to its output: a room the caller may not see is never searched,
    // so nothing about it — content, existence, or match count — can leak. An
    // empty `room_ids` matches nothing, which is the fail-closed direction.
    //
    // `terms` are bare words. They are quoted as literal phrases here, so no
    // caller can hand FTS5 an expression: MATCH syntax is a prepare-time error
    // surface and `*` matches the whole index.
    SearchResult search_messages(const std::vector<std::string>& room_ids,
                                 const std::vector<std::string>& terms,
                                 const std::vector<std::string>& senders,
                                 int limit, int offset, bool order_recent);

    // Rows currently in the search index. For tests asserting the index is
    // maintained rather than merely appended to.
    int count_search_index_rows();

    // ── Moderation audit log ──────────────────────────────────────────────
    //
    // Append-only, by schema as well as by convention: migration v13 installs
    // triggers that abort any UPDATE or DELETE against `audit_log`, so this class
    // deliberately exposes one write (append) and one read (list) and nothing
    // else. There is no "edit an audit record" and no "prune the audit log"
    // anywhere in the server.
    //
    // Records are NOT room events, which is the entire point. delete_room
    // hard-deletes a room's events, so anything inferred from the timeline
    // evaporates the moment somebody deletes the channel — and channel deletion is
    // one of the audited actions. Nothing here references rooms or users by
    // foreign key either: a record must outlive the room, category and account it
    // describes.
    //
    // Records are also invisible to message search. They never pass through
    // insert_event, so they never reach reindex_search_locked, which is the single
    // choke point for the FTS5 index — a ban reason is not message content and
    // must not surface in anyone's /search results.
    struct AuditRecord {
        int64_t id = 0;           // assigned by append_audit_record; strictly monotonic
        int64_t created_at = 0;   // ms; filled in with "now" when left at 0
        std::string actor;        // the AUTHENTICATED user who performed the action
        std::string action;       // see audit_action:: in audit/AuditLog.h
        std::string target_user;  // "" when the action has no user target
        std::string target_room;  // "" when the action has no room target
        std::string target_key;   // role id, override target ("role:x"/"user:@a:b"), or ""
        std::string reason;       // moderator-supplied reason, "" if none
        std::string before_json;  // state before the change, "" if there was none
        std::string after_json;   // state after the change, "" if there is none
    };

    // Appends one record and returns its id.
    //
    // `id` comes from an AUTOINCREMENT rowid, so ids are strictly increasing and
    // never reused for the lifetime of the database. That is what makes
    // list_audit_records() stable under concurrent inserts: a cursor of "older
    // than id N" can never be invalidated by a later write, because a later write
    // always lands above N. Deriving the id from MAX(id) + 1 instead would
    // reintroduce, on the one table where it matters most, the position-reuse bug
    // that migration v4 exists to fix for events.stream_position.
    //
    // RETENTION IS UNBOUNDED, deliberately. Nothing in the server deletes from
    // this table. The reasoning:
    //   * Volume is tiny and bounded by privilege, not by traffic. Only kicks,
    //     bans, unbans, role definition/assignment changes, channel and category
    //     deletions and per-channel override changes are recorded — every one of
    //     them requires KICK_MEMBERS, BAN_MEMBERS, MANAGE_ROLES or
    //     MANAGE_CHANNELS. An untrusted account cannot inflate it, unlike events,
    //     media or push_queue, all of which already grow without bound and are
    //     driven by ordinary users. A row is a few hundred bytes: 100 moderation
    //     actions a day, which would be a remarkably turbulent self-hosted server,
    //     is about 15 MB a YEAR.
    //   * Deletion-based retention on this table is an anti-feature. A window
    //     after which records disappear is a documented way for a moderator to
    //     outwait their own audit trail, and a prune path is an
    //     evidence-destruction primitive sitting behind whatever bug next lets
    //     somebody reach it. "The log is complete" is worth more here than
    //     bounded disk.
    // An operator who genuinely must prune can do it deliberately and visibly,
    // out of band: drop the audit_log_is_append_only_delete trigger, DELETE, and
    // recreate it. That is a conscious administrative act with a trail in the
    // schema, which is the correct ergonomics for destroying an audit log — not
    // a config key that quietly does it on a timer.
    int64_t append_audit_record(const AuditRecord& record);

    // Filters for list_audit_records. Every field is an EXACT match; there is no
    // prefix or substring matching, deliberately. An investigator has the exact
    // user id, room id or action name in front of them (the log itself is where
    // they came from), and a LIKE '%…%' would be both unindexable and a way to
    // accidentally match a different account whose id contains another's.
    //
    // A set field must be non-empty. '' is this schema's "not applicable"
    // sentinel, so filtering for it would mean "records with no user target",
    // which is not a question anybody investigating an incident asks — and the
    // partial indexes v16 installs deliberately do not cover those rows.
    // Callers reject an empty value rather than passing it through; see
    // AuditHandler, which 400s instead of silently ignoring it.
    struct AuditFilter {
        std::optional<std::string> actor;
        std::optional<std::string> target_user;
        std::optional<std::string> target_room;
        std::optional<std::string> action;

        bool any() const {
            return actor || target_user || target_room || action;
        }
    };

    struct AuditPage {
        std::vector<AuditRecord> records;  // newest first
        // Cursor for the following page: pass it back as `before_id` to get
        // records strictly older than the last one returned here. Absent when
        // this page reached the end of the table.
        //
        // The cursor is an id, NOT an offset, and that is what keeps it correct
        // under a filter: "the matching records older than id N" is a stable set
        // no matter how many rows (matching or not) land while the reader pages.
        // An OFFSET-based cursor would skip a record every time a new one landed.
        std::optional<int64_t> next_from;
        int64_t total = 0;                 // rows in the table, for growth visibility
        // Rows matching the filter. Absent when no filter was applied, where it
        // would just repeat `total`. `total` deliberately stays whole-table: it
        // exists so an operator can see the log growing under unbounded retention
        // (see append_audit_record), and a filtered request must not make that
        // number look smaller than it is.
        std::optional<int64_t> matching;
    };

    // Newest-first page of at most `limit` records, restricted to ids strictly
    // below `before_id` when one is given and to rows matching `filter`.
    AuditPage list_audit_records(int limit, std::optional<int64_t> before_id,
                                 const AuditFilter& filter = {});

    // The exact statements list_audit_records() runs, and the filter values bound
    // to them in order (the trailing cursor / limit parameters are bound by the
    // caller after these).
    //
    // Public because whether the v16 indexes are USED is invisible in the results:
    // an unindexed full scan returns byte-identical rows. The only way to assert
    // it is EXPLAIN QUERY PLAN, and a test that EXPLAINs a hand-copied lookalike
    // asserts nothing about this file. So the builder is the seam, and the test
    // plans the real statement. In particular the `<> ''` guards that make the
    // partial indexes usable live here and nowhere else.
    struct AuditQuery {
        std::string sql;
        std::vector<std::string> binds;
    };
    static AuditQuery audit_page_query(const AuditFilter& filter, bool with_cursor);
    static AuditQuery audit_match_count_query(const AuditFilter& filter);

    // ── Account data, and the ignore list it carries (schema v29) ─────────
    //
    // Matrix's per-account key/value store. Global only; see migrate_v29 for
    // why the room-scoped variant is deliberately absent.

    // The stored document for `type`, or nullopt when this account has never
    // written one. Raw JSON text, exactly as it was PUT.
    std::optional<std::string> get_account_data(const std::string& user_id,
                                                const std::string& type);

    // Replaces the document for `type`.
    //
    // When `type` is m.ignored_user_list this ALSO rewrites that account's rows
    // in `ignored_users`, in the same transaction. The two are not two stores:
    // account_data is the authority and ignored_users is an index over it, the
    // same relationship insert_event maintains with the FTS5 search index and
    // taken for the same reason — see migrate_v29.
    //
    // `ignored` is the projection the caller parsed out of `content_json`, and
    // it is a parameter rather than something re-derived here so that the
    // parsing rules (what a valid entry is, what the ceiling is, what a
    // malformed one means) stay in the handler where they can be refused with a
    // 400. This function is the atomicity, not the policy. It must be nullopt
    // for every other type, and the store enforces the pairing: passing one
    // without the other for the ignore list is a programming error that would
    // leave the index disagreeing with the document.
    void set_account_data(const std::string& user_id, const std::string& type,
                          const std::string& content_json,
                          const std::optional<std::vector<std::string>>& ignored,
                          int64_t when_ms);

    // One account's documents that were written above `since_pos` and at or
    // below `until_pos` — the account-data delta for a /sync whose token names
    // `since_pos`. Raw JSON text, as stored. See get_read_markers_changed for
    // why the range is half-open at the bottom.
    //
    // Every type is returned, including ones this server never interprets: an
    // account-data store whose contents only propagate if the server
    // understands them is not a store, it is a list of features.
    struct AccountDataDocument {
        std::string type;
        std::string content_json;
    };
    std::vector<AccountDataDocument> get_account_data_changed(const std::string& user_id,
                                                              int64_t since_pos,
                                                              int64_t until_pos);
    // Every document this account has, for an initial sync.
    std::vector<AccountDataDocument> get_all_account_data(const std::string& user_id);

    // Every account `user_id` currently ignores, ascending. Read from the index,
    // so it is what the /sync and /messages filters will actually apply — a test
    // that asserts on this asserts on the enforcement, not on a re-parse of the
    // document.
    std::vector<std::string> get_ignored_users(const std::string& user_id);

    // Whether `ignorer` ignores `sender`. One primary-key probe.
    bool is_ignoring(const std::string& ignorer, const std::string& sender);

    // ── Content reports (schema v29) ──────────────────────────────────────
    //
    // Apple guideline 1.2 and Google Play's UGC policy both require a way to
    // report content. Stored here AND appended to the audit log: the audit log
    // answers "what has happened on this server, in order", this answers "what
    // is outstanding about this account or this channel".

    struct ContentReport {
        int64_t id = 0;         // assigned by add_content_report; monotonic
        int64_t created_at = 0; // ms; filled with "now" when left at 0
        std::string reporter;
        // The account the report is about. For an event report this is the
        // event's sender, resolved by the handler rather than taken from the
        // request — a reporter does not get to say whose record this lands on.
        std::string target_user;
        std::string room_id;   // empty for a user-level report
        std::string event_id;  // empty for a user-level report
        std::string event_sender;
        // Bounded copy of the reported event's content at report time; see
        // migrate_v29 for why the report does not just point at the event.
        std::string event_snapshot;
        // Matrix's severity hint: -100 (most offensive) to 0. Zero for a
        // user-level report, which the spec gives no score.
        int score = 0;
        std::string reason;
    };

    int64_t add_content_report(const ContentReport& report);

    struct ReportPage {
        std::vector<ContentReport> reports;  // newest first
        std::optional<int64_t> next_from;    // pass back as before_id
        int64_t total = 0;                   // whole table
    };

    // Newest-first page of at most `limit` reports, restricted to ids strictly
    // below `before_id` when one is given. Same cursor shape as the audit log,
    // and stable for the same reason: ids are monotonic and never reused.
    ReportPage list_content_reports(int limit, std::optional<int64_t> before_id = std::nullopt);

    // Profile
    void set_display_name(const std::string& user_id, const std::string& display_name);
    void set_avatar_url(const std::string& user_id, const std::string& avatar_url);
    std::optional<std::string> get_display_name(const std::string& user_id);
    std::optional<std::string> get_avatar_url(const std::string& user_id);

    // Per-server nickname (schema v14). Authoritative storage: room state only
    // ever mirrors this, because four separate code paths rewrite a member
    // event's displayname from the profile and would otherwise clobber it.
    //
    // nullopt CLEARS the nickname, and reading it back returns nullopt — which is
    // not the same as an empty string, so a cleared nickname is distinguishable
    // from one that was never set only in that both are absent. That is
    // deliberate: "no nickname" has exactly one representation.
    void set_nickname(const std::string& user_id, const std::optional<std::string>& nickname);
    std::optional<std::string> get_nickname(const std::string& user_id);

    // Media
    struct MediaMeta {
        std::string media_id;
        std::string uploader;
        std::string content_type;
        std::string filename;
        int64_t file_size;
        std::string file_path;
    };

    void insert_media(const std::string& media_id, const std::string& uploader,
                      const std::string& content_type, const std::string& filename,
                      int64_t file_size, const std::string& file_path);
    std::optional<MediaMeta> get_media(const std::string& media_id);
    bool delete_media(const std::string& media_id);

    // --- media access control -------------------------------------------
    //
    // Media has no room column of its own and never can: POST /upload carries
    // no room. The binding is recorded when the object is first *named* by an
    // event, by insert_event(), and these are the two reads the download path
    // uses to decide whether a caller may have the bytes.

    /// Every room in which a surviving, unredacted event names this exact
    /// `mxc://host/id`. Empty means the object is not attached to anything —
    /// which the caller must treat as "nobody but the uploader", NOT as
    /// "public". Whole URIs, not bare ids: see media_uris_in_content().
    std::vector<std::string> get_media_rooms(const std::string& mxc_uri);

    /// True when this URI is `user_id`'s current profile avatar. Avatars are
    /// the one legitimately room-less media class — they are shown next to a
    /// name in every channel and in profile cards — so they are readable by
    /// any authenticated caller, matching what /profile already discloses.
    ///
    /// Takes the account rather than answering "is this ANYBODY's avatar",
    /// which is what it used to do. The caller passes the object's UPLOADER,
    /// so the question this really answers is "is this object its own
    /// uploader's avatar". The difference is audit F5's worst variant: this
    /// rule is reached only when media_refs is empty, and emptying media_refs
    /// is exactly what a redaction does, so "anybody's avatar" meant that
    /// wearing a redacted attachment you did not upload made it readable by
    /// every account on the server. handle_put_avatar_url refuses such a write
    /// now; this is the second, independent gate, and it is the one that also
    /// covers rows written before that check existed.
    bool is_avatar_of(const std::string& mxc_uri, const std::string& user_id);

    /// Objects nothing references any more: no surviving event names them, no
    /// account wears them as an avatar, no server-scoped document mentions
    /// them, and they are older than `created_before_ms`.
    ///
    /// This is the ONLY erasure path media has, and it is deliberately a sweep
    /// rather than a delete at the redaction and room-deletion sites. Three
    /// reasons, in order of how badly each alternative fails:
    ///
    ///   1. A blob is a file and a media row is a transaction. redact_event()
    ///      and delete_room() do their work inside BEGIN IMMEDIATE, and there
    ///      is no unlink() that a ROLLBACK can undo. Deleting the file in there
    ///      means a rolled-back redaction has already destroyed the image.
    ///   2. Neither site knows the answer on its own. One object can be named
    ///      by events in several rooms (a forward, a repost), so "this event
    ///      was redacted" is not "this object is unreferenced" — the question
    ///      is about the whole table, and it is cheapest to ask it once.
    ///   3. Only a sweep collects the orphan class those sites cannot see at
    ///      all: an upload that was never attached to anything. That is the
    ///      case handle_upload's failure path already apologises for.
    ///
    /// `created_before_ms` is the grace period and it is load-bearing, not a
    /// tuning knob. POST /upload and the PUT /send that names the object are
    /// two requests, and between them the object is indistinguishable from an
    /// orphan. A grace period shorter than the longest plausible compose-and-
    /// send deletes attachments out from under people who are still typing.
    ///
    /// Reference sources, and why these three are all of them: media_refs
    /// (every event that names an object, maintained by insert_event and
    /// shrunk by redact_event and delete_room), users.avatar_url (the one
    /// legitimately room-less class, see is_avatar_of), and server_state,
    /// which holds server-scoped documents that are NOT events and so are not
    /// in media_refs. The last is scanned in C++ with media_uris_in_content(),
    /// the same extractor insert_event indexes with, so the two cannot drift.
    std::vector<MediaMeta> find_orphaned_media(const std::string& server_name,
                                               int64_t created_before_ms, int limit);

private:
    // Drops spent refresh-token records once no live session could still
    // belong to their family. Called with mutex_ already held.
    void prune_consumed_refresh_tokens_locked();
    // Deletes sessions past their expiry (or, when they hold a refresh token,
    // past refresh_deadline_ms). Throttled to hourly unless `force`. Called
    // with mutex_ already held.
    void reap_expired_tokens_locked(int64_t now, bool force);
    int64_t last_token_sweep_ms_ = 0;

    void exec(const std::string& sql);
    // Strips group/other access from the database file and its -wal/-shm
    // siblings. No-op for an in-memory database; never fatal.
    void restrict_database_file_mode();
    // One-time VACUUM that discards free pages left behind by pre-hardening
    // deletes. Caller must hold mutex_ and must NOT be inside a transaction.
    void vacuum_freelist_once_locked(bool fresh_database);
    // Claims the next stream position. Caller must hold mutex_.
    int64_t claim_stream_position_locked();
    // Re-points `target_event_id` at the newest surviving (non-redacted)
    // replacement, clearing the pointer when none is left. Caller must hold
    // mutex_.
    void reresolve_edit_locked(const std::string& room_id, const std::string& target_event_id);

    // Every event that can carry `event_id`'s text: the event itself, then each
    // m.replace of it, transitively. Our own client chain-resolves an edit to
    // the original before sending, so in practice this is one hop — but
    // `replaces` records whatever the sender claimed, and a third-party client
    // that edits an edit must not leave the newest version behind. Bounded:
    // a cycle or a flood of relations cannot make this walk forever.
    // Caller must hold mutex_.
    std::vector<std::string> edit_family_locked(const std::string& event_id);

    // Drops every queued push notification for the given events, so a redaction
    // reaches the copy of the text that is sitting in the delivery buffer.
    // Caller must hold mutex_.
    void delete_queued_pushes_for_events_locked(const std::vector<std::string>& event_ids);

    // As is_event_redacted(), for callers that already hold mutex_. An empty id
    // is "not an event", not "redacted".
    bool is_event_redacted_locked(const std::string& event_id);

    // THE single choke point for the search index. Upserts the searchable text
    // for `event_id`, or removes it when `body` is empty/absent.
    //
    // External-content FTS5 does not maintain itself: the index must be told to
    // forget the OLD text before the new text is added, and that requires having
    // the old text to hand. Getting that wrong leaves an index that still matches
    // deleted or pre-edit words — exactly the bug this feature must not ship. So
    // every path that changes what a message says goes through here and nowhere
    // else. Caller must hold mutex_.
    void reindex_search_locked(const std::string& event_id, const std::string& room_id,
                              const std::string& sender, int64_t stream_position,
                              const std::optional<std::string>& body);
    // Recomputes the searchable text for `event_id` from its current stored state
    // (resolving any winning edit, honouring redaction) and reindexes.
    // Caller must hold mutex_.
    void refresh_search_for_event_locked(const std::string& event_id);
    // The generation in force for `room_id`: its stored value, or the install
    // baseline when it has never been rotated. Caller must hold mutex_.
    uint64_t voice_key_generation_locked(const std::string& room_id);

    // Cached result of "does event_search_fts exist"; -1 = not yet checked.
    int fts5_available_ = -1;
    bool fts5_available_locked();

    sqlite3* db_ = nullptr;
    // Kept so the file mode can be re-applied after a VACUUM replaces the file.
    std::string db_path_;
    std::mutex mutex_;
    // Monotonic; never reused even after delete_room removes the newest rows.
    // Mirrored into server_meta so it survives a restart.
    int64_t next_stream_position_ = 1;
};

} // namespace bsfchat
