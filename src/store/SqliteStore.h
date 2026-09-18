#pragma once

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

// Sentinel "user id" a room-wide (`@room`) mention is stored under. Safe as a
// sentinel because every real Matrix user id is "@localpart:server" and so
// always contains a colon — no account can ever collide with it, which means a
// client cannot manufacture a room-wide mention by claiming to mention a user
// literally called "@room".
inline constexpr const char* kRoomMentionSentinel = "@room";

class SqliteStore {
public:
    explicit SqliteStore(const std::string& db_path);
    ~SqliteStore();

    SqliteStore(const SqliteStore&) = delete;
    SqliteStore& operator=(const SqliteStore&) = delete;

    void initialize();

    // Users
    bool create_user(const std::string& user_id, const std::string& password_hash);
    std::optional<std::string> get_password_hash(const std::string& user_id);
    // Replaces the stored hash (used to transparently upgrade a hash that was
    // generated with a weaker cost factor at the next successful login).
    void update_password_hash(const std::string& user_id, const std::string& password_hash);
    bool user_exists(const std::string& user_id);
    bool username_exists(const std::string& localpart);

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
    // block redemption — refreshing an expired access token is the whole point.
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
    std::vector<std::string> list_all_users();

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
    // The direct room both users are currently joined to, if any — oldest
    // first, so the answer is stable when legacy duplicates exist.
    std::optional<std::string> find_direct_room(const std::string& user_a,
                                                const std::string& user_b);
    // Remove a room and everything that references it (events, members,
    // read markers). Destructive; intended for admin-driven channel deletion.
    void delete_room(const std::string& room_id);
    std::vector<std::string> get_joined_rooms(const std::string& user_id);
    bool is_room_member(const std::string& room_id, const std::string& user_id);
    // Public, non-category, non-direct rooms — i.e. rooms every user on the
    // instance is expected to be a member of.
    std::vector<std::string> list_public_rooms();
    // Non-category, non-direct rooms.
    std::vector<std::string> list_all_non_category_rooms();
    // Non-category, non-direct rooms that carry no bsfchat.room.type state
    // event. Those predate the Discord-like channel model and are the only
    // rooms the one-time legacy-publicize migration is allowed to touch.
    std::vector<std::string> list_legacy_untyped_rooms();

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
    int64_t insert_event(const std::string& event_id, const std::string& room_id,
                         const std::string& sender, const std::string& event_type,
                         const std::optional<std::string>& state_key,
                         const std::string& content_json, int64_t origin_server_ts);

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
    std::pair<std::vector<RoomEvent>, std::optional<int64_t>>
    get_room_events_paginated(const std::string& room_id, int limit,
                              const std::string& direction = "b",
                              const std::optional<std::string>& from = std::nullopt,
                              const std::optional<std::string>& viewer = std::nullopt);

    std::vector<RoomEvent> get_room_events(const std::string& room_id, int limit, const std::string& direction = "b",
                                            const std::optional<std::string>& from = std::nullopt);

    std::vector<RoomEvent> get_state_events(const std::string& room_id);
    std::optional<RoomEvent> get_state_event(const std::string& room_id, const std::string& event_type, const std::string& state_key);
    std::optional<RoomEvent> get_event_by_id(const std::string& event_id);

    // Redact an event in place: replaces its content with an empty object and
    // records who redacted it. The event row itself (id, type, sender,
    // timestamp) survives as a tombstone, per the Matrix redaction algorithm.
    // Returns false if the event doesn't exist. Idempotent.
    //
    // Interacts with edits in both directions: redacting an original discards
    // its edit pointer (an edit must never resurrect redacted content), and
    // redacting a replacement re-resolves its target to the newest surviving
    // replacement, or back to the pristine original if there is none.
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
    // Refuses to apply to a redacted event. Returns false if the target does
    // not exist or is redacted.
    bool apply_edit(const std::string& target_event_id, const std::string& replacement_event_id);

    // The replacement currently winning for an event, or nullopt if unedited.
    std::optional<std::string> get_edit_pointer(const std::string& event_id);

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
    // Returns the content this write REPLACED, or nullopt if the key was unset.
    // Read inside the same lock as the write, which is what lets the audit log
    // record a before/after pair that no concurrent writer can have already
    // superseded — reading it with a separate get_server_state() call first would
    // leave a window where two simultaneous role edits both report the same
    // "before".
    std::optional<std::string> set_server_state(const std::string& event_type,
                                               const std::string& state_key,
                                               const std::string& sender,
                                               const std::string& content_json);
    std::optional<std::string> get_server_state(const std::string& event_type,
                                                 const std::string& state_key);

    // Server metadata key/value store (migration markers etc.).
    std::optional<std::string> get_meta(const std::string& key);
    void set_meta(const std::string& key, const std::string& value);

    // Permissions / roles (reads)
    // Returns the server-wide role definitions, empty if unset.
    std::vector<ServerRole> get_server_roles();
    // Role IDs assigned to the given user, empty if none.
    std::vector<std::string> get_member_role_ids(const std::string& user_id);
    // All per-channel allow/deny overrides for the room, keyed by target ("role:..." / "user:...").
    std::map<std::string, ChannelPermissionOverride> get_channel_overrides(const std::string& room_id);
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
    // (`@room`) mention. Entries equal to `sender` are dropped — mentioning
    // yourself must not badge your own room. Idempotent per (event, user).
    void record_mentions(const std::string& event_id, const std::string& room_id,
                         const std::string& sender, int64_t stream_position,
                         const std::vector<std::string>& mentioned_user_ids);

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
    void set_read_marker(const std::string& user_id, const std::string& room_id, int64_t stream_pos);
    int64_t get_read_marker(const std::string& user_id, const std::string& room_id);
    // Counts messages in the room past the user's marker that somebody else
    // sent. Excludes m.replace replacements (editing a message used to bump
    // everyone else's badge as if it were a new message) and redacted events (a
    // deleted message must not keep a badge lit for content nobody can read).
    int count_unread(const std::string& user_id, const std::string& room_id);

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
    // `append: false` semantics: a pushkey belongs to exactly one session, so
    // registering it removes every other pusher holding it, including ones
    // belonging to other users (a reused device token must not keep delivering
    // the previous account's messages).
    int delete_pushers_by_pushkey_except(const std::string& pushkey,
                                        const std::string& keep_user_id,
                                        const std::string& keep_app_id);
    // A gateway reporting a pushkey as rejected means the device is gone.
    int delete_pushers_by_pushkey(const std::string& pushkey);

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
    };

    // Enqueue only. Never performs network I/O, so the event-insert path is
    // never blocked on a gateway.
    void enqueue_pushes(const std::vector<QueuedPush>& pushes);
    // Claims up to `limit` rows that are due at `now`, pushing their
    // next_attempt_at out by `lease_ms` so the same row is not picked up again
    // while it is in flight. Returns with the store mutex RELEASED — the caller
    // must do its HTTP work outside any store call, never holding the store's
    // global lock across network I/O.
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

private:
    // Drops spent refresh-token records once no live session could still
    // belong to their family. Called with mutex_ already held.
    void prune_consumed_refresh_tokens_locked();

    void exec(const std::string& sql);
    // Claims the next stream position. Caller must hold mutex_.
    int64_t claim_stream_position_locked();
    // Re-points `target_event_id` at the newest surviving (non-redacted)
    // replacement, clearing the pointer when none is left. Caller must hold
    // mutex_.
    void reresolve_edit_locked(const std::string& room_id, const std::string& target_event_id);

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
    // Cached result of "does event_search_fts exist"; -1 = not yet checked.
    int fts5_available_ = -1;
    bool fts5_available_locked();

    sqlite3* db_ = nullptr;
    std::mutex mutex_;
    // Monotonic; never reused even after delete_room removes the newest rows.
    // Mirrored into server_meta so it survives a restart.
    int64_t next_stream_position_ = 1;
};

} // namespace bsfchat
