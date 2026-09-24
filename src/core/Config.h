#pragma once

#include <bsfchat/Constants.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bsfchat {

// PBKDF2 work factor we consider adequate, as a power of two: 2^19 = 524,288
// iterations. It is both the built-in default below and the threshold
// Config::validate() warns under, so a deployment that carries an older,
// weaker value from a previous deploy template says so on every start instead
// of looking fine. Raising it is always safe — see the comment on
// password_hash_cost.
inline constexpr int kRecommendedPasswordHashCost = 19;

struct IdentityConfig {
    std::string provider_url;
    bool required = false;
    bool allow_local_accounts = true;
    // The OAuth client an identity token must have been issued to — checked
    // against the token's `azp` claim. Empty skips that check.
    //
    // This USED to be the expected `aud`, and that was identity audit
    // 2026-09 finding C1: every server checked for the same value, so an
    // id_token handed to one server (a hostile one included) signed its
    // holder in at every other server trusting the provider, and through
    // link_identity could attach the victim's identity to the attacker's
    // account for good. The audience is now this server's own public URL —
    // see Config::public_url and expected_identity_audience() — and the
    // client id moved to `azp`, where OIDC puts it once `aud` names somebody
    // else. Keeping the check stops a token some other registered relying
    // party obtained for this server from signing anybody in here.
    std::string client_id = "bsfchat-desktop";
};

struct StorageS3Config {
    std::string endpoint = "http://localhost:9000";
    std::string access_key;
    std::string secret_key;
    std::string bucket = "bsfchat-media";
    std::string region = "us-east-1";
    bool use_path_style = true;
};

struct StorageConfig {
    std::string type = "local";  // "local" or "s3"
    StorageS3Config s3;
};

// LiveKit SFU. Optional: when unset, voice uses the peer-to-peer mesh below.
// Configured as a [voice.livekit] sub-table.
struct LiveKitConfig {
    // Base URL the CLIENT should connect to, e.g. "wss://sfu.example.com".
    // Handed to clients verbatim; the server never dials it itself.
    std::string url;
    // Credential pair matching the LiveKit server's own `keys:` map.
    std::string api_key;
    // SECRET. Never logged, never returned in any API response.
    std::string api_secret;
    // Join-token lifetime. Short by design: LiveKit only checks `exp` when a
    // connection is established, and refreshes tokens for already-connected
    // participants itself, so a short TTL costs nothing during a call and
    // limits the blast radius of a leaked token. Clamped to
    // [kLiveKitMinTtl, kLiveKitMaxTtl] at mint time.
    int64_t token_ttl = 600; // 10 minutes

    // Media encryption between clients, with a per-room key this server
    // mints and hands out alongside the join token.
    //
    // READ THIS BEFORE DESCRIBING THE FEATURE ANYWHERE.
    //
    // This is NOT end-to-end encryption, and must never be called that.
    // What it buys is precisely one thing: the LiveKit SFU relays media it
    // cannot read. That is worth having when the SFU runs on separate
    // infrastructure or on someone else's cloud. It is not confidentiality
    // from THIS server.
    //
    // Two limitations, both deliberate and both permanent under this design:
    //
    //   1. This server generates and holds the key. Anyone who can read the
    //      server's config or memory can decrypt the media.
    //   2. A member who leaves keeps the ability to decrypt that room's
    //      traffic until the key is rotated. LiveKit's ratchet cannot fix
    //      this — the ratchet derives the next key from the current one with
    //      a public salt and no secret input, so anyone who ever held a
    //      generation can compute every later one. Only issuing a fresh
    //      unrelated key excludes them, which is what rekey does.
    //
    // Rekey-on-leave is not automatic; call the rekey endpoint. A rotation is
    // durable: the generation lives in the database (schema v19), not in the
    // handler, so it survives a restart. The one thing that can undo it is
    // restoring a database snapshot taken before it.
    //
    // A rotation also moves the channel to a new SFU room, because the room
    // name is derived from the same generation. That is what retires tokens
    // already in circulation: they are signed JWTs the server cannot recall,
    // so instead they are left naming a room nobody is in. It takes effect
    // per participant at their next token fetch — reconnect, or token_ttl
    // below — and cannot reach a client that is already connected.
    bool room_encryption = true;

    // Key-derivation secret for room keys. Optional: when empty, api_secret
    // is used instead, under a distinct HKDF info string so the two uses can
    // never produce the same bytes.
    //
    // Set this to a dedicated high-entropy value if you would rather not
    // have one secret serving two purposes. Either way it is a KDF input and
    // never leaves the server.
    std::string room_key_secret;

    // True when all three of url/api_key/api_secret are present. A partially
    // configured LiveKit is treated as "not configured" rather than as an
    // error, so a half-finished config can never mint a broken token.
    bool configured() const {
        return !url.empty() && !api_key.empty() && !api_secret.empty();
    }

    // The secret room keys are derived from. Never logged, never returned.
    const std::string& key_material() const {
        return room_key_secret.empty() ? api_secret : room_key_secret;
    }
};

struct VoiceConfig {
    bool enabled = true;
    LiveKitConfig livekit;
    // TURN server URIs. Config key `turn_uri` accepts either a single string
    // or an array of strings (e.g. udp + tcp transport variants).
    std::vector<std::string> turn_uris;
    std::string turn_username;
    std::string turn_password;
    // coturn REST-API shared secret (use-auth-secret / static-auth-secret).
    // When set, /voip/turnServer returns time-limited ephemeral credentials
    // instead of the static turn_username/turn_password.
    std::string turn_secret;
    int64_t turn_ttl = 3600; // Ephemeral credential lifetime, seconds
    std::string stun_uri; // No default — admin should configure their own STUN/TURN
    // Was `false` ("TURN-only for IP privacy") while turn_uris/stun_uri
    // defaulted to EMPTY and voice.enabled defaulted true — relay-only with
    // zero relays, i.e. 100% voice failure on a fresh install. For a
    // self-hosted product the sane default is working voice; an admin who
    // deploys TURN and wants every call relayed sets this back to false.
    // Config::load additionally warns loudly (and falls back to P2P) if this
    // is false with no relay configured.
    bool allow_peer_to_peer = true;
};

// Push notifications.
//
// Deployment note: this server is deliberately provider-agnostic. It speaks only
// the Matrix push-gateway "notify" shape and POSTs it to whatever URL a client
// registered on its pusher. A deployment that wants mobile push must run a push
// gateway (sygnal or equivalent) holding the FCM/APNs credentials; none of those
// credentials belong in this config, and none are read here.
// True when /voip/turnServer is configured to hand every authenticated account
// the SAME long-lived TURN credential: voice on, no `turn_secret` (so the
// ephemeral REST-API branch is unreachable), and a static `turn_password` to
// give out. See Config::validate for why that is a misconfiguration rather than
// a mode, and VoiceHandler::handle_turn_server for the branch it selects.
bool turn_credentials_are_shared(const VoiceConfig& voice);

struct Config;
// The `aud` an identity token must carry to sign in here: public_url, or
// "https://<server_name>" when that is unset, canonicalised with the same
// function the client and the identity provider use. Empty when neither is a
// usable URL — and an empty audience means NO identity token is accepted,
// never that the audience goes unchecked.
std::string expected_identity_audience(const Config& cfg);

struct PushConfig {
    bool enabled = true;
    // How long the delivery worker sleeps when the queue is empty. It is also
    // woken immediately whenever something is enqueued, so this is only the
    // ceiling on picking up a retry that has come due.
    int worker_poll_ms = 1000;
    // Per-attempt HTTP timeouts against the gateway, seconds.
    int connect_timeout_s = 5;
    int request_timeout_s = 10;
    // Attempts before a notification is dropped. Exponential backoff between
    // them, capped at max_backoff_ms.
    int max_attempts = 6;
    int64_t base_backoff_ms = 5000;
    int64_t max_backoff_ms = 60LL * 60 * 1000;
    // Rows claimed per wakeup.
    int batch_size = 20;
    // How long a claimed row stays invisible to the worker. Must comfortably
    // exceed request_timeout_s or a slow gateway would get duplicate deliveries.
    int64_t lease_ms = 60LL * 1000;

    // URL prefixes a client is allowed to register as a push gateway.
    //
    // This matters more than it looks, and it is DEFAULT CLOSED. /pushers/set
    // lets any authenticated user name a URL that the SERVER will then POST the
    // notification to, so an unrestricted list is two things at once: a
    // server-side request forgery primitive aimed at whatever this host can
    // reach, and a self-serve exfiltration feed — any account can point a pusher
    // at a collector it owns and have message content delivered there forever,
    // with the client closed and nothing in any moderator surface to show it.
    //
    // Empty therefore means "no gateway is permitted", not "any gateway". A
    // deployment that wants mobile push names its gateway here; one that does
    // not gets push.enabled forced to false at startup with an error, so the
    // failure is loud and the feature is off rather than open.
    //
    // Entries are matched on scheme + host + port, then on a path-segment
    // boundary — never as a raw string prefix, which would let
    // "https://push.example.com" also authorise "https://push.example.com.evil.tld/".
    std::vector<std::string> allowed_gateway_prefixes;

    // Whether an allowlisted gateway may live on an internal address (loopback,
    // RFC1918, link-local/metadata, a bare compose service name...).
    //
    // Separate from the allowlist on purpose: the allowlist answers "which
    // gateway", this answers "may the server be made to talk to the inside of
    // its own network at all". Sygnal in the same compose file is a legitimate
    // and common self-hosted shape, so it is configurable — but it is off by
    // default, so an allowlist entry typo'd onto an internal host fails closed
    // rather than becoming an SSRF aperture.
    bool allow_internal_gateway = false;

    // What a pusher that does not ask for a specific format gets.
    //
    // "event_id_only": the gateway learns that something happened in a room and
    // nothing about what was said. "full": the verbatim event content, sender
    // and display name, the Matrix default.
    //
    // event_id_only is the default here because the third party behind the
    // gateway is exactly the party this product exists not to trust, and
    // because a pusher omitting `format` is saying nothing about consent. An
    // operator who runs their own gateway and wants rich notifications sets
    // "full" deliberately.
    std::string default_payload = "event_id_only";
};

// Per-account limits on the endpoints that write to a room. Flat keys under
// [limits]; see core/SendLimiter.h for why these key on the ACCOUNT while the
// [auth] limits below key on the client address.
//
// Separate from AuthLimitsConfig on purpose. That block is about credential
// guessing on endpoints with no authenticated caller yet; this one is about
// how much an account that has already signed in may do. Folding them together
// would mean one `enabled` switch turning off two unrelated protections.
struct SendLimitsConfig {
    // Master switch for everything below.
    bool enabled = true;

    // Deliberately far above human use: this exists to stop a loop, not to
    // pace a conversation. 120 events/minute is two a second sustained, which
    // no one reaches by typing or by clicking reactions. Anything that trips
    // it is a script or a bug. 0 = unlimited.
    int send_limit = 120;
    // Lower, because deleting is rarer than sending and a deletion loop is
    // more destructive than a send loop. Still well above a moderator clearing
    // a run of messages by hand.
    int redact_limit = 60;
    // Lowest of the three: an upload carries a whole file into storage, so the
    // unit of work behind each one is orders of magnitude larger.
    int media_upload_limit = 30;
    // Profile writes (displayname / avatar_url / nickname). Far the smallest
    // number here because it is far the largest amplifier: ONE request re-emits
    // an m.room.member event in every channel the account is joined to and wakes
    // every parked /sync on the server, so on a 50-channel deployment the unit of
    // work is 50 event inserts and a server-wide poll storm. Nobody renames
    // themselves ten times a minute; anything that does is a loop.
    int profile_limit = 10;
    // Room creation (POST /createRoom), for both channels and DMs.
    //
    // Same philosophy as send_limit and deliberately not tighter: this is here
    // to stop a loop, not to pace a person. An operator setting up a fresh
    // deployment creates a category and eight channels in about a minute, and
    // a number that refused them would be a bug reported as "the server broke
    // while I was making channels". Thirty a minute is one every two seconds
    // sustained; nobody reaches it by clicking.
    //
    // It is the only write budget here an account holding NO permissions can
    // spend, because opening a DM is deliberately ungated and creating a
    // channel is not — so this is the ceiling on the one expensive route
    // @everyone can reach. The unit of work behind each request is a room row,
    // half a dozen state events, and a membership row plus an m.room.member
    // event plus a sync wake per participant.
    //
    // It does NOT replace the shape rules in handle_create_room, and the
    // distinction matters: a rate limit bounds how FAST the wrong thing can be
    // done, never whether it can be done. The invite-list rule lives in the
    // handler and this sits behind it. The real ceiling on DM abuse is the
    // per-pair dedup — one room per pair, so an attacker is bounded by the
    // number of accounts however long they run — and this bounds the burst.
    int room_create_limit = 30;

    // Content reports (POST /rooms/{id}/report/{event}, /users/{id}/report).
    //
    // The smallest number in this block, deliberately. Every other limit here
    // protects the SERVER from a loop; this one protects the MODERATION QUEUE
    // from one, and the queue is read by a person. Ten a minute is far more
    // than anyone reports by hand and still low enough that a script cannot
    // bury a real report under a thousand fabricated ones between two glances
    // at the log.
    //
    // It bounds the burst and nothing else — the same honest reading the other
    // limits here get. An attacker with patience can still file reports slowly,
    // and the answer to that is the ban list, not a smaller number.
    int report_limit = 10;

    // Account-data writes (PUT /user/{userId}/account_data/{type}), which is
    // where a client's block list is stored.
    //
    // The most generous, because the write is the cheapest here: one upserted
    // row, no event, no fan-out, no sync wake. It is not zero, though, because
    // the account-data TYPE is caller-chosen — each new type is a new row, so a
    // loop grows a table rather than rewriting one value. A client that blocks
    // somebody sends one of these; a client syncing settings sends a handful.
    int account_data_limit = 60;

    int window_seconds = 60;

    // ── How big one write may be, as opposed to how many ──────────────────
    //
    // Everything above is a RATE: how often an account may do a thing. These
    // two are a SIZE: how big one of those things may be. They live in the
    // same block because they defend the same resource from the same caller,
    // and because an operator reading "[limits]" is looking for both — but
    // note they are deliberately NOT under `enabled`. Turning the rate limiter
    // off is a defensible choice when something upstream is pacing requests;
    // there is no upstream that can decide a message body is too big for this
    // server's database, so the size ceilings always apply.
    //
    // Both are bytes. See limits::kMaxMessageBodyBytes in the protocol headers
    // for why bytes and not characters, and why the default is where it is.

    // Ceiling on `body` (and `m.new_content.body`) of an m.room.message.
    // `formatted_body` is allowed limits::kFormattedBodyMultiplier times this,
    // derived rather than configured, because it is the same message with
    // markup and an operator setting the two independently would only ever set
    // them inconsistently.
    size_t max_message_bytes = limits::kMaxMessageBodyBytes;

    // Ceiling on the whole request body of a PUT .../send/{type}/{txn},
    // whatever the type, checked before the JSON is parsed. Covers the event
    // types that are not messages — m.reaction and the call signalling — and
    // any field on a message that nothing reads.
    size_t max_event_bytes = limits::kMaxEventContentBytes;
};

// Rate limiting and lockout for /login, /register, /refresh and
// /account/password. Flat keys under [auth]; grouped here so AuthHandler can
// take the lot.
//
// Until this existed nothing limited any of them: unlimited password guesses,
// unlimited account creation, and — because every attempt runs PBKDF2 on an
// HTTP worker — an unauthenticated CPU-exhaustion lever.
struct AuthLimitsConfig {
    // Master switch. Off means every limit below is ignored.
    bool enabled = true;

    // Addresses (or CIDR networks) of reverse proxies whose X-Forwarded-For is
    // believed. Behind a proxy the socket peer is the proxy for EVERY request;
    // without this list the per-address limits below would put the whole
    // internet in one bucket and the first attacker to trip it would lock out
    // everyone. See http/ClientAddress.h for how the client is derived.
    //
    // Loopback by default: only a process on this host can connect from it,
    // and the worst it can do by forging the header is dodge a rate limit. A
    // proxy anywhere else — including the Docker bridge gateway, which is what
    // a containerised server sees when nginx runs on the host — must be listed.
    //
    // Config::validate() merges trusted_public_proxies (below) into this, so
    // by the time anything reads it this is the whole effective trust set and
    // ClientAddressResolver still takes one list.
    std::vector<std::string> trusted_proxies = {"127.0.0.0/8", "::1"};

    // The same thing, for ranges that reach into PUBLIC address space, which
    // an operator may have a real reason to trust: a CDN in front of the
    // origin appends its edge address to X-Forwarded-For, so the edge fleet
    // has to be trusted or every client behind it shares one rate-limit
    // bucket.
    //
    // Why a second key rather than a flag, or a CDN list built into the
    // server:
    //
    //   * Startup warns about every public range that is NOT written here, so
    //     a range added to `trusted_proxies` next month is still called out —
    //     which a one-time "I know what I'm doing" boolean would swallow.
    //   * It is the list, not a duplicate of it, so there is nothing to keep
    //     in step. The CDN's ranges are written exactly once.
    //   * No published CDN range list ships in the binary. Those lists change
    //     between our releases, so a built-in copy would be wrong in both
    //     directions — blessing a range the CDN has given up, and warning
    //     about one it has just added. The operator's own copy is the only one
    //     that can be current, and the server's job is to make them state it,
    //     not to guess it.
    //
    // Entries here are parsed and rejected exactly like the ones above, and a
    // range too wide to be a proxy fleet still warns (see
    // is_too_wide_to_be_a_proxy_fleet) — this key narrows the check, it does
    // not switch it off.
    std::vector<std::string> trusted_public_proxies;

    // Whose ranges those are and when they were last refreshed. Required for
    // the acknowledgement to count: an empty reason leaves the ranges trusted
    // but still warned about, because a list nobody has explained is
    // indistinguishable from one somebody pasted in.
    std::string trusted_public_proxies_reason;

    // Attempts per client address per window, counted separately for each of
    // /login, /register, /refresh and /account/password. Successful attempts
    // count too: this bounds the PBKDF2 work one address can demand.
    int rate_limit = 30;
    int rate_window_seconds = 60;

    // Failed password attempts before a lockout, tracked independently per
    // client address (stops one host spraying many accounts) and per target
    // username (stops many hosts grinding one account). Lockout length doubles
    // as the memory of the counter: failures older than this are forgotten.
    //
    // The per-username lockout is a deliberate trade: it lets anyone who knows
    // a username hold that account's NEW logins off for lockout_seconds at a
    // time. Existing sessions are untouched, which is why the price is
    // acceptable, and it is the reason the lockout is minutes rather than
    // hours.
    int max_failures = 10;
    int lockout_seconds = 300;

    // Accounts one client address may create per window.
    int register_limit = 10;
    int register_window_seconds = 3600;

    // Accounts the WHOLE SERVER will create per window, regardless of source.
    // The per-address limit alone is cheap to sidestep with many addresses,
    // and every signup costs a password hash plus role bootstrap across all
    // existing users. This one is a global switch by design — but it only
    // closes new signups, never sign-in, and only for the rest of the window.
    // 0 disables it.
    int register_global_limit = 200;
};

struct Config {
    // Server
    std::string server_name = "localhost";
    // The URL clients use to reach this server, e.g. "https://chat.example".
    // Identity tokens are accepted only when their `aud` is exactly this URL
    // (in canonical form): it is what the desktop client names as the
    // `resource` when it signs in here, so it must match the address users
    // actually type or are sent to by .well-known. Empty means
    // "https://<server_name>", which is right for the shipped deployment.
    // A wrong value fails CLOSED — every identity sign-in is refused, password
    // sign-in is unaffected — and the server says so at startup.
    std::string public_url;
    std::string bind_address = "0.0.0.0";
    int port = 8448;
    // Base size of the HTTP worker pool. cpp-httplib dispatches one pool task
    // per CONNECTION and runs that connection's entire keep-alive session on
    // it, so a worker is held for as long as the socket lives — for a /sync
    // long poll, that is the full poll timeout. This is therefore a count of
    // concurrent *connections*, not of concurrent requests, and every signed-in
    // client holds several.
    int workers = 64;
    // Hard ceiling on the pool. Threads beyond `workers` are spawned on demand
    // when a connection arrives and no worker is idle, and retire themselves
    // after a few seconds idle.
    //
    // Treat this as a safety net, not as the mechanism — `workers` is what
    // must actually be sized. httplib only grows the pool when it observes
    // zero idle workers at the instant a connection is enqueued, and a thread
    // it spawns then takes the OLDEST queued job rather than the arrival that
    // triggered it. A burst that lands faster than the workers can decrement
    // the idle counter — every client reconnecting after a restart, say —
    // therefore leaves a backlog that growth alone never clears.
    //
    // This exists because the pool used to be constructed with a base size and
    // no ceiling argument, which httplib reads as "ceiling == base": a hard cap
    // with no growth at all. With workers = 4 and two desktop clients — each
    // parking a 30s /sync plus a second connection for its voice poll — all
    // four workers were held, and the next request to arrive (a message send)
    // sat in the job queue with no thread to run it until a long poll timed
    // out. Measured: 28.4s to deliver a message that takes 81ms on an idle
    // pool. Growth is what makes the pool degrade gracefully instead of
    // deadlocking at exactly the size an operator configured.
    int max_workers = 512;

    // Browser origins allowed to read this API cross-origin, exactly as a
    // browser sends them in `Origin` ("https://app.example.com"). Empty — the
    // default — means no CORS headers at all, which is right for every client
    // that exists today: the desktop client is Qt and the bots are plain HTTP
    // clients, none of which enforce CORS. Add an origin when a browser client
    // ships. "*" is refused by Config::validate: a wildcard is what this
    // replaced (security-audit-2026-09 finding S8). See http/RequestGuard.h.
    std::vector<std::string> cors_allowed_origins;

    // Database
    std::string database_path = "./data/bsfchat.db";

    // Media
    std::string media_path = "./data/media/";
    size_t max_upload_size_mb = 50;
    // Require an access token (header or ?access_token=) on media downloads.
    // On by default. The desktop client appends ?access_token= (see
    // util/MediaUrl.h) because QML Image.source cannot set headers.
    //
    // TURNING THIS OFF ALSO TURNS OFF THE PER-ROOM ACL. Media downloads are
    // gated on VIEW_CHANNEL in a room that names the object
    // (MediaHandler::may_download), and that check needs a caller to evaluate;
    // with no token there is nobody to check, so every object on the server
    // becomes a bare capability URL again. The previous wording here said the
    // switch existed because a media id "is a bare capability URL: no
    // revocation, no per-room ACL" — implying the switch mitigated those. It
    // never did, and now it is the thing that disables the ACL.
    //
    // Set to false only for a deployment still running pre-token clients, and
    // understand that doing so makes every attachment in every private channel
    // readable by anyone who learns its id.
    bool require_media_auth = true;

    // ── Collecting media nothing references any more ──────────────────────
    //
    // See storage/MediaReaper.h. Before this existed there was no erasure path
    // for media at all: redaction dropped the reference and left the bytes
    // served, and data/media/ only ever grew.
    bool media_reaper_enabled = true;

    // Log what would be deleted; delete nothing. Defaults TRUE, and should
    // stay true for one release.
    //
    // This is the only thing in the server that destroys user data from disk
    // on a timer, and the consequence of a wrong reference query is silent and
    // unrecoverable. An operator should read a night of "would delete" lines
    // against their own corpus and satisfy themselves it names nothing they
    // recognise, and only then arm it. The cost of the default is that disk
    // keeps growing for one more release; the cost of the other default, if
    // the query is wrong anywhere, is somebody's attachments.
    bool media_reaper_dry_run = true;

    // How long an object may exist unreferenced before it is collected.
    //
    // Load-bearing, not a tuning knob: POST /upload and the PUT /send that
    // names the object are two separate requests, and in between the object is
    // indistinguishable from an orphan. This has to comfortably exceed the
    // longest plausible gap between attaching a file and sending the message —
    // someone attaches a screenshot, writes three paragraphs, gets pulled into
    // a meeting, comes back. A day is generous on purpose; the disk saving
    // from making it an hour is not worth the class of bug it opens.
    int media_orphan_grace_hours = 24;

    // How often to sweep. Cheap (two indexed NOT EXISTS over the media table)
    // and nothing depends on collection being prompt.
    int media_reaper_interval_minutes = 60;
    // Lifetime of a signed media ticket, in seconds. See api/MediaTicket.h.
    //
    // A ticket is what the client puts in a media URL instead of the session
    // token, so this is how long a URL recovered from an access log, a browser
    // history entry or a clipboard is worth anything — and it is worth one
    // object, to the one already-authorized user it names, even then. Clamped
    // to [30, 3600] at use: the ceiling is the point, an operator must not be
    // able to turn a capability URL back into a long-lived bearer token.
    //
    // 300 is sized so a channel's images resolve on one mint each and a video
    // plays through without the client re-minting mid-stream.
    int media_ticket_ttl_seconds = 300;

    // Storage
    StorageConfig storage;

    // First run. What a deployment that has never held a room creates for
    // itself at startup: a #general text channel and a General Voice channel,
    // so the first person to sign in lands somewhere instead of in an empty
    // shell they cannot add to. See core/FirstRun.h for the guards that keep
    // this away from an established server — turning this off does NOT make an
    // existing deployment safer, because the guards already do, and it does not
    // remove channels a previous boot created.
    bool create_default_channels = true;

    // Auth
    bool registration_enabled = true;
    // PBKDF2-HMAC-SHA256 work factor, as a power of two: iterations = 2^cost.
    // 19 => 524,288 iterations, in line with current OWASP guidance (~600k).
    // The old default of 12 gave 4,096. Each stored hash records the cost it
    // was created with, so existing hashes still verify; AuthHandler
    // transparently re-hashes on the next successful login.
    int password_hash_cost = kRecommendedPasswordHashCost;
    // Access-token validity, in days. Long on purpose: the desktop client
    // stores one access token and has no background refresh, so a short
    // lifetime would log people out mid-session. Every authenticated request
    // slides the expiry forward once the session is past half its lifetime, so
    // an active client never lapses while an unused (or leaked-and-idle) token
    // dies on schedule. Clients that opt in with `refresh_token: true` also get
    // a refresh token for POST /_matrix/client/v3/refresh.
    // Keep the default in sync with kDefaultAccessTokenLifetimeMs.
    int access_token_lifetime_days = 90;

    // Request limits on the unauthenticated credential endpoints. See
    // AuthLimitsConfig. TOML keys live flat under [auth].
    AuthLimitsConfig auth_limits;
    // SendLimitsConfig. TOML keys live flat under [limits].
    SendLimitsConfig send_limits;

    // TLS. NOTE: not implemented — HttpServer has no SSLServer path. Kept in
    // the schema so an existing config with a [tls] block still parses, but
    // Server::start() refuses to start when tls_enabled is true rather than
    // silently serving plaintext on a port the admin believes is HTTPS.
    // Terminate TLS at a reverse proxy.
    bool tls_enabled = false;
    std::string tls_cert_file;
    std::string tls_key_file;

    // Identity (optional)
    std::optional<IdentityConfig> identity;

    // Voice
    VoiceConfig voice;

    // Push notifications
    PushConfig push;

    static Config load(const std::string& path);
    static Config defaults();

    // Clamps unsafe values and warns about combinations that cannot work
    // (voice enabled with relay-only and no relay, unset identity audience,
    // absurd password cost). Applied by load(); exposed for tests.
    static void validate(Config& cfg);
};

} // namespace bsfchat
