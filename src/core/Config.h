#pragma once

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
    // Expected `aud` claim on identity tokens. Without an audience check, an
    // ID token minted for ANY other OAuth client registered with the same
    // identity provider is accepted as a chat login. Defaults to the id the
    // shipped desktop client registers under.
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

    int window_seconds = 60;
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
    std::vector<std::string> trusted_proxies = {"127.0.0.0/8", "::1"};

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

    // Storage
    StorageConfig storage;

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
