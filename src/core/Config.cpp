#include "core/Config.h"
#include "core/Logger.h"
#include "http/ClientAddress.h"

// For kLiveKitMinTtl/kLiveKitMaxTtl — validate() warns using the same bounds
// the signer clamps to, so the two can't drift apart.
#include <bsfchat/JwtUtils.h>
// For kMaxSyncTimeoutMs — the worker-headroom warning quotes the real
// long-poll ceiling rather than restating it as a literal.
#include <bsfchat/Constants.h>

#include <toml++/toml.hpp>
#include <stdexcept>

namespace bsfchat {

Config Config::load(const std::string& path) {
    Config cfg;

    try {
        auto tbl = toml::parse_file(path);

        // toml++'s table::get returns nullptr for a missing key, so
        // every read must guard before value_or — a table that exists
        // with any key omitted would otherwise null-deref. Same
        // pattern as [voice] below.

        // [server]
        if (auto server = tbl["server"].as_table()) {
            if (auto v = server->get("name")) cfg.server_name = v->value_or(cfg.server_name);
            if (auto v = server->get("bind_address")) cfg.bind_address = v->value_or(cfg.bind_address);
            if (auto v = server->get("port")) cfg.port = v->value_or(cfg.port);
            if (auto v = server->get("workers")) cfg.workers = v->value_or(cfg.workers);
            if (auto v = server->get("max_workers")) cfg.max_workers = v->value_or(cfg.max_workers);
        }

        // [database]
        if (auto db = tbl["database"].as_table()) {
            if (auto v = db->get("path")) cfg.database_path = v->value_or(cfg.database_path);
        }

        // [media]
        if (auto media = tbl["media"].as_table()) {
            if (auto v = media->get("path")) cfg.media_path = v->value_or(cfg.media_path);
            if (auto v = media->get("max_upload_size_mb"))
                cfg.max_upload_size_mb = static_cast<size_t>(
                    v->value_or(static_cast<int64_t>(cfg.max_upload_size_mb)));
            if (auto v = media->get("require_auth"))
                cfg.require_media_auth = v->value_or(cfg.require_media_auth);
            if (auto v = media->get("reaper_enabled"))
                cfg.media_reaper_enabled = v->value_or(cfg.media_reaper_enabled);
            if (auto v = media->get("reaper_dry_run"))
                cfg.media_reaper_dry_run = v->value_or(cfg.media_reaper_dry_run);
            if (auto v = media->get("orphan_grace_hours"))
                cfg.media_orphan_grace_hours = v->value_or(cfg.media_orphan_grace_hours);
            if (auto v = media->get("reaper_interval_minutes"))
                cfg.media_reaper_interval_minutes =
                    v->value_or(cfg.media_reaper_interval_minutes);
        }

        // [auth]
        if (auto auth = tbl["auth"].as_table()) {
            if (auto v = auth->get("registration_enabled")) cfg.registration_enabled = v->value_or(cfg.registration_enabled);
            if (auto v = auth->get("password_hash_cost")) cfg.password_hash_cost = v->value_or(cfg.password_hash_cost);
            if (auto v = auth->get("access_token_lifetime_days"))
                cfg.access_token_lifetime_days = v->value_or(cfg.access_token_lifetime_days);

            auto& lim = cfg.auth_limits;
            if (auto v = auth->get("rate_limit_enabled")) lim.enabled = v->value_or(lim.enabled);
            if (auto v = auth->get("rate_limit")) lim.rate_limit = v->value_or(lim.rate_limit);
            if (auto v = auth->get("rate_window_seconds"))
                lim.rate_window_seconds = v->value_or(lim.rate_window_seconds);
            if (auto v = auth->get("max_failures")) lim.max_failures = v->value_or(lim.max_failures);
            if (auto v = auth->get("lockout_seconds")) lim.lockout_seconds = v->value_or(lim.lockout_seconds);
            if (auto v = auth->get("register_limit")) lim.register_limit = v->value_or(lim.register_limit);
            if (auto v = auth->get("register_window_seconds"))
                lim.register_window_seconds = v->value_or(lim.register_window_seconds);
            if (auto v = auth->get("register_global_limit"))
                lim.register_global_limit = v->value_or(lim.register_global_limit);
            // Single string or array, same as voice.turn_uri. Present-but-empty
            // is meaningful ("trust nothing, not even loopback"), so the
            // default is replaced rather than appended to.
            if (auto v = auth->get("trusted_proxies")) {
                lim.trusted_proxies.clear();
                if (auto arr = v->as_array()) {
                    for (const auto& el : *arr) {
                        if (auto s = el.value<std::string>()) lim.trusted_proxies.push_back(*s);
                    }
                } else if (auto s = v->value<std::string>()) {
                    lim.trusted_proxies.push_back(*s);
                }
            }
        }

        // [limits] — per-account limits on writes to a room.
        if (auto limits_tbl = tbl["limits"].as_table()) {
            auto& sl = cfg.send_limits;
            if (auto v = limits_tbl->get("enabled")) sl.enabled = v->value_or(sl.enabled);
            if (auto v = limits_tbl->get("send_limit")) sl.send_limit = v->value_or(sl.send_limit);
            if (auto v = limits_tbl->get("redact_limit"))
                sl.redact_limit = v->value_or(sl.redact_limit);
            if (auto v = limits_tbl->get("media_upload_limit"))
                sl.media_upload_limit = v->value_or(sl.media_upload_limit);
            if (auto v = limits_tbl->get("profile_limit"))
                sl.profile_limit = v->value_or(sl.profile_limit);
            if (auto v = limits_tbl->get("window_seconds"))
                sl.window_seconds = v->value_or(sl.window_seconds);
        }

        // [tls]
        if (auto tls = tbl["tls"].as_table()) {
            if (auto v = tls->get("enabled")) cfg.tls_enabled = v->value_or(cfg.tls_enabled);
            if (auto v = tls->get("cert_file")) cfg.tls_cert_file = v->value_or(std::string{});
            if (auto v = tls->get("key_file")) cfg.tls_key_file = v->value_or(std::string{});
        }

        // [storage]
        if (auto storage = tbl["storage"].as_table()) {
            if (auto v = storage->get("type")) cfg.storage.type = v->value_or(cfg.storage.type);

            if (auto s3 = (*storage)["s3"].as_table()) {
                if (auto v = s3->get("endpoint")) cfg.storage.s3.endpoint = v->value_or(cfg.storage.s3.endpoint);
                if (auto v = s3->get("access_key")) cfg.storage.s3.access_key = v->value_or(cfg.storage.s3.access_key);
                if (auto v = s3->get("secret_key")) cfg.storage.s3.secret_key = v->value_or(cfg.storage.s3.secret_key);
                if (auto v = s3->get("bucket")) cfg.storage.s3.bucket = v->value_or(cfg.storage.s3.bucket);
                if (auto v = s3->get("region")) cfg.storage.s3.region = v->value_or(cfg.storage.s3.region);
                if (auto v = s3->get("use_path_style")) cfg.storage.s3.use_path_style = v->value_or(cfg.storage.s3.use_path_style);
            }
        }

        // [voice]
        if (auto voice = tbl["voice"].as_table()) {
            if (auto v = voice->get("enabled")) cfg.voice.enabled = v->value_or(cfg.voice.enabled);
            // turn_uri accepts a single string or an array of strings
            if (auto v = voice->get("turn_uri")) {
                if (auto arr = v->as_array()) {
                    for (const auto& el : *arr) {
                        if (auto s = el.value<std::string>()) cfg.voice.turn_uris.push_back(*s);
                    }
                } else if (auto s = v->value<std::string>()) {
                    cfg.voice.turn_uris.push_back(*s);
                }
            }
            if (auto v = voice->get("turn_username")) cfg.voice.turn_username = v->value_or(cfg.voice.turn_username);
            if (auto v = voice->get("turn_password")) cfg.voice.turn_password = v->value_or(cfg.voice.turn_password);
            if (auto v = voice->get("turn_secret")) cfg.voice.turn_secret = v->value_or(cfg.voice.turn_secret);
            if (auto v = voice->get("turn_ttl")) cfg.voice.turn_ttl = v->value_or(cfg.voice.turn_ttl);
            if (auto v = voice->get("stun_uri")) cfg.voice.stun_uri = v->value_or(cfg.voice.stun_uri);
            if (auto v = voice->get("allow_peer_to_peer")) cfg.voice.allow_peer_to_peer = v->value_or(cfg.voice.allow_peer_to_peer);

            // [voice.livekit] — SFU credentials. Sub-table, same shape as
            // [storage.s3] above. Flat `livekit_url` style keys are NOT
            // read: keep one convention.
            if (auto lk = (*voice)["livekit"].as_table()) {
                if (auto v = lk->get("url")) cfg.voice.livekit.url = v->value_or(cfg.voice.livekit.url);
                if (auto v = lk->get("api_key")) cfg.voice.livekit.api_key = v->value_or(cfg.voice.livekit.api_key);
                if (auto v = lk->get("api_secret")) cfg.voice.livekit.api_secret = v->value_or(cfg.voice.livekit.api_secret);
                if (auto v = lk->get("token_ttl")) cfg.voice.livekit.token_ttl = v->value_or(cfg.voice.livekit.token_ttl);
                if (auto v = lk->get("room_encryption"))
                    cfg.voice.livekit.room_encryption = v->value_or(cfg.voice.livekit.room_encryption);
                if (auto v = lk->get("room_key_secret"))
                    cfg.voice.livekit.room_key_secret = v->value_or(cfg.voice.livekit.room_key_secret);
            }
        }

        // [push]. No provider credentials here on purpose — see PushConfig.
        if (auto push = tbl["push"].as_table()) {
            if (auto v = push->get("enabled")) cfg.push.enabled = v->value_or(cfg.push.enabled);
            if (auto v = push->get("worker_poll_ms")) cfg.push.worker_poll_ms = v->value_or(cfg.push.worker_poll_ms);
            if (auto v = push->get("connect_timeout_s")) cfg.push.connect_timeout_s = v->value_or(cfg.push.connect_timeout_s);
            if (auto v = push->get("request_timeout_s")) cfg.push.request_timeout_s = v->value_or(cfg.push.request_timeout_s);
            if (auto v = push->get("max_attempts")) cfg.push.max_attempts = v->value_or(cfg.push.max_attempts);
            if (auto v = push->get("base_backoff_ms")) cfg.push.base_backoff_ms = v->value_or(cfg.push.base_backoff_ms);
            if (auto v = push->get("max_backoff_ms")) cfg.push.max_backoff_ms = v->value_or(cfg.push.max_backoff_ms);
            if (auto v = push->get("batch_size")) cfg.push.batch_size = v->value_or(cfg.push.batch_size);
            if (auto v = push->get("lease_ms")) cfg.push.lease_ms = v->value_or(cfg.push.lease_ms);
            if (auto v = push->get("allow_internal_gateway"))
                cfg.push.allow_internal_gateway = v->value_or(cfg.push.allow_internal_gateway);
            if (auto v = push->get("default_payload"))
                cfg.push.default_payload = v->value_or(cfg.push.default_payload);
            // Accepts a single string or an array, same as voice.turn_uri.
            if (auto v = push->get("allowed_gateway_prefixes")) {
                if (auto arr = v->as_array()) {
                    for (auto&& el : *arr) {
                        if (auto s = el.value<std::string>()) {
                            cfg.push.allowed_gateway_prefixes.push_back(*s);
                        }
                    }
                } else if (auto s = v->value<std::string>()) {
                    cfg.push.allowed_gateway_prefixes.push_back(*s);
                }
            }
        }

        // [identity]
        if (auto id = tbl["identity"].as_table()) {
            IdentityConfig id_cfg;
            if (auto v = id->get("provider_url")) id_cfg.provider_url = v->value_or(std::string{});
            if (auto v = id->get("required")) id_cfg.required = v->value_or(false);
            if (auto v = id->get("allow_local_accounts")) id_cfg.allow_local_accounts = v->value_or(true);
            if (auto v = id->get("client_id")) id_cfg.client_id = v->value_or(id_cfg.client_id);
            if (!id_cfg.provider_url.empty()) {
                cfg.identity = id_cfg;
            }
        }

    } catch (const toml::parse_error& e) {
        throw std::runtime_error(std::string("Failed to parse config: ") + e.what());
    }

    validate(cfg);
    return cfg;
}

bool turn_credentials_are_shared(const VoiceConfig& voice) {
    // The three conditions are exactly the branch VoiceHandler::handle_turn_server
    // takes. `turn_secret` wins when set — that path mints a per-user,
    // time-limited HMAC credential and is the safe mode — so the shared case is
    // "voice is on, there is no secret, and there is a static password to give
    // away".
    return voice.enabled && voice.turn_secret.empty() && !voice.turn_password.empty();
}

void Config::validate(Config& cfg) {
    auto log = get_logger();

    if (cfg.voice.enabled) {
        const bool has_relay = !cfg.voice.turn_uris.empty();
        const bool has_stun = !cfg.voice.stun_uri.empty();
        if (!cfg.voice.allow_peer_to_peer && !has_relay) {
            // Relay-only with zero relays configured means every call fails.
            // Fall back to peer-to-peer and say so loudly rather than shipping
            // a voice feature that is enabled but cannot ever connect.
            log->warn("voice.allow_peer_to_peer is false but no voice.turn_uri is configured — "
                      "that combination can never establish a call. Falling back to "
                      "peer-to-peer. Configure voice.turn_uri (and turn_secret or "
                      "turn_username/turn_password) to force relayed calls.");
            cfg.voice.allow_peer_to_peer = true;
        }
        if (!has_relay && !has_stun) {
            log->warn("voice.enabled is true but neither voice.stun_uri nor voice.turn_uri is "
                      "set — calls will only connect between clients on the same local network. "
                      "Set voice.stun_uri for NAT traversal.");
        }

        // LiveKit SFU. Partial config is the dangerous case: a deployment that
        // sets the URL and forgets the secret would otherwise look configured
        // to an operator while silently serving mesh voice forever.
        //
        // Every message below names only KEYS, never values — api_secret must
        // not reach the log at any level.
        auto& lk = cfg.voice.livekit;
        const bool any_lk = !lk.url.empty() || !lk.api_key.empty() || !lk.api_secret.empty();
        if (any_lk && !lk.configured()) {
            log->warn("voice.livekit is partially configured — url={}, api_key={}, api_secret={}. "
                      "All three are required; ignoring the LiveKit config and using "
                      "peer-to-peer mesh voice.",
                      lk.url.empty() ? "missing" : "set",
                      lk.api_key.empty() ? "missing" : "set",
                      lk.api_secret.empty() ? "missing" : "set");
        }
        if (lk.configured()) {
            if (lk.token_ttl < kLiveKitMinTtl || lk.token_ttl > kLiveKitMaxTtl) {
                log->warn("voice.livekit.token_ttl = {}s is outside [{}, {}] and will be clamped "
                          "when tokens are minted.", lk.token_ttl, kLiveKitMinTtl, kLiveKitMaxTtl);
            }
            // A ws:// SFU URL means join tokens — bearer credentials — cross
            // the network in the clear.
            if (lk.url.rfind("ws://", 0) == 0) {
                log->warn("voice.livekit.url uses ws:// (no TLS). Join tokens are bearer "
                          "credentials; use wss:// for anything but a loopback test.");
            }
        }

        // The static TURN credential pair is a single-user development
        // affordance, and there is no way to make it anything else: with no
        // `turn_secret`, GET /voip/turnServer hands `turn_username` and
        // `turn_password` verbatim to EVERY authenticated account — including
        // one that just self-registered, if registration is open. The
        // credential has no expiry (the `ttl` in that response is a refresh
        // hint and nothing enforces it) and no revocation short of editing this
        // file and restarting coturn, so a banned account keeps a working relay
        // credential: chat tokens are revoked by the ban, coturn's are not.
        //
        // Warned rather than refused. deploy/config/server.toml.template ships
        // `turn_secret`, so a deployment in this state was hand-configured, and
        // turning somebody's working voice into a failed start on upgrade is a
        // worse outcome than telling them clearly on every boot. The message
        // names the fix and the value to set, and no secret is logged.
        if (turn_credentials_are_shared(cfg.voice)) {
            log->warn("voice.turn_password is set with no voice.turn_secret, so "
                      "/voip/turnServer hands the SAME long-lived TURN credential to every "
                      "authenticated account on this server. It never expires and cannot be "
                      "revoked without editing this config and restarting coturn, so a banned "
                      "account keeps a working relay credential and your TURN server can be "
                      "used as an open proxy billed to you. Switch coturn to "
                      "`use-auth-secret` / `static-auth-secret` and set voice.turn_secret to "
                      "the same value; the server then mints a per-user credential with a TTL. "
                      "The static pair is a single-user development affordance only.");
        }
    }

    // The cost is an EXPONENT: iterations = 2^cost. 12 is 4,096 PBKDF2-HMAC-SHA256
    // iterations, which a single GPU works through at hundreds of millions of
    // guesses a second — a stolen database is then a wordlist exercise, not a
    // wall. The recommended value is 19 (524,288), in line with OWASP, and it is
    // what Config.h defaults to and what config/bsfchat-server.example.toml and
    // deploy/config/server.toml.template both ship.
    //
    // Two thresholds on purpose:
    //
    //   * below 12 is clamped, because those values are indistinguishable from
    //     a typo and provide no meaningful resistance at all;
    //   * 12..18 is warned about but honoured, because the login cost is the
    //     operator's to spend. Silently multiplying their per-login CPU by up
    //     to 128x on an upgrade is not a decision to make on their behalf on a
    //     box that may be sized for exactly the load it has.
    //
    // Older deploy templates shipped 12, so this warning is the upgrade path for
    // every deployment created from one: it fires on every start, names the fix,
    // and the fix is genuinely one line because stored hashes record their own
    // cost and are re-derived at the owner's next login
    // (AuthHandler.cpp, "Transparently upgrade a hash").
    if (cfg.password_hash_cost < 12) {
        log->warn("auth.password_hash_cost = {} is dangerously low ({} PBKDF2 iterations). "
                  "Raising to 12; 19 or higher is recommended.",
                  cfg.password_hash_cost, 1u << cfg.password_hash_cost);
        cfg.password_hash_cost = 12;
    }
    if (cfg.password_hash_cost < kRecommendedPasswordHashCost) {
        log->warn("auth.password_hash_cost = {} is only {} PBKDF2 iterations — {}x weaker than "
                  "the recommended {} ({}). If this database is ever stolen, local-account "
                  "passwords fall to offline cracking. Set auth.password_hash_cost = {} in your "
                  "server.toml and restart: existing password hashes record the cost they were "
                  "created with, keep verifying, and are re-hashed at each owner's next "
                  "successful login, so nobody is locked out.",
                  cfg.password_hash_cost, 1u << cfg.password_hash_cost,
                  1u << (kRecommendedPasswordHashCost - cfg.password_hash_cost),
                  kRecommendedPasswordHashCost, 1u << kRecommendedPasswordHashCost,
                  kRecommendedPasswordHashCost);
    }
    if (cfg.password_hash_cost > 24) {
        // 2^24 iterations would take seconds per login.
        cfg.password_hash_cost = 24;
    }

    if (cfg.access_token_lifetime_days < 1) {
        // A sub-day lifetime with no refresh flow in the shipped client means
        // users get logged out while they are still using the app.
        log->warn("auth.access_token_lifetime_days = {} is too short to be usable; raising to 1.",
                  cfg.access_token_lifetime_days);
        cfg.access_token_lifetime_days = 1;
    }
    if (cfg.access_token_lifetime_days > 3650) {
        log->warn("auth.access_token_lifetime_days = {} is effectively 'never expires'; "
                  "clamping to 3650.", cfg.access_token_lifetime_days);
        cfg.access_token_lifetime_days = 3650;
    }

    {
        auto& lim = cfg.auth_limits;
        // Fail startup on a bad entry instead of dropping it. The entry that
        // failed to parse is the one that was meant to stop every client
        // sharing the proxy's rate-limit bucket.
        for (const auto& entry : lim.trusted_proxies) {
            if (!IpNetwork::parse(entry)) {
                throw std::runtime_error("auth.trusted_proxies: '" + entry +
                                         "' is not an IP address or CIDR network");
            }
        }
        if (!lim.enabled) {
            log->warn("auth.rate_limit_enabled is false — /login, /register, /refresh and "
                      "/account/password accept unlimited attempts. Only sensible if an "
                      "upstream proxy enforces its own limits.");
        }
        // A zero or negative COUNT means "no limit" and is honoured; a zero
        // window would make every count meaningless, so windows are clamped.
        if (lim.rate_window_seconds < 1) lim.rate_window_seconds = 1;
        if (lim.lockout_seconds < 1) lim.lockout_seconds = 1;
        if (lim.register_window_seconds < 1) lim.register_window_seconds = 1;
        if (lim.enabled && lim.max_failures > 0 && lim.max_failures < 3) {
            log->warn("auth.max_failures = {} locks an account out after fewer mistakes than "
                      "people routinely make; raising to 3.", lim.max_failures);
            lim.max_failures = 3;
        }

        // A trusted_proxies entry that covers public address space is not a
        // limit setting, it is an off switch for every per-address limit on
        // the server: anything inside it can pick its own X-Forwarded-For and
        // therefore its own identity, once per request. Loud, because the
        // symptom — limits silently never firing for the attacker who matters
        // — looks exactly like limits working.
        //
        // Warned rather than refused: an operator may genuinely have a proxy
        // on a public address, and failing startup on an upgrade over a
        // configuration that was working would be its own outage.
        for (const auto& entry : lim.trusted_proxies) {
            auto net = IpNetwork::parse(entry);
            if (!net) continue; // already thrown on above
            if (!is_private_or_loopback_network(*net)) {
                log->warn("auth.trusted_proxies contains '{}', which covers addresses outside "
                          "loopback and the private ranges. Every client that can reach this "
                          "server from inside it can choose its own X-Forwarded-For, and so its "
                          "own rate-limit identity — the per-address limits do not apply to it "
                          "at all. List only the proxies you operate.", entry);
            }
        }
    }

    {
        auto& sl = cfg.send_limits;
        // Same rule as the auth block: a zero COUNT means "no limit" and is
        // honoured, a zero window would make every count meaningless.
        if (sl.window_seconds < 1) sl.window_seconds = 1;
        if (!sl.enabled) {
            log->warn("limits.enabled is false — there is no server-side ceiling on how fast an "
                      "account can post, delete or upload. A looping client or a buggy bot can "
                      "flood a channel until someone notices.");
        }
    }

    if (cfg.identity && cfg.identity->client_id.empty()) {
        log->warn("identity.client_id is empty — identity tokens will be accepted regardless of "
                  "their audience, so a token minted for any other OAuth client registered with "
                  "the same provider will be accepted as a chat login.");
    }

    if (cfg.push.worker_poll_ms < 50) cfg.push.worker_poll_ms = 50;
    if (cfg.push.batch_size < 1) cfg.push.batch_size = 1;
    if (cfg.push.max_attempts < 1) cfg.push.max_attempts = 1;
    if (cfg.push.base_backoff_ms < 100) cfg.push.base_backoff_ms = 100;
    if (cfg.push.max_backoff_ms < cfg.push.base_backoff_ms) {
        cfg.push.max_backoff_ms = cfg.push.base_backoff_ms;
    }
    if (cfg.push.connect_timeout_s < 1) cfg.push.connect_timeout_s = 1;
    if (cfg.push.request_timeout_s < 1) cfg.push.request_timeout_s = 1;
    {
        // A lease shorter than the request timeout would hand a still-in-flight
        // notification to the next wakeup, duplicating it on every slow gateway
        // response.
        const int64_t min_lease =
            static_cast<int64_t>(cfg.push.connect_timeout_s + cfg.push.request_timeout_s) * 1000 * 2;
        if (cfg.push.lease_ms < min_lease) {
            log->warn("push.lease_ms = {} is shorter than twice the configured HTTP timeouts; "
                      "raising to {} so a slow gateway cannot cause duplicate notifications.",
                      cfg.push.lease_ms, min_lease);
            cfg.push.lease_ms = min_lease;
        }
    }

    if (cfg.push.default_payload != "event_id_only" && cfg.push.default_payload != "full") {
        log->warn("push.default_payload = \"{}\" is not one of \"event_id_only\" or \"full\"; "
                  "using \"event_id_only\".",
                  cfg.push.default_payload);
        cfg.push.default_payload = "event_id_only";
    }

    if (cfg.push.enabled && cfg.push.allowed_gateway_prefixes.empty()) {
        // Fail CLOSED, and loudly.
        //
        // This used to be a warning over a default-open allowlist, which meant
        // any authenticated user could register a gateway they controlled and
        // have message content POSTed there forever — an exfiltration feed and
        // an SSRF primitive in one, on an out-of-the-box deployment.
        //
        // Turning the feature off rather than refusing to start is deliberate:
        // an upgrade must not brick a running deployment over a key that did
        // not exist in the previous release, and push stopping is a visible
        // failure an operator can act on, whereas push staying open is not.
        log->error("push.enabled is true but push.allowed_gateway_prefixes is empty. Push is "
                   "now DISABLED. An empty allowlist means no gateway is permitted, not any "
                   "gateway: /pushers/set is the one endpoint where an ordinary user names a "
                   "URL this server will POST notification data to, so an open list is both a "
                   "self-serve exfiltration channel for message content and a server-side "
                   "request forgery primitive. Set push.allowed_gateway_prefixes to your push "
                   "gateway's URL to turn push back on.");
        cfg.push.enabled = false;
    } else if (cfg.push.enabled) {
        // Say out loud, at every startup, where this server is willing to send
        // message data. An operator should never have to read the config to
        // find out.
        std::string list;
        for (const auto& prefix : cfg.push.allowed_gateway_prefixes) {
            if (!list.empty()) list += ", ";
            list += prefix;
        }
        log->info("Push enabled. Permitted push gateways: {}. Default payload: {}. "
                  "Internal-address gateways: {}.",
                  list, cfg.push.default_payload,
                  cfg.push.allow_internal_gateway ? "permitted" : "refused");
        for (const auto& prefix : cfg.push.allowed_gateway_prefixes) {
            // An entry with no scheme can never match anything, and the only
            // symptom would be every pusher registration failing with "not an
            // allowed push gateway". Name it here instead.
            if (prefix.rfind("http://", 0) != 0 && prefix.rfind("https://", 0) != 0) {
                log->error("push.allowed_gateway_prefixes entry \"{}\" is not an absolute "
                           "http(s) URL and will never match any pusher. Entries are compared "
                           "on scheme, host and port, so the scheme is required — write "
                           "\"https://{}/\".",
                           prefix, prefix);
                continue;
            }
            if (prefix.rfind("http://", 0) == 0) {
                log->warn("push.allowed_gateway_prefixes contains a cleartext entry ({}). "
                          "Notification payloads and pushkeys will cross the network "
                          "unencrypted, and an on-path attacker can forge the gateway's "
                          "response. Use https:// unless the gateway is on this host.",
                          prefix);
            }
        }
        if (cfg.push.default_payload == "full") {
            log->warn("push.default_payload = \"full\": a pusher that does not ask for "
                      "\"event_id_only\" will have verbatim message content, the sender and "
                      "their display name sent to the push gateway and stored in push_queue "
                      "in the clear until delivery.");
        }
    }

    if (cfg.workers < 1) cfg.workers = 1;
    // httplib throws std::invalid_argument from the ThreadPool constructor if
    // the ceiling is below the base, which would abort startup on a config
    // that is merely odd rather than wrong. Raise it to the base instead:
    // that reproduces the old fixed-size behaviour, which is what an operator
    // who deliberately sets max_workers = workers is asking for.
    if (cfg.max_workers < cfg.workers) cfg.max_workers = cfg.workers;
    if (cfg.max_workers < cfg.workers + 8) {
        log->warn("server.max_workers ({}) leaves little headroom above server.workers ({}). "
                  "Each connection holds a worker for its whole lifetime, and a /sync long poll "
                  "holds one for up to {}s, so a message send can queue behind idle long polls "
                  "once the ceiling is reached.",
                  cfg.max_workers, cfg.workers, limits::kMaxSyncTimeoutMs / 1000);
    }
}

Config Config::defaults() {
    return Config{};
}

} // namespace bsfchat
