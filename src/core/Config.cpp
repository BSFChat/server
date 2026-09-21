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

#include <algorithm>
#include <stdexcept>
#include <vector>

namespace bsfchat {

namespace {

// Floor under limits::max_message_bytes. A ceiling below this is a typo or a
// misunderstanding of the unit (someone who meant kilobytes), and honouring it
// literally would make the server refuse ordinary sentences — a failure mode
// far more disruptive than the one the ceiling prevents, and one that presents
// as "chat is broken" rather than as a config error.
constexpr size_t kMinConfigurableMessageBytes = 512;

// Everything in a maximal m.room.message that is neither `body` nor
// `formatted_body`: msgtype, format, fifty mention ids, an m.relates_to block,
// an m.new_content wrapper and JSON punctuation. Generous, because the cost of
// overshooting is a slightly larger request ceiling and the cost of
// undershooting is a legitimate message refused with a misleading error.
constexpr size_t kEventEnvelopeSlack = 8 * 1024;

} // namespace

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
            if (auto v = media->get("ticket_ttl_seconds"))
                cfg.media_ticket_ttl_seconds = static_cast<int>(
                    v->value_or(static_cast<int64_t>(cfg.media_ticket_ttl_seconds)));
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
            const auto read_proxy_list = [](const toml::node& v, std::vector<std::string>& out) {
                out.clear();
                if (auto arr = v.as_array()) {
                    for (const auto& el : *arr) {
                        if (auto s = el.value<std::string>()) out.push_back(*s);
                    }
                } else if (auto s = v.value<std::string>()) {
                    out.push_back(*s);
                }
            };
            if (auto v = auth->get("trusted_proxies")) {
                read_proxy_list(*v, lim.trusted_proxies);
            }
            // Public ranges the operator has deliberately trusted — a CDN in
            // front of the origin. validate() merges these into
            // trusted_proxies; kept separate here so it can tell an
            // acknowledged range from one that just turned up.
            if (auto v = auth->get("trusted_public_proxies")) {
                read_proxy_list(*v, lim.trusted_public_proxies);
            }
            if (auto v = auth->get("trusted_public_proxies_reason"))
                lim.trusted_public_proxies_reason =
                    v->value_or(lim.trusted_public_proxies_reason);
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
            if (auto v = limits_tbl->get("room_create_limit"))
                sl.room_create_limit = v->value_or(sl.room_create_limit);
            if (auto v = limits_tbl->get("window_seconds"))
                sl.window_seconds = v->value_or(sl.window_seconds);
            // Sizes, not rates. Read as int64 and clamped in validate(): toml++
            // will happily hand back a negative, and a negative folded into a
            // size_t is the largest ceiling there is — which would silently
            // turn a typo into "no limit at all", the state this whole block
            // exists to leave.
            if (auto v = limits_tbl->get("max_message_bytes")) {
                if (auto n = v->value<int64_t>(); n && *n > 0) {
                    sl.max_message_bytes = static_cast<size_t>(*n);
                }
            }
            if (auto v = limits_tbl->get("max_event_bytes")) {
                if (auto n = v->value<int64_t>(); n && *n > 0) {
                    sl.max_event_bytes = static_cast<size_t>(*n);
                }
            }
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
        //
        // Parsed once, here, and carried to the checks below: they used to
        // re-parse the same strings.
        struct Entry {
            std::string text; // by value: the merge below reallocates the list
            IpNetwork net;
            bool acknowledged;
        };
        std::vector<Entry> entries;
        const auto parse_all = [&](const std::vector<std::string>& list, const char* key,
                                   bool acknowledged) {
            for (const auto& text : list) {
                auto net = IpNetwork::parse(text);
                if (!net) {
                    throw std::runtime_error(std::string("auth.") + key + ": '" + text +
                                             "' is not an IP address or CIDR network");
                }
                entries.push_back({text, *net, acknowledged});
            }
        };
        parse_all(lim.trusted_proxies, "trusted_proxies", false);
        parse_all(lim.trusted_public_proxies, "trusted_public_proxies", true);

        // The acknowledged ranges are trusted exactly like the others — the
        // second key exists to record intent, not to create a second trust
        // tier. Merged rather than kept apart so ClientAddressResolver and
        // every other reader still see one list, and appended only when
        // absent so a second validate() over the same Config is a no-op.
        for (const auto& text : lim.trusted_public_proxies) {
            if (std::find(lim.trusted_proxies.begin(), lim.trusted_proxies.end(), text) ==
                lim.trusted_proxies.end()) {
                lim.trusted_proxies.push_back(text);
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

        // A trusted range that covers public address space is not a limit
        // setting, it is an off switch for every per-address limit on the
        // server: anything inside it can pick its own X-Forwarded-For and
        // therefore its own identity, once per request. Loud, because the
        // symptom — limits silently never firing for the attacker who matters
        // — looks exactly like limits working.
        //
        // Warned rather than refused: an operator may genuinely have a proxy
        // on a public address, and failing startup on an upgrade over a
        // configuration that was working would be its own outage.
        //
        // ── Why this is not one warning per entry ─────────────────────────
        // It was, and the first CDN-fronted deployment it met produced eleven
        // consecutive warnings on a correct configuration, because production
        // is behind Cloudflare and Cloudflare publishes fifteen IPv4 ranges
        // and seven IPv6 ones. Every line was true and every line was
        // deliberate. A wall of true warnings on a correct server is worse
        // than no warning: it is how an operator learns to skim the log, and
        // this is the log the auth lockout records land in.
        //
        // So the check asks a sharper question than "is this public". Public
        // and deliberate — written under auth.trusted_public_proxies with a
        // stated reason — is reported once, at info, as a record of what is
        // trusted and why. Public and unexplained is one warning naming the
        // count, the widest range and the way to acknowledge it. And a range
        // too wide to be any proxy fleet gets its own line whichever key it
        // was written under, because that is the entry the check exists for
        // and it is not something a reason can talk away.
        std::vector<const Entry*> unexplained; // public, under trusted_proxies
        std::vector<const Entry*> unreasoned;  // public, acknowledged, but no reason given
        std::vector<const Entry*> explained;   // public, acknowledged, reason given
        const bool have_reason =
            lim.trusted_public_proxies_reason.find_first_not_of(" \t\r\n") != std::string::npos;

        for (const auto& e : entries) {
            // Private first. The private ranges are themselves wide — 10/8 is
            // a /8 and fc00::/7 is a /7 — and none of that matters, because
            // nothing outside this network can present an address in them.
            // Width is only alarming once the range is publicly routable.
            if (is_private_or_loopback_network(e.net)) continue;
            if (is_too_wide_to_be_a_proxy_fleet(e.net)) {
                log->warn(
                    "auth.{} contains '{}'. That is not a proxy fleet, it is every address "
                    "this server can be reached from: anything that reaches it picks its own "
                    "X-Forwarded-For, and so its own rate-limit identity, once per request — "
                    "the per-address limits on /login, /register, /refresh and "
                    "/account/password stop applying to exactly the client they exist for. "
                    "No auth.trusted_public_proxies_reason acknowledges a range this wide. "
                    "Replace it with the addresses your proxy actually speaks from.",
                    e.acknowledged ? "trusted_public_proxies" : "trusted_proxies", e.text);
                continue;
            }
            if (!e.acknowledged) unexplained.push_back(&e);
            else if (have_reason) explained.push_back(&e);
            else unreasoned.push_back(&e);
        }

        // Widest by the prefix length as written. Comparing an IPv4 /15 with
        // an IPv6 /29 is not meaningful arithmetic, but the shortest prefix is
        // what an operator scanning the list would point at, and the number is
        // there to be recognised, not summed.
        const auto widest = [](const std::vector<const Entry*>& v) {
            return (*std::min_element(v.begin(), v.end(), [](const Entry* a, const Entry* b) {
                return a->net.cidr_prefix() < b->net.cidr_prefix();
            }))->text;
        };
        const auto join = [](const std::vector<const Entry*>& v) {
            std::string out;
            for (const auto* e : v) {
                if (!out.empty()) out += ", ";
                out += e->text;
            }
            return out;
        };

        if (!unexplained.empty()) {
            log->warn("auth.trusted_proxies trusts {} range(s) reaching outside loopback and "
                      "the private ranges (widest: {}) — {}. Trusting a network means believing "
                      "its X-Forwarded-For, so every client that can reach this server from "
                      "inside one of them chooses its own rate-limit identity and the "
                      "per-address limits do not apply to it. If these are a CDN in front of "
                      "the origin and you meant them, move them to "
                      "auth.trusted_public_proxies and set auth.trusted_public_proxies_reason "
                      "to whose they are and when you last refreshed them — they stay trusted "
                      "and this stops. Otherwise remove them.",
                      unexplained.size(), widest(unexplained), join(unexplained));
        }
        if (!unreasoned.empty()) {
            log->warn("auth.trusted_public_proxies lists {} public range(s) (widest: {}) but "
                      "auth.trusted_public_proxies_reason is empty, so they are being trusted "
                      "with no record of why. Set the reason to whose ranges these are and when "
                      "you last refreshed them from the source that publishes them; it is what "
                      "tells the next person whether the list is still current.",
                      unreasoned.size(), widest(unreasoned));
        }
        if (!explained.empty()) {
            // Not silent. The decision is deliberate, so it is stated rather
            // than warned about — but it is stated in full, every boot, so
            // that diffing this line across restarts shows the list changing.
            log->info("auth: trusting {} public proxy range(s) as deliberate — {}. Their "
                      "X-Forwarded-For is believed, so this list has to stay in step with what "
                      "the provider publishes: a range they add and you have not listed puts "
                      "every client behind it in one rate-limit bucket, and a range they give "
                      "up stays trusted here after somebody else is issued it. Ranges: {}.",
                      explained.size(), log_safe(lim.trusted_public_proxies_reason, 200),
                      join(explained));
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

        // Size ceilings. Unlike the counts above, zero is NOT "no limit" — it
        // is a value that would refuse every message — so both are floored at
        // something usable rather than honoured literally.
        if (sl.max_message_bytes < kMinConfigurableMessageBytes) {
            log->warn("limits.max_message_bytes = {} is below the {}-byte floor and would refuse "
                      "ordinary messages; using the floor. Set it to a real ceiling or leave it "
                      "unset to get the {}-byte default.",
                      sl.max_message_bytes, kMinConfigurableMessageBytes,
                      limits::kMaxMessageBodyBytes);
            sl.max_message_bytes = kMinConfigurableMessageBytes;
        }

        // The request ceiling has to admit a message that passes both field
        // ceilings, or the field ceilings are unreachable and their error
        // messages lie: the caller is told "body may be N bytes" by a server
        // that refused the request before it looked at `body`. Same relation
        // the static_assert in Constants.h pins for the defaults; enforced here
        // for the operator-set pair, which can be edited one at a time.
        const size_t required_event_bytes =
            sl.max_message_bytes * (1 + limits::kFormattedBodyMultiplier) + kEventEnvelopeSlack;
        if (sl.max_event_bytes < required_event_bytes) {
            log->warn("limits.max_event_bytes = {} cannot hold a message of "
                      "limits.max_message_bytes = {} plus its formatted_body ({}x) and envelope; "
                      "raising it to {}. Lower max_message_bytes instead if a smaller ceiling is "
                      "what you meant.",
                      sl.max_event_bytes, sl.max_message_bytes, limits::kFormattedBodyMultiplier,
                      required_event_bytes);
            sl.max_event_bytes = required_event_bytes;
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
        // Same shape as the trusted_proxies check above, and for the same
        // reason: one line per offending entry turns a list into a wall. The
        // list is short in practice, but a cleartext gateway is a deliberate,
        // documented deployment shape (sygnal in the same compose file), so it
        // is exactly the case that would repeat on a correct configuration.
        std::string cleartext;
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
                if (!cleartext.empty()) cleartext += ", ";
                cleartext += prefix;
            }
        }
        if (!cleartext.empty()) {
            log->warn("push.allowed_gateway_prefixes contains cleartext entries ({}). "
                      "Notification payloads and pushkeys will cross the network "
                      "unencrypted, and an on-path attacker can forge the gateway's "
                      "response. Use https:// unless the gateway is on this host.",
                      cleartext);
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
