#include "api/AuthHandler.h"
#include "audit/AuditLog.h"
#include "auth/AutoJoin.h"
#include "auth/LocalAuth.h"
#include "auth/OidcAuth.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "core/Version.h"
#include "http/Middleware.h"
#include "identity/Localpart.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>

#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <limits>

namespace bsfchat {

using json = nlohmann::json;

namespace {

// Map an arbitrary OIDC subject onto the Matrix localpart grammar
// (lowercase alphanumerics plus . _ = - /) using the spec's recommended
// reversible escaping: uppercase X becomes "_x", anything else invalid
// becomes "=hh". Literal '_' is escaped so it can't collide with the
// uppercase form. Blindly concatenating the raw subject is what produced the
// "@@josh:" double-@ user ids.
std::string sanitize_localpart(const std::string& input) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(input.size());
    for (unsigned char c : input) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '.' || c == '-' || c == '/') {
            out += static_cast<char>(c);
        } else if (c >= 'A' && c <= 'Z') {
            out += '_';
            out += static_cast<char>(c - 'A' + 'a');
        } else {
            out += '=';
            out += kHex[(c >> 4) & 0x0F];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

// The user id an OIDC subject maps to WHEN IT HAS NEVER BEEN LINKED — the
// "shadow" account the m.login.token path mints on first sign-in. Empty when
// the subject does not produce a usable id.
//
// Factored out because linking has to be able to name the same account the
// login path would have created, in order to say "this identity currently
// signs in as @oidc_…, and after this link it will sign in as you". Two copies
// of this derivation would eventually disagree, and the disagreement would be
// invisible: the link would be recorded against one id while logins kept
// landing on another.
std::string shadow_user_id_for_subject(const std::string& subject,
                                       const std::string& server_name) {
    const std::string localpart = "oidc_" + sanitize_localpart(subject);
    if (localpart == "oidc_") return {};
    std::string user_id = "@" + localpart + ":" + server_name;
    if (!UserId::is_valid(user_id)) return {};
    return user_id;
}

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// 429 + M_LIMIT_EXCEEDED, with the wait in both places a client might look:
// the Matrix body field (milliseconds) and the HTTP header (whole seconds,
// rounded UP — telling a client to come back a fraction early just earns it a
// second 429).
void send_rate_limited(httplib::Response& res, int64_t retry_ms, const std::string& message) {
    retry_ms = std::clamp<int64_t>(retry_ms, 1, std::numeric_limits<int>::max());
    res.set_header("Retry-After", std::to_string((retry_ms + 999) / 1000));
    send_error(res, 429, MatrixError::limit_exceeded(message, static_cast<int>(retry_ms)));
}

// Failure-tracker key for a login target. Keyed on what was SUBMITTED, whether
// or not such an account exists, so a lockout says nothing about existence.
// Truncated because the string is attacker-supplied and lives in a map; no
// real user id is anywhere near this long.
std::string user_failure_key(const std::string& user_id) {
    return "user:" + user_id.substr(0, 255);
}

// The address inside an "ip:<address>" failure-tracker key, redacted to its
// network. See redact_ip_for_log() in http/ClientAddress.h for what that means
// and why the log gets a network rather than a host.
//
// THIS IS APPLIED TO THE ADDRESS KEY AND TO NOTHING ELSE, which is the whole
// difficulty of finding 16. record_failure() prints two keys and only one of
// them is an address: the other is user_failure_key(), "user:" + the login
// identifier exactly as submitted, deliberately keyed on what was typed rather
// than on an account that exists so a lockout is not an existence oracle. It is
// not an address, and redact_ip_for_log — which by design never echoes input it
// could not parse — would flatten it to the constant "unparseable", deleting the
// only half of the lockout line an operator can act on.
std::string redact_ip_key(const std::string& key) {
    constexpr std::string_view kPrefix = "ip:";
    const bool prefixed = key.compare(0, kPrefix.size(), kPrefix) == 0;
    std::string address = prefixed ? key.substr(kPrefix.size()) : key;

    // The address half can ALREADY be a network: ClientAddressResolver::resolve
    // collapses every IPv6 client to a /64 before the key is built, for the same
    // subscriber-granularity reason the redactor uses. redact_ip_for_log parses
    // bare addresses only, so handing it "2001:db8::/64" verbatim would come
    // back "unparseable" and drop a line that was already correct. Give it the
    // base address; it re-derives the identical prefix.
    if (const auto slash = address.find('/'); slash != std::string::npos) {
        address.resize(slash);
    }

    // Fail closed if the "ip:" prefix is ever missing: this must not become a
    // pass-through for an address in a shape it did not expect.
    return (prefixed ? std::string(kPrefix) : std::string{}) + redact_ip_for_log(address);
}

// Rejects a client-supplied device_id, answering 400 if it is unusable.
// Returns true when the response has been sent and the caller must stop.
//
// Every login and register path takes device_id straight from the request and
// stored it unexamined, so this is checked at all three rather than in one of
// them.
bool device_id_rejected(const std::optional<std::string>& device_id,
                        httplib::Response& res) {
    if (!device_id) return false;
    auto err = device_id_error(*device_id);
    if (!err) return false;
    send_error(res, 400, MatrixError::invalid_param(*err));
    return true;
}

} // namespace

AuthHandler::AuthHandler(SqliteStore& store, SyncEngine& sync_engine,
                         const Config& config, OidcAuth* oidc_auth, LimiterClock clock)
    : store_(store), sync_engine_(sync_engine), config_(config), oidc_auth_(oidc_auth)
    , client_address_(config.auth_limits.trusted_proxies)
    , attempt_limiter_(config.auth_limits.rate_limit,
                       std::chrono::seconds(config.auth_limits.rate_window_seconds), clock)
    , register_limiter_(config.auth_limits.register_limit,
                        std::chrono::seconds(config.auth_limits.register_window_seconds), clock)
    , register_global_limiter_(config.auth_limits.register_global_limit,
                               std::chrono::seconds(config.auth_limits.register_window_seconds), clock)
    , failures_(config.auth_limits.max_failures,
                std::chrono::seconds(config.auth_limits.lockout_seconds), clock) {}

std::string AuthHandler::client_key(const httplib::Request& req) {
    if (!config_.auth_limits.enabled) return {};

    if (client_address_.looks_like_untrusted_proxy(req)) {
        // Every client of this deployment is sharing one bucket. Say so, with
        // the fix, but not once per request.
        const auto now = limiter_steady_now_ms();
        auto last = last_proxy_warning_ms_.load();
        if ((last == 0 || now - last > 60'000) &&
            last_proxy_warning_ms_.compare_exchange_strong(last, now)) {
            //
            // The NETWORK, not the peer. looks_like_untrusted_proxy only fires
            // for a peer inside private or loopback space, so what would be
            // printed here is infrastructure topology rather than a subscriber
            // — but this line and the lockout line below are the only two
            // places any address reaches the log at all (audit-data finding
            // 16), and leaving one of them exact makes the pair depend on that
            // private-range gate never widening. The operator set their own
            // reverse proxy up and knows its address; the network is what the
            // message needs to identify which one it means.
            get_logger()->warn(
                "Requests from {} carry X-Forwarded-For, but that network is not in "
                "auth.trusted_proxies, so the header is ignored and every client behind it is "
                "rate-limited as ONE address — one abusive client can lock all of them out of "
                "/login. If that is your reverse proxy, add its address to auth.trusted_proxies.",
                redact_ip_for_log(req.remote_addr));
        }
    }

    auto addr = client_address_.resolve(req);
    return addr ? "ip:" + *addr : std::string{};
}

bool AuthHandler::over_attempt_limit(const char* endpoint, const std::string& client,
                                     httplib::Response& res) {
    if (client.empty()) return false;
    const auto wait = attempt_limiter_.acquire(std::string(endpoint) + "|" + client);
    if (wait == 0) return false;
    send_rate_limited(res, wait, "Too many requests. Try again later.");
    return true;
}

bool AuthHandler::locked_out(const std::string& key_a, const std::string& key_b,
                             httplib::Response& res) {
    if (!config_.auth_limits.enabled) return false;
    int64_t wait = 0;
    if (!key_a.empty()) wait = std::max(wait, failures_.locked_for(key_a));
    if (!key_b.empty()) wait = std::max(wait, failures_.locked_for(key_b));
    if (wait == 0) return false;
    // One message for both causes: distinguishing "your address" from "this
    // account" would tell a sprayer which usernames other people are attacking.
    send_rate_limited(res, wait, "Too many failed attempts. Try again later.");
    return true;
}

void AuthHandler::record_failure(const std::string& ip_key, const std::string& id_key) {
    if (!config_.auth_limits.enabled) return;
    // log_safe, and not merely for tidiness. One of these keys is
    // user_failure_key(), which is "user:" + the login identifier EXACTLY AS
    // SUBMITTED — deliberately so, since keying on an account that exists would
    // make the lockout an existence oracle. That makes it arbitrary bytes from
    // an unauthenticated request body, newlines included, and this line is the
    // one an attacker wants: the log pattern is one record per line, so a
    // submitted identifier of
    //
    //     victim\n[2026-09-19 03:11:00.000] [warning] Auth lockout engaged for ip:203.0.113.9
    //
    // failed max_failures times puts a fabricated lockout for somebody else's
    // address in the server log, indistinguishable from a real one. That matters
    // here specifically because auth-hardening-2026-09.md finding 19 decided not
    // to mirror auth events into AuditLog on the grounds that the server log
    // already records them — so this log IS the security-event record, and this
    // was the unauthenticated write to it.
    //
    // Same defect as docs/audit-requests-2026-09.md finding 17 (the rejected
    // pusher URL) and as auth finding 9 (device_id); this is the third field and
    // the only one reachable without an account.
    //
    // redact_ip_key on the FIRST key only, and log_safe still on both. The two
    // guards answer different problems and neither replaces the other: log_safe
    // stops the identifier forging log records, redact_ip_key stops the address
    // naming a subscriber. Applying the address redactor to `id_key` as well —
    // the obvious two-line version of this change — would print
    // "user:unparseable" for every lockout and destroy the half of the line that
    // says who was being attacked. See redact_ip_key above.
    if (!ip_key.empty() && failures_.record_failure(ip_key)) {
        get_logger()->warn("Auth lockout engaged for {}", log_safe(redact_ip_key(ip_key)));
    }
    if (!id_key.empty() && failures_.record_failure(id_key)) {
        get_logger()->warn("Auth lockout engaged for {}", log_safe(id_key));
    }
}

int64_t AuthHandler::token_lifetime_ms() const {
    return static_cast<int64_t>(config_.access_token_lifetime_days) * 24 * 60 * 60 * 1000;
}

void AuthHandler::handle_versions(const httplib::Request& req, httplib::Response& res) {
    json resp = {
        {"versions", {std::string(spec::kVersion)}},
    };

    // Additive only. `versions` keeps exactly the value it had, because a
    // Matrix client keys its whole feature negotiation off that array and
    // an extra entry there would be a protocol claim we cannot honour.
    //
    // The build identity goes in vendor-namespaced sibling keys instead.
    // Anything that does not know them ignores them (the spec requires
    // unknown keys to be tolerated), and `bsfchat.version` is the one an
    // operator or a support conversation actually wants:
    //
    //   curl -s http://host:8448/_matrix/client/versions | jq .
    //
    // `unstable_features` is a map of string->BOOLEAN per the spec, so
    // the version string cannot live there; we advertise the capability
    // flag there and put the string beside it.
    resp["unstable_features"] = {{"bsfchat.server", true}};

    // The BUILD IDENTITY is for whoever is running the server, so it is served
    // only to a caller holding a valid token.
    //
    // Unauthenticated, these three keys let anyone fingerprint any BSFChat
    // deployment down to the commit with one GET. For self-hosted software,
    // where upgrades are manual and staggered, that is a list of which
    // instances have not taken the latest security fix yet — including this
    // RC's own, which is exactly the window in which such a list is worth the
    // most. Nothing has to be guessed and nothing is logged as an attempt.
    //
    // The cost of moving them is close to zero, which is why this is worth
    // doing rather than merely arguing about:
    //
    //   * no client reads them. The desktop client touches /versions in exactly
    //     one place — ServerDiscovery::looksLikeHomeserver — and all it asks is
    //     whether `versions` is an array. Feature negotiation is `versions` plus
    //     `unstable_features`, both of which stay exactly as they were and stay
    //     unauthenticated, because discovery necessarily runs before login.
    //   * the operator keeps every use. docs/release-channels.md lists three
    //     ways to read the build: the startup log line, this endpoint, and the
    //     OCI image labels. Two of them need no HTTP at all, and an operator
    //     debugging their own server has a token for the third. A scanner has
    //     none of them.
    //
    // Deliberately NOT a 401 for the unauthenticated case: this endpoint is how
    // a client decides an address is a homeserver at all, so requiring auth
    // would break adding a server. The keys are simply absent, which is a shape
    // the spec requires clients to tolerate.
    if (authenticate(store_, req.get_header_value("Authorization"))) {
        resp["bsfchat.version"] = build::version_string();
        resp["bsfchat.revision"] = build::revision_string();
        resp["bsfchat.channel"] = build::channel_of(build::kVersion);
    }

    res.set_content(resp.dump(), "application/json");
}

void AuthHandler::handle_login_flows(const httplib::Request&, httplib::Response& res) {
    auto flows = json::array();

    // Always include password login unless identity is required and local accounts are disabled
    if (!config_.identity || !config_.identity->required || config_.identity->allow_local_accounts) {
        flows.push_back({{"type", "m.login.password"}});
    }

    // Include token login if OIDC is configured
    if (oidc_auth_) {
        json token_flow = {{"type", "m.login.token"}};
        if (config_.identity) {
            token_flow["identity_provider"] = config_.identity->provider_url;
        }
        flows.push_back(token_flow);
    }

    json resp = {{"flows", flows}};
    res.set_content(resp.dump(), "application/json");
}

void AuthHandler::handle_login(const httplib::Request& req, httplib::Response& res) {
    // Before anything else, including the JSON parse: the point is to bound the
    // work an address can demand, and a refused request should cost nothing.
    const auto client = client_key(req);
    if (over_attempt_limit("login", client, res)) return;

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    LoginRequest login_req;
    try {
        from_json(body, login_req);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing required fields").to_json().dump(), "application/json");
        return;
    }

    if (login_req.type == "m.login.password") {
        std::string user_id = login_req.identifier.user;
        // If user provided just a localpart, construct the full user_id
        if (!user_id.empty() && user_id[0] != '@') {
            user_id = "@" + user_id + ":" + config_.server_name;
        }

        // Must come before verify_password: PBKDF2 is the expensive part, and
        // a locked-out guesser should not get to make us run it.
        const auto user_key = config_.auth_limits.enabled ? user_failure_key(user_id) : std::string{};
        if (locked_out(client, user_key, res)) return;

        if (device_id_rejected(login_req.device_id, res)) return;

        // Spend the same PBKDF2 whether or not the account exists.
        //
        // The error message below is deliberately identical for "no such user"
        // and "wrong password", but the CODE was not: `!hash` short-circuited
        // the `||`, so a login for an account that does not exist returned in
        // microseconds while one for an account that does spent half a second
        // in PBKDF2 at cost 19. Nobody needs statistics to read a difference
        // that size — it is a remote account-enumeration oracle behind an
        // endpoint whose wording was chosen specifically not to be one, and it
        // is available before any rate limit has been tripped.
        //
        // An account with an EMPTY hash (OIDC-backed — see create_user on the
        // m.login.token path) goes the same way for the same reason: it must
        // never authenticate by password, and "this account exists but signs
        // in elsewhere" is not something an unauthenticated caller should be
        // able to time.
        auto hash = store_.get_password_hash(user_id);
        const bool password_usable = hash && !hash->empty();
        const std::string& material =
            password_usable ? *hash : dummy_password_hash(config_.password_hash_cost);
        const bool verified = verify_password(login_req.password, material);
        if (!password_usable || !verified) {
            record_failure(client, user_key);
            res.status = 403;
            res.set_content(MatrixError::forbidden("Invalid username or password").to_json().dump(), "application/json");
            return;
        }

        // A banned identity cannot start a new session.
        //
        // This is what makes revoking sessions on ban worth doing. Revocation
        // alone would be theatre: the target's client would be logged out, it
        // would immediately re-authenticate with the password it still has, and
        // receive a fresh 90-day token. The ban would hold only because /sync and
        // /join happen to consult the ban list.
        //
        // Checked AFTER the password verification on purpose. Refusing earlier
        // would turn /login into an oracle that reports whether an arbitrary
        // username is banned, to anyone who asks and without credentials.
        // The password was right, so the account's failure count resets. The
        // ADDRESS's count deliberately does not: if it did, anyone with one
        // valid account could log into it between guesses and spray other
        // accounts from the same address forever. It simply ages out.
        if (!user_key.empty()) failures_.clear(user_key);

        if (store_.is_server_banned(user_id)) {
            get_logger()->info("Refused login for banned user {}", user_id);
            res.status = 403;
            res.set_content(MatrixError::forbidden("You are banned from this server")
                                .to_json().dump(), "application/json");
            return;
        }

        // Transparently upgrade a hash that was created with a weaker work
        // factor. The cost is recorded in the stored hash, so old hashes keep
        // verifying; this is the only moment we hold the plaintext and can
        // re-derive at the current cost.
        auto stored_cost = password_hash_cost(*hash);
        if (stored_cost && *stored_cost < config_.password_hash_cost) {
            try {
                store_.update_password_hash(
                    user_id, hash_password(login_req.password, config_.password_hash_cost));
                get_logger()->info("Upgraded password hash cost {} -> {} for {}",
                                   *stored_cost, config_.password_hash_cost, user_id);
            } catch (const std::exception& e) {
                get_logger()->warn("Password hash upgrade failed for {}: {}", user_id, e.what());
            }
        }

        auto access_token = generate_access_token();
        auto device_id = login_req.device_id.value_or(generate_device_id());
        std::optional<std::string> refresh_token;
        if (login_req.refresh_token) refresh_token = generate_access_token();
        store_.store_access_token(access_token, user_id, device_id, token_lifetime_ms(),
                                  refresh_token);

        LoginResponse login_resp{
            .user_id = user_id,
            .access_token = access_token,
            .device_id = device_id,
        };
        login_resp.refresh_token = refresh_token;
        login_resp.expires_in_ms = token_lifetime_ms();

        json resp;
        to_json(resp, login_resp);
        res.set_content(resp.dump(), "application/json");

        get_logger()->info("User logged in: {}", user_id);

    } else if (login_req.type == "m.login.token") {
        if (!oidc_auth_) {
            res.status = 400;
            res.set_content(MatrixError::unknown("Token login is not configured").to_json().dump(), "application/json");
            return;
        }

        if (device_id_rejected(login_req.device_id, res)) return;

        if (locked_out(client, {}, res)) return;

        std::string refusal;
        auto claims = verify_identity_token(login_req.token, refusal);
        if (!claims) {
            record_failure(client, {});
            res.status = 403;
            res.set_content(MatrixError::forbidden(refusal).to_json().dump(), "application/json");
            return;
        }

        // LINKED IDENTITY FIRST, before any id is derived from the subject.
        //
        // This one lookup is the whole of account linking as a signing-in user
        // experiences it. When the owner of an account has proved control of
        // both sides (POST /account/link_identity), this identity signs in as
        // THAT account — with its roles, its DMs and its history — instead of
        // minting or reusing a parallel `oidc_<sub>` one. When they have not,
        // the code below runs exactly as it always did.
        //
        // Keyed on the VERIFIED issuer from the token, never on the configured
        // provider URL: the two are normally the same, but a server that
        // changes provider must not have old links silently start matching
        // subjects minted by the new one.
        auto linked = store_.find_linked_user(claims->iss, claims->sub);

        // Unlinked: build user_id from the OIDC subject. The subject is
        // provider-chosen and can contain anything — concatenating it unchecked
        // is how the "@@josh:" double-@ incident happened. Sanitise to the
        // Matrix localpart grammar, then validate the assembled id before it
        // reaches the database (shadow_user_id_for_subject does both, and
        // returns empty when the result is unusable).
        //
        // Linked: no derivation at all. The id came from a row that was only
        // written after its owner proved control of the account, the row has a
        // foreign key to `users`, and the id passed UserId validation when the
        // account was created.
        std::string user_id = linked ? *linked
                                     : shadow_user_id_for_subject(claims->sub,
                                                                  config_.server_name);
        if (user_id.empty()) {
            // log_safe: this is the string that just FAILED validation, which is
            // the same shape as the lockout key above and as finding 17's
            // rejected pusher URL. The IdP signed it, but an IdP is not this
            // server's log format.
            get_logger()->warn("Rejected identity token: subject '{}' does not map to a valid user id",
                               log_safe(claims->sub));
            res.status = 403;
            res.set_content(MatrixError::forbidden("Identity token subject is not usable as a user id")
                                .to_json().dump(), "application/json");
            return;
        }

        // Same gate on the identity path. Checked after the identity token has
        // been validated, for the same oracle reason as the password path — and
        // before create_user, so a banned OIDC identity is not silently recreated
        // as a fresh account by the very request that should be refused.
        if (store_.is_server_banned(user_id)) {
            get_logger()->info("Refused identity login for banned user {}", user_id);
            res.status = 403;
            res.set_content(MatrixError::forbidden("You are banned from this server")
                                .to_json().dump(), "application/json");
            return;
        }

        // Create user if they don't exist (OIDC-only user with empty password hash)
        bool newly_created = !store_.user_exists(user_id);
        if (newly_created) {
            // The lookalike rule is NOT applied here, and must never be. This
            // is a login: the identity provider has already said who this is,
            // and refusing to create their account — or, once created, refusing
            // to let them back in — because the name resembles a local one
            // would lock a legitimate user out of a server on the strength of a
            // heuristic. Local registration refuses the `oidc_` prefix outright
            // and refuses any name colliding with an account that already
            // exists, which is where this is defended. If one slipped in before
            // the rule existed, say so once, loudly, so an operator can act.
            //
            // Asked BEFORE create_user, so the row about to be inserted cannot
            // be the one the lookup finds and hide a real twin behind itself.
            auto parsed = UserId::parse(user_id);
            if (auto twin = store_.find_user_by_localpart_skeleton(
                    localpart_skeleton(parsed ? parsed->localpart : user_id))) {
                get_logger()->warn("Identity account {} resembles existing account {}; "
                                   "creating it anyway, because refusing a login is worse "
                                   "than the resemblance", user_id, *twin);
            }
            store_.create_user(user_id, ""); // empty hash — cannot log in with password
        }

        // Set display name from claims if available.
        //
        // NOT on a linked login, and the omission is deliberate. For a shadow
        // account the provider's `name` claim is the only profile there is, so
        // tracking it is right. A LINKED account is somebody's existing
        // account: they chose its display name here, possibly years ago, and
        // having it silently overwritten by an IdP directory entry on every
        // sign-in is both surprising and, on a server where the IdP is
        // administered by someone else, a way for that administrator to rename
        // people. The link attaches a sign-in route; it does not hand the
        // provider the profile.
        if (!linked && claims->name) {
            store_.set_display_name(user_id, *claims->name);
        }

        auto access_token = generate_access_token();
        auto device_id = login_req.device_id.value_or(generate_device_id());
        std::optional<std::string> refresh_token;
        if (login_req.refresh_token) refresh_token = generate_access_token();
        store_.store_access_token(access_token, user_id, device_id, token_lifetime_ms(),
                                  refresh_token);

        if (newly_created) {
            auto_join_public_rooms(store_, sync_engine_, config_, user_id);
            // Same reason as in handle_register: without this the new account
            // holds no bsfchat.member.roles row at all and falls through to
            // @everyone until the next restart runs bootstrap_roles.
            //
            // It matters most on exactly the deployment shape we ship:
            // identity-only (identity.required, allow_local_accounts = false)
            // refuses local registration, so m.login.token is the ONLY way an
            // account is ever created there — and the very first user, who
            // should be the admin, came out with no admin role and therefore
            // no MANAGE_CHANNELS. They could not create the first channel,
            // and the only cure was restarting the server. That is the
            // deadlock RoleBootstrap was written to prevent, reappearing on
            // the one path that did not call it.
            bootstrap_roles(store_, sync_engine_, config_);
        }

        LoginResponse login_resp{
            .user_id = user_id,
            .access_token = access_token,
            .device_id = device_id,
        };
        login_resp.refresh_token = refresh_token;
        login_resp.expires_in_ms = token_lifetime_ms();

        json resp;
        to_json(resp, login_resp);
        res.set_content(resp.dump(), "application/json");

        // log_safe on the subject, for the reason the rejection path above
        // already gives: it is provider-chosen bytes, the log pattern is one
        // record per line, and a signature from the IdP is not a promise about
        // this server's log format. The success path was the one place it still
        // reached the log raw.
        //
        // "linked" in the line because the single most confusing support
        // question this feature can produce is "why did signing in with my
        // BSFChat ID put me in a different account than last week", and the
        // answer is visible here or nowhere.
        get_logger()->info("OIDC user logged in: {} (sub: {}){}", user_id,
                           log_safe(claims->sub), linked ? " [linked]" : "");

    } else {
        res.status = 400;
        res.set_content(MatrixError::unknown("Unsupported login type").to_json().dump(), "application/json");
        return;
    }
}

void AuthHandler::handle_register(const httplib::Request& req, httplib::Response& res) {
    if (!config_.registration_enabled) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Registration is disabled").to_json().dump(), "application/json");
        return;
    }
    // An identity-only server (identity.required with local accounts off)
    // advertises no m.login.password flow, so a locally registered account
    // could never sign in. Until now this handler still created one — and the
    // client, having been told "password-only" by a failed flow check, walked
    // people straight into that dead end. Refuse up front and say where to go.
    if (config_.identity && config_.identity->required && !config_.identity->allow_local_accounts) {
        res.status = 403;
        res.set_content(MatrixError::forbidden(
            "This server does not have local accounts. Sign in with your BSFChat ID ("
            + config_.identity->provider_url + ") and an account is created for you.").to_json().dump(),
            "application/json");
        return;
    }

    // Two layers. This one counts every attempt, so the "is this username
    // taken" answer below cannot be used to enumerate accounts at line rate.
    // The (much tighter) creation limit further down only spends a slot on a
    // request that is actually about to create an account — someone working
    // through taken usernames or a rejected password is not burning their
    // allowance for the hour.
    const auto client = client_key(req);
    if (over_attempt_limit("register", client, res)) return;

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    RegisterRequest reg_req;
    try {
        from_json(body, reg_req);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing username or password").to_json().dump(), "application/json");
        return;
    }

    // Validate username
    auto& username = reg_req.username;
    if (username.empty() || username.size() > limits::kMaxUsernameLength) {
        res.status = 400;
        res.set_content(MatrixError::invalid_username("Username must be 1-64 characters").to_json().dump(), "application/json");
        return;
    }
    if (!std::all_of(username.begin(), username.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        })) {
        res.status = 400;
        res.set_content(MatrixError::invalid_username("Username may only contain lowercase letters, digits, ., _, -").to_json().dump(), "application/json");
        return;
    }

    // The confusable skeleton of the requested name, used twice below: once
    // against the reserved names and once against every existing account.
    // identity/Localpart.h says what the folding is and why it is small.
    const std::string skeleton = localpart_skeleton(username);
    if (skeleton.empty()) {
        // Nothing but separators. Refused so that "" stays a value no CANDIDATE
        // ever has — it is also the column's default, and a candidate that
        // folds to nothing would otherwise be compared against every row that
        // had never been backfilled.
        res.status = 400;
        res.set_content(MatrixError::invalid_username(
            "Username must contain at least one letter or digit").to_json().dump(),
            "application/json");
        return;
    }

    // "server" is the synthetic actor PermissionsEngine grants ADMINISTRATOR
    // to unconditionally (@server:<server_name>), so registering it would hand
    // that account god mode. "oidc_*" is the namespace identity logins map
    // into, so a local account must not be able to squat an identity user.
    // "bot_*" is the same shape of reservation for bot accounts: a client
    // badges an account as a bot from its profile, and a person who could
    // register bot_deploy would be a person who can impersonate one. The
    // reservation also runs the other way — BotHandler REQUIRES the prefix — so
    // the two sets are disjoint by construction rather than by inspection.
    //
    // "console" is reserved for the same class of reason, one step removed: it
    // is the actor the offline admin CLI records its writes under
    // (@console:<server_name>, see src/cli/AdminCli.cpp). It carries no
    // permissions of its own, so registering it would not grant anything — what
    // it would do is make the audit log ambiguous, and the audit log is the only
    // answer to "how did that account get admin?". A record saying @console
    // must mean "somebody with shell access on the host", never "a user who
    // picked a clever name".
    //
    // The words "server" and "console" are matched on their SKELETON, so
    // `serv.er`, `s0erver` and `c0nsole` are reserved too — a reservation that
    // only covered the literal spelling was a reservation of one spelling out
    // of many that read the same.
    //
    // The PREFIXES deliberately stay literal matches. Comparing prefixes under
    // the skeleton would fold `oidc_` to `oldc` (separators go) and then refuse
    // every innocent name beginning with those four letters — `oldcoolguy`
    // among them. The case that actually matters, squatting a name that looks
    // like a REAL identity account, is caught below by the collision check
    // against existing users, which sees `oidc_josh` and refuses `o1dc_josh`.
    if (skeleton == localpart_skeleton("server") || skeleton == localpart_skeleton("console") ||
        username.rfind("oidc_", 0) == 0 ||
        username.rfind(std::string(bot::kLocalpartPrefix), 0) == 0) {
        res.status = 400;
        res.set_content(MatrixError::invalid_username("That username is reserved").to_json().dump(),
                        "application/json");
        return;
    }

    // Length was the whole policy. The two additions are the ones that pay for
    // themselves against how this server is actually attacked: a password
    // built out of the username defeats the per-account lockout (the attacker
    // needs one guess, not thousands), and so does spraying a single common
    // password across many accounts — neither ever accumulates enough failures
    // on one account to trip a counter. See password_policy_error().
    if (auto err = password_policy_error(reg_req.password, username)) {
        res.status = 400;
        res.set_content(MatrixError::invalid_param(*err).to_json().dump(), "application/json");
        return;
    }

    if (device_id_rejected(reg_req.device_id, res)) return;

    std::string user_id = "@" + username + ":" + config_.server_name;

    // A banned identity cannot be re-registered.
    //
    // What this DOES guarantee: the ban outlives the account row. If an operator
    // ever deletes a banned user, or a future account-deletion feature does, the
    // freed username cannot be claimed back by the person who was banned from it —
    // the ban list holds no foreign key to users(user_id) precisely so that
    // deleting the account cannot launder the ban.
    //
    // What it CANNOT guarantee: that the same human does not simply register a
    // different username. Nothing here binds an account to a person — there is no
    // email verification, no invite gating, no IP or device record, and OIDC
    // identities land in a separate "oidc_*" namespace. A ban is a ban on an
    // IDENTITY, not on a human being, and on an open-registration deployment it
    // stays that way. Closing that gap is a registration-policy problem
    // (invite-only signup, or identity-provider-only login), not something the ban
    // list can solve on its own.
    if (store_.is_server_banned(user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("This user is banned from this server")
                            .to_json().dump(), "application/json");
        return;
    }

    if (store_.user_exists(user_id)) {
        res.status = 400;
        res.set_content(MatrixError::user_in_use().to_json().dump(), "application/json");
        return;
    }

    // Lookalike accounts. `@josh` and `@j0sh` are different accounts that read
    // the same in a member list, which is an impersonation primitive that costs
    // an attacker one keystroke. Refused at the point the name is chosen.
    //
    // Checked AFTER user_exists so an exactly-taken name still answers
    // M_USER_IN_USE: the skeleton check would also fire on it, and "that name
    // is taken" is the true and more useful of the two answers.
    //
    // This leaks no more than the line above it already does. Probing `j0sh` to
    // learn that `josh` exists tells an enumerator nothing they could not learn
    // by probing `josh`, and the per-address attempt limiter at the top of this
    // handler counts both. The message deliberately does not NAME the account
    // it resembles — the user does not need it to pick another name, and there
    // is no reason to volunteer which account someone was trying to imitate.
    if (auto lookalike = store_.find_user_by_localpart_skeleton(skeleton)) {
        get_logger()->info("Refused registration of {}: too similar to existing account {}",
                           user_id, *lookalike);
        res.status = 400;
        res.set_content(MatrixError::invalid_username(
            "That username is too similar to an existing account. Choose one that differs "
            "by more than punctuation or lookalike characters.").to_json().dump(),
            "application/json");
        return;
    }

    // Everything past this point is the expensive part: a password hash, then
    // auto-join and a role bootstrap that walks every existing user under the
    // store's global lock. Per-address first, so an address that is already
    // over its own limit cannot also drain the server-wide allowance.
    if (config_.auth_limits.enabled) {
        if (!client.empty()) {
            if (auto wait = register_limiter_.acquire(client)) {
                return send_rate_limited(res, wait,
                    "Too many accounts created from your address. Try again later.");
            }
        }
        if (auto wait = register_global_limiter_.acquire("*")) {
            get_logger()->warn("Server-wide registration limit reached "
                               "(auth.register_global_limit = {}); refusing signups for {}s",
                               config_.auth_limits.register_global_limit, (wait + 999) / 1000);
            return send_rate_limited(res, wait,
                "This server is not accepting new registrations right now. Try again later.");
        }
    }

    auto password_hash = hash_password(reg_req.password, config_.password_hash_cost);
    if (!store_.create_user(user_id, password_hash)) {
        res.status = 500;
        res.set_content(MatrixError::unknown("Failed to create user").to_json().dump(), "application/json");
        return;
    }

    auto access_token = generate_access_token();
    auto device_id = reg_req.device_id.value_or(generate_device_id());
    std::optional<std::string> refresh_token;
    if (reg_req.refresh_token) refresh_token = generate_access_token();
    store_.store_access_token(access_token, user_id, device_id, token_lifetime_ms(),
                              refresh_token);

    // Auto-join all existing public channels so new users immediately see the server's content
    auto_join_public_rooms(store_, sync_engine_, config_, user_id);

    // Give the new account its role assignment now rather than at the next
    // restart. On a brand-new deployment this is also what makes the very
    // first registered user an admin — without it nobody would hold
    // MANAGE_CHANNELS and the first channel could never be created.
    bootstrap_roles(store_, sync_engine_, config_);

    LoginResponse login_resp{
        .user_id = user_id,
        .access_token = access_token,
        .device_id = device_id,
    };
    login_resp.refresh_token = refresh_token;
    login_resp.expires_in_ms = token_lifetime_ms();

    json resp;
    to_json(resp, login_resp);
    res.status = 200;
    res.set_content(resp.dump(), "application/json");

    get_logger()->info("User registered: {}", user_id);
}

void AuthHandler::handle_logout(const httplib::Request& req, httplib::Response& res) {
    auto token = extract_access_token(req.get_header_value("Authorization"));
    if (!token) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    store_.delete_access_token(*token);
    res.set_content("{}", "application/json");
}

void AuthHandler::handle_logout_all(const httplib::Request& req, httplib::Response& res) {
    auto token = extract_access_token(req.get_header_value("Authorization"));
    if (!token) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }
    auto user_id = store_.get_user_by_token(*token);
    if (!user_id) {
        return send_error(res, 401, MatrixError::unknown_token());
    }

    // Panic button: revokes every session for the account, this one included.
    // Before tokens had any invalidation path at all, a user who believed their
    // token had leaked had no remedy short of an admin editing the database.
    store_.delete_all_tokens_for_user(*user_id);
    get_logger()->info("All sessions revoked for {}", *user_id);
    res.set_content("{}", "application/json");
}

void AuthHandler::handle_password_change(const httplib::Request& req, httplib::Response& res) {
    const auto client = client_key(req);
    if (over_attempt_limit("password", client, res)) return;

    auto token = extract_access_token(req.get_header_value("Authorization"));
    if (!token) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }
    auto user_id = store_.get_user_by_token(*token);
    if (!user_id) {
        return send_error(res, 401, MatrixError::unknown_token());
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }
    if (!body.is_object()) {
        return send_error(res, 400, MatrixError::bad_json());
    }

    // Re-authentication is mandatory. A valid access token proves "this client
    // holds a token", not "the account owner is present" — without the current
    // password, anyone who got hold of a token could lock the real owner out by
    // changing their password. This is the m.login.password stage of Matrix's
    // user-interactive auth, supplied inline in the `auth` object.
    if (!body.contains("auth") || !body["auth"].is_object()) {
        res.status = 401;
        res.set_content(json{
            {"flows", json::array({json{{"stages", json::array({"m.login.password"})}}})},
            {"params", json::object()},
            {"completed", json::array()},
            {"session", generate_device_id()},
        }.dump(), "application/json");
        return;
    }

    const auto& auth = body["auth"];
    if (auth.value("type", "") != "m.login.password") {
        return send_error(res, 400, MatrixError::unknown("Unsupported auth type"));
    }
    // If the client names a user, it must be the authenticated one — a token
    // must never be usable to re-authenticate as somebody else.
    if (auth.contains("identifier") && auth["identifier"].is_object()) {
        auto named = auth["identifier"].value("user", "");
        if (!named.empty()) {
            if (named[0] != '@') named = "@" + named + ":" + config_.server_name;
            if (named != *user_id) {
                return send_error(res, 403, MatrixError::forbidden(
                    "Authentication identifier does not match the access token"));
            }
        }
    }
    const std::string current_password = auth.value("password", "");

    std::string new_password;
    if (body.contains("new_password") && body["new_password"].is_string()) {
        new_password = body["new_password"].get<std::string>();
    }
    if (new_password.empty()) {
        return send_error(res, 400, MatrixError::invalid_param("Missing new_password"));
    }
    // The same policy registration applies. A rule that only guards the front
    // door is not a rule: without this, "password1" is two requests away for
    // any account — register with something acceptable, then change it.
    //
    // Checked against the authenticated user's own localpart, which is why it
    // is parsed out of *user_id rather than taken from the request.
    {
        const auto colon = user_id->find(':');
        const std::string localpart =
            (user_id->size() > 1 && colon != std::string::npos)
                ? user_id->substr(1, colon - 1) : std::string{};
        if (auto err = password_policy_error(new_password, localpart)) {
            return send_error(res, 400, MatrixError::invalid_param(*err));
        }
    }

    auto stored = store_.get_password_hash(*user_id);
    if (!stored) {
        // The token resolved to a user, so this should be unreachable.
        return send_error(res, 404, MatrixError::not_found("Account not found"));
    }
    // OIDC-backed accounts are created with an empty hash precisely so password
    // login can never work for them. Say so plainly instead of failing
    // verification and looking like a wrong-password error.
    if (stored->empty()) {
        return send_error(res, 403, MatrixError::forbidden(
            "This account signs in through the identity provider; change your password there."));
    }
    if (config_.identity && config_.identity->required && !config_.identity->allow_local_accounts) {
        return send_error(res, 403, MatrixError::forbidden(
            "Local password login is disabled on this server"));
    }

    // verify_password reads the cost out of the stored hash, so an account
    // still on the old cost-12 hash re-authenticates fine here...
    //
    // This endpoint is a password oracle for whoever holds a token, so it gets
    // the same lockout as /login — under its own key. Sharing /login's would
    // let a stolen token lock the owner out of signing in.
    const auto change_key = config_.auth_limits.enabled
        ? "pwchange:" + *user_id : std::string{};
    if (locked_out(client, change_key, res)) return;
    if (current_password.empty() || !verify_password(current_password, *stored)) {
        record_failure(client, change_key);
        return send_error(res, 403, MatrixError::forbidden("Invalid password"));
    }
    if (!change_key.empty()) failures_.clear(change_key);

    // Rejected only AFTER the current password has been proved, and only then:
    // answering "that is your current password" to a caller who has not yet
    // demonstrated they know it would turn this endpoint into a password
    // checker. The current password is already in hand here, so this costs a
    // string comparison of the two plaintexts and no extra hashing.
    //
    // Worth refusing because the sessions below are revoked either way: a
    // no-op change would log every other device out and leave the credential
    // that prompted it in place, which is the opposite of what the user asked
    // for.
    if (new_password == current_password) {
        return send_error(res, 400, MatrixError::invalid_param(
            "New password must be different from your current password"));
    }

    // ...and the replacement is always written at the CURRENT configured cost,
    // which makes a password change a second upgrade path alongside
    // migrate-on-login.
    try {
        store_.update_password_hash(*user_id,
                                    hash_password(new_password, config_.password_hash_cost));
    } catch (const std::exception& e) {
        get_logger()->error("Password change failed for {}: {}", *user_id, e.what());
        return send_error(res, 500, MatrixError::unknown("Failed to update password"));
    }

    // Matrix default: revoke the account's other sessions. This is the point of
    // a password change — if the reason for changing it is a suspected leak,
    // leaving the leaked token alive defeats the exercise. The session that
    // just re-authenticated is kept so the user isn't kicked out of the client
    // they made the change from.
    const bool logout_devices = body.value("logout_devices", true);
    int revoked = 0;
    if (logout_devices) {
        revoked = store_.delete_other_tokens_for_user(*user_id, *token);
    }

    get_logger()->info("Password changed for {} ({} other session(s) revoked)", *user_id, revoked);
    res.set_content("{}", "application/json");
}

void AuthHandler::handle_refresh(const httplib::Request& req, httplib::Response& res) {
    // Attempt limit only, no failure lockout: refresh tokens are 256-bit
    // random, so guessing is not the threat — unmetered database work is.
    // And a client looping on a stale token must not be able to lock the
    // other people behind its NAT out of /login.
    if (over_attempt_limit("refresh", client_key(req), res)) return;

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }
    std::string refresh_token;
    if (body.is_object() && body.contains("refresh_token") && body["refresh_token"].is_string()) {
        refresh_token = body["refresh_token"].get<std::string>();
    }
    if (refresh_token.empty()) {
        return send_error(res, 400, MatrixError::invalid_param("Missing refresh_token"));
    }

    // Redemption is single-use and rotates both secrets, so a stolen refresh
    // token stops working the moment the legitimate client refreshes.
    auto session = store_.consume_refresh_token(refresh_token);
    if (!session) {
        // Rotation alone left theft profitable: whoever redeems SECOND is the
        // one locked out, and if that is the real user they simply sign in
        // again while the thief keeps rotating a session that no longer shares
        // a secret with anybody. A second redemption of an already-spent token
        // is the one observable sign that the chain was copied, so it revokes
        // everything descended from that login — the two branches cannot be
        // told apart, and guessing wrong in the other direction leaves the
        // attacker inside.
        //
        // The response is the same 401 either way. A caller who has just had a
        // family revoked has, by construction, presented a token that is no
        // longer valid; saying more would tell an attacker probing old tokens
        // which of them were once real.
        store_.revoke_family_for_replayed_refresh_token(refresh_token);
        return send_error(res, 401, MatrixError::unknown_token("Invalid refresh token"));
    }

    auto access_token = generate_access_token();
    auto new_refresh = generate_access_token();
    // Carries the family forward. Passing nothing here would start a new
    // family on every refresh, which quietly reduces reuse detection to "the
    // single most recent hop" — the chain would be one session long and
    // revoking it would leave every earlier rotation alive.
    store_.store_access_token(access_token, session->user_id, session->device_id,
                              token_lifetime_ms(), new_refresh, session->family_id);

    res.set_content(json{
        {"access_token", access_token},
        {"refresh_token", new_refresh},
        {"expires_in_ms", token_lifetime_ms()},
    }.dump(), "application/json");
}

void AuthHandler::handle_whoami(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    json resp = {{"user_id", *user_id}};
    // Bot-ness of the CALLER. A bot's own client needs to know what it is — to
    // skip the "set a password" and "your session expires" affordances that make
    // no sense for it, and to render itself the way everyone else will see it —
    // and whoami is already the request it makes to reconcile its identity, so
    // this costs no extra round trip.
    //
    // Emitted only when true, matching /profile: absent means "not a bot", the
    // same way an unset displayname is absent rather than "". A client reads it
    // as `resp.value("bsfchat.bot", false)` either way.
    if (store_.is_bot(*user_id)) resp[std::string(bot::kProfileKey)] = true;
    res.status = 200;
    res.set_content(resp.dump(), "application/json");
}

// ── Identity tokens ───────────────────────────────────────────────────────

std::optional<JwtClaims> AuthHandler::verify_identity_token(const std::string& token,
                                                            std::string& refusal) {
    auto log = get_logger();
    refusal = "Invalid identity token";
    if (!oidc_auth_ || !config_.identity) return std::nullopt;

    // Fail closed. jwt_verify treats an empty audience as "do not check",
    // which is exactly the hole C1 was, so an underivable audience refuses
    // everything rather than reaching it. Config::validate has already said
    // why at startup.
    const std::string audience = expected_identity_audience(config_);
    if (audience.empty()) {
        log->error("Refused an identity token: this server has no usable public URL "
                   "(set server.public_url)");
        return std::nullopt;
    }

    auto claims = oidc_auth_->validate_token(token, audience);
    if (!claims) {
        // Worth one more look, because the commonest failure right after this
        // change ships is not an attack: it is somebody on a desktop client
        // from before the fix, whose token still carries the legacy client-id
        // audience. Telling them to update beats a bare "invalid". The token
        // is still refused — that audience is precisely the replayable one.
        auto unbound = oidc_auth_->validate_token(token, std::string());
        // A URL audience that is not ours is a token for another server: no
        // hint, it is either a mistake or an attack.
        if (unbound && !canonical_audience_url(unbound->aud)) {
            refusal = "This sign-in token is not bound to this server. Your BSFChat app is out "
                      "of date: update it and sign in again.";
        }
        return std::nullopt;
    }

    // Issued to the client we expect. A token some OTHER registered relying
    // party obtained for this server — with the user's consent to that
    // party, not to this app — does not sign anybody in here.
    const std::string& client_id = config_.identity->client_id;
    if (!client_id.empty() && claims->azp.value_or(std::string()) != client_id) {
        log->warn("Refused an identity token issued to another client");
        return std::nullopt;
    }

    // One use per token. The nonce is generated per authorization by the
    // client and echoed by the provider, so it names this token; a second
    // presentation is a copy. The +60 matches jwt_verify's leeway, so the
    // record outlives every moment at which the token could still verify.
    if (!claims->nonce || claims->nonce->empty()) {
        refusal = "This sign-in token carries no nonce. Update your BSFChat app and sign in again.";
        return std::nullopt;
    }
    if (!oidc_auth_->first_presentation(claims->iss, claims->sub, *claims->nonce,
                                        claims->exp + 60)) {
        log->warn("Refused a second presentation of an identity token");
        refusal = "This sign-in token has already been used";
        return std::nullopt;
    }

    return claims;
}

// ── Account linking ───────────────────────────────────────────────────────
//
// POST /_matrix/client/v3/bsfchat/account/link_identity
//   { "type": "m.login.token", "token": "<id_token>" }
//
// THE SECURITY PROPERTY, stated once: this endpoint requires the caller to be
// authenticated as BOTH sides at the same moment. The bearer token proves
// control of the account that will survive; the id_token in the body, verified
// against the provider's published keys and audienced to THIS server's own
// public URL, proves control of the identity being attached. There is no flow in which
// merely ASSERTING an identity — a subject string, an email, a display name —
// attaches anything, which is the attack this shape exists to make
// unrepresentable: if it were enough to name an identity, the first person to
// name the owner's would inherit the owner's account.
//
// Each half alone is already sufficient to sign in as its own side, so holding
// both is exactly "this is one person with two logins", which is the claim
// being recorded. Nothing weaker would do, and nothing stronger is available
// to a self-hosted server with no out-of-band channel to its users.
//
// WHAT HAPPENS TO THE ABANDONED ACCOUNT. Nothing is deleted, ever:
//
//   * its `users` row stays, so its user id stays TAKEN and can never be
//     handed to anybody else. Local registration already refuses the `oidc_`
//     prefix, and create_user would refuse the id anyway — but the row is the
//     guarantee, not the policy.
//   * its messages stay exactly where they are, under its own sender id. They
//     are not rewritten to the surviving account: a rewrite would forge
//     history (it would make the surviving account appear to have said things
//     it never said, in rooms it may never have been in) and it would have to
//     touch every event, redaction, read marker, mention and push record that
//     names the old sender. Old messages keep showing the old name. That is
//     honest, and it is the same thing every other account-merge in this
//     product's category does.
//   * its live sessions are revoked, because after this request the person has
//     one account and a still-valid token for the other one is a session they
//     did not ask to keep.
//   * it becomes unreachable as a LOGIN: the identity that used to mint it now
//     resolves through the link table, and the account has an empty password
//     hash, so no m.login.password will ever authenticate it either.
void AuthHandler::handle_link_identity(const httplib::Request& req, httplib::Response& res) {
    // Half one: who is asking. Before anything expensive, and before the body
    // is parsed at all.
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }

    // Rate-limited on the same per-address budget as /login, because the work
    // is the same work: an id_token verification, and possibly a JWKS fetch.
    // An authenticated endpoint is still an endpoint one account can hammer.
    const auto client = client_key(req);
    if (over_attempt_limit("link_identity", client, res)) return;

    if (!oidc_auth_) {
        send_error(res, 400, MatrixError::unknown("This server has no identity provider "
                                                  "configured, so there is nothing to link"));
        return;
    }

    // A bot is not a person and has no identity-provider account. Refused
    // explicitly rather than left to fail further down, because "a bot token
    // can attach a human identity to the bot" is the kind of thing that only
    // looks harmless until somebody notices the bot then signs in as a human.
    if (store_.is_bot(*actor)) {
        send_error(res, 403, MatrixError::forbidden("Bot accounts cannot link an identity"));
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        send_error(res, 400, MatrixError::bad_json());
        return;
    }
    // `type` is required and must be m.login.token, mirroring /login's body.
    // Accepting a bare token would leave no room to add a second proof shape
    // later without guessing what an old client meant.
    if (!body.is_object() || body.value("type", "") != "m.login.token" ||
        !body.contains("token") || !body["token"].is_string()) {
        send_error(res, 400, MatrixError::bad_json(
            "Expected {\"type\": \"m.login.token\", \"token\": \"<id_token>\"}"));
        return;
    }

    // Half two: control of the identity. Verified with the SAME call the login
    // path makes — same keys, same issuer, same audience, same single use —
    // so an id_token that could not sign anybody in cannot link anything
    // either.
    //
    // The audience is what makes this half mean anything. Until identity
    // audit 2026-09 (C1) it was the desktop client id, shared by every
    // server: a hostile server that received a user's token at sign-in could
    // post it here beside a bearer for its OWN account on this server, and
    // this endpoint would link the victim's identity to the attacker's
    // account and revoke the victim's sessions — permanently, links being
    // insert-only. Production blocked the route in nginx on 2026-09-22 until
    // this shipped. A token is now accepted only if it names this server.
    std::string refusal;
    auto claims = verify_identity_token(body["token"].get<std::string>(), refusal);
    if (!claims) {
        record_failure(client, {});
        send_error(res, 403, MatrixError::forbidden(refusal));
        return;
    }

    // A banned account cannot acquire a new way to sign in, and a banned
    // shadow account cannot be laundered into an unbanned one by linking its
    // identity somewhere else. Both directions, because a ban is on a person
    // as much as on a row, and linking is the one operation that moves a login
    // between rows.
    const std::string shadow = shadow_user_id_for_subject(claims->sub, config_.server_name);
    if (store_.is_server_banned(*actor) ||
        (!shadow.empty() && store_.is_server_banned(shadow))) {
        get_logger()->info("Refused identity link for banned user {}", *actor);
        send_error(res, 403, MatrixError::forbidden("You are banned from this server"));
        return;
    }

    // Already linked? Three distinct answers, and they must stay distinct.
    if (auto existing = store_.find_linked_user(claims->iss, claims->sub)) {
        if (*existing == *actor) {
            // Idempotent. A client retrying a request whose response it lost
            // must not be told its own link is a conflict.
            res.status = 200;
            res.set_content(json{{"user_id", *actor}, {"already_linked", true}}.dump(),
                            "application/json");
            return;
        }
        // Linked elsewhere. Says so WITHOUT naming the other account: the
        // caller has just proved control of the identity, not of whatever
        // account somebody attached it to, and "this identity belongs to
        // @alice" is not a fact this endpoint gets to disclose. An operator
        // can read the audit log.
        get_logger()->warn("Refused identity link for {}: that identity is already linked "
                           "to another account", *actor);
        send_error(res, 409, MatrixError::user_in_use(
            "That identity is already linked to an account on this server. Sign in with it "
            "to reach that account, or ask an administrator."));
        return;
    }

    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (!store_.link_identity(claims->iss, claims->sub, *actor, *actor, now)) {
        // Lost a race with a concurrent link of the same identity. The row that
        // won is authoritative; report the conflict rather than reporting
        // success for a link this request did not make.
        send_error(res, 409, MatrixError::user_in_use(
            "That identity was linked to an account while this request was in flight."));
        return;
    }

    // The shadow account, if one was ever created for this identity. Revoking
    // its sessions is the only thing done TO it — see the block comment above
    // for everything deliberately not done.
    //
    // Skipped when the shadow IS the caller: an account linking the identity
    // it already signs in as would otherwise log itself out mid-request. That
    // is a legitimate thing to do (it pins the mapping so a later localpart
    // change cannot move it), just not a reason to end the session.
    std::string superseded;
    if (!shadow.empty() && shadow != *actor && store_.user_exists(shadow)) {
        superseded = shadow;
        const int revoked = store_.delete_all_tokens_for_user(shadow);
        get_logger()->info("Identity linked to {}; superseded account {} keeps its user id and "
                           "its messages, and had {} session(s) revoked",
                           *actor, shadow, revoked);
    } else {
        get_logger()->info("Identity linked to {}", *actor);
    }

    // Audited. The subject is not passed and cannot be: audit_account_link
    // takes the pieces and assembles the payload itself. See
    // audit_action::kAccountLink for why the superseded user id, which is
    // derived from the subject, is nonetheless the right thing to record.
    audit_account_link(store_, *actor, claims->iss, superseded);

    json resp = {
        {"user_id", *actor},
        {"issuer", claims->iss},
    };
    // Named so the client can explain the consequence rather than making the
    // user discover it: "your old @oidc_… account will no longer be signed
    // into; its messages stay where they are".
    if (!superseded.empty()) resp["superseded_user_id"] = superseded;
    res.status = 200;
    res.set_content(resp.dump(), "application/json");
}

void AuthHandler::handle_linked_identities(const httplib::Request& req, httplib::Response& res) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }

    // The CALLER's own links, with no way to ask about anybody else's. There is
    // deliberately no user id parameter and no admin-scoped variant: "which
    // identity-provider account is @josh?" is a question about a person's
    // presence on another system, and a chat server that answers it has made
    // itself into a correlation service for whoever holds MANAGE_SERVER.
    auto links = store_.list_linked_identities(*actor);

    json out = json::array();
    for (const auto& link : links) {
        // The SUBJECT IS NOT RETURNED, even to its own owner. A client has no
        // use for it — it renders "signed in with <issuer>, linked on <date>" —
        // and an opaque provider identifier that never leaves the database is
        // one that cannot leak from a client log, a screenshot or a bug report.
        out.push_back({
            {"issuer", link.issuer},
            {"linked_at", link.linked_at},
        });
    }
    res.status = 200;
    res.set_content(json{{"identities", out}}.dump(), "application/json");
}

} // namespace bsfchat
