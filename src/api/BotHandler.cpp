#include "api/BotHandler.h"

#include "audit/AuditLog.h"
#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <string>

namespace bsfchat {

using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Server scope for PermissionsEngine — the empty room id. See the class comment
// in BotHandler.h for why every endpoint in this file uses it.
const std::string kServerScope;

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// The localpart grammar for a bot, which is the human registration grammar plus
// a mandatory prefix.
//
// Deliberately the SAME character set AuthHandler::handle_register enforces, not
// a looser one. A bot id is rendered wherever a person's is, gets quoted into
// mention text, and ends up in an audit record an operator greps — so "what may
// appear in a user id" must have one answer on this server, not one answer for
// people and a more permissive one for accounts created by an admin.
bool valid_bot_localpart(const std::string& localpart) {
    if (localpart.size() <= bot::kLocalpartPrefix.size()) return false;  // prefix alone
    if (localpart.size() > limits::kMaxUsernameLength) return false;
    if (localpart.rfind(std::string(bot::kLocalpartPrefix), 0) != 0) return false;
    return std::all_of(localpart.begin(), localpart.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '.' || c == '_' || c == '-';
    });
}

// The list shape. Token material appears in NO branch of this function, and the
// store never held the plaintext to put there in the first place.
json bot_to_json(const SqliteStore::BotRecord& bot) {
    json out = {
        {"user_id", bot.user_id},
        {"display_name", bot.display_name},
        {"description", bot.description},
        {"owner_id", bot.owner_id},
        {"created_at", bot.created_at},
        // Always present, unlike the optional fields below: a client rendering a
        // bot list has to decide whether to grey the row out on every row, and an
        // absent key would make "not deactivated" and "old server that did not
        // report it" the same value.
        {"deactivated", bot.deactivated_at.has_value()},
    };
    // Emitted only when there is one, so a reader is never handed a 0 that looks
    // like "deactivated at the epoch" or "last seen in 1970".
    if (bot.deactivated_at) out["deactivated_at"] = *bot.deactivated_at;
    if (bot.last_seen_at) out["last_seen_at"] = *bot.last_seen_at;
    return out;
}

} // namespace

BotHandler::BotHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void BotHandler::handle_create_bot(const httplib::Request& req, httplib::Response& res) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*actor, kServerScope, permission::kManageBots)) {
        return send_error(res, 403, MatrixError::forbidden(
            "Insufficient permissions to create a bot account"));
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }
    if (!body.is_object()) return send_error(res, 400, MatrixError::bad_json());

    const std::string localpart = body.value("localpart", "");
    const std::string display_name = body.value("display_name", "");
    const std::string description = body.value("description", "");

    if (!valid_bot_localpart(localpart)) {
        return send_error(res, 400, MatrixError::invalid_username(
            "A bot localpart must start with \"" + std::string(bot::kLocalpartPrefix) +
            "\", be at most " + std::to_string(limits::kMaxUsernameLength) +
            " characters, and contain only lowercase letters, digits, ., _, -"));
    }
    if (description.size() > limits::kMaxBotDescriptionLength) {
        return send_error(res, 400, MatrixError::invalid_param(
            "description must be at most " +
            std::to_string(limits::kMaxBotDescriptionLength) + " characters"));
    }

    const std::string user_id = "@" + localpart + ":" + config_.server_name;
    if (!UserId::is_valid(user_id)) {
        // Unreachable given the grammar above, but the assembled id is what
        // reaches the database and the "@@josh:" incident came from trusting a
        // localpart check to imply a valid id.
        return send_error(res, 400, MatrixError::invalid_username(
            "That localpart does not form a valid user id on this server"));
    }

    // A banned identity cannot come back as a bot.
    //
    // Without this, "ban the user, then recreate the same localpart as a bot"
    // would be a way for anyone holding MANAGE_BOTS to resurrect a banned id —
    // and because the ban list holds no foreign key to users(user_id)
    // (deliberately, see migrate_v15), the ban row would still be sitting there
    // while the account it names was answering requests.
    if (store_.is_server_banned(user_id)) {
        return send_error(res, 403, MatrixError::forbidden(
            "That user id is banned from this server"));
    }

    SqliteStore::BotRecord record;
    record.user_id = user_id;
    record.display_name = display_name.empty() ? localpart : display_name;
    record.description = description;
    // Owner and creator are the same person today, and are separate columns
    // because they stop being the same person the moment ownership is
    // transferable or the creating admin leaves. `created_by` is history and must
    // never change; `owner_id` is a current fact about who is responsible for it.
    record.owner_id = *actor;
    record.created_by = *actor;
    record.created_at = now_ms();

    if (!store_.create_bot(record)) {
        // create_bot returns false only for a taken user id.
        return send_error(res, 400, MatrixError::user_in_use(
            "That bot localpart is already taken"));
    }

    // Mint the credential through the same call a rotation uses, so there is
    // exactly ONE code path in the server that issues a bot token and exactly one
    // place its non-expiring properties are set.
    const auto token = generate_access_token();
    if (!store_.rotate_bot_token(user_id, token, generate_device_id())) {
        // The account exists and is a bot — we just created it under a lock — so
        // this is a genuine fault, not a refusal. Report it rather than returning
        // a 201 for a bot nobody can authenticate as.
        get_logger()->error("Created bot {} but failed to issue its token", user_id);
        return send_error(res, 500, MatrixError::unknown("Failed to issue the bot token"));
    }

    // Give the new account its role assignment now rather than at the next
    // restart, for the same reason handle_register does: without it the bot holds
    // no bsfchat.member.roles row and falls through to @everyone until somebody
    // reboots the server. A bot is supposed to go through the ordinary roles
    // machinery, and that starts by actually being in it.
    //
    // Note what this does NOT do: auto-join. bootstrap_roles assigns roles, and
    // auto_join_public_rooms — which handle_register calls right before it — is
    // deliberately absent here. AutoJoin refuses bots at its own funnel too, so
    // this is belt and braces rather than the only guard.
    bootstrap_roles(store_, sync_engine_, config_);

    audit_bot_lifecycle(store_, *actor, audit_action::kBotCreate, user_id,
                        json{{"display_name", record.display_name},
                             {"description", record.description},
                             {"owner_id", record.owner_id}}
                            .dump());

    get_logger()->info("Bot account created: {} (by {})", user_id, *actor);

    res.status = 201;
    // `token` appears in this response and nowhere else, ever. Only its hash was
    // stored, so a later read of the database — or of the audit log — cannot
    // recover it, and an operator who loses it rotates rather than looking it up.
    res.set_content(json{
        {"user_id", user_id},
        {"display_name", record.display_name},
        {"token", token},
    }.dump(), "application/json");
}

void BotHandler::handle_list_bots(const httplib::Request& req, httplib::Response& res) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*actor, kServerScope, permission::kManageBots)) {
        return send_error(res, 403, MatrixError::forbidden(
            "Insufficient permissions to list bot accounts"));
    }

    // Deactivated bots are INCLUDED, flagged rather than hidden. A deactivated
    // bot still owns its user id, its messages are still in channels under that
    // name, and "why can't I create bot_deploy?" has no answer if the list only
    // shows live ones.
    json bots = json::array();
    for (const auto& bot : store_.list_bots()) bots.push_back(bot_to_json(bot));

    res.set_content(json{{"bots", std::move(bots)}}.dump(), "application/json");
}

void BotHandler::handle_rotate_token(const httplib::Request& req, httplib::Response& res) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*actor, kServerScope, permission::kManageBots)) {
        return send_error(res, 403, MatrixError::forbidden(
            "Insufficient permissions to rotate a bot token"));
    }

    auto match = match_route(std::string(api_path::kBots) + "/{userId}/token", req.path);
    if (!match.matched) return send_error(res, 404, MatrixError::not_found());
    const auto& user_id = match.params.at("userId");

    auto bot = store_.get_bot(user_id);
    if (!bot) return send_error(res, 404, MatrixError::not_found("No such bot"));

    // A deactivated bot does not get a new credential. Deactivation is how a bot
    // is turned off, and if rotating could revive one then "deactivated" would
    // mean "until somebody rotates it" — which is not what the operator who
    // deactivated it was promised. Bringing a bot back is deliberately not an
    // operation: create a new one, so there is a creation record for it.
    if (bot->deactivated_at) {
        return send_error(res, 400, MatrixError::invalid_param(
            "That bot is deactivated; deactivated bots cannot be issued new tokens"));
    }

    const auto token = generate_access_token();
    if (!store_.rotate_bot_token(user_id, token, generate_device_id())) {
        // get_bot() found a bots row, so the users row must say kind = 'bot'
        // (the foreign key and create_bot's transaction guarantee the pair).
        get_logger()->error("Failed to rotate token for bot {}", user_id);
        return send_error(res, 500, MatrixError::unknown("Failed to rotate the bot token"));
    }

    audit_bot_lifecycle(store_, *actor, audit_action::kBotTokenRotate, user_id,
                        json{{"rotated", true}}.dump());

    get_logger()->info("Bot token rotated for {} (by {}); all prior tokens revoked",
                       user_id, *actor);

    res.set_content(json{{"token", token}}.dump(), "application/json");
}

void BotHandler::handle_deactivate_bot(const httplib::Request& req, httplib::Response& res) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*actor, kServerScope, permission::kManageBots)) {
        return send_error(res, 403, MatrixError::forbidden(
            "Insufficient permissions to deactivate a bot account"));
    }

    auto match = match_route(std::string(api_path::kBots) + "/{userId}", req.path);
    if (!match.matched) return send_error(res, 404, MatrixError::not_found());
    const auto& user_id = match.params.at("userId");

    auto bot = store_.get_bot(user_id);
    if (!bot) return send_error(res, 404, MatrixError::not_found("No such bot"));

    // Rooms are left BEFORE the store call, because leaving is the part that has
    // to be visible to everyone else and the part that can be interrupted.
    //
    // Order matters in one direction only: whatever happens here, the tokens die
    // below, so a failure halfway through leaves a bot that is still in some
    // channels but cannot act in any of them. The opposite order would leave a
    // revoked bot sitting in every channel as an apparently-live member.
    //
    // get_joined_rooms(), not "every room it has a row in": invite and ban rows
    // are decisions somebody else took about this bot and are not ours to
    // rewrite, and a `leave` row is already where we want it.
    int left = 0;
    for (const auto& room_id : store_.get_joined_rooms(user_id)) {
        store_.set_membership(room_id, user_id, std::string(membership::kLeave));
        store_.insert_event(generate_event_id(config_.server_name), room_id, user_id,
                            std::string(event_type::kRoomMember), user_id,
                            json{{"membership", membership::kLeave}}.dump(), now_ms());
        ++left;
    }
    if (left > 0) sync_engine_.notify_new_event();

    // Idempotent by construction: deactivate_bot revokes tokens on every call and
    // reports whether THIS call was the one that flipped the flag. A second
    // DELETE is a 200 that changes nothing and — importantly — writes no second
    // audit record, so the log says the bot was deactivated once, which is what
    // happened.
    const bool newly_deactivated = store_.deactivate_bot(user_id, now_ms());

    if (newly_deactivated) {
        audit_bot_lifecycle(store_, *actor, audit_action::kBotDeactivate, user_id,
                            json{{"rooms_left", left}}.dump());
        get_logger()->info("Bot deactivated: {} (by {}); tokens revoked, left {} room(s)",
                           user_id, *actor, left);
    }

    res.set_content("{}", "application/json");
}

} // namespace bsfchat
