#include "api/BotHandler.h"
#include "api/InputLimits.h"

#include "audit/AuditLog.h"
#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "auth/RoomVisibility.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/JsonIo.h"
#include "http/Router.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
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

std::optional<BotHandler::BotAdminContext> BotHandler::authorize_bot_admin(
    const httplib::Request& req, httplib::Response& res, const std::string& bot_user_id,
    const char* action) {
    auto actor = authenticate(store_, req.get_header_value("Authorization"));
    if (!actor) {
        send_error(res, 401, auth_error(req.get_header_value("Authorization")));
        return std::nullopt;
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*actor, kServerScope, permission::kManageBots)) {
        send_error(res, 403, MatrixError::forbidden(
            std::string("Insufficient permissions to ") + action));
        return std::nullopt;
    }

    auto bot = store_.get_bot(bot_user_id);
    if (!bot) {
        send_error(res, 404, MatrixError::not_found("No such bot"));
        return std::nullopt;
    }

    // The hierarchy check. See BotHandler.h for why handing out a bot credential
    // is a role grant and therefore needs the same rank rule role grants get.
    //
    // AFTER the lookup, so a bot that does not exist is a 404 rather than a 403
    // that leaks whether the id is taken. That ordering costs nothing here:
    // everyone who reaches this line already holds MANAGE_BOTS and can list every
    // bot on the server, so there is no existence oracle to protect.
    //
    // outranks() is strict, and strictness is the point: an actor at the SAME
    // position as the bot is refused, because equal rank means the bot's roles
    // are not already theirs to hold. That is the same rule may_assign_roles
    // applies to a human target ("at or above you").
    //
    // And since F6 it also answers for the bot's CHANNEL access, which for a
    // scoped bot is the whole of what the credential is worth — see
    // BotHandler.h and PermissionsEngine::channel_access_excess.
    const bool exempt = perms.can(*actor, kServerScope, permission::kAdministrator);
    if (!exempt && !perms.outranks(*actor, bot_user_id)) {
        get_logger()->warn(
            "Refused attempt by {} to {} for bot {}, which ranks at or above them "
            "(bot credentials confer the bot's roles and its channel access)",
            *actor, action, bot_user_id);
        send_error(res, 403, MatrixError::forbidden(
            std::string("You cannot ") + action +
            " for a bot that ranks at or above you: its token would grant you the "
            "bot's roles and its access to channels"));
        return std::nullopt;
    }

    return BotAdminContext{.actor = *actor, .bot = std::move(*bot)};
}

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
        body = parse_request_json(req.body);
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
    // The bot's display name rides in its m.room.member event in every channel
    // it joins, exactly like a human's set through PUT /displayname, so it gets
    // the same ceiling (audit S2, api/InputLimits.h).
    if (auto err = oversize_field("display_name", display_name,
                                  input_limits::kMaxDisplayNameBytes)) {
        return send_error(res, 400, *err);
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
    // never change; `owner_id` is who to go and ask about this bot.
    //
    // Both are ADVISORY: neither gates anything, here or anywhere else. What
    // gates rotation and deactivation is rank — see authorize_bot_admin. The
    // reasoning is on SqliteStore::BotRecord::owner_id.
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

    // Give the new account its role assignment now: an EMPTY one.
    //
    // A bot starts with no permissions anywhere. It does not inherit @everyone
    // (permission::inherits_everyone_role), so this empty document is the whole
    // of what it may do until an operator grants something — which is the point
    // of the feature: a credential that can be minted and then scoped, rather
    // than one that arrives holding VIEW_CHANNEL and SEND_MESSAGES on every
    // channel the server has and has to be cut back afterwards.
    //
    // WRITTEN, not left absent, and through write_server_scoped_state like every
    // other assignment. Three things follow from that and none of them would
    // from a missing row: the grant is audited from the first moment ("this bot
    // was created with nothing" is a record an owner can read), it is mirrored
    // to clients so the Bots tab has a document to edit rather than an absence
    // to interpret, and it is indistinguishable in shape from a human's, so
    // every existing reader of bsfchat.member.roles keeps working.
    //
    // bootstrap_roles is deliberately NOT called here any more. It assigns
    // @everyone to any account without an assignment and runs at every boot; it
    // now skips bots for exactly that reason, so calling it would be a no-op
    // that reads as though it did the work this block does.
    //
    // Note what this does NOT do, as before: auto-join. AutoJoin refuses bots at
    // its own funnel, and a bot with no VIEW_CHANNEL would have nothing to read
    // in those channels anyway.
    {
        MemberRolesContent assignment;  // no roles
        json j;
        to_json(j, assignment);
        write_server_scoped_state(store_, config_, std::string(event_type::kMemberRoles),
                                  user_id, j.dump(), pick_server_state_mirror_room(store_),
                                  *actor);
        sync_engine_.notify_new_event();
    }

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
    //
    // `role_ids` AND A WARNING, because the block above just decided the most
    // surprising thing about this account and said so nowhere. A bot arrives
    // able to authenticate and to join, and able to do nothing else; an
    // operator who does not already know that reads three 200s and a join, and
    // meets the fact for the first time as a 403 about a channel. Saying it
    // here is the earliest point at which it can be said.
    //
    // `role_ids` is spelt and shaped exactly as GET /bots/{id}/access spells
    // it — the editable assignment document, empty today and empty for the
    // foreseeable future — so a tab can render the new bot from this response
    // without a second call and without a second vocabulary. It is not
    // hardcoded to `[]`: it is read back out of what was actually written, so
    // if that ever stops being empty this response stops claiming it is.
    json role_ids = json::array();
    for (const auto& id : store_.get_member_role_ids(user_id)) role_ids.push_back(id);
    res.set_content(json{
        {"user_id", user_id},
        {"display_name", record.display_name},
        {"token", token},
        {"role_ids", std::move(role_ids)},
        {std::string(bot::kWarningKey),
         "This bot holds no roles and no channel grant: it can authenticate and join "
         "channels, but cannot see or post in any of them until an operator grants it "
         "access. Grant a role with PUT bsfchat.member.roles, or one channel with PUT "
         "bsfchat.channel.permissions/user:" + user_id + " — both need MANAGE_ROLES. "
         "GET " + std::string(api_path::kBots) + "/" + user_id + "/access reports where "
         "it may go."},
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
    auto match = match_route(std::string(api_path::kBots) + "/{userId}/token", req.path);
    if (!match.matched) return send_error(res, 404, MatrixError::not_found());
    const auto& user_id = match.params.at("userId");

    // Authentication, MANAGE_BOTS, the lookup and the rank check, in one call.
    // Rotation is the endpoint the hierarchy check exists for: it hands the
    // caller a live, non-expiring credential for the bot.
    auto ctx = authorize_bot_admin(req, res, user_id, "rotate a bot token");
    if (!ctx) return;
    const auto& actor = ctx->actor;
    const auto* bot = &ctx->bot;

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

    audit_bot_lifecycle(store_, actor, audit_action::kBotTokenRotate, user_id,
                        json{{"rotated", true}}.dump());

    get_logger()->info("Bot token rotated for {} (by {}); all prior tokens revoked",
                       user_id, actor);

    res.set_content(json{{"token", token}}.dump(), "application/json");
}

void BotHandler::handle_deactivate_bot(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route(std::string(api_path::kBots) + "/{userId}", req.path);
    if (!match.matched) return send_error(res, 404, MatrixError::not_found());
    const auto& user_id = match.params.at("userId");

    // Same gate as rotation, and it belongs here for a second reason: deactivating
    // a bot that outranks you is destroying a higher-ranked principal. That is the
    // shape outranks() already refuses for kicking or banning a person above you,
    // and a moderation bot is exactly the thing a badly-behaved moderator would
    // most like to switch off.
    auto ctx = authorize_bot_admin(req, res, user_id, "deactivate a bot account");
    if (!ctx) return;
    const auto& actor = ctx->actor;

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
        // Bare insert_event: the content is this literal and nothing else. A
        // leave event deliberately carries no profile fields — see
        // member_event_content, which returns early for anything but join and
        // invite — so there is nothing here to bind.
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
        audit_bot_lifecycle(store_, actor, audit_action::kBotDeactivate, user_id,
                            json{{"rooms_left", left}}.dump());
        get_logger()->info("Bot deactivated: {} (by {}); tokens revoked, left {} room(s)",
                           user_id, actor, left);
    }

    res.set_content("{}", "application/json");
}

void BotHandler::handle_get_bot_access(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route(std::string(api_path::kBots) + "/{userId}/access", req.path);
    if (!match.matched) return send_error(res, 404, MatrixError::not_found());
    const auto& user_id = match.params.at("userId");

    // The same gate rotation and deactivation get, for the reason on the
    // declaration: this is reconnaissance for a rotation. It also settles the
    // "is this a bot" question — a person's id takes the 404 branch, byte for
    // byte identical to a bot id nobody has ever created.
    auto ctx = authorize_bot_admin(req, res, user_id, "read a bot's access");
    if (!ctx) return;
    const auto& actor = ctx->actor;

    // ONE engine across both questions and every channel, so the server role
    // document and both accounts' assignments are each read once. Constructing
    // one per room is the N+1 that RoomVisibility.h warns about, behind the
    // store's global mutex, on a server with a few hundred channels.
    PermissionsEngine perms(store_, config_);

    // The CALLER's directory. See the declaration: MANAGE_BOTS does not confer
    // the right to enumerate channels, and this is the filter that already
    // decides what a caller may be told exists.
    const auto directory = visible_channel_directory(store_, perms, actor);

    json channels = json::array();
    for (const auto& entry : directory) {
        json c = {
            {"room_id", entry.room_id},
            {"name", entry.name},
            {"type", entry.type},
            // The BOT's membership, not the caller's — the directory computed
            // that field about the caller and it would be the wrong answer to
            // the only question worth asking here. A bot must be in a channel
            // to post in it, so a tab that has just granted VIEW_CHANNEL still
            // has to tell the operator the bot is not in there yet.
            {"joined", store_.is_room_member(entry.room_id, user_id)},
            // THE authority, asked about the bot, in this channel. Not derived
            // from the override below, which is only one of the four terms that
            // produce it.
            {"permissions", permission::flags_to_hex(perms.compute(user_id, entry.room_id))},
        };
        if (!entry.category_id.empty()) c["category_id"] = entry.category_id;

        // The override as stored, so an editor can tell "granted here" from
        // "arrived from a role", and so it can round-trip an edit without
        // inventing the half it did not read. Emitted only where one exists:
        // an absent key is "nothing is written for this bot in this channel",
        // which is a different state from allow=0 deny=0 and is the state an
        // operator undoing a grant should end up in.
        auto overrides = store_.get_channel_overrides(entry.room_id);
        auto it = overrides.find("user:" + user_id);
        if (it != overrides.end()) {
            c["override"] = {{"allow", permission::flags_to_hex(it->second.allow)},
                             {"deny", permission::flags_to_hex(it->second.deny)}};
        }
        channels.push_back(std::move(c));
    }

    json role_ids = json::array();
    for (const auto& id : perms.roles_of(user_id)) role_ids.push_back(id);

    // THE HEADLINE, computed rather than left for the reader to compute.
    //
    // Everything needed to answer "can this bot do anything at all?" was
    // already in the body — role_ids, server_permissions, and a mask per
    // channel — and answering it meant scanning the channel array and reading
    // hex. That is a fine job for a tab and a bad one for the operator with
    // curl who is, by the time they call this, already confused. So the
    // endpoint says it.
    //
    // VIEW_CHANNEL rather than "any bit", because VIEW_CHANNEL is the
    // prerequisite for everything in a channel (auth/Permissions.h): a bot
    // holding SEND_MESSAGES and not VIEW_CHANNEL can do nothing with it.
    //
    // OVER THE CHANNELS LISTED, which is the caller's own visible directory
    // and not the server's. For a caller who cannot see every channel this is
    // therefore "nothing I can see it in", not "nothing anywhere" — the same
    // caveat the `channels` array itself carries, and the reason this is named
    // for the list rather than for the bot.
    bool any_listed_channel = false;
    for (const auto& c : channels) {
        if (permission::has(permission::flags_from_hex(c.value("permissions", "0x0")),
                            permission::kViewChannel)) {
            any_listed_channel = true;
            break;
        }
    }

    res.set_content(json{
        {"user_id", user_id},
        // Repeated from the bot list so a tab rendering this page does not have
        // to hold the two responses side by side to grey the controls out.
        {"deactivated", ctx->bot.deactivated_at.has_value()},
        // What it was GIVEN, and separately what that amounts to. The role ids
        // are the editable document; the mask is what the server will actually
        // enforce, ADMINISTRATOR already short-circuited into kAllFlags — so a
        // tab can render "this bot is an administrator" without knowing which
        // role did it.
        {"role_ids", std::move(role_ids)},
        {"server_permissions", permission::flags_to_hex(perms.compute(user_id, kServerScope))},
        // True when the bot holds VIEW_CHANNEL in at least one of the channels
        // below. False is the state this whole change exists to make legible:
        // a bot that has been minted and never granted anything.
        {"can_view_any_listed_channel", any_listed_channel},
        {"channels", std::move(channels)},
    }.dump(), "application/json");
}

} // namespace bsfchat
