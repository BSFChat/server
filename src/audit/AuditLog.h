#pragma once

#include <optional>
#include <string>

namespace bsfchat {

class SqliteStore;

// Moderation audit log: what gets recorded, and how a "before" is turned into a
// before/after pair.
//
// Every function here is called AT THE ACTION SITE — the handler that performs
// the kick, writes the role, deletes the channel — and never from a later pass
// over the timeline. That is not a stylistic preference: delete_room hard-deletes
// a room's events, so anything derived from the timeline is destroyed by the next
// channel deletion, and channel deletion is itself one of the audited actions.
//
// Storage lives outside room events for the same reason server-wide roles do
// (SqliteStore::set_server_state): a record has to survive the deletion of the
// room, category and account it describes.
namespace audit_action {

// Action names are a stable part of the read API — an operator greps these, and a
// client may group by them. Treat them as append-only: renaming one silently
// rewrites the meaning of records already on disk.
constexpr const char* kMemberKick = "member.kick";
constexpr const char* kMemberBan = "member.ban";
constexpr const char* kMemberUnban = "member.unban";
// A membership transition driven by a moderator through
// PUT /rooms/{id}/state/m.room.member/{user} that is not a kick, ban or unban.
constexpr const char* kMemberMembershipSet = "member.membership_set";
// A moderator setting or clearing SOMEBODY ELSE'S per-server nickname
// (MANAGE_NICKNAMES). A user renaming themselves is not recorded — that is
// self-service, like changing an avatar, not an act of authority over anyone.
constexpr const char* kMemberNicknameSet = "member.nickname_set";

constexpr const char* kRoleCreate = "role.create";
constexpr const char* kRoleUpdate = "role.update";
constexpr const char* kRoleDelete = "role.delete";
// A change to which roles a user holds (bsfchat.member.roles).
constexpr const char* kRoleAssign = "role.assign";

// The bot lifecycle. All three are acts of authority over the server, performed
// by a human holding MANAGE_BOTS, and all three create or destroy the ability of
// a non-human account to act — which makes them exactly the sort of thing
// somebody asks "who did that, and when" about six months later.
//
// bot.create is recorded even though a bot's own later actions are attributed to
// the bot: without it, an audit log shows an account that has always existed and
// says nothing about who brought it into being. bot.token.rotate matters because
// a rotation is how a bot's credential changes hands, which is either an
// operator responding to a leak or the leak itself.
constexpr const char* kBotCreate = "bot.create";
constexpr const char* kBotTokenRotate = "bot.token.rotate";
constexpr const char* kBotDeactivate = "bot.deactivate";

constexpr const char* kChannelDelete = "channel.delete";
constexpr const char* kCategoryDelete = "category.delete";
// A change to what KIND of room this is (bsfchat.room.type): text, voice or
// category. Recorded because converting a channel into a category changes who
// may see it — the sidebar exemption in SyncEngine applies to categories — so
// without a record it is a visibility change disguised as a tidy-up, and the
// only symptom is an icon changing in the sidebar.
constexpr const char* kRoomTypeSet = "room.type.set";
// A per-channel allow/deny override for a role or user
// (bsfchat.channel.permissions).
constexpr const char* kChannelPermissionsSet = "channel.permissions.set";

} // namespace audit_action

// The action name for a membership transition, so the same ban is recorded under
// the same name whether it arrived at POST /rooms/{id}/ban or at the generic
// state endpoint. Without this the two routes would produce two different
// vocabularies and "show me every ban" would silently miss half of them.
std::string membership_audit_action(const std::string& before_membership,
                                   const std::string& after_membership);

// Records one membership transition performed BY a moderator ON another user.
// Never called for a user changing their own membership — leaving a channel is
// not a moderation action.
void audit_membership_change(SqliteStore& store, const std::string& actor,
                            const std::string& room_id, const std::string& target_user,
                            const std::string& before_membership,
                            const std::string& after_membership,
                            const std::string& reason);

// Records one moderator-driven nickname change. `before`/`after` are nullopt when
// there was / is no nickname, so a record distinguishes set, changed and cleared.
// Writes nothing when the value is unchanged, matching the other audit writers.
// Not called when actor == target.
void audit_nickname_change(SqliteStore& store, const std::string& actor,
                          const std::string& target_user,
                          const std::optional<std::string>& before,
                          const std::optional<std::string>& after);

// Records a channel or category deletion. MUST be called BEFORE
// SqliteStore::delete_room: it reads the room's name, type, parent category and
// member count to build the "before" payload, and all of that is gone afterwards.
// Getting the order wrong is the difference between a useful record and one that
// only names a room id nothing else in the database still mentions.
void audit_room_deletion(SqliteStore& store, const std::string& actor,
                         const std::string& room_id);

// Records a change to a room's kind (bsfchat.room.type). `before` is the type
// this write supersedes, or empty for a room that carried no type event.
// Writes nothing when the type is unchanged, matching the other audit writers.
void audit_room_type_change(SqliteStore& store, const std::string& actor,
                            const std::string& room_id, const std::string& before,
                            const std::string& after);

// Records a per-channel permission override change. `before_json` is the content
// of the override event this write supersedes (nullopt when the target had none).
// Writes nothing when the allow/deny pair is unchanged.
void audit_channel_override_change(SqliteStore& store, const std::string& actor,
                                   const std::string& room_id, const std::string& state_key,
                                   const std::optional<std::string>& before_json,
                                   const std::string& after_json);

// Records one bot lifecycle action: creation, token rotation, or deactivation.
//
// `after_json` describes the bot AFTER the action and is the only payload —
// there is no "before", because none of the three is an edit of a previous
// value: a bot is created, its credential is replaced wholesale, or it is turned
// off. A before/after pair would be two views of the same row with nothing
// between them.
//
// TOKEN MATERIAL NEVER REACHES THIS FUNCTION, and callers must not put it in
// `after_json`. A bot token is shown exactly once, to the operator who caused it
// to be minted; writing it into an append-only table that a second permission
// (MANAGE_SERVER, to read the audit log) can read would turn "shown once" into
// "stored forever, readable by a different set of people, and impossible to
// redact" — the audit log has no delete path, deliberately. What is recorded is
// that a rotation happened, by whom, and to which bot.
void audit_bot_lifecycle(SqliteStore& store, const std::string& actor,
                         const std::string& action, const std::string& bot_user_id,
                         const std::string& after_json);

// Records a change to server-scoped state (bsfchat.server.roles /
// bsfchat.member.roles). Called from write_server_scoped_state, which is the one
// choke point every role definition and role assignment write passes through, so
// no future call site can add an unaudited role write by accident.
//
// A roles write carries the WHOLE role list, so this diffs it: one record per
// role actually created, deleted or modified, with the permission bitfields on
// both sides. A write that changes nothing (the idempotent bootstrap re-seed, a
// client resubmitting an unchanged list) records nothing. Any other event type is
// ignored.
void audit_server_scoped_change(SqliteStore& store, const std::string& actor,
                                const std::string& evt_type, const std::string& state_key,
                                const std::optional<std::string>& before_json,
                                const std::string& after_json);

} // namespace bsfchat
