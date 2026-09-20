#pragma once

#include <cstdint>
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
//
// ── Reading the log deliberately bypasses VIEW_CHANNEL ──────────────────
//
// This is a decided position, recorded here because it is the kind of thing a
// later reader finds and files as a bug. It is not one.
//
// GET /_matrix/client/v3/admin/audit requires kManageServer at SERVER scope,
// and that scope genuinely holds: PermissionsEngine::compute returns the base
// mask before per-channel overrides are consulted, so an ALLOW MANAGE_SERVER
// override on one channel cannot unlock the log. The check is the first thing
// the handler does, ahead of every filter and the pagination cursor, so
// narrowing by actor, target_user, target_room or action cannot reach around
// it. There is no write endpoint, and a room-scoped moderator reads nothing.
//
// What the records then contain is NOT filtered against the reader's
// VIEW_CHANNEL. A record carries target_room, and audit_room_deletion stores
// the deleted channel's name, type, parent_id and member count. A server
// administrator reading the log therefore learns that "#staff-only" existed
// and was deleted, whether or not they could see it while it lived.
//
// That is the point of an audit log. The holder of kManageServer can grant
// themselves VIEW_CHANNEL on any channel on the server in one request, so
// filtering the log against it withholds nothing they cannot trivially take —
// it only makes the record incomplete, and an incomplete record of who deleted
// what is worse than no record, because it reads as authoritative. An admin
// who cannot audit hidden channels cannot audit; the deletion of a private
// channel is precisely the event somebody asks about six months later.
//
// The boundary that IS load-bearing is the one above: server scope, checked
// once, before anything else. Do not add per-record VIEW_CHANNEL filtering.
// (Audit data-path finding 27, September 2026 — examined and declined.)
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

// An identity-provider identity being attached to an account
// (POST /account/link_identity). Recorded because it changes WHO CAN SIGN IN
// as an account — which, for an account holding admin, is the same class of
// event as handing out the admin role, and the same question gets asked about
// it six months later.
//
// THE OIDC SUBJECT IS NOT RECORDED AS A CLAIM OF ITS OWN, and callers must
// not put it in the payload. The audit log is readable by every MANAGE_SERVER
// holder and has no delete path, so a subject written here is a permanent,
// widely-readable identifier for a person at their identity provider — one
// this server has no need to keep. Same reasoning as the bot-token rule below.
//
// The one thing that looks like an exception and is not: `superseded_user_id`
// is a user id of the form `@oidc_<sanitised sub>:server`, from which the
// subject is legible. That is recorded deliberately. It is an account id on
// THIS server — already in every member list and on every message that account
// sent — and saying which account lost its sign-in route is the whole content
// of the record. Omitting it would protect nothing and destroy the entry.
constexpr const char* kAccountLink = "account.link";

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

// A rotation of a voice channel's media key (MANAGE_CHANNELS). Recorded because
// rotation is the server's answer to "stop this departed member decrypting", so
// "was it ever done, and when" has to be answerable afterwards — including by an
// operator deciding whether a database they are about to restore predates one.
constexpr const char* kVoiceRekey = "voice.rekey";

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

// Records one media-key rotation, as the generation before and after. Called
// AFTER the generation is durably bumped, so the log can never claim a rotation
// that did not land.
void audit_voice_rekey(SqliteStore& store, const std::string& actor,
                       const std::string& room_id, uint64_t before, uint64_t after);

// Records one identity link. `actor` is the account that proved control of
// both sides and is also the account the identity now signs in as; `issuer` is
// the verified `iss` claim; `superseded_user_id` is the shadow `oidc_*`
// account this link makes unreachable, or empty when there was none.
//
// Takes the pieces rather than a pre-built JSON blob specifically so no call
// site can pass the subject through by accident. See kAccountLink.
void audit_account_link(SqliteStore& store, const std::string& actor,
                        const std::string& issuer,
                        const std::string& superseded_user_id);

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
