#pragma once

#include "store/SqliteStore.h"

#include <bsfchat/MatrixTypes.h>

#include <httplib.h>

#include <optional>
#include <string>
#include <vector>

namespace bsfchat {

class SyncEngine;
struct Config;

// Server role administration, and the one thing an ordinary member may do to
// their own roles.
//
// WHY THESE EXIST AT ALL, given that roles are already writable.
//
// A role list has always been ONE state event, `bsfchat.server.roles`, written
// wholesale: the caller PUTs the entire document and
// PermissionsEngine::may_edit_role_definitions diffs it against what is stored.
// For an administrator driving a settings dialog that is fine. For a delegated
// MANAGE_ROLES holder — which is what a bot is — it is unusable, for two
// reasons that are not about permissions at all:
//
//   1. To change one role you must resubmit every role, including the ones
//      ranked above you that you are forbidden to modify. You may echo them
//      back unchanged, but you must reproduce them exactly or the rank check
//      refuses the whole write. A caller that is not the authority on a
//      document is being asked to be its editor.
//   2. Two callers editing different roles at the same time silently lose one
//      of the two edits, because each read the document, changed its own part,
//      and wrote the whole thing back. A bot reacting to chat and an admin in
//      the settings dialog are exactly that race.
//
// So the endpoints here take a DELTA — create this role, change these fields of
// that role, delete this one — and the SERVER performs the read-modify-write,
// under the store's own lock, against the document as it stands at that moment.
//
// WHAT THEY DELIBERATELY DO NOT DO is introduce a second authority. Each one
// builds the proposed document and hands it to the same
// may_edit_role_definitions the wholesale PUT uses, then writes it through the
// same write_server_scoped_state — which is where the audit records and the
// sync mirror come from, so neither had to be reimplemented and neither can
// drift. The hierarchy rules are unchanged and unweakened; these routes are a
// better way to ask the same question.
//
// Every administration endpoint requires MANAGE_ROLES at SERVER scope. Server
// scope is load-bearing and has been a real hole in this codebase before: with
// a room id, PermissionsEngine::compute applies that channel's overrides, so
// MANAGE_ROLES granted inside one unimportant channel would otherwise unlock
// the server's whole role graph. handle_set_state says the same thing at
// greater length; these routes have no room to be confused about in the first
// place.
class RoleHandler {
public:
    RoleHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

    // GET /_matrix/client/v3/bsfchat/roles -> {roles: [...]}
    //
    // Authentication only, no permission. The role list already reaches every
    // client on the server through the sync mirror of the state event, so
    // gating the read would hide nothing and would break the one client that
    // most needs it: a member rendering a self-assignable role picker holds no
    // role permission by definition.
    void handle_list_roles(const httplib::Request& req, httplib::Response& res);

    // POST /_matrix/client/v3/bsfchat/roles
    // {name, color?, position?, permissions?, hoist?, mentionable?,
    //  self_assignable?} -> 201 {role: {...}}
    //
    // The id is minted by the server. A caller-chosen id would let a caller
    // collide with a role above their rank, or with a well-known id
    // ("everyone", "admin") that other code matches on by string.
    void handle_create_role(const httplib::Request& req, httplib::Response& res);

    // PATCH /_matrix/client/v3/bsfchat/roles/{roleId} -> {role: {...}}
    //
    // Partial: absent keys keep their current value. That is not a convenience,
    // it is what stops a client that predates a field from clearing it — the
    // wholesale PUT has exactly that bug, and it is how `self_assignable` would
    // otherwise be silently reset by the next save from an older settings
    // dialog. Repositioning is this endpoint with `position` set; there is no
    // separate reorder route, because positions here are a sparse ladder
    // (0/10/100 at bootstrap), not array indices that shift.
    void handle_update_role(const httplib::Request& req, httplib::Response& res);

    // DELETE /_matrix/client/v3/bsfchat/roles/{roleId} -> {}
    //
    // Also strips the role from every member who holds it, in the same call.
    // Leaving the ids behind would be tidy-looking and wrong: a stale id makes
    // the next wholesale member.roles PUT for that user fail with "Unknown
    // role", so a deletion would quietly break role editing for whoever held
    // the deleted role.
    void handle_delete_role(const httplib::Request& req, httplib::Response& res);

    // PUT /_matrix/client/v3/bsfchat/self_roles/{roleId} -> {role_ids: [...]}
    // DELETE /_matrix/client/v3/bsfchat/self_roles/{roleId} -> {role_ids: [...]}
    //
    // The member-facing half, and the reason this whole file exists: a boss
    // notification picker. No MANAGE_ROLES, no rank — see
    // PermissionsEngine::may_self_assign_role for what is paid instead, and why
    // removal is gated exactly as tightly as addition.
    //
    // Both are idempotent: taking a role you already hold, or dropping one you
    // do not, is a 200 that writes nothing and audits nothing.
    void handle_add_self_role(const httplib::Request& req, httplib::Response& res);
    void handle_remove_self_role(const httplib::Request& req, httplib::Response& res);

private:
    // Authentication plus MANAGE_ROLES at server scope. Writes the refusal and
    // returns nullopt on failure, so no handler can act without it.
    std::optional<std::string> authorize_role_admin(const httplib::Request& req,
                                                    httplib::Response& res);

    // Runs `proposed` past may_edit_role_definitions and, if it passes, stores
    // it. THE only write path in this file. Returns false having already
    // written the refusal.
    bool commit_roles(const std::string& actor, const std::vector<ServerRole>& proposed,
                      httplib::Response& res);

    // The shared body of the two self-role endpoints.
    void change_self_role(const httplib::Request& req, httplib::Response& res, bool add);

    // Room to mirror server-scoped state into, so clients still learn about the
    // change through /sync. Presentation only — see RoleBootstrap.h.
    std::string mirror_room();

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
};

} // namespace bsfchat
