#pragma once

#include "store/MediaReferences.h"
#include "store/SqliteStore.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace bsfchat {

class PermissionsEngine;
struct Config;

// The single authority on "may this account have these bytes", and therefore
// also on "may this account create a reference to them".
//
// Why those are the same question, and why this class exists at all.
//
// Media carries no room of its own — POST /upload has no room in it — so the
// server learns which channel an object belongs to only when an event NAMES
// it. `media_refs` records that binding and `may_read()` reads it back: you
// may have the bytes if you have VIEW_CHANNEL in a room where a surviving
// event names the object.
//
// Until the September 2026 audit (finding F5) the two halves lived apart. The
// READ was checked, carefully, in MediaHandler. The WRITE was not checked at
// all: `insert_event` indexed every `mxc://` string at every depth of every
// event, so anyone who knew a media id could bind it to a channel they could
// see by mentioning it — in a plain `m.text` message, under a key no client
// renders, needing nothing beyond `@everyone`. `ATTACH_FILES` did not stand in
// the way because it keys off `msgtype`, not off the presence of a URI.
//
// That made the ACL self-referential in the attacker's favour: the table the
// read consults was written by whoever wanted the read to succeed. It reversed
// both of the mechanisms that are supposed to take media access away after the
// fact — a channel locked down (audit B3) and, worse, a REDACTION, because
// `redact_event` empties `media_refs` for the event and a later mention refills
// it. The avatar fall-through made the redaction case worse still: rule 3 below
// is reached only when `media_refs` is empty, which redaction is precisely what
// causes, so pointing your own `avatar_url` at a redacted object promoted it
// from channel-scoped to readable by every authenticated account on the server.
//
// The principle this class states, in one sentence: **a reference to a media
// object may only be created by somebody who could already read it.** That
// keeps the invariant `media_uris_in_content()` was always documented against —
// a reader of an event may fetch every id printed in it — true, by making the
// only way to print an id be to have been able to read it first.
//
// What it deliberately does NOT do is make media unreachable from a second
// room. Quoting, replying, forwarding, editing and re-posting all legitimately
// carry a URI the sender did not upload, and every one of them is performed by
// somebody who can see the room the object is already in — so rule 2 answers
// yes and the new reference is created. A forward still works; a forward BY
// SOMEONE WHO CANNOT SEE THE SOURCE does not, which is the whole of the
// change.
//
// Not a second copy of any permission algorithm: rule 2 is
// `is_room_member() && PermissionsEngine::can(VIEW_CHANNEL)`, the same pair
// `can_read_room()` uses, and the vetting path calls this same function rather
// than approximating it.
class MediaAccess {
public:
    MediaAccess(SqliteStore& store, const Config& config);

    // May `user_id` have the bytes of `media_id`?
    //
    // `meta` is the object's row, which every caller has already read (and
    // whose absence is "no such object", answered by the caller so that
    // "missing" and "refused" stay indistinguishable).
    bool may_read(const std::string& user_id, const std::string& media_id,
                  const SqliteStore::MediaMeta& meta);

    // The same question asked about a whole `mxc://host/id`, resolving the row
    // itself. False for a URI on another host and for one naming an object
    // this server does not have: there is nothing here that could vouch for
    // either, and federation would need its own rule rather than this one
    // relaxed.
    bool may_read_uri(const std::string& user_id, const std::string& mxc_uri);

    // The subset of the media URIs in `content_json` that this event may bind
    // to its room — see MediaReferences.
    //
    // The principal whose access is tested is normally the sender. The one
    // exception is `m.room.member`, where it is the SUBJECT (`state_key`):
    // member content is a projection of that account's own profile, including
    // its avatar, and it is written by whoever happens to be performing the
    // membership change — an auto-join, a moderator's kick, the server at
    // bootstrap. Testing it against the sender would make whether a member's
    // avatar stays bound depend on who last touched their membership. This is
    // safe precisely because member content is never taken from a request
    // body: every writer builds it with member_event_content() from the
    // server's own records (RoomHandler's self-membership branch says so in as
    // many words), so naming the subject cannot be turned into a way to borrow
    // their access.
    MediaReferences vet(const std::string& sender, const std::string& event_type,
                        const std::optional<std::string>& state_key,
                        const std::string& content_json);

private:
    // Created on first use and shared by every question this object answers;
    // see the definition for why both halves of that matter.
    PermissionsEngine& engine();

    SqliteStore& store_;
    const Config& config_;
    std::unique_ptr<PermissionsEngine> perms_;
};

// Insert an event, binding only the media its author may legitimately bind.
//
// THIS is the call every path with a principal behind it uses.
// `SqliteStore::insert_event` still owns extraction — it re-derives the URIs
// from the content itself, so nothing here can bind a URI the event does not
// name — and this wrapper supplies the authorisation half. Splitting them that
// way is forced rather than chosen: the vetting needs PermissionsEngine, which
// reads the store, and `insert_event` runs under the store's own mutex inside
// BEGIN IMMEDIATE. A predicate evaluated in there would deadlock, and the
// transaction comment's promise that nothing between BEGIN and COMMIT calls
// back into a handler would stop being true.
//
// Calling `store.insert_event()` directly is still legal and binds NOTHING.
// That is the right default for the handful of server-composed events that
// name no media, and it is fail-closed for anything else.
int64_t insert_event_vetted(SqliteStore& store, const Config& config,
                            const std::string& event_id, const std::string& room_id,
                            const std::string& sender, const std::string& event_type,
                            const std::optional<std::string>& state_key,
                            const std::string& content_json, int64_t origin_server_ts);

} // namespace bsfchat
