#include "auth/MediaAccess.h"

#include "auth/Permissions.h"
#include "core/Config.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Permissions.h>

namespace bsfchat {

MediaAccess::MediaAccess(SqliteStore& store, const Config& config)
    : store_(store), config_(config) {}

PermissionsEngine& MediaAccess::engine() {
    // One engine for the lifetime of this object, created on first use.
    //
    // Lazy because the common answer never needs it: rule 1 (the uploader) and
    // an object with no references at all both return before any permission is
    // evaluated, and constructing an engine costs a server_state read and a
    // parse of the whole role document.
    //
    // Shared because vet() asks this question once per media URI in an event,
    // and `content` is attacker-supplied up to send_limits.max_event_bytes —
    // which is several hundred `mxc://` strings if somebody wants it to be. A
    // fresh engine per URI would turn one PUT /send into that many role-document
    // reads under the store's global mutex, which is an amplification primitive
    // any member could drive. PermissionsEngine memoises the role document and
    // keys its per-member cache on the user id, so sharing it across URIs — and
    // even across principals — is safe; that is the same reason the mention path
    // reuses the engine it already has.
    if (!perms_) perms_ = std::make_unique<PermissionsEngine>(store_, config_);
    return *perms_;
}

bool MediaAccess::may_read(const std::string& user_id, const std::string& media_id,
                           const SqliteStore::MediaMeta& meta) {
    // 1. The uploader. They supplied the bytes, and this is also what keeps a
    //    freshly uploaded object fetchable in the window between POST /upload
    //    and the PUT /send that attaches it to a room.
    if (meta.uploader == user_id) return true;

    // The whole URI, not the bare id — see SqliteStore::get_media_rooms().
    const std::string mxc_uri = "mxc://" + config_.server_name + "/" + media_id;

    // 2. VIEW_CHANNEL in any room where a surviving event names this object.
    //    One object can legitimately be in several rooms (a forward, a repost),
    //    and access to any one of those rooms is access to the bytes, because
    //    that room's timeline already shows them.
    auto rooms = store_.get_media_rooms(mxc_uri);
    if (!rooms.empty()) {
        PermissionsEngine& perms = engine();
        for (const auto& room_id : rooms) {
            // Membership AND VIEW_CHANNEL, the same pair can_read_room() uses.
            //
            // Neither half is redundant. Everyone is force-joined into every
            // public channel, so membership alone is not authorization — that
            // is the bug can_read_room's own comment describes. And VIEW_CHANNEL
            // alone is not either: a DM has no channel overrides, so @everyone's
            // default VIEW_CHANNEL evaluates true for a user who has never been
            // near it, which would have made every DM attachment on the server
            // world-readable.
            //
            // Deliberately NOT mirroring can_read_room's is_category_room()
            // short-circuit: that exemption is an unbounded VIEW_CHANNEL bypass
            // (audit A3/B2, work package P2) and reproducing it here would carry
            // it into the media path too.
            if (store_.is_room_member(room_id, user_id) &&
                perms.can(user_id, room_id, permission::kViewChannel)) {
                return true;
            }
        }
        return false;
    }

    // 3. Room-less media. This is the case the fix turns on: "no room recorded"
    //    must mean "nobody", not "everybody", or the backfill gap and every
    //    future ingestion path become the bypass.
    //
    //    The one legitimate room-less class is a profile avatar, which is shown
    //    next to its owner's name everywhere and is already disclosed by
    //    /profile, so any authenticated caller may have it.
    //
    //    This rule is only sound while an account cannot point `avatar_url` at
    //    an object that is not its own — otherwise it is a laundry: redaction
    //    empties media_refs, which is exactly what makes this rule reachable,
    //    and an unvalidated avatar write would then make the redacted object
    //    server-public (audit F5, the worst of its variants). The write side of
    //    that is ProfileHandler::handle_put_avatar_url, which now refuses an
    //    avatar the caller did not upload; the comment there is the other half
    //    of this one.
    //    Its UPLOADER's avatar, not anybody's: see is_avatar_of(). Two gates,
    //    because either alone is a single point of failure — the write check
    //    stops a laundered avatar being set, and this one stops any that were
    //    already set from granting, which is the half a deployment that has
    //    been running needs.
    return store_.is_avatar_of(mxc_uri, meta.uploader);
}

bool MediaAccess::may_read_uri(const std::string& user_id, const std::string& mxc_uri) {
    // Built, not parsed: comparing against the URI this server would itself
    // produce is what makes "same id, different host" a non-match rather than
    // something a splitter has to get right. media_uris_in_content() has
    // already guaranteed the id is hex, so nothing here can escape the prefix.
    const std::string prefix = "mxc://" + config_.server_name + "/";
    if (mxc_uri.rfind(prefix, 0) != 0) return false;
    const std::string media_id = mxc_uri.substr(prefix.size());
    if (media_id.empty()) return false;

    auto meta = store_.get_media(media_id);
    if (!meta) return false;
    return may_read(user_id, media_id, *meta);
}

MediaReferences MediaAccess::vet(const std::string& sender, const std::string& event_type,
                                 const std::optional<std::string>& state_key,
                                 const std::string& content_json) {
    auto uris = media_uris_in_content(content_json);
    // The overwhelmingly common case — a message with no media in it at all —
    // costs one JSON walk and no permission evaluation, which is what it cost
    // before this check existed.
    if (uris.empty()) return MediaReferences::none();

    // See the header for why a member event is vouched for by its subject.
    const std::string& principal =
        (event_type == std::string(bsfchat::event_type::kRoomMember) && state_key && !state_key->empty())
            ? *state_key
            : sender;

    std::vector<std::string> permitted;
    permitted.reserve(uris.size());
    for (auto& uri : uris) {
        if (may_read_uri(principal, uri)) permitted.push_back(std::move(uri));
    }
    // Silently dropped, not refused. Refusing the send would turn "your message
    // happens to contain a string that looks like a media URI" into a 403 — and
    // worse, into an oracle, because the difference between accepted and
    // refused would tell the sender whether that id is real and readable. The
    // event is stored exactly as sent; it simply grants nothing, which is the
    // same state an object has between upload and its first send.
    return MediaReferences(std::move(permitted));
}

int64_t insert_event_vetted(SqliteStore& store, const Config& config,
                            const std::string& event_id, const std::string& room_id,
                            const std::string& sender, const std::string& event_type,
                            const std::optional<std::string>& state_key,
                            const std::string& content_json, int64_t origin_server_ts) {
    MediaAccess media(store, config);
    return store.insert_event(event_id, room_id, sender, event_type, state_key,
                              content_json, origin_server_ts,
                              media.vet(sender, event_type, state_key, content_json));
}

} // namespace bsfchat
