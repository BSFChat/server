#pragma once

#include <string>
#include <vector>

namespace bsfchat {

class MediaAccess;

// Every media id this event's content names, so the event row and the media
// ACL can never disagree about what the event grants access to.
//
// A full recursive walk for any string beginning with `mxc://`, rather than a
// list of known keys (`$.url`, `$.info.thumbnail_url`, `$.m.new_content.url`,
// …). That is not laziness — it is the exact invariant we want to index:
//
//   a reader of this event can learn every mxc id printed anywhere in it,
//   so a reader of this event may fetch every one of them.
//
// Keyed extraction would under-collect the moment a new message shape puts a
// URI somewhere unanticipated, and an under-collected id is a working image
// that suddenly 404s for everyone but its uploader.
//
// The sentence that used to follow — "over-collecting is impossible by
// construction" — was wrong, and it is finding F5 of the September 2026
// permissions audit. It is true that a string not in the content cannot be
// collected. It is NOT true that a string that IS in the content is already
// visible to whoever can read the event: the sender CHOSE the content, so
// naming an id was itself the act that made it visible. Extraction stayed
// exactly as it is — it is the right rule for "what does this event name" —
// and the missing half, "may this sender name it", now lives in MediaAccess
// and arrives here as a MediaReferences.
//
// Whole `mxc://host/id` URIs are extracted, never the bare id. The host is
// load-bearing: with only the id, posting `mxc://anything/<id-from-a-private-
// channel>` into a channel you control would bind that id to your channel and
// hand you the object. The download path looks up the URI it builds from its
// own configured server name, so a foreign host simply never matches.
std::vector<std::string> media_uris_in_content(const std::string& content_json);

/// The media URIs an event's author may legitimately bind to its room.
///
/// This type exists to make one thing unrepresentable: an event that binds an
/// object its sender could not read. Before F5, `insert_event` indexed every
/// `mxc://` string at every depth of every event with no check of any kind, so
/// the object→room binding — which is what `MediaHandler::may_download` reads
/// to decide who may have the bytes — was a value the caller wrote. Naming a
/// redacted or revoked id in a plain `m.text` message re-attached it.
///
/// The only way to obtain a non-empty instance is to ask MediaAccess, which is
/// why its constructor is private and MediaAccess is its friend. A handler
/// cannot assemble one out of a list it invented, and `insert_event` still
/// runs the content through `media_uris_in_content()` itself and indexes only
/// the intersection — so a caller cannot bind a URI the content does not name
/// either. Extraction stays on the door; authorisation is supplied to it.
class MediaReferences {
public:
    /// Binds nothing.
    ///
    /// This is the default `insert_event` applies when no caller vouched for
    /// anything, and it is deliberately the fail-CLOSED direction: a future
    /// ingestion path that forgets to vet its content produces attachments
    /// that 404 for everyone but their uploader — visible, reported, fixable —
    /// rather than an access-control bypass nobody notices. The pre-F5
    /// behaviour was the other one.
    static MediaReferences none();

    /// May this event bind `mxc_uri` to its room?
    bool permits(const std::string& mxc_uri) const;

    bool empty() const { return uris_.empty(); }
    size_t size() const { return uris_.size(); }

private:
    friend class MediaAccess;
    MediaReferences() = default;
    explicit MediaReferences(std::vector<std::string> uris);

    // Sorted, so `permits()` is a binary search rather than a scan. An event
    // with a hundred thumbnails is not the common case, but the content is
    // attacker-supplied and the quadratic version would be theirs to drive.
    std::vector<std::string> uris_;
};

} // namespace bsfchat
