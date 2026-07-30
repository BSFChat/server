#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <tuple>

namespace bsfchat {

/// Size + content type of a stored object, obtainable without reading the
/// object body. This is what lets a Range request answer "how big is it?"
/// (needed for Content-Range and for satisfiability checks) without pulling
/// the whole file into memory.
struct MediaStat {
    size_t size = 0;
    std::string content_type;
};

class MediaStorage {
public:
    virtual ~MediaStorage() = default;

    /// Upload file data. Returns the storage key/path used.
    virtual std::string upload(const std::string& media_id, const std::string& data,
                               const std::string& content_type, const std::string& filename) = 0;

    /// Download file data. Returns {data, content_type} or nullopt if not found.
    ///
    /// NO PRODUCTION CALLER, DELIBERATELY. Nothing under src/ calls this. It
    /// materialises the ENTIRE object into one std::string, so serving a 50 MB
    /// upload through it costs 50 MB of resident memory per concurrent request —
    /// which is exactly the defect handle_download was rewritten to remove. That
    /// path now uses stat() + download_range() below, and the range tests assert
    /// `whole_object_reads == 0` against a storage double.
    ///
    /// It survives on the interface as a REGRESSION TRIPWIRE rather than as a
    /// facility: CountingStorage (tests/test_media.cpp) overrides it purely to
    /// count, so if handle_download ever reaches for it again the range tests go
    /// red immediately and name the reason. Deleting it would delete that alarm.
    ///
    /// So: a new call site in src/ is a bug, not a shortcut. If you want the whole
    /// object, you want a loop over download_range() with one reused buffer.
    virtual std::optional<std::tuple<std::string, std::string>> download(const std::string& media_id) = 0;

    /// Object metadata without the body. nullopt if the object is not found.
    virtual std::optional<MediaStat> stat(const std::string& media_id) = 0;

    /// Read the window [offset, offset + length) of an object into `out`.
    ///
    /// `out` is overwritten (not appended to) and resized to the number of
    /// bytes actually read, which is short of `length` when the window runs
    /// past the end of the object. Callers are expected to reuse one buffer
    /// across successive calls so a long transfer allocates once, not once per
    /// chunk. Returns false if the object is missing or unreadable; a
    /// zero-byte read past EOF is a success with `out` empty.
    ///
    /// Implementations must not read more than `length` bytes from the
    /// underlying store: the whole point of this method is that a 1-byte range
    /// on a 50 MB object costs 1 byte, not 50 MB.
    virtual bool download_range(const std::string& media_id, size_t offset, size_t length,
                                std::string& out) = 0;

    /// Remove a stored file. Returns true if the file was deleted.
    virtual bool remove(const std::string& media_id) = 0;
};

} // namespace bsfchat
