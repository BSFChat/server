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
    /// NOTE: this materialises the entire object. handle_download deliberately
    /// does NOT use it — see stat() + download_range() below. Prefer those for
    /// anything that might be large.
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
