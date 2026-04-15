#pragma once

#include <optional>
#include <string>
#include <tuple>

namespace bsfchat {

class MediaStorage {
public:
    virtual ~MediaStorage() = default;

    /// Upload file data. Returns the storage key/path used.
    virtual std::string upload(const std::string& media_id, const std::string& data,
                               const std::string& content_type, const std::string& filename) = 0;

    /// Download file data. Returns {data, content_type} or nullopt if not found.
    virtual std::optional<std::tuple<std::string, std::string>> download(const std::string& media_id) = 0;

    /// Remove a stored file. Returns true if the file was deleted.
    virtual bool remove(const std::string& media_id) = 0;
};

} // namespace bsfchat
