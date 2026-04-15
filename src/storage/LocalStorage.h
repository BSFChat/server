#pragma once

#include "storage/MediaStorage.h"
#include <string>

namespace bsfchat {

class LocalStorage : public MediaStorage {
public:
    explicit LocalStorage(const std::string& base_path);

    std::string upload(const std::string& media_id, const std::string& data,
                       const std::string& content_type, const std::string& filename) override;

    std::optional<std::tuple<std::string, std::string>> download(const std::string& media_id) override;

    bool remove(const std::string& media_id) override;

private:
    std::string base_path_;
    std::string metadata_path(const std::string& media_id) const;
    std::string data_path(const std::string& media_id) const;
};

} // namespace bsfchat
