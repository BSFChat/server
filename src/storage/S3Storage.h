#pragma once

#include "storage/MediaStorage.h"
#include "storage/S3Client.h"

#include <memory>

namespace bsfchat {

class S3Storage : public MediaStorage {
public:
    explicit S3Storage(S3Config config);

    std::string upload(const std::string& media_id, const std::string& data,
                       const std::string& content_type, const std::string& filename) override;

    std::optional<std::tuple<std::string, std::string>> download(const std::string& media_id) override;

    bool remove(const std::string& media_id) override;

private:
    std::unique_ptr<S3Client> client_;
    std::string bucket_;
};

} // namespace bsfchat
