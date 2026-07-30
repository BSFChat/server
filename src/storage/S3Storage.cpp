#include "storage/S3Storage.h"
#include "core/Logger.h"

namespace bsfchat {

S3Storage::S3Storage(S3Config config)
    : bucket_(config.bucket)
    , client_(std::make_unique<S3Client>(std::move(config))) {
}

std::string S3Storage::upload(const std::string& media_id, const std::string& data,
                               const std::string& content_type, const std::string& filename) {
    auto log = get_logger();

    if (!client_->put_object(media_id, data, content_type)) {
        throw std::runtime_error("S3 upload failed for media_id: " + media_id);
    }

    log->debug("S3Storage: uploaded {} to bucket {} ({} bytes)", media_id, bucket_, data.size());
    return "s3://" + bucket_ + "/" + media_id;
}

std::optional<std::tuple<std::string, std::string>> S3Storage::download(const std::string& media_id) {
    auto obj = client_->get_object(media_id);
    if (!obj) {
        return std::nullopt;
    }
    return std::make_tuple(std::move(obj->data), std::move(obj->content_type));
}

std::optional<MediaStat> S3Storage::stat(const std::string& media_id) {
    MediaStat info;
    if (!client_->head_object(media_id, &info.content_type, &info.size)) {
        return std::nullopt;
    }
    if (info.content_type.empty()) {
        info.content_type = "application/octet-stream";
    }
    return info;
}

bool S3Storage::download_range(const std::string& media_id, size_t offset, size_t length,
                               std::string& out) {
    out.clear();

    if (length == 0) {
        return true;
    }

    auto obj = client_->get_object_range(media_id, offset, length);
    if (!obj) {
        return false;
    }

    out = std::move(obj->data);
    // Never hand back more than was asked for, even if a non-conforming
    // endpoint over-delivers.
    if (out.size() > length) {
        out.resize(length);
    }
    return true;
}

bool S3Storage::remove(const std::string& media_id) {
    return client_->delete_object(media_id);
}

} // namespace bsfchat
