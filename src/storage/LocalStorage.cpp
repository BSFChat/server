#include "storage/LocalStorage.h"
#include "core/Logger.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace bsfchat {

LocalStorage::LocalStorage(const std::string& base_path)
    : base_path_(base_path) {
    std::filesystem::create_directories(base_path_);
}

std::string LocalStorage::metadata_path(const std::string& media_id) const {
    return base_path_ + "/" + media_id + ".meta";
}

std::string LocalStorage::data_path(const std::string& media_id) const {
    return base_path_ + "/" + media_id;
}

std::string LocalStorage::upload(const std::string& media_id, const std::string& data,
                                  const std::string& content_type, const std::string& filename) {
    auto log = get_logger();

    auto file_path = data_path(media_id);
    {
        std::ofstream ofs(file_path, std::ios::binary);
        if (!ofs) {
            throw std::runtime_error("Failed to open file for writing: " + file_path);
        }
        ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
    }

    // Write metadata (content_type on first line, filename on second)
    {
        std::ofstream meta(metadata_path(media_id));
        if (!meta) {
            throw std::runtime_error("Failed to write metadata for: " + media_id);
        }
        meta << content_type << "\n" << filename << "\n";
    }

    log->debug("LocalStorage: stored {} ({} bytes)", media_id, data.size());
    return file_path;
}

std::optional<std::tuple<std::string, std::string>> LocalStorage::download(const std::string& media_id) {
    auto file_path = data_path(media_id);
    if (!std::filesystem::exists(file_path)) {
        return std::nullopt;
    }

    // Read data
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs) {
        return std::nullopt;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    std::string data = oss.str();

    // Read metadata
    std::string content_type = "application/octet-stream";
    auto meta_file = metadata_path(media_id);
    if (std::filesystem::exists(meta_file)) {
        std::ifstream meta(meta_file);
        if (meta) {
            std::getline(meta, content_type);
        }
    }

    return std::make_tuple(std::move(data), std::move(content_type));
}

bool LocalStorage::remove(const std::string& media_id) {
    bool removed = false;
    auto file_path = data_path(media_id);
    if (std::filesystem::exists(file_path)) {
        std::filesystem::remove(file_path);
        removed = true;
    }
    auto meta = metadata_path(media_id);
    if (std::filesystem::exists(meta)) {
        std::filesystem::remove(meta);
    }
    return removed;
}

} // namespace bsfchat
