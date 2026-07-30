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

std::string LocalStorage::read_content_type(const std::string& media_id) const {
    std::string content_type = "application/octet-stream";
    auto meta_file = metadata_path(media_id);
    if (std::filesystem::exists(meta_file)) {
        std::ifstream meta(meta_file);
        if (meta) {
            std::string line;
            if (std::getline(meta, line) && !line.empty()) {
                content_type = std::move(line);
            }
        }
    }
    return content_type;
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

    return std::make_tuple(std::move(data), read_content_type(media_id));
}

std::optional<MediaStat> LocalStorage::stat(const std::string& media_id) {
    std::error_code ec;
    auto file_path = data_path(media_id);
    auto status = std::filesystem::status(file_path, ec);
    if (ec || !std::filesystem::is_regular_file(status)) {
        return std::nullopt;
    }

    auto size = std::filesystem::file_size(file_path, ec);
    if (ec) {
        return std::nullopt;
    }

    MediaStat info;
    info.size = static_cast<size_t>(size);
    info.content_type = read_content_type(media_id);
    return info;
}

bool LocalStorage::download_range(const std::string& media_id, size_t offset, size_t length,
                                  std::string& out) {
    out.clear();

    auto file_path = data_path(media_id);
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs) {
        return false;
    }

    if (length == 0) {
        return true;
    }

    // seekg past the end is not an error on its own; the subsequent read
    // simply returns 0 bytes, which we report as a successful empty read.
    ifs.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!ifs) {
        return false;
    }

    // Only the requested window is ever allocated — never the whole file.
    out.resize(length);
    ifs.read(out.data(), static_cast<std::streamsize>(length));
    if (ifs.bad()) {
        out.clear();
        return false;
    }
    out.resize(static_cast<size_t>(ifs.gcount()));
    return true;
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
