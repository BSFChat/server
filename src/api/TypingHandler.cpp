#include "api/TypingHandler.h"

#include <algorithm>

#include "http/Middleware.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"
#include "core/Config.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>

#include <nlohmann/json.hpp>

namespace bsfchat {

using json = nlohmann::json;

static constexpr int kMaxTypingTimeoutMs = 30000;
static constexpr int kDefaultTypingTimeoutMs = 30000;

TypingHandler::TypingHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void TypingHandler::handle_typing(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    // Extract room_id and target user_id from URL path
    // Pattern: /_matrix/client/v3/rooms/{roomId}/typing/{userId}
    auto room_id = req.matches[1].str();
    auto target_user_id = req.matches[2].str();

    // Verify the authenticated user matches the target user
    if (*user_id != target_user_id) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot set typing for another user").to_json().dump(),
                        "application/json");
        return;
    }

    // Verify user is a member of the room
    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(),
                        "application/json");
        return;
    }

    // Parse request body
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    bool typing = body.value("typing", false);

    {
        std::lock_guard lock(mutex_);

        auto& entries = typing_[room_id];

        if (typing) {
            int timeout_ms = body.value("timeout", kDefaultTypingTimeoutMs);
            timeout_ms = std::min(timeout_ms, kMaxTypingTimeoutMs);
            auto expires = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

            // Update existing entry or add new one
            bool found = false;
            for (auto& entry : entries) {
                if (entry.user_id == *user_id) {
                    entry.expires_at = expires;
                    found = true;
                    break;
                }
            }
            if (!found) {
                entries.push_back({*user_id, expires});
            }
        } else {
            // Remove the user from typing
            entries.erase(
                std::remove_if(entries.begin(), entries.end(),
                    [&](const TypingEntry& e) { return e.user_id == *user_id; }),
                entries.end());
        }
    }

    // Wake sync waiters so they pick up the typing change
    sync_engine_.notify_new_event();

    res.status = 200;
    res.set_content("{}", "application/json");
}

std::vector<std::string> TypingHandler::get_typing_users(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    cleanup_expired(room_id);

    std::vector<std::string> result;
    auto it = typing_.find(room_id);
    if (it != typing_.end()) {
        for (const auto& entry : it->second) {
            result.push_back(entry.user_id);
        }
    }
    return result;
}

void TypingHandler::cleanup_expired(const std::string& room_id) {
    auto it = typing_.find(room_id);
    if (it == typing_.end()) return;

    auto now = std::chrono::steady_clock::now();
    auto& entries = it->second;
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
            [&](const TypingEntry& e) { return e.expires_at <= now; }),
        entries.end());

    if (entries.empty()) {
        typing_.erase(it);
    }
}

} // namespace bsfchat
