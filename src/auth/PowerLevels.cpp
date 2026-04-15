#include "auth/PowerLevels.h"

namespace bsfchat {

PowerLevelChecker::PowerLevelChecker(const PowerLevelsContent& levels)
    : levels_(levels) {}

int PowerLevelChecker::getUserPowerLevel(const std::string& user_id) const {
    auto it = levels_.users.find(user_id);
    if (it != levels_.users.end()) {
        return it->second;
    }
    return levels_.users_default;
}

bool PowerLevelChecker::canSendEvent(const std::string& user_id, const std::string& event_type, bool is_state) const {
    int user_level = getUserPowerLevel(user_id);

    // Check if there's a per-event-type requirement
    auto it = levels_.events.find(event_type);
    if (it != levels_.events.end()) {
        return user_level >= it->second;
    }

    // Use the default for state or non-state events
    if (is_state) {
        return user_level >= levels_.state_default;
    }
    return user_level >= levels_.events_default;
}

bool PowerLevelChecker::canKick(const std::string& user_id) const {
    return getUserPowerLevel(user_id) >= levels_.kick;
}

bool PowerLevelChecker::canBan(const std::string& user_id) const {
    return getUserPowerLevel(user_id) >= levels_.ban;
}

bool PowerLevelChecker::canInvite(const std::string& user_id) const {
    return getUserPowerLevel(user_id) >= levels_.invite;
}

bool PowerLevelChecker::canRedact(const std::string& user_id) const {
    return getUserPowerLevel(user_id) >= levels_.redact;
}

} // namespace bsfchat
