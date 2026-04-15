#pragma once

#include <bsfchat/MatrixTypes.h>
#include <string>

namespace bsfchat {

class PowerLevelChecker {
public:
    explicit PowerLevelChecker(const PowerLevelsContent& levels);

    int getUserPowerLevel(const std::string& user_id) const;
    bool canSendEvent(const std::string& user_id, const std::string& event_type, bool is_state = false) const;
    bool canKick(const std::string& user_id) const;
    bool canBan(const std::string& user_id) const;
    bool canInvite(const std::string& user_id) const;
    bool canRedact(const std::string& user_id) const;

private:
    PowerLevelsContent levels_;
};

} // namespace bsfchat
