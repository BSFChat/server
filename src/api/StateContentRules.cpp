#include "api/StateContentRules.h"

#include "api/PermissionInput.h"

#include <bsfchat/Constants.h>

#include <algorithm>
#include <cctype>
#include <initializer_list>

namespace bsfchat {

using json = nlohmann::json;

namespace {

using Error = std::optional<std::string>;

// A field that may be absent but, when present, must satisfy `ok`.
template <typename Pred>
Error optional_field(const json& c, const char* key, Pred ok, const char* what) {
    const auto it = c.find(key);
    if (it == c.end() || ok(*it)) return std::nullopt;
    return std::string(key) + " must be " + what;
}

// A field that must be present and satisfy `ok`.
template <typename Pred>
Error required_field(const json& c, const char* key, Pred ok, const char* what) {
    if (!c.contains(key)) return std::string("Missing ") + key;
    return optional_field(c, key, ok, what);
}

bool is_string(const json& v) { return v.is_string(); }
bool is_bool(const json& v) { return v.is_boolean(); }
bool is_int(const json& v) { return v.is_number_integer(); }
bool is_object(const json& v) { return v.is_object(); }
bool is_string_array(const json& v) {
    return v.is_array() &&
           std::all_of(v.begin(), v.end(), [](const json& e) { return e.is_string(); });
}
bool is_int_map(const json& v) {
    if (!v.is_object()) return false;
    for (const auto& [_, e] : v.items()) {
        if (!e.is_number_integer()) return false;
    }
    return true;
}

Error one_of(const json& c, const char* key, std::initializer_list<std::string_view> allowed) {
    if (!c.contains(key)) return std::string("Missing ") + key;
    const auto& v = c[key];
    if (v.is_string()) {
        const auto& s = v.get_ref<const std::string&>();
        for (auto a : allowed) {
            if (s == a) return std::nullopt;
        }
    }
    std::string msg = std::string(key) + " must be one of";
    bool first = true;
    for (auto a : allowed) {
        msg += first ? " " : ", ";
        msg += a;
        first = false;
    }
    return msg;
}

template <typename... Checks>
Error first_error(Checks&&... checks) {
    Error out;
    ((out ? void() : void(out = checks)), ...);
    return out;
}

bool is_blank(const std::string& s) {
    return std::all_of(s.begin(), s.end(),
                       [](unsigned char ch) { return std::isspace(ch) != 0; });
}

} // namespace

bool is_known_room_type(std::string_view type) {
    return type == room_type::kText || type == room_type::kVoice ||
           type == room_type::kCategory;
}

std::optional<std::string> state_content_error(std::string_view type, const json& c) {
    if (!c.is_object()) return std::string("State content must be a JSON object");

    if (type == event_type::kRoomName) {
        if (auto e = required_field(c, "name", is_string, "a string")) return e;
        // A channel is listed by its name; a blank one is an unlabelled row
        // nobody can pick out (audit 3, server nits).
        if (is_blank(c["name"].get_ref<const std::string&>())) {
            return std::string("name cannot be empty");
        }
        return std::nullopt;
    }
    if (type == event_type::kRoomTopic) {
        return optional_field(c, "topic", is_string, "a string");
    }
    if (type == event_type::kRoomAvatar) {
        return first_error(optional_field(c, "url", is_string, "a string"),
                           optional_field(c, "info", is_object, "an object"));
    }
    if (type == event_type::kRoomJoinRules) {
        // The two the server acts on, plus the spec's others so a Matrix
        // client's write is not refused for naming a rule this server treats
        // as "not public".
        return one_of(c, "join_rule",
                      {"public", "invite", "knock", "private", "restricted",
                       "knock_restricted"});
    }
    if (type == event_type::kRoomCanonicalAlias) {
        return first_error(optional_field(c, "alias", is_string, "a string"),
                           optional_field(c, "alt_aliases", is_string_array,
                                          "an array of strings"));
    }
    if (type == event_type::kRoomHistoryVisibility) {
        return one_of(c, "history_visibility",
                      {"invited", "joined", "shared", "world_readable"});
    }
    if (type == event_type::kRoomPowerLevels) {
        for (const char* key : {"users_default", "events_default", "state_default", "ban",
                                "kick", "invite", "redact"}) {
            if (auto e = optional_field(c, key, is_int, "an integer")) return e;
        }
        return first_error(
            optional_field(c, "users", is_int_map, "an object of integers"),
            optional_field(c, "events", is_int_map, "an object of integers"),
            optional_field(c, "notifications", is_int_map, "an object of integers"));
    }
    if (type == event_type::kRoomPinnedEvents) {
        return required_field(c, "pinned", is_string_array, "an array of event ids");
    }
    if (type == event_type::kRoomVoice) {
        // max_participants: 0 = the server default, -1 = explicitly unlimited
        // (docs/voice.md), N = N.
        return first_error(
            optional_field(c, "enabled", is_bool, "a boolean"),
            optional_field(
                c, "max_participants",
                [](const json& v) {
                    return v.is_number_integer() && v.get<std::int64_t>() >= -1 &&
                           v.get<std::int64_t>() <= limits::kMaxVoiceParticipants;
                },
                "an integer from -1 (unlimited) to 10000"));
    }
    if (type == event_type::kRoomCategory) {
        return first_error(optional_field(c, "parent_id", is_string, "a string"),
                           optional_field(c, "order", is_int, "an integer"));
    }
    if (type == event_type::kRoomType) {
        return one_of(c, "type", {room_type::kText, room_type::kVoice, room_type::kCategory});
    }
    if (type == event_type::kChannelSettings) {
        return optional_field(
            c, "slowmode_seconds",
            [](const json& v) { return v.is_number_integer() && v.get<std::int64_t>() >= 0; },
            "a non-negative integer");
    }
    if (type == event_type::kChannelPermissions) {
        return permission_input::channel_override_error(c);
    }
    if (type == event_type::kServerRoles) {
        return permission_input::role_document_error(c);
    }
    if (type == event_type::kMemberRoles) {
        return required_field(c, "role_ids", is_string_array, "an array of role ids");
    }
    if (type == event_type::kServerInfo) {
        return first_error(optional_field(c, "name", is_string, "a string"),
                           optional_field(c, "avatar", is_string, "a string"));
    }
    if (type == event_type::kServerScreenShare) {
        for (const char* key : {"max_quality", "max_fps", "max_width", "max_jpeg_quality",
                                "max_bitrate_kbps"}) {
            if (auto e = optional_field(c, key, is_int, "an integer")) return e;
        }
        return optional_field(c, "allow_lossless", is_bool, "a boolean");
    }
    if (type == event_type::kRoomMember) {
        // Profile fields are filled in server-side and never read from here.
        return first_error(required_field(c, "membership", is_string, "a string"),
                           optional_field(c, "reason", is_string, "a string"));
    }
    return std::nullopt;
}

} // namespace bsfchat
