#include "core/SendLimiter.h"

#include "core/Config.h"

namespace bsfchat {

SendLimiter::SendLimiter(const SendLimitsConfig& config, LimiterClock clock)
    : enabled_(config.enabled)
    , send_(config.send_limit, std::chrono::seconds(config.window_seconds), clock)
    , redact_(config.redact_limit, std::chrono::seconds(config.window_seconds), clock)
    , media_upload_(config.media_upload_limit, std::chrono::seconds(config.window_seconds),
                    clock)
    , profile_(config.profile_limit, std::chrono::seconds(config.window_seconds), clock)
    , room_create_(config.room_create_limit, std::chrono::seconds(config.window_seconds),
                   clock)
    , report_(config.report_limit, std::chrono::seconds(config.window_seconds), clock)
    , account_data_(config.account_data_limit, std::chrono::seconds(config.window_seconds),
                    clock) {}

int64_t SendLimiter::acquire(Bucket bucket, const std::string& identity) {
    if (!enabled_ || identity.empty()) return 0;
    switch (bucket) {
        case Bucket::kSend:        return send_.acquire(identity);
        case Bucket::kRedact:      return redact_.acquire(identity);
        case Bucket::kMediaUpload: return media_upload_.acquire(identity);
        case Bucket::kProfile:     return profile_.acquire(identity);
        case Bucket::kRoomCreate:  return room_create_.acquire(identity);
        case Bucket::kReport:      return report_.acquire(identity);
        case Bucket::kAccountData: return account_data_.acquire(identity);
    }
    return 0;
}

const char* SendLimiter::message_for(Bucket bucket) {
    switch (bucket) {
        case Bucket::kSend:
            return "You are sending too fast. Slow down and try again shortly.";
        case Bucket::kRedact:
            return "Too many deletions in a row. Try again shortly.";
        case Bucket::kMediaUpload:
            return "Too many uploads in a row. Try again shortly.";
        case Bucket::kProfile:
            return "Too many profile changes in a row. Try again shortly.";
        case Bucket::kRoomCreate:
            // Phrased for both callers this route has — someone opening DMs and
            // someone creating channels — because the handler cannot say which
            // one a 429 belongs to without telling an attacker which of the two
            // budgets they are burning.
            return "Too many rooms created in a row. Try again shortly.";
        case Bucket::kReport:
            return "Too many reports in a row. Try again shortly.";
        case Bucket::kAccountData:
            return "Too many settings changes in a row. Try again shortly.";
    }
    return "Too many requests. Try again later.";
}

} // namespace bsfchat
