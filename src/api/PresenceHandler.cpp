#include "api/PresenceHandler.h"

#include "core/Config.h"
#include "core/Utf8.h"
#include "http/Middleware.h"
#include "http/JsonIo.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/ErrorCodes.h>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace bsfchat {

using json = nlohmann::json;

PresenceHandler::PresenceHandler(SqliteStore& store,
                                  SyncEngine& sync_engine,
                                  const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void PresenceHandler::handle_put_presence(const httplib::Request& req,
                                           httplib::Response& res) {
    auto user_id = authenticate(store_,
        req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }

    // /presence/{userId}/status — the userId in the URL must match
    // the authenticated user. Setting another user's presence is
    // forbidden (matches Matrix spec §10.5).
    auto target_user_id = req.matches[1].str();
    if (*user_id != target_user_id) {
        res.status = 403;
        res.set_content(MatrixError::forbidden(
            "Cannot set presence for another user").to_json().dump(),
            "application/json");
        return;
    }

    json body;
    try {
        body = parse_request_json(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(),
                        "application/json");
        return;
    }

    // value() below throws type_error on a non-object body or a non-string
    // field, which escaped as a bare 500. A malformed body is a 400.
    if (!body.is_object() ||
        (body.contains("presence") && !body["presence"].is_string()) ||
        (body.contains("status_msg") && !body["status_msg"].is_null() &&
         !body["status_msg"].is_string())) {
        res.status = 400;
        res.set_content(MatrixError::bad_json(
            "presence and status_msg must be strings").to_json().dump(),
            "application/json");
        return;
    }

    // Whitelist the presence values — accept Matrix's three
    // canonical states and reject anything else so a malicious
    // client can't sneak markup or arbitrary tokens in.
    std::string presence = body.value("presence", "");
    if (presence != "online" && presence != "unavailable"
        && presence != "offline") {
        res.status = 400;
        res.set_content(MatrixError::bad_json(
            "presence must be online|unavailable|offline").to_json().dump(),
            "application/json");
        return;
    }
    std::string status_msg;
    if (body.contains("status_msg") && body["status_msg"].is_string()) {
        status_msg = body["status_msg"].get<std::string>();
    }

    // Cap status length to keep clients honest. 80 chars matches Discord's
    // status field (and the client's StatusPicker maximumLength).
    //
    // CHARACTERS, on a code-point boundary. This used to be
    // `status_msg.resize(80)` — a byte count — and that was security-audit
    // 2026-09 finding S1, the one rated High: 79 ASCII bytes and a two-byte
    // character put the cut between the character's two bytes, the stored
    // string ended in a lone UTF-8 lead byte, and SyncHandler's strict dump()
    // threw on it while serialising the presence of EVERY co-member. One
    // unprivileged PUT made /sync answer 500 to everyone sharing a room with
    // the sender, for as long as the entry lived, renewable by re-PUTting.
    // See core/Utf8.h; SyncHandler now also serialises leniently, so a bad
    // string from anywhere else cannot do this again either.
    status_msg = truncate_utf8(status_msg, kMaxStatusMsgCodepoints);

    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard lock(mutex_);
        auto& e = entries_[*user_id];
        e.presence = std::move(presence);
        e.status_msg = std::move(status_msg);
        e.updated_at = now;
        e.last_active_at = now;
        // Stamped unconditionally (a PUT is rare and user-initiated), and
        // under mutex_ with the change: see live_for_sync() for why the stamp
        // and the change must be one step.
        e.changed_at_pos = store_.get_current_stream_position();
    }

    // Wake any longpolling /sync waiters so other clients see
    // the new presence quickly. Ephemeral notifier — no event row is
    // written, so the stream position the normal notifier publishes is
    // unchanged and nothing would actually wake.
    //
    // Scoped (audit R-2) to the accounts SyncHandler's presence pass could
    // show this to: everyone sharing a joined room with the subject — a
    // superset of the visible-room co-members it actually uses — plus the
    // subject's own other devices. On a deployment where everyone is
    // force-joined everywhere this is still nearly everyone; presence PUTs
    // are user-initiated status changes, so that is a rare broadcast, not a
    // hot one.
    auto audience = store_.get_co_members(*user_id);
    audience.push_back(*user_id);
    sync_engine_.notify_ephemeral_for(audience);

    res.status = 200;
    res.set_content("{}", "application/json");
}

bool PresenceHandler::is_expired_locked(
    const Entry& e, std::chrono::steady_clock::time_point now) const {
    return now - e.last_active_at > kExpiry;
}

std::optional<PresenceHandler::Entry>
PresenceHandler::get_for(const std::string& user_id) const {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(user_id);
    if (it == entries_.end()) return std::nullopt;
    // Don't report a stale entry as live even if the sweep hasn't run yet.
    if (is_expired_locked(it->second, std::chrono::steady_clock::now())) {
        return std::nullopt;
    }
    return it->second;
}

void PresenceHandler::sweep_expired() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(mutex_);
    // At most once a second. Every /sync calls this, and walking every entry
    // once per woken poll was O(N) per poll, O(N²) per message, for hygiene
    // only: readers already treat an expired entry as absent.
    if (now - last_sweep_ < std::chrono::seconds(1)) return;
    last_sweep_ = now;
    for (auto it = entries_.begin(); it != entries_.end(); ) {
        if (is_expired_locked(it->second, now)) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void PresenceHandler::touch(const std::string& user_id) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(mutex_);
    auto& e = entries_[user_id];
    // Coming online — never seen, or back after expiring but before the sweep
    // erased the entry — is a change every peer's client should hear about;
    // refreshing a live entry is not.
    const bool appears = e.presence.empty() || is_expired_locked(e, now);
    if (e.presence.empty()) e.presence = "online"; // never seen
    e.last_active_at = now;
    if (appears) e.changed_at_pos = store_.get_current_stream_position();
}

std::vector<std::pair<std::string, PresenceHandler::Entry>> PresenceHandler::live_for_sync(
    const std::vector<std::string>& peers, const std::string& self, int64_t since_pos) const {
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::pair<std::string, Entry>> out;
    std::lock_guard lock(mutex_);
    auto live = [&](const Entry& e) { return !e.presence.empty() && !is_expired_locked(e, now); };
    if (since_pos < 0) {
        for (const auto& uid : peers) {
            if (uid == self) continue;
            auto it = entries_.find(uid);
            if (it != entries_.end() && live(it->second)) out.emplace_back(uid, it->second);
        }
    } else {
        // Walk the entries, not the peers: only entries stamped at or after
        // the token qualify, and the peer test is a binary search.
        for (const auto& [uid, e] : entries_) {
            if (uid == self || e.changed_at_pos < since_pos || !live(e)) continue;
            if (std::binary_search(peers.begin(), peers.end(), uid)) out.emplace_back(uid, e);
        }
    }
    auto it = entries_.find(self);
    if (it != entries_.end() && live(it->second)) out.emplace_back(self, it->second);
    return out;
}

} // namespace bsfchat
