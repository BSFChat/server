#pragma once

#include "sync/ParkedSyncGate.h"

#include <httplib.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace bsfchat {

class SqliteStore;
struct Config;
class SyncEngine;
class TypingHandler;
class PresenceHandler;
class PermissionsEngine;

class SyncHandler {
public:
    // `config` is here for the permission engine the typing and presence
    // passes need: both derive from the caller's joined rooms, and membership
    // on this server does not imply visibility (auth/RoomVisibility.h).
    SyncHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config);

    void set_typing_handler(TypingHandler* handler) { typing_handler_ = handler; }
    void set_presence_handler(PresenceHandler* handler) { presence_handler_ = handler; }

    void handle_sync(const httplib::Request& req, httplib::Response& res);

    // Concurrent parked long polls allowed per account; see
    // sync/ParkedSyncGate.h (audit S7). One per signed-in device with room to
    // spare for reconnect overlap.
    static constexpr std::size_t kMaxParkedSyncsPerAccount = 8;

    // Tests only: the gate is otherwise fixed at kMaxParkedSyncsPerAccount.
    ParkedSyncGate& parked_sync_gate_for_test() { return parked_; }

private:
    using RoomList = std::shared_ptr<const std::vector<std::string>>;

    // The caller's visible joined rooms, and everyone joined to any of them,
    // for the typing and presence restatement every delivered poll makes.
    //
    // Computing them was a VIEW_CHANNEL evaluation per joined room plus
    // get_room_members() per visible room — rooms x members rows — on EVERY
    // delivered response, idle or not (audit 2026-11-15, R-2). Both are now
    // cached against SqliteStore::visibility_generation(), which every write
    // that could change either answer bumps; a stale generation drops the
    // whole cache. Peers are keyed by the visible-room SET, not by user, since
    // on a real server most accounts see the same rooms and would otherwise
    // each hold a copy of the member list.
    RoomList visible_rooms_for(const std::string& user_id, PermissionsEngine& perms);
    RoomList peers_of(const RoomList& rooms);

    std::mutex restate_mutex_;
    uint64_t restate_generation_ = UINT64_MAX;
    std::unordered_map<std::string, RoomList> visible_rooms_cache_;
    std::map<std::vector<std::string>, RoomList> peers_cache_;

    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    TypingHandler* typing_handler_ = nullptr;
    PresenceHandler* presence_handler_ = nullptr;
    ParkedSyncGate parked_{kMaxParkedSyncsPerAccount};
};

} // namespace bsfchat
