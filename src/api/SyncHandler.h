#pragma once

#include "sync/ParkedSyncGate.h"

#include <httplib.h>

#include <cstddef>

namespace bsfchat {

class SqliteStore;
struct Config;
class SyncEngine;
class TypingHandler;
class PresenceHandler;

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
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    const Config& config_;
    TypingHandler* typing_handler_ = nullptr;
    PresenceHandler* presence_handler_ = nullptr;
    ParkedSyncGate parked_{kMaxParkedSyncsPerAccount};
};

} // namespace bsfchat
