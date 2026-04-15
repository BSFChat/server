#pragma once

#include <httplib.h>

namespace bsfchat {

class SqliteStore;
class SyncEngine;
class TypingHandler;

class SyncHandler {
public:
    SyncHandler(SqliteStore& store, SyncEngine& sync_engine);

    void set_typing_handler(TypingHandler* handler) { typing_handler_ = handler; }

    void handle_sync(const httplib::Request& req, httplib::Response& res);

private:
    SqliteStore& store_;
    SyncEngine& sync_engine_;
    TypingHandler* typing_handler_ = nullptr;
};

} // namespace bsfchat
