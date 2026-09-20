cmake_minimum_required(VERSION 3.20)

# Version.cmake before project(): project(VERSION ...) needs the strict
# MAJOR.MINOR.PATCH form, and CI passes -DBSFCHAT_SERVER_VERSION on tag
# builds so the number in the image matches the tag that produced it.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Version.cmake)

project(bsfchat-server VERSION ${BSFCHAT_SERVER_VERSION_DOTS} LANGUAGES CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Ccache.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(GAMECHAT_SERVER_BUILD_TESTS "Build server tests" ON)

include(cmake/Dependencies.cmake)

add_executable(bsfchat-server
    src/main.cpp
    src/core/Server.cpp
    src/core/Config.cpp
    src/core/Logger.cpp
    src/core/InstanceSecret.cpp
    src/core/RateLimiter.cpp
    src/core/SendLimiter.cpp
    src/http/HttpServer.cpp
    src/http/ClientAddress.cpp
    src/http/Router.cpp
    src/http/Middleware.cpp
    src/auth/AutoJoin.cpp
    src/auth/LocalAuth.cpp
    src/auth/OidcAuth.cpp
    src/auth/Permissions.cpp
    src/auth/PowerLevels.cpp
    src/auth/RoleBootstrap.cpp
    src/auth/RoomVisibility.cpp
    src/audit/AuditLog.cpp
    src/identity/Localpart.cpp
    src/identity/Nickname.cpp
    src/api/AuditHandler.cpp
    src/api/AuthHandler.cpp
    src/api/BotHandler.cpp
    src/api/RoleHandler.cpp
    src/api/RoomHandler.cpp
    src/api/EventHandler.cpp
    src/api/SyncHandler.cpp
    src/api/TypingHandler.cpp
    src/api/PresenceHandler.cpp
    src/api/MediaHandler.cpp
    src/api/MediaPolicy.cpp
    src/api/MediaTicket.cpp
    src/api/ProfileHandler.cpp
    src/api/VoiceHandler.cpp
    src/api/PushHandler.cpp
    src/api/SearchHandler.cpp
    src/push/PushService.cpp
    src/storage/LocalStorage.cpp
    src/storage/MediaReaper.cpp
    src/storage/S3Client.cpp
    src/storage/S3Storage.cpp
    src/store/SqliteStore.cpp
    src/store/Migrations.cpp
    src/sync/SyncEngine.cpp
    src/sync/SyncToken.cpp
)

target_include_directories(bsfchat-server PRIVATE src)

# src/core/Version.h reads these. Defined on the target rather than
# globally so a stale definition cannot leak in from a parent scope.
target_compile_definitions(bsfchat-server PRIVATE
    BSFCHAT_SERVER_VERSION="${BSFCHAT_SERVER_VERSION}"
    BSFCHAT_SERVER_REVISION="${BSFCHAT_SERVER_REVISION}")

target_link_libraries(bsfchat-server PRIVATE
    bsfchat_protocol
    httplib::httplib
    spdlog::spdlog
    tomlplusplus::tomlplusplus
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Copy example config to build dir
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config/bsfchat-server.example.toml
    ${CMAKE_CURRENT_BINARY_DIR}/bsfchat-server.example.toml
    COPYONLY
)

if(GAMECHAT_SERVER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
