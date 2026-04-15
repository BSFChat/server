cmake_minimum_required(VERSION 3.20)
project(bsfchat-server VERSION 0.1.0 LANGUAGES CXX)

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
    src/http/HttpServer.cpp
    src/http/Router.cpp
    src/http/Middleware.cpp
    src/auth/AutoJoin.cpp
    src/auth/LocalAuth.cpp
    src/auth/OidcAuth.cpp
    src/auth/Permissions.cpp
    src/auth/PowerLevels.cpp
    src/auth/RoleBootstrap.cpp
    src/api/AuthHandler.cpp
    src/api/RoomHandler.cpp
    src/api/EventHandler.cpp
    src/api/SyncHandler.cpp
    src/api/TypingHandler.cpp
    src/api/MediaHandler.cpp
    src/api/ProfileHandler.cpp
    src/api/VoiceHandler.cpp
    src/storage/LocalStorage.cpp
    src/storage/S3Client.cpp
    src/storage/S3Storage.cpp
    src/store/SqliteStore.cpp
    src/store/Migrations.cpp
    src/sync/SyncEngine.cpp
)

target_include_directories(bsfchat-server PRIVATE src)

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
