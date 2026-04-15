include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
    GIT_SHALLOW    TRUE
)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(server_tests
    test_auth.cpp
    test_rooms.cpp
    test_sync.cpp
    test_permissions.cpp
    test_media.cpp
    test_voice.cpp
    test_typing.cpp
)

target_include_directories(server_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(server_tests PRIVATE
    bsfchat_protocol
    httplib::httplib
    spdlog::spdlog
    tomlplusplus::tomlplusplus
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
    GTest::gtest_main
)

# We need to compile the server sources for testing (except main.cpp)
target_sources(server_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/Logger.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/LocalAuth.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/Permissions.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/PowerLevels.cpp
    ${CMAKE_SOURCE_DIR}/src/store/SqliteStore.cpp
    ${CMAKE_SOURCE_DIR}/src/store/Migrations.cpp
    ${CMAKE_SOURCE_DIR}/src/sync/SyncEngine.cpp
    ${CMAKE_SOURCE_DIR}/src/http/Router.cpp
    ${CMAKE_SOURCE_DIR}/src/http/Middleware.cpp
    ${CMAKE_SOURCE_DIR}/src/api/TypingHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/storage/LocalStorage.cpp
    ${CMAKE_SOURCE_DIR}/src/storage/S3Client.cpp
    ${CMAKE_SOURCE_DIR}/src/storage/S3Storage.cpp
)

include(GoogleTest)
gtest_discover_tests(server_tests)
