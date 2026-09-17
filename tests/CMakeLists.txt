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
    test_regressions.cpp
    test_mentions.cpp
    test_push.cpp
    test_migration_v11.cpp
    test_search.cpp
    test_audit.cpp
    test_permission_scope.cpp
    test_server_ban.cpp
    test_version.cpp
)

target_include_directories(server_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Same definitions the server target gets, so test_version.cpp checks the
# string the shipped binary would actually report rather than the
# #ifndef fallback inside the header.
target_compile_definitions(server_tests PRIVATE
    BSFCHAT_SERVER_VERSION="${BSFCHAT_SERVER_VERSION}"
    BSFCHAT_SERVER_REVISION="${BSFCHAT_SERVER_REVISION}")

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
    ${CMAKE_SOURCE_DIR}/src/api/AuthHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/TypingHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/VoiceHandler.cpp
    # The permission-gated request surface was structurally untestable: none
    # of these handlers were compiled into the test binary at all.
    ${CMAKE_SOURCE_DIR}/src/api/RoomHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/EventHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/SyncHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/PresenceHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/MediaHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/ProfileHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/PushHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/SearchHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/AuditHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/audit/AuditLog.cpp
    ${CMAKE_SOURCE_DIR}/src/identity/Nickname.cpp
    ${CMAKE_SOURCE_DIR}/src/push/PushService.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/AutoJoin.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/OidcAuth.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/RoleBootstrap.cpp
    ${CMAKE_SOURCE_DIR}/src/storage/LocalStorage.cpp
    ${CMAKE_SOURCE_DIR}/src/storage/S3Client.cpp
    ${CMAKE_SOURCE_DIR}/src/storage/S3Storage.cpp
)

include(GoogleTest)
gtest_discover_tests(server_tests)

# --- end-to-end scripts ------------------------------------------------------
#
# These start the real bsfchat-server binary on a real socket, so they cover
# what the unit tests structurally cannot: routing, auth middleware, JSON on
# the wire, and what /sync actually shows the other participant. They are
# labelled `e2e` and separated from the unit tests:
#
#   ctest --test-dir build -L  e2e     # the e2e scripts only
#   ctest --test-dir build -LE e2e     # the unit tests only
#   cmake --build build --target e2e   # shorthand for the first
#
# BSFCHAT_SERVER_BIN is handed to the script as a generator expression rather
# than a guessed path, so the script always exercises the binary from THIS
# build tree and never a stale scratch tree lying around the repo.
add_test(NAME e2e_voice
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/e2e/e2e_voice.sh)
set_tests_properties(e2e_voice PROPERTIES
    LABELS e2e
    ENVIRONMENT "BSFCHAT_SERVER_BIN=$<TARGET_FILE:bsfchat-server>"
    # Generous: it registers two users (bcrypt) and makes ~40 HTTP round trips.
    TIMEOUT 300
    # It binds a socket and starts a server process; two copies at once would
    # be fine (the port is ephemeral) but there is nothing to gain from it.
    RUN_SERIAL TRUE)

# --- release-channel script --------------------------------------------------
#
# scripts/channel_tags.py decides which of :latest / :latest-beta a pushed
# git tag takes. It runs in CI, but it is registered here too so that
# breaking the semver rule fails the same `ctest` run everyone already
# does before pushing, instead of only being caught by a release.
#
# Not labelled e2e: it is a pure unit test, it needs no network and no
# server process, and it belongs in the default `ctest -LE e2e` sweep.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME channel_tags
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_SOURCE_DIR}/scripts/test_channel_tags.py)
else()
    message(STATUS "python3 not found - skipping the channel_tags test "
                   "(CI always has it; this only affects local ctest runs)")
endif()

add_custom_target(e2e
    COMMAND ${CMAKE_CTEST_COMMAND} --test-dir ${CMAKE_BINARY_DIR} -L e2e --output-on-failure
    DEPENDS bsfchat-server
    USES_TERMINAL
    COMMENT "Running the end-to-end scripts against the real server binary")
