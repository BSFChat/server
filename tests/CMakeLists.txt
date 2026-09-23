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
    test_sync_latency.cpp
    test_read_state_sync.cpp
    test_sync_token.cpp
    test_sync_invites.cpp
    test_call_privacy.cpp
    test_permissions.cpp
    test_media.cpp
    test_media_security.cpp
    test_media_reference_authz.cpp
    test_media_tickets.cpp
    test_voice.cpp
    test_typing.cpp
    test_regressions.cpp
    test_redaction_residue.cpp
    test_mentions.cpp
    test_push.cpp
    test_migration_v11.cpp
    test_search.cpp
    test_audit.cpp
    test_permission_scope.cpp
    test_permission_audit_2026_09.cpp
    test_room_visibility.cpp
    test_category_visibility.cpp
    test_server_ban.cpp
    test_version.cpp
    test_bots.cpp
    test_localpart.cpp
    test_request_hardening.cpp
    test_kick_enforcement.cpp
    test_role_management.cpp
    test_account_linking.cpp
    test_admin_cli.cpp
    test_channel_directory.cpp
    test_effective_permissions.cpp
    test_mirror_room.cpp
    test_phantom_membership.cpp
    test_bot_scoping.cpp
    test_invite_idempotency.cpp
    test_invite_refusal_codes.cpp
    test_dm_membership.cpp
    test_permission_audit_2026_09.cpp
    test_permission_containment.cpp
    # docs/security-audit-2026-09.md: the audit's proof tests, unchanged, and
    # the tests added with the fixes.
    test_security_audit_2026_09.cpp
    test_security_fixes_2026_09.cpp
    # Blocking, reporting and self-service account deletion (schema v29).
    test_ugc_safety.cpp
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
    ${CMAKE_SOURCE_DIR}/src/core/InstanceSecret.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/core/RateLimiter.cpp
    ${CMAKE_SOURCE_DIR}/src/core/SendLimiter.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Utf8.cpp
    ${CMAKE_SOURCE_DIR}/src/http/ClientAddress.cpp
    ${CMAKE_SOURCE_DIR}/src/http/JsonIo.cpp
    ${CMAKE_SOURCE_DIR}/src/http/RequestGuard.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/LocalAuth.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/MediaAccess.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/Permissions.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/RoomVisibility.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/PowerLevels.cpp
    ${CMAKE_SOURCE_DIR}/src/store/MediaReferences.cpp
    ${CMAKE_SOURCE_DIR}/src/store/SqliteStore.cpp
    ${CMAKE_SOURCE_DIR}/src/store/Migrations.cpp
    ${CMAKE_SOURCE_DIR}/src/sync/SyncEngine.cpp
    ${CMAKE_SOURCE_DIR}/src/sync/SyncToken.cpp
    ${CMAKE_SOURCE_DIR}/src/http/Router.cpp
    # For the worker-pool regression test: the defect was in how this
    # constructs httplib's ThreadPool, so the test must build the real thing.
    ${CMAKE_SOURCE_DIR}/src/http/HttpServer.cpp
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
    ${CMAKE_SOURCE_DIR}/src/api/MediaPolicy.cpp
    ${CMAKE_SOURCE_DIR}/src/api/MediaTicket.cpp
    ${CMAKE_SOURCE_DIR}/src/api/ProfileHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/PushHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/SearchHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/AccountDataHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/AuditHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/ReportHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/BotHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/RoleHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/PermissionsHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/audit/AuditLog.cpp
    ${CMAKE_SOURCE_DIR}/src/identity/Localpart.cpp
    ${CMAKE_SOURCE_DIR}/src/identity/Nickname.cpp
    ${CMAKE_SOURCE_DIR}/src/push/PushService.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/AutoJoin.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/OidcAuth.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/RoleBootstrap.cpp
    # The offline recovery CLI. Compiled in because the whole point of the
    # command is the write path it takes, which only a real store can show.
    ${CMAKE_SOURCE_DIR}/src/cli/AdminCli.cpp
    ${CMAKE_SOURCE_DIR}/src/storage/LocalStorage.cpp
    ${CMAKE_SOURCE_DIR}/src/storage/MediaReaper.cpp
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

add_test(NAME e2e_sync_latency
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/e2e/e2e_sync_latency.sh)
set_tests_properties(e2e_sync_latency PROPERTIES
    LABELS e2e
    ENVIRONMENT "BSFCHAT_SERVER_BIN=$<TARGET_FILE:bsfchat-server>"
    # The unit test covers the pool in isolation; this one proves the number
    # an owner actually feels — send on one connection, watch a parked /sync
    # on another come back — over real sockets with the real binary.
    TIMEOUT 300
    # RUN_SERIAL, but do not mistake it for protection. ctest serialises this
    # against OTHER CTEST TESTS and nothing else: a concurrent `cmake --build`,
    # a second agent's ctest run, or anything else on the box is invisible to
    # it. That is why this test no longer asserts an absolute millisecond
    # budget — it measures an unwoken poll in the same run and requires the
    # woken ones to beat it, which is true whatever else the machine is doing.
    # RUN_SERIAL stays only because a fixed port (18471) genuinely cannot be
    # shared with a second copy of itself.
    RUN_SERIAL TRUE)

add_test(NAME e2e_profile_shape
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/e2e/e2e_profile_shape.sh)
set_tests_properties(e2e_profile_shape PROPERTIES
    LABELS e2e
    ENVIRONMENT "BSFCHAT_SERVER_BIN=$<TARGET_FILE:bsfchat-server>"
    # The shape of a response body is exactly what a unit test on the handler
    # cannot see: the bug it pins down was a `json resp;` that serialised as
    # `null` rather than `{}`, which is only visible once something dumps it
    # and a client parses it off the wire.
    TIMEOUT 300
    # Registers two users (bcrypt) and starts a server process.
    RUN_SERIAL TRUE)

add_test(NAME e2e_channel_directory
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/e2e/e2e_channel_directory.sh)
set_tests_properties(e2e_channel_directory PROPERTIES
    LABELS e2e
    ENVIRONMENT "BSFCHAT_SERVER_BIN=$<TARGET_FILE:bsfchat-server>"
    # The unit tests call RoomHandler directly, so the one thing they cannot
    # cover is whether anything ROUTES to it — and the disclosure assertion here
    # is a substring scan over the bytes curl received, which is the only form
    # of "the room id is nowhere in the response" that a C++ struct cannot
    # quietly satisfy.
    TIMEOUT 300
    # Registers two accounts (bcrypt), restarts the server so role bootstrap
    # runs, and binds a fixed port (8907) that a second copy cannot share.
    RUN_SERIAL TRUE)

add_test(NAME e2e_invites
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/e2e/e2e_invites.sh)
set_tests_properties(e2e_invites PROPERTIES
    LABELS e2e
    ENVIRONMENT "BSFCHAT_SERVER_BIN=$<TARGET_FILE:bsfchat-server>"
    # It registers three accounts (bcrypt), restarts the server so role
    # bootstrap runs, and parks two long polls it has to let expire.
    TIMEOUT 300
    # Fixed port, so a second copy of itself cannot run alongside. Its two
    # timing assertions no longer depend on this: T4 is a lower bound (load
    # can only help it) and T5 is stated as a fraction of the poll timeout it
    # is distinguishing itself from. See the note on e2e_sync_latency above
    # for why RUN_SERIAL is not a defence against load in the first place.
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
