include(FetchContent)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Protocol library (local path for development)
FetchContent_Declare(
    bsfchat_protocol
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../protocol
)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.14.1
    GIT_SHALLOW    TRUE
)

FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG        v0.18.3
    GIT_SHALLOW    TRUE
)

FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG        v3.4.0
    GIT_SHALLOW    TRUE
)

set(HTTPLIB_COMPILE ON CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(bsfchat_protocol spdlog httplib tomlplusplus)
