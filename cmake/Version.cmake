# Single source of truth for the server's version string.
#
# Deliberately the same shape as client/cmake/Version.cmake so the two
# resolve identically — the version the server reports and the version
# the desktop client reports have to be comparable by eye when someone
# is working out which half of a deployment is stale.
#
# Resolved in this order:
#   1. -DBSFCHAT_SERVER_VERSION=X.Y.Z   (CI passes this on tag builds)
#   2. `git describe --tags --abbrev=0` in the source tree
#   3. Fallback "0.0.0-dev"
#
# Exposes in the parent scope:
#   BSFCHAT_SERVER_VERSION   — full string, may carry a "-rc.N" suffix
#   BSFCHAT_SERVER_VERSION_DOTS — strict MAJOR.MINOR.PATCH, for project()
#   BSFCHAT_SERVER_REVISION  — short commit sha, or "unknown"
#
# The fallback is 0.0.0-dev and NOT the last tag on purpose: an untagged
# working build must sort below every published release, so nobody reads
# "0.0.44" off a container that is actually three weeks of unreviewed
# commits past it.

if(NOT DEFINED BSFCHAT_SERVER_VERSION OR BSFCHAT_SERVER_VERSION STREQUAL "")
    find_package(Git QUIET)
    if(Git_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/..
            OUTPUT_VARIABLE _git_tag
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE _git_rc)
        if(_git_rc EQUAL 0 AND _git_tag)
            string(REGEX REPLACE "^v" "" BSFCHAT_SERVER_VERSION "${_git_tag}")
        endif()
    endif()
endif()

if(NOT DEFINED BSFCHAT_SERVER_VERSION OR BSFCHAT_SERVER_VERSION STREQUAL "")
    set(BSFCHAT_SERVER_VERSION "0.0.0-dev")
endif()

string(REGEX REPLACE "-.*$" "" BSFCHAT_SERVER_VERSION_DOTS "${BSFCHAT_SERVER_VERSION}")
if(NOT BSFCHAT_SERVER_VERSION_DOTS MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR
        "BSFCHAT_SERVER_VERSION='${BSFCHAT_SERVER_VERSION}' does not parse as "
        "MAJOR.MINOR.PATCH[-suffix]. Pass -DBSFCHAT_SERVER_VERSION explicitly, "
        "or tag the repo with a vX.Y.Z release.")
endif()

# Revision: informational only, so a detached/exportless tree degrades to
# "unknown" rather than failing the configure.
if(NOT DEFINED BSFCHAT_SERVER_REVISION OR BSFCHAT_SERVER_REVISION STREQUAL "")
    find_package(Git QUIET)
    set(BSFCHAT_SERVER_REVISION "unknown")
    if(Git_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/..
            OUTPUT_VARIABLE _git_sha
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE _sha_rc)
        if(_sha_rc EQUAL 0 AND _git_sha)
            set(BSFCHAT_SERVER_REVISION "${_git_sha}")
        endif()
    endif()
endif()

message(STATUS "BSFChat server version: ${BSFCHAT_SERVER_VERSION} "
               "(strict=${BSFCHAT_SERVER_VERSION_DOTS} "
               "rev=${BSFCHAT_SERVER_REVISION})")
