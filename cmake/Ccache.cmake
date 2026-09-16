# Compiler cache.
#
# Rebuilds in this tree are dominated by recompiling unchanged third-party
# sources, so ccache is worth defaulting on. Precedence:
#
#   1. An explicit -DCMAKE_CXX_COMPILER_LAUNCHER=... on the configure line
#      (or in the cache) always wins — nothing here overrides it.
#   2. Otherwise, if ccache is on PATH, it becomes the launcher.
#   3. -DBSFCHAT_USE_CCACHE=OFF opts out entirely.
#
# These are plain (non-cache) variables so they propagate into
# add_subdirectory/FetchContent children without being sticky across a
# reconfigure with different flags.

option(BSFCHAT_USE_CCACHE "Use ccache as the compiler launcher when found" ON)

if(BSFCHAT_USE_CCACHE
   AND NOT DEFINED CMAKE_CXX_COMPILER_LAUNCHER
   AND NOT DEFINED CMAKE_C_COMPILER_LAUNCHER)
    find_program(BSFCHAT_CCACHE_PROGRAM ccache)
    if(BSFCHAT_CCACHE_PROGRAM)
        set(CMAKE_C_COMPILER_LAUNCHER "${BSFCHAT_CCACHE_PROGRAM}")
        set(CMAKE_CXX_COMPILER_LAUNCHER "${BSFCHAT_CCACHE_PROGRAM}")
        message(STATUS "ccache: ${BSFCHAT_CCACHE_PROGRAM}")
    else()
        message(STATUS "ccache: not found (set BSFCHAT_USE_CCACHE=OFF to silence)")
    endif()
elseif(DEFINED CMAKE_CXX_COMPILER_LAUNCHER)
    message(STATUS "compiler launcher (explicit): ${CMAKE_CXX_COMPILER_LAUNCHER}")
endif()
