# Shared location logic for the e2e scripts. Sourced, never executed.
#
# Nothing in here may hard-code an absolute path. Every script in this
# directory used to carry a literal /Users/josh/dev/gamechat, which meant none
# of them ran in a git worktree, in CI, or on any machine but one. Everything
# below is derived from this file's own location or taken from the
# environment.
#
#   BSFCHAT_SERVER_BIN   explicit path to the bsfchat-server binary
#   BSFCHAT_REAL_DATA    the live dev data directory the guards protect
#
# shellcheck shell=bash

# The server repo root: this file is at <repo>/tests/e2e/lib.sh.
e2e_server_root() {
    ( cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd )
}

# The bsfchat-server binary to exercise.
#
# BSFCHAT_SERVER_BIN wins. Otherwise build/ is preferred over the build-*
# scratch trees, because build/ is what this repo's documented build line
# produces and the scratch trees are frequently stale — running a months-old
# build-fix/ against fresh expectations is worse than not running at all.
e2e_find_server_bin() {
    if [ -n "${BSFCHAT_SERVER_BIN:-}" ]; then
        printf '%s\n' "$BSFCHAT_SERVER_BIN"
        return 0
    fi
    local root candidate
    root=$(e2e_server_root)
    for candidate in "$root"/build/bsfchat-server "$root"/build-*/bsfchat-server; do
        if [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# Resolve the binary or abort with a usable message.
e2e_require_server_bin() {
    local bin
    if ! bin=$(e2e_find_server_bin) || [ ! -x "$bin" ]; then
        echo "bsfchat-server binary not found." >&2
        echo "Build it (cmake --build build) or set BSFCHAT_SERVER_BIN." >&2
        return 1
    fi
    printf '%s\n' "$bin"
}

# The live dev data directory these scripts must never write to.
#
# The guards exist because an agent once misparsed the TOML, the server fell
# back to ./data/bsfchat.db, and it migrated the owner's real database. The
# directory is a property of the checkout's neighbourhood, not of the repo, so
# it is derived and then verified to exist — a checkout with no sibling data/
# has nothing to protect and says so rather than inventing a path.
e2e_real_data_dir() {
    if [ -n "${BSFCHAT_REAL_DATA:-}" ]; then
        printf '%s\n' "$BSFCHAT_REAL_DATA"
        return 0
    fi
    local root
    root=$(e2e_server_root)
    # Up to three levels: <repo>/data, the sibling data/ next to a normal
    # checkout, and the same for a git worktree living at <workspace>/wt/<name>.
    for candidate in "$root/data" "$root/../data" "$root/../../data" "$root/../../../data"; do
        if [ -d "$candidate" ]; then
            ( cd "$candidate" && pwd )
            return 0
        fi
    done
    return 1
}
