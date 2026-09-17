# BSFChat chat server.
#
#   docker build -t bsfchat/server .
#   docker run --rm -p 8448:8448 \
#     -v "$PWD/data:/data" -v "$PWD/server.toml:/etc/bsfchat/server.toml:ro" \
#     bsfchat/server
#
# Two stages: the builder carries cmake, g++ and the whole FetchContent
# dependency tree (~1 GB); the runtime carries the binary and three
# shared libraries. Nothing from the builder is reachable at runtime, so
# a compiler is not sitting on an internet-facing host.

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
# Pinned by digest, not just by tag: `ubuntu:24.04` is a moving target, so
# a tag-only base means the image for v0.0.44 does not reproduce a month
# later. Digest obtained from `docker pull ubuntu:24.04` on 2026-09-17 —
# refresh it deliberately (docker pull, copy the Digest line) rather than
# letting it drift. Both stages use the same digest so the glibc the
# binary is linked against is the glibc it runs on.
FROM ubuntu:24.04@sha256:69cecf4bbf72d2d44a9eef1b71fb98c7fb973d78af11399deccef19beb008ad9 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build g++ git python3 ca-certificates libssl-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# CI passes the pushed tag through so the binary reports the version of
# the image it is in. Without it, cmake/Version.cmake falls back to
# `git describe` (the .git directory is excluded by .dockerignore, so
# that will not resolve either) and then to 0.0.0-dev — correct, but not
# something to ship under a release tag.
ARG BSFCHAT_SERVER_VERSION=0.0.0-dev
ARG BSFCHAT_SERVER_REVISION=unknown

COPY . /src
WORKDIR /src

RUN cmake -B /build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DGAMECHAT_SERVER_BUILD_TESTS=OFF \
    -DBSFCHAT_SERVER_VERSION="${BSFCHAT_SERVER_VERSION}" \
    -DBSFCHAT_SERVER_REVISION="${BSFCHAT_SERVER_REVISION}" \
    && cmake --build /build -j"$(nproc)"

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM ubuntu:24.04@sha256:69cecf4bbf72d2d44a9eef1b71fb98c7fb973d78af11399deccef19beb008ad9

ARG BSFCHAT_SERVER_VERSION=0.0.0-dev
ARG BSFCHAT_SERVER_REVISION=unknown

# OCI labels, so `docker inspect` answers "what is actually running here"
# without starting the container or reading its logs:
#   docker inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' <image>
LABEL org.opencontainers.image.title="BSFChat server"
LABEL org.opencontainers.image.description="BSFChat chat server"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.source=https://github.com/BSFChat/server
LABEL org.opencontainers.image.url=https://bsfchat.com
LABEL org.opencontainers.image.version=${BSFCHAT_SERVER_VERSION}
LABEL org.opencontainers.image.revision=${BSFCHAT_SERVER_REVISION}

# curl is here for HEALTHCHECK, which needs to make a real HTTP request:
# a bash /dev/tcp probe only proves something accepted a TCP connection,
# which a wedged server with a full worker pool still does.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 libsqlite3-0 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime. Fixed uid/gid rather than whatever adduser picks,
# because host bind mounts have to be chown'd to match it and a number
# that moves between image builds would silently break them on upgrade.
# 10001 is above the 0-999 system range and clear of typical host users.
RUN groupadd --system --gid 10001 bsfchat \
    && useradd --system --uid 10001 --gid 10001 \
               --home-dir /data --shell /usr/sbin/nologin bsfchat

COPY --from=builder /build/bsfchat-server /usr/local/bin/
COPY config/bsfchat-server.example.toml /etc/bsfchat/server.toml

# Created before the VOLUME declaration so their ownership is baked into
# the image and an anonymous volume inherits it. A bind mount from the
# host does NOT inherit it — the host directory keeps its own owner — so
# deploy/setup.sh chowns data/ to 10001:10001. See deploy/README.md.
RUN mkdir -p /data/media /data/keys \
    && chown -R 10001:10001 /data \
    && chown -R 10001:10001 /etc/bsfchat

USER 10001:10001

EXPOSE 8448
VOLUME ["/data", "/etc/bsfchat"]

# /_matrix/client/versions is unauthenticated, cheap, and goes through
# the real router — so it fails if the HTTP server is up but routing is
# not. start-period covers first-start database migrations.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8448/_matrix/client/versions >/dev/null || exit 1

CMD ["bsfchat-server", "--config", "/etc/bsfchat/server.toml"]
