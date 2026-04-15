LABEL org.opencontainers.image.source=https://github.com/BSFChat/server
LABEL org.opencontainers.image.description="BSFChat chat server"
LABEL org.opencontainers.image.licenses=MIT

# Stage 1: Build
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake make g++ git python3 ca-certificates libssl-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN cmake -B /build \
    -DCMAKE_BUILD_TYPE=Release \
    -DGAMECHAT_SERVER_BUILD_TESTS=OFF \
    && cmake --build /build -j$(nproc)

# Stage 2: Runtime
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 libsqlite3-0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/bsfchat-server /usr/local/bin/
COPY config/bsfchat-server.example.toml /etc/bsfchat/server.toml

RUN mkdir -p /data/media /data/keys

EXPOSE 8448
VOLUME ["/data", "/etc/bsfchat"]

CMD ["bsfchat-server", "--config", "/etc/bsfchat/server.toml"]
