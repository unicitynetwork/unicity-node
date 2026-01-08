# Dockerfile for Eclipse Attack Testing
#
# Builds unicityd and includes attack tools

FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /app
COPY . .

# Build
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j$(nproc) --target unicityd node_simulator unicity-cli

# Runtime image
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libssl3 \
    python3 \
    python3-pip \
    netcat-openbsd \
    curl \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binaries
COPY --from=builder /app/build/bin/unicityd /app/build/bin/unicityd
COPY --from=builder /app/build/bin/node_simulator /app/build/bin/node_simulator
COPY --from=builder /app/build/bin/unicity-cli /app/build/bin/unicity-cli

# Copy test framework
COPY --from=builder /app/test/functional /app/test/functional

WORKDIR /app

# Create data directory
RUN mkdir -p /data

EXPOSE 29590 29591
