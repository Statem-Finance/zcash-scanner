# Multi-stage build for the internal Zcash scanner.
# Build stage: compile a release binary against the pinned crates.
FROM rust:1-bookworm AS build
WORKDIR /app

# librustzcash crates pull in C deps for some backends; protobuf compiler is
# needed if any transitive crate regenerates protos at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies first.
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release || true
COPY src ./src
RUN cargo build --release

# Runtime stage: slim image, non-root, binary only.
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 scanner
COPY --from=build /app/target/release/zcash-scanner /usr/local/bin/zcash-scanner
USER scanner

# Port handling: the app binds `$PORT` when the platform sets it (Railway, Render,
# Fly all do — and they route to THAT port, so binding anything else yields a 502
# "connection dial timeout"). Otherwise it falls back to SCANNER_BIND_ADDR, then
# 8080. The ENV/EXPOSE below are just defaults for a plain `docker run`. Prefer the
# platform's PRIVATE network over a public domain (shared-secret auth). Health: /healthz.
ENV SCANNER_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/zcash-scanner"]
