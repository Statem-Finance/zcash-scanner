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

# Internal port. Railway maps this on the PRIVATE network only — never expose
# this service publicly (see README). Health probe at /healthz.
ENV SCANNER_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/zcash-scanner"]
