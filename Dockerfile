# ---- Build stage ----
FROM rust:1.94-slim-bookworm AS builder
WORKDIR /app

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src

COPY src ./src
COPY migrations ./migrations
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home encryptr
COPY --from=builder /app/target/release/encryptr-server /usr/local/bin/encryptr-server
USER encryptr
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/encryptr-server"]
