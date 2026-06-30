# syntax=docker/dockerfile:1
#
# Multi-stage build for Reader (clip/rss vhost demux over two vendored library crates).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# The two surfaces embed their templates + static CSS via include_str! at COMPILE time, so the
# runtime image carries only the single statically-templated binary — no assets to ship. sqlx AND
# reqwest use rustls with the `ring` provider (no openssl, no aws-lc/cmake), so there is NO OpenSSL.
# ca-certificates is present because both surfaces make outbound HTTPS (page clipping / feed
# polling). The HEALTHCHECK uses the built-in `reader healthcheck` subcommand, so the image needs
# no curl.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Bring the whole self-contained crate (the binary + the two vendored surface crates under
# crates/) and build the release binary. The surfaces' static/ + templates/ are needed at build
# time for their include_str! embeds.
COPY Cargo.toml ./
COPY src ./src
COPY crates ./crates
RUN cargo build --release --bin reader \
    && strip target/release/reader

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home reader
COPY --from=builder /build/target/release/reader /usr/local/bin/reader

USER reader
ENV BIND_ADDR=0.0.0.0:8980
EXPOSE 8980

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["reader", "healthcheck"]

CMD ["reader"]
