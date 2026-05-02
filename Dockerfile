# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM rust:1.95-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

# Cache dependency compilation separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN rm -rf src

# Build the real binary
COPY . .
RUN touch src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl

# ---- Runtime stage ----
FROM scratch

COPY --from=builder \
    /build/target/x86_64-unknown-linux-musl/release/auth-proxy \
    /auth-proxy

VOLUME ["/var/lib/auth-proxy"]

EXPOSE 8080

ENTRYPOINT ["/auth-proxy"]
CMD ["serve"]
