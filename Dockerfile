# syntax=docker/dockerfile:1

# ---- ビルドステージ ----
FROM rust:1.95-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

ARG TARGETARCH

# TARGETARCH（BuildKit提供）をRustのターゲットトリプルに変換
RUN case "$TARGETARCH" in \
      amd64) echo "x86_64-unknown-linux-musl"   > /rust_target ;; \
      arm64) echo "aarch64-unknown-linux-musl"   > /rust_target ;; \
      *)     echo "unsupported arch: $TARGETARCH" >&2; exit 1   ;; \
    esac

# 依存クレートのキャッシュ層
COPY Cargo.toml Cargo.loc[k] ./
RUN target=$(cat /rust_target) && \
    rustup target add "$target" && \
    mkdir src && \
    echo 'fn main(){}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release --target "$target" && \
    rm -rf src

COPY . .
RUN target=$(cat /rust_target) && \
    cargo build --release --target "$target" && \
    cp "target/$target/release/auth-proxy" /auth-proxy

# ---- 実行ステージ ----
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/YOUR_GITHUB_USERNAME/auth-proxy"

COPY --from=builder /auth-proxy /auth-proxy

VOLUME ["/var/lib/auth-proxy"]
EXPOSE 8080
ENTRYPOINT ["/auth-proxy"]
CMD ["serve"]
