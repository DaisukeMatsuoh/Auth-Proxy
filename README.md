# auth-proxy

An authentication-focused reverse proxy that **adds authentication to existing web apps and static files without touching their code**.

auth-proxy handles all authentication and forwards only authenticated requests to upstream services. Upstream services never need to implement authentication themselves — they simply read the `X-Auth-*` headers to identify users.

## Modes

auth-proxy supports two deployment modes:

| Mode | Environment Variable | Use Case | Recommended Deployment |
|---|---|---|---|
| **Static File Mode** | `AUTH_PROXY_SERVE_PATH` only | Serve internal documents, photos, or static sites with authentication. auth-proxy handles both authentication and file hosting. | Single binary |
| **Proxy Mode** | `AUTH_PROXY_UPSTREAM_APP_URL` only | Add authentication to an existing dynamic web app. Docker is required to keep the upstream app hidden behind auth-proxy. | Docker Compose |
| **Combined Mode** | Both set | Use static file serving and upstream proxying at the same time. | Docker Compose |

Set at least one of `AUTH_PROXY_SERVE_PATH` or `AUTH_PROXY_UPSTREAM_APP_URL`. **Leaving both unset is a startup error.**

## Comparison with oauth2-proxy

| | auth-proxy | oauth2-proxy |
|---|---|---|
| User management | Built-in SQLite with admin UI | Depends on external IdP (Google, GitHub, etc.) |
| Setup | Drop in a binary or add to Docker Compose | Requires OAuth app registration and IdP configuration |
| Static file serving | ✅ Built-in | ❌ |
| MFA | ✅ TOTP built-in | Depends on IdP |
| No external services | ✅ | ❌ |
| Image size | Minimal (static binary) | Medium |

---

## Table of Contents

- [Features](#features)
- [Security Design](#security-design)
- [Deploy: Static File Mode](#deploy-static-file-mode)
- [Deploy: Proxy Mode (Docker)](#deploy-proxy-mode-docker)
- [Environment Variable Reference](#environment-variable-reference)
- [CLI Reference](#cli-reference)
- [Headers Forwarded to Upstream](#headers-forwarded-to-upstream)
- [Guest Token Feature](#guest-token-feature)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)

---

## Features

| Phase | Feature | Status |
|---|---|---|
| Phase 1 | Reverse proxy core · SQLite session persistence | ✅ Done |
| Phase 2 | Web admin UI (list, add, edit, delete users) | ✅ Done |
| Phase 3a | MFA (TOTP · backup codes · device remembering) | ✅ Done |
| Phase 3a-2 | Admin-forced MFA disable · user security settings · password change | ✅ Done |
| Phase 4 | Guest tokens (use-count limits · password-protected share links) | ✅ Done |
| Phase Docker | Dockerfile · Compose example · mode validation | ✅ Done |
| Phase 3b | Passkeys (WebAuthn) | 🔜 Planned |

---

## Security Design

### Static File Mode

auth-proxy gates all HTTP requests against the session store. Only authenticated users can access files under `AUTH_PROXY_SERVE_PATH`. Path traversal (`../` etc.) is prevented internally.

### Proxy Mode

In proxy mode, the upstream service runs alongside auth-proxy in Docker. Because the upstream service omits `ports:` in `docker-compose.yml`, it is unreachable directly from the host or the internet. Only requests that have passed through auth-proxy reach the upstream service.

Upstream services receive user identity via `X-Auth-*` headers. Because auth-proxy always strips any `X-Auth-*` headers arriving from clients before forwarding, upstream services do not need to implement JWT signature verification or any other auth logic — they simply read the headers.

### Cookie Attributes

```
Set-Cookie: session_id=<token>; HttpOnly; Secure; SameSite=Strict; Max-Age=<seconds>
```

All four attributes are required. The `Secure` attribute means auth-proxy must sit behind a TLS-terminating reverse proxy (Traefik, nginx, etc.).

### Other

- Passwords: hashed with Argon2id. Plaintext is never stored or logged.
- Session IDs: 16 bytes from `OsRng`, hex-encoded (32 characters).
- Brute-force protection: 500 ms delay on login failure.
- `X-Auth-*` spoofing prevention: any `X-Auth-` headers sent by clients are stripped before forwarding.

---

## Deploy: Static File Mode

Use this when you want to **host static files with authentication** — internal documentation, photo galleries, and so on.

```
[Browser]
    │ HTTPS
    ▼
[Traefik / nginx]  ← TLS termination
    │ HTTP (127.0.0.1)
    ▼
[auth-proxy binary]  ← launched directly via systemd
    │
    ├── /login  /logout  /admin/*   handled by auth-proxy
    └── /*                          served from AUTH_PROXY_SERVE_PATH
         └── SQLite (sessions, users)
```

### Setup

```bash
# 1. Place the binary
sudo cp target/release/auth-proxy /usr/local/bin/
sudo chmod +x /usr/local/bin/auth-proxy

# 2. Create directories and config file
sudo mkdir -p /etc/auth-proxy /var/lib/auth-proxy
sudo cp .env.auth-proxy.example /etc/auth-proxy/.env
sudo chmod 600 /etc/auth-proxy/.env

# 3. Edit .env (set AUTH_PROXY_SERVE_PATH, AUTH_PROXY_LISTEN_ADDR=127.0.0.1:8080, etc.)
sudo vim /etc/auth-proxy/.env

# 4. Create the first admin user
sudo auth-proxy init-admin

# 5. Register and start the systemd service
sudo cp systemd/auth-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable auth-proxy
sudo systemctl start auth-proxy
```

### systemd Unit File Example

`/etc/systemd/system/auth-proxy.service`:

```ini
[Unit]
Description=Auth Proxy Server
After=network.target

[Service]
Type=simple
User=www-data
EnvironmentFile=/etc/auth-proxy/.env
ExecStart=/usr/local/bin/auth-proxy serve
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/auth-proxy
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Traefik Configuration Example (Static File Mode)

```yaml
http:
  routers:
    my-docs:
      rule: "Host(`docs.example.com`)"
      entryPoints:
        - websecure
      tls: {}
      service: auth-proxy-svc
  services:
    auth-proxy-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

---

## Deploy: Proxy Mode (Docker)

Use this when you want to **add authentication to an existing dynamic web app**. The upstream service is kept inside Docker's internal network so it cannot be reached directly.

```
[Browser]
    │ HTTPS
    ▼
[Traefik / nginx]
    │ HTTP (127.0.0.1)
    ▼
[auth-proxy container]
    │
    ├── /login  /logout  /admin/*   handled by auth-proxy
    └── /*                          X-Auth-* headers added → forwarded upstream
         │ Docker internal network
         ▼
    [upstream service container]  ← no ports exposed to the host
```

### Step 1: Containerize Your App

Proxy mode assumes the upstream service (your app) is available as a Docker image. **You do not need to change any application logic.**

One thing to check: your app must listen on `0.0.0.0` (all interfaces), not `127.0.0.1`. Binding to `127.0.0.1` inside a container makes the app unreachable from other containers including auth-proxy.

Below are Dockerfile examples for common stacks.

#### Python (Flask / FastAPI)

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Must listen on 0.0.0.0, not 127.0.0.1
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3000"]
```

#### Go

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 produces a fully static binary required for the scratch base image
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app .

FROM scratch
COPY --from=builder /build/app /app
ENTRYPOINT ["/app"]
```

```go
// main.go: bind to 0.0.0.0
http.ListenAndServe("0.0.0.0:3000", handler)
```

#### Rust

```dockerfile
FROM rust:1.77-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN rm -rf src
COPY . .
RUN touch src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/my-app /my-app
ENTRYPOINT ["/my-app"]
```

```rust
// main.rs: listen on 0.0.0.0
let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
axum::serve(listener, app).await?;
```

auth-proxy itself is written in Rust and uses the same `scratch`-based multi-stage build pattern. Using the same approach for your app minimizes image size.

#### Node.js (Express)

```dockerfile
FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
CMD ["node", "server.js"]
```

```js
// server.js: omitting host defaults to 0.0.0.0 in Node.js
app.listen(3000);
```

#### Using an Existing Official Image

For apps like nginx or WordPress that already have official images, no Dockerfile is needed. Reference the image directly in Compose.

```yaml
# docker-compose.yml — app service section
app:
  image: nginx:alpine
  volumes:
    - ./html:/usr/share/nginx/html:ro
  # No ports: — auth-proxy handles all incoming traffic
```

---

#### What Is a Dockerfile?

A Dockerfile is a recipe that tells Docker how to build an image. Once your app's image is defined, Docker Compose builds and runs both auth-proxy and your app together as a single service stack.

```
Dockerfile (recipe)
    │
    │ docker build  (builds your app image alongside auth-proxy)
    ▼
Docker image  (stored on the server)
    │
    │ docker compose up  (runs the containers)
    ▼
Container  (running process)
```

#### Suggested Directory Layout

```
my-project/                     ← working directory (any name)
├── docker-compose.yml          ← manages auth-proxy + your app together  (Step 2)
├── .env.auth-proxy             ← auth-proxy configuration
│
└── my-app/                     ← your upstream app repository
    ├── Dockerfile              ← created in Step 1
    ├── main.py  (or main.go, etc.)
    └── ...
```

---

### Step 2: Create docker-compose.yml

```bash
cp docker-compose.example.yml docker-compose.yml
```

Edit `docker-compose.yml` and replace the `app` service with your own. **Do not add `ports:` to the `app` service.** That is the key to network isolation — adding ports would expose the upstream service directly, bypassing auth-proxy entirely.

```yaml
services:
  auth-proxy:
    # Uncomment exactly one of the following:
    image: ghcr.io/your-org/auth-proxy:latest    # [Recommended] use the published image
    # build: .                                     # [Development] build locally
    ports:
      - "127.0.0.1:${AUTH_PROXY_HOST_PORT:-8080}:8080"   # host-side port (configurable via env var)
    volumes:
      # Mount ./data on the host. DB and data persist in ./data even if the container is removed.
      - ./data:/var/lib/auth-proxy
    env_file:
      - .env.auth-proxy
    networks:
      - internal
    restart: unless-stopped
    depends_on:
      - app

  app:
    # Uncomment exactly one of the following:
    build: ./my-app             # [Custom app] build from ./my-app/Dockerfile
    # image: my-app:latest      # [Pre-built] use an already-built image
    # image: nginx:alpine       # [Official image] use directly without a Dockerfile
    # No ports: ← this is the network isolation ❗
    networks:
      - internal
    restart: unless-stopped

networks:
  internal:
    # Setting internal: true blocks all outbound internet access from containers on this network.
    # Do not set this if your upstream app needs to call external APIs.
    # Network isolation is already achieved by not publishing ports on the app service;
    # internal: true is not required.
```

Set `AUTH_PROXY_UPSTREAM_APP_URL` using the Compose service name (e.g. `app`) as the hostname:

```dotenv
# .env.auth-proxy
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000   # "app" matches the service name in docker-compose.yml
```

If your app listens on a different port (e.g. 8000), update the port number accordingly.

**Host-side port**: `docker-compose.yml` uses `${AUTH_PROXY_HOST_PORT:-8080}`, defaulting to 8080. To use a different port:
- `AUTH_PROXY_HOST_PORT=9000 docker compose up`, or
- edit the `ports:` section in `docker-compose.yml` directly.

---

### Step 3: Create the Environment File

```bash
cp .env.auth-proxy.example .env.auth-proxy
```

Set at minimum:

```dotenv
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db  # must match the volume mount path in docker-compose.yml
AUTH_PROXY_LISTEN_ADDR=0.0.0.0:8080   # fixed value inside the container
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_ISSUER_NAME=my-service
AUTH_PROXY_MFA_ENCRYPTION_KEY=xxx    # generate with: openssl rand -hex 32
AUTH_PROXY_GUEST_TOKEN_SECRET=yyy    # generate with: openssl rand -hex 32
AUTH_PROXY_GUEST_TOKEN_API_KEY=zzz   # generate with: openssl rand -hex 32
```

**About port settings**:
- `AUTH_PROXY_LISTEN_ADDR=0.0.0.0:8080` is the listen address inside the container. Leave it as-is.
- The host-side port is controlled by `${AUTH_PROXY_HOST_PORT:-8080}` in `docker-compose.yml`.

**About data persistence**:
- The `./data:/var/lib/auth-proxy` bind mount stores the DB on the host under `./data/`.
- Running `docker compose down` removes containers but leaves `./data/` untouched.
- The `.env.auth-proxy` file lives on the host and is never affected by container lifecycle.

Do not change `AUTH_PROXY_MFA_ENCRYPTION_KEY` or other secrets after initial setup. Changing them invalidates existing MFA configurations.

---

### Step 4: Build the Docker Images

```bash
docker compose build

# Example output:
# => [app builder 1/5] FROM golang:1.22-alpine
# => [app builder 2/5] COPY go.mod go.sum ./
# => [app builder 3/5] RUN go mod download
# => [app builder 4/5] RUN go build -o app .
# => [app] COPY --from=builder /build/app /app
# => exporting to image
```

Verify the images were created:

```bash
docker images
# REPOSITORY         TAG       IMAGE ID       SIZE
# my-project-app     latest    abc123def456   8.2MB
# auth-proxy         latest    xyz789ghi012   4.1MB
```

To rebuild after changing application code:

```bash
docker compose build app    # rebuild only the app image
docker compose up -d app    # restart only the app container
```

---

### Step 5: First Launch and Admin User Setup

```bash
# Build images
docker compose build

# Create the first admin user interactively (run once only)
docker compose run --rm auth-proxy init-admin

# Start all services in the background
docker compose up -d

# Verify startup via logs
docker compose logs -f auth-proxy
```

Expected log output on successful startup:

```
auth-proxy  | INFO auth_proxy: listening on 0.0.0.0:8080
auth-proxy  | INFO auth_proxy: upstream: http://app:3000
auth-proxy  | INFO auth_proxy: mode: proxy
```

---

### Step 6: Route Traffic via Traefik or nginx

Point your Traefik or nginx configuration at auth-proxy's host port (`127.0.0.1:8080`).

**Traefik example (running directly on the host)**:

```yaml
http:
  routers:
    my-app:
      rule: "Host(`app.example.com`)"
      entryPoints:
        - websecure
      tls: {}
      service: auth-proxy-svc
  services:
    auth-proxy-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

**nginx example**:

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;
    # ... TLS configuration ...

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Environment Variable Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `AUTH_PROXY_SERVE_PATH` | ※1 | — | Directory path to serve as static files |
| `AUTH_PROXY_UPSTREAM_APP_URL` | ※1 | — | Upstream service URL (e.g. `http://app:3000`) |
| `AUTH_PROXY_DB_PATH` | — | `auth_proxy.db` | SQLite database file path |
| `AUTH_PROXY_LISTEN_ADDR` | — | `0.0.0.0:8080` | Address and port the server listens on (inside the container) |
| `AUTH_PROXY_SESSION_TTL_HOURS` | — | `8` | Session lifetime in hours |
| `AUTH_PROXY_ISSUER_NAME` | — | `auth-proxy` | Value of the `X-Auth-Issuer` header |
| `AUTH_PROXY_MFA_ENCRYPTION_KEY` | — | ※2 | TOTP secret encryption key (64 hex characters) |
| `AUTH_PROXY_GUEST_TOKEN_SECRET` | — | ※2 | Guest token signing key (64 hex characters) |
| `AUTH_PROXY_GUEST_TOKEN_API_KEY` | — | ※2 | API key for the guest token issuance endpoint |
| `AUTH_PROXY_HOST_PORT` | — | `8080` | Host-side bind port for Docker Compose |
| `RUST_LOG` | — | `info` | Log level (`trace` / `debug` / `info` / `warn` / `error`) |

※1 Set at least one of `AUTH_PROXY_SERVE_PATH` or `AUTH_PROXY_UPSTREAM_APP_URL`. Both unset is a startup error.

※2 Has a default, but always generate a proper value with `openssl rand -hex 32` for production.

**Port settings**:
- **`AUTH_PROXY_LISTEN_ADDR`** (inside the container):
  - Single binary (static file mode): set `AUTH_PROXY_LISTEN_ADDR=127.0.0.1:8080` explicitly in `.env`
  - Docker mode: leave as `0.0.0.0:8080` (no change needed)
- **`AUTH_PROXY_HOST_PORT`** (host side, Docker Compose only):
  - Controls the `ports:` binding in `docker-compose.yml`
  - Example: `AUTH_PROXY_HOST_PORT=9000 docker compose up` binds port 9000 on the host

**Data persistence**:
- Docker mode uses a bind mount (`./data:/var/lib/auth-proxy`). The DB file is stored in `./data/` on the host.
- `docker compose down` removes containers but does not touch `./data/`. Adding `-v` removes named volumes but not bind-mount directories; use plain `down` to be safe.
- The `.env.auth-proxy` file lives on the host and is never affected by container lifecycle.

### Configuration Example (Static File Mode)

```dotenv
AUTH_PROXY_SERVE_PATH=/var/www/html
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db
AUTH_PROXY_LISTEN_ADDR=127.0.0.1:8080
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_MFA_ENCRYPTION_KEY=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_SECRET=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_API_KEY=<openssl rand -hex 32>
RUST_LOG=info
```

### Configuration Example (Proxy Mode / Docker)

```dotenv
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db  # must match the volume mount path in docker-compose.yml
AUTH_PROXY_LISTEN_ADDR=0.0.0.0:8080
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_MFA_ENCRYPTION_KEY=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_SECRET=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_API_KEY=<openssl rand -hex 32>
RUST_LOG=info
```

---

## CLI Reference

| Command | Description |
|---|---|
| `serve` | Start the server |
| `init-admin` | Interactively create the first admin user |
| `hash` | Generate an Argon2id hash of a password |
| `verify <username>` | Verify a user's password (for debugging) |
| `list` | List all registered users |

### Static File Mode (Single Binary)

Run the binary directly:

```bash
auth-proxy init-admin
auth-proxy list
auth-proxy verify alice
auth-proxy hash
```

### Proxy Mode (Docker)

Use `docker compose exec` or `docker compose run` to run commands inside the container. **You cannot run `auth-proxy` directly from your terminal in this mode.**

```bash
# Commands to run while the server is already running (exec)
docker compose exec auth-proxy auth-proxy list
docker compose exec auth-proxy auth-proxy verify alice
docker compose exec auth-proxy auth-proxy hash

# Commands to run before starting the server, in a temporary container (run)
# init-admin is typically run before first startup
docker compose run --rm auth-proxy init-admin
```

`exec` attaches to a running container. `run` starts a temporary container and removes it after the command finishes (`--rm`). Use `run` for initial setup when the server is not yet running.

---

## Headers Forwarded to Upstream

**Applies to proxy mode only.** This section is not relevant for static file mode.

auth-proxy adds the following headers to every authenticated request before forwarding it upstream:

| Header | Content | Example |
|---|---|---|
| `X-Auth-User` | Username | `alice` |
| `X-Auth-User-Id` | User ID (stable integer, equivalent to OIDC `sub`) | `42` |
| `X-Auth-Role` | Role | `admin` or `user` |
| `X-Auth-Issuer` | Value of `AUTH_PROXY_ISSUER_NAME` | `auth-proxy` |
| `X-Auth-Guest` | `true` for guest token access only; absent for normal sessions | `true` |

Because usernames can change, use `X-Auth-User-Id` as the stable identifier when the upstream service needs to associate records with a specific user.

### Implementation Examples

```python
# Python (Flask)
@app.route("/")
def index():
    user_id  = request.headers.get("X-Auth-User-Id")   # "42"
    username = request.headers.get("X-Auth-User")       # "alice"
    role     = request.headers.get("X-Auth-Role")       # "user" | "admin"
    # No auth logic needed — just read the headers
```

```go
// Go
func handler(w http.ResponseWriter, r *http.Request) {
    userID   := r.Header.Get("X-Auth-User-Id")   // "42"
    username := r.Header.Get("X-Auth-User")       // "alice"
    role     := r.Header.Get("X-Auth-Role")       // "user" | "admin"
}
```

---

## Guest Token Feature

Guest tokens allow limited, unauthenticated access to specific paths — managed centrally within auth-proxy. The upstream service only needs to tell auth-proxy which path to share; token generation, verification, and expiry are all handled by auth-proxy.

### Issuing a Token

```bash
curl -X POST https://your-domain/api/guest-token \
  -H "Authorization: Bearer <AUTH_PROXY_GUEST_TOKEN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/shared/report",
    "expires_in": 86400,
    "max_uses": 10,
    "password": "secret123",
    "ui": {
      "title": "Q3 Report",
      "description": "Enter the password from your invitation email"
    }
  }'
```

| Parameter | Required | Description |
|---|---|---|
| `path` | ✅ | Path prefix to allow access to (must start with `/`) |
| `expires_in` | ✅ | Token lifetime in seconds |
| `max_uses` | — | Maximum number of accesses. Omit for unlimited. |
| `password` | — | Optional password. Omit to allow access via URL alone. |
| `ui.title` / `ui.description` | — | Text displayed on the password entry form |

### End-User Access

```
https://your-domain/shared/report?guest_token=<token>
```

If a password is set, a form is displayed. After entering the correct password, a `guest_session_id` cookie is issued, allowing continued access without re-entering the token in the URL.

---

## Operations

### User Management

Use the browser-based admin UI for day-to-day user management. The CLI is a secondary tool for debugging or emergencies.

```bash
# Open the admin UI in a browser (both modes)
https://your-domain/admin/users
```

CLI verification (method differs by mode):

```bash
# Static file mode (single binary)
auth-proxy list
auth-proxy verify alice

# Proxy mode (Docker)
docker compose exec auth-proxy auth-proxy list
docker compose exec auth-proxy auth-proxy verify alice
```

### Viewing Logs

```bash
# Static file mode (systemd)
sudo journalctl -u auth-proxy -f
sudo journalctl -u auth-proxy -n 100

# Proxy mode (Docker)
docker compose logs -f auth-proxy
docker compose logs --tail=100 auth-proxy
```

---

## Troubleshooting

### Server Won't Start

| Error | Cause | Fix |
|---|---|---|
| `Neither AUTH_PROXY_SERVE_PATH nor AUTH_PROXY_UPSTREAM_APP_URL is set` | No mode configured | Set at least one in `.env` |
| `Path does not exist: /path/to/...` | `AUTH_PROXY_SERVE_PATH` directory missing | Create the directory or correct the path |
| `Address already in use` | Port in use | Change `AUTH_PROXY_LISTEN_ADDR` or stop the conflicting process |
| DB permission error | No write access | Ensure Docker can write to the `./data` directory |
| Data lost after `docker compose down -v` | `-v` removes volumes | With a bind mount (`./data`), the directory itself is not removed even with `-v`, but use plain `down` to be safe |

### Can't Log In

First, check the logs to identify the error:

```bash
# Static file mode
sudo journalctl -u auth-proxy -n 50

# Proxy mode (Docker)
docker compose logs --tail=50 auth-proxy
```

Then verify the user exists and the password is correct:

```bash
# Static file mode
auth-proxy list
auth-proxy verify alice

# Proxy mode (Docker)
docker compose exec auth-proxy auth-proxy list
docker compose exec auth-proxy auth-proxy verify alice
```

### Can't Reach the Upstream Service (Proxy Mode Only)

Verify the service name and port in `AUTH_PROXY_UPSTREAM_APP_URL`. In Docker mode, use the Compose service name as the hostname (e.g. `http://app:3000`). `localhost` and `127.0.0.1` refer to auth-proxy itself inside the container and cannot be used to reach the upstream service.

```bash
# Check connectivity from the auth-proxy container to the upstream service
docker compose exec auth-proxy wget -qO- http://app:3000 || echo "unreachable"

# Check that both services are on the same network
docker compose ps
docker network inspect <project-name>_internal
```

### Container Won't Start (Proxy Mode Only)

```bash
# View logs including exited containers
docker compose logs auth-proxy

# Check container status
docker compose ps -a
```

---

## Project Structure

```
auth-proxy/
├── Cargo.toml
├── Cargo.lock
├── Dockerfile
├── docker-compose.example.yml
├── .env.auth-proxy.example
├── .dockerignore
├── migrations/                    # SQLite migration files
├── internal/                      # Internal specification documents
└── src/
    ├── main.rs                    # Entry point · CLI dispatch
    ├── config.rs                  # Environment variable loading · mode validation
    ├── users.rs                   # UserStore (Argon2id)
    ├── session.rs                 # SessionStore
    ├── mfa.rs                     # MfaStore (TOTP · backup codes · device tokens)
    ├── state.rs                   # AppState (DB · HTTP client)
    ├── router.rs                  # Route definitions
    ├── handlers/
    │   ├── login.rs               # GET/POST /login
    │   ├── logout.rs              # POST /logout
    │   ├── proxy.rs               # /* fallback (static files or upstream proxy)
    │   ├── mfa.rs                 # MFA verification flow
    │   ├── settings/
    │   │   ├── mod.rs             # GET/POST /settings/mfa/*
    │   │   └── security.rs        # GET/POST /settings/security/*
    │   └── admin/
    │       ├── mod.rs
    │       ├── dashboard.rs       # GET /admin/
    │       └── users.rs           # GET/POST /admin/users/*
    ├── middleware/
    │   ├── auth.rs                # Session validation · X-Auth-* spoofing prevention
    │   └── admin.rs               # Admin role check
    └── cli/
        ├── hash.rs
        ├── verify.rs
        ├── list.rs
        └── init_admin.rs
```

---

## License

MIT
