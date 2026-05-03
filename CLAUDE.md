# CLAUDE.md — auth-proxy

This file provides context for Claude (and other AI agents) working on this repository. Read this before making any changes.

---

## What This Project Is

**auth-proxy** is a single-binary Rust authentication reverse proxy. It sits between a reverse proxy (Traefik, nginx) and upstream services, handling all authentication so that upstream services never need to implement auth themselves.

- Upstream services receive authenticated user identity via `X-Auth-*` headers
- Guest token feature enables time-limited, optionally password-protected shared links
- SQLite is embedded — no external database dependency
- Targets low-resource hardware; memory footprint is a first-class concern

Binary name: `auth-proxy`  
License: MIT

---

## Operating Modes

| Mode | Required env vars | Typical deployment |
|---|---|---|
| Static file mode | `AUTH_PROXY_SERVE_PATH` only | Single binary + systemd |
| Proxy mode | `AUTH_PROXY_UPSTREAM_APP_URL` only | Docker Compose |
| Combined mode | Both set | Docker Compose |

Both vars unset → startup error. This is intentional and enforced in `src/config.rs`.

---

## Architecture

```
src/
├── main.rs              CLI entry point (clap derive). Subcommands: serve, init-admin, list, passwd
├── config.rs            Config struct + from_env(). All env var parsing lives here.
├── db.rs                SQLite pool init + sqlx::migrate!("./migrations")
├── state.rs             AppState (Arc-wrapped stores, passed to all handlers)
├── router.rs            Axum router. Route → handler mapping. Middleware layering.
├── users.rs             UserStore: create/get/verify/update. Argon2id hashing.
├── session.rs           SessionStore: create/get/delete/cleanup
├── guest_token.rs       GuestTokenStore: issue/verify/revoke/cleanup
├── mfa.rs               MfaStore: TOTP (AES-256-GCM encrypted), backup codes, device tokens
├── middleware/
│   ├── auth.rs          auth_middleware: session/guest resolution → AuthContext extension
│   └── admin.rs         admin_middleware: role == Admin check
└── handlers/
    ├── login.rs         GET/POST /login
    ├── logout.rs        GET /logout
    ├── proxy.rs         Fallback handler: verifies AuthContext, adds X-Auth-* headers, proxies
    ├── static_files.rs  Static file serving (AUTH_PROXY_SERVE_PATH mode)
    ├── admin/           /admin/* — user management UI
    ├── guest_token.rs   POST /api/guest-token (API key auth)
    ├── guest_auth.rs    GET/POST /guest-auth (password-protected guest links)
    ├── mfa.rs           GET/POST /mfa/verify, /mfa/backup
    └── settings.rs      /settings/security — password change, MFA setup/disable
migrations/
    001_init.sql
    002_guest_tokens.sql
    003_mfa.sql
    ...
```

---

## Request Flow

```
Incoming request
  └─ auth_middleware
       ├─ Strip all X-Auth-* headers from client (forgery prevention)
       ├─ Check guest_session_id cookie  → AuthContext::Guest
       ├─ Check session_id cookie        → AuthContext::Authenticated
       ├─ Check ?guest_token= query param
       │    ├─ password_hash present → redirect /guest-auth
       │    └─ none → verify_and_increment → AuthContext::Guest
       └─ No auth → redirect /login
            │
            ▼
       handler (proxy / static_files)
            └─ Inject X-Auth-* headers based on AuthContext
```

Guest token failures always return **403**, never redirect to `/login`.

---

## X-Auth-* Headers Forwarded to Upstream

| Header | Value | Notes |
|---|---|---|
| `X-Auth-User` | username | Authenticated only |
| `X-Auth-User-Id` | users.id (integer string) | Authenticated only |
| `X-Auth-Role` | `admin` or `user` | Authenticated only |
| `X-Auth-Guest` | `true` | Guest only |
| `X-Auth-Issuer` | `AUTH_PROXY_ISSUER_NAME` | Always |

---

## Implemented Phases

| Phase | Description |
|---|---|
| Phase 1 | Core proxy, session persistence, SQLite, user cache hot-reload |
| Phase 2 | Web admin UI for user management |
| Phase 3a | TOTP MFA, backup codes, device remembering, brute-force delay |
| Phase 3a-2 | Admin-forced MFA disable, `/settings/security`, self-service password change, MFA status in admin user list |
| Phase 4 | Guest tokens: time-limited, use-count-limited, password-protected, UI metadata |
| Phase Docker | Dockerfile (scratch base, musl static binary), docker-compose.example.yml, .env.auth-proxy.example |

---

## Key Invariants — Never Violate These

**Migration files are append-only.**  
Never edit an existing file under `migrations/`. New schema changes always go in a new numbered file (e.g., `004_*.sql`). Always `ls migrations/` before creating a new one to find the correct next number.

**auth_middleware is the sole authentication gate.**  
No handler should perform its own session/token validation. All auth state arrives via `Extension<AuthContext>`.

**X-Auth-* headers must be stripped before any upstream contact.**  
This is the forgery prevention boundary. Do not remove this logic or move it downstream.

**Use `OsRng`, never `thread_rng`**, for session IDs, guest token IDs, TOTP secrets, device tokens.

**Argon2id operations must run inside `tokio::task::spawn_blocking`.**  
Direct async calls will block the executor.

**Timing attack mitigations must not be removed:**
- Login failure: 500ms delay before returning error
- Backup code verification: iterate all codes, no early return on match
- Guest auth password failure: 500ms delay before re-rendering form
- Invalid guest token vs wrong token: always return 403 (no distinguishing response)

**`use_count` enforcement must be atomic.**  
Use `UPDATE ... WHERE use_count < max_uses RETURNING id`. A separate SELECT+Rust comparison is a race condition.

**Guest token errors always return 403, never redirect to `/login`.**

**TOTP secrets are stored AES-256-GCM encrypted.**  
The key is `AUTH_PROXY_MFA_ENCRYPTION_KEY`. Never store plaintext secrets.

**`/api/guest-token` and `/guest-auth` are outside `auth_middleware`.**  
In Axum 0.8, `layer()` applies to the fallback but not to explicitly defined routes. These routes rely on this behavior. Do not restructure the router in a way that applies `auth_middleware` to them.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `AUTH_PROXY_UPSTREAM_APP_URL` | One of these two is required | — | Upstream service URL |
| `AUTH_PROXY_SERVE_PATH` | One of these two is required | — | Static file root |
| `AUTH_PROXY_DB_PATH` | Yes | — | SQLite file path |
| `AUTH_PROXY_LISTEN_ADDR` | No | `0.0.0.0:8080` | Bind address |
| `AUTH_PROXY_SESSION_TTL_HOURS` | No | `8` | Session lifetime |
| `AUTH_PROXY_ISSUER_NAME` | No | `auth-proxy` | Label in UI and X-Auth-Issuer |
| `AUTH_PROXY_MFA_ENCRYPTION_KEY` | Yes | — | 32-byte hex; encrypts TOTP secrets |
| `AUTH_PROXY_GUEST_TOKEN_SECRET` | Yes | — | 32-byte hex; HMAC key for guest tokens |
| `AUTH_PROXY_GUEST_TOKEN_API_KEY` | Yes | — | Bearer token for POST /api/guest-token |
| `RUST_LOG` | No | `info` | Tracing filter |

---

## Development

```bash
cargo build                          # must pass with zero warnings
cargo test                           # must pass before any PR
cargo build --release \
  --target x86_64-unknown-linux-musl # production static binary (via cross)
```

Tests use in-memory SQLite (`:memory:`). Each test creates its own pool. Do not share pools across tests.

### Test Helpers Pattern

```rust
async fn test_state() -> AppState {
    let pool = db::init(Path::new(":memory:")).await.unwrap();
    // build AppState with test_default config
}
```

### Adding a New Phase

1. `cargo build && cargo test` — confirm baseline is clean
2. Create `migrations/00N_description.sql` — new file, never edit existing
3. Implement Rust code
4. Add unit tests covering: happy path, all error variants, relevant security invariants
5. Update `CLAUDE.md` phase table if a new phase is complete

---

## PR / Issue Review Guidance

**For PRs, verify:**

- [ ] `cargo build` passes with zero warnings
- [ ] `cargo test` passes
- [ ] No existing migration files were modified
- [ ] No authentication logic added inside individual handlers (must go in middleware)
- [ ] `X-Auth-*` header stripping is intact in `auth_middleware`
- [ ] `OsRng` used for all random generation (not `thread_rng`)
- [ ] Argon2 calls are inside `spawn_blocking`
- [ ] Guest token errors return 403, not redirect
- [ ] `use_count` increment is atomic SQL (not Rust-side compare)
- [ ] New env vars are documented in both `config.rs` comments and this file
- [ ] New migration file has correct numeric prefix (check `ls migrations/`)

**For issues, consider:**

- Does this belong in auth-proxy, or in the upstream service? auth-proxy owns authentication only.
- Does this require a new migration? If yes, is it purely additive?
- Does this change the `X-Auth-*` contract? That affects all upstream service integrations.

---

## Dependency Versions (key crates)

```toml
axum          = "0.8"      # with macros feature
sqlx          = "0.8"      # runtime-tokio, sqlite, chrono features
argon2        = "0.5"
hmac          = "0.12"     # must match sha2 version
sha2          = "0.10"
aes-gcm       = "0.10"
totp-rs       = "5"        # with qr feature
chrono        = "0.4"      # with serde feature
rand          = "0.8"
hex           = "0.4"
subtle        = "2"        # constant-time comparison
hyper         = "1"
hyper-util    = "0.1"
```

`hmac` and `sha2` versions must stay in sync (digest trait version dependency).

---

## Spec Document

The canonical design reference is `auth-proxy-spec_v9.md` (or the highest version present in the repo). When this file and the spec conflict, the spec wins for design intent; this file wins for implementation constraints and invariants.

Agent instruction documents (`phase*-agent-instructions.md`) are derived from the spec for use by Haiku agents implementing individual phases. They are one-time-use documents and should not be treated as authoritative after implementation is complete.
