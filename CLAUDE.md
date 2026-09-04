# CLAUDE.md — auth-proxy

This file provides context for Claude (and other AI agents) working on this repository. Read this before making any changes.

---

## What This Project Is

**auth-proxy** is a single-binary Rust authentication reverse proxy. It sits between a reverse proxy (Traefik, nginx) and upstream services, handling all authentication so that upstream services never need to implement auth themselves.

- Upstream services receive authenticated user identity via `X-Auth-*` headers
- Guest token feature is **designed in the spec but not yet implemented** (see "Guest Tokens — Not Yet Implemented" below). It is intended to enable time-limited, optionally password-protected shared links
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
├── state.rs             AppState (Arc-wrapped stores, passed to all handlers). DB init + sqlx::migrate!("./migrations") happens here — there is no separate db.rs.
├── router.rs            Axum router. Route → handler mapping. Middleware layering.
├── users.rs             UserStore: parses the APP_USERS/AUTH_PROXY_USERS seed format only. Not the live user store — see users_db.rs.
├── users_db.rs          UserStoreDb: the live, SQLite-backed user store. create/get/verify/update. Argon2id hashing.
├── session.rs           SessionStore: in-memory implementation, currently unreferenced by AppState or any handler (dead code, kept for its own unit tests). The live session store is sessions_db.rs.
├── sessions_db.rs       SessionStoreDb: the live, SQLite-backed session store. create/get/delete/cleanup.
├── api_tokens_db.rs     ApiTokenStoreDb: issue/verify/revoke Bearer API tokens (SHA-256 hashed, Phase API-1)
├── mfa.rs               MfaStore: TOTP (AES-256-GCM encrypted), backup codes, device tokens
├── middleware/
│   ├── auth.rs          auth_middleware: Bearer-token resolution, then session-cookie resolution, → Extension<AuthUser>. There is no guest-token resolution — see "Guest Tokens — Not Yet Implemented" below.
│   └── admin.rs         Defines the AuthUser struct. Also defines an admin_middleware fn, but it has zero callers (dead code) — admin role checks are done per-handler in handlers/admin/*.rs instead.
└── handlers/
    ├── login.rs         GET/POST /login
    ├── logout.rs        GET /logout
    ├── proxy.rs         Fallback handler: requires Extension<AuthUser>, adds X-Auth-* headers, proxies
    ├── static_files.rs  Static file serving (AUTH_PROXY_SERVE_PATH mode)
    ├── admin/           /admin/* — user management UI (session auth only, see Key Invariants)
    ├── api_tokens.rs    GET/POST /api/tokens, DELETE /api/tokens/{id} (session auth only, Phase API-1)
    ├── mfa.rs           GET/POST /mfa/verify, /mfa/backup
    ├── me.rs            GET /me, /me/password, /me/mfa, /me/devices — stable redirect URLs (Phase Me)
    └── settings/        /settings/security — password change, MFA setup/disable
migrations/
    001_initial.sql
    003_mfa.sql
    004_mfa_add_attempt_count.sql
    005_api_tokens.sql
```

There is no `guest_token.rs` store, no `guest_token.rs`/`guest_auth.rs` handlers, and migration `002` does not exist (a genuine gap in the numbering — the next new migration is `006_*.sql`). See "Guest Tokens — Not Yet Implemented" below.

---

## Request Flow

```
Incoming request
  └─ auth_middleware
       ├─ Strip all X-Auth-* headers from client (forgery prevention)
       ├─ AUTH_PROXY_API_TOKEN_ENABLED && Authorization: Bearer present?
       │    ├─ valid token   → Extension<AuthUser> (auth_method="token"), continue
       │    └─ invalid token → 401 JSON (RFC 6750), never redirect (Phase API-1)
       ├─ Check session_id cookie → Extension<AuthUser> (auth_method="session")
       └─ No auth → handler decides (proxy/static_files redirect to /login;
                     /settings/*, /admin/*, /api/tokens require Extension<AuthUser>
                     via extractor and fail closed if absent)
            │
            ▼
       handler (proxy / static_files / admin / api_tokens / ...)
            └─ Inject X-Auth-* headers based on AuthUser
```

There is currently no guest-token resolution step in this flow — see "Guest Tokens — Not Yet Implemented" below.

---

## X-Auth-* Headers Forwarded to Upstream

| Header | Value | Notes |
|---|---|---|
| `X-Auth-User` | username | Authenticated only |
| `X-Auth-User-Id` | users.id (integer string) | Authenticated only |
| `X-Auth-Role` | `admin` or `user` | Authenticated only |
| `X-Auth-Guest` | `true` | **Not yet implemented** — planned for the guest-token feature, never actually sent today |
| `X-Auth-Issuer` | `AUTH_PROXY_ISSUER_NAME` | Always |
| `X-Auth-Method` | `session` or `token` | Authenticated only (Phase API-1) |
| `X-Auth-Token-Name` | API token's user-assigned name (sanitized) | Token auth only (Phase API-1) |

---

## Implemented Phases

| Phase | Description |
|---|---|
| Phase 1 | Core proxy, session persistence, SQLite, user cache hot-reload |
| Phase 2 | Web admin UI for user management |
| Phase 3a | TOTP MFA, backup codes, device remembering, brute-force delay |
| Phase 3a-2 | Admin-forced MFA disable, `/settings/security`, self-service password change, MFA status in admin user list |
| Phase Docker | Dockerfile (scratch base, musl static binary), docker-compose.example.yml, .env.auth-proxy.example |
| Phase Me | Stable `/me`, `/me/password`, `/me/mfa`, `/me/devices` redirect URLs for upstream app integration |
| Phase API-1 | Bearer API token authentication for non-browser clients (`api_tokens` table, `X-Auth-Method`/`X-Auth-Token-Name` headers, RFC 6750-style 401 JSON errors, opt-in via `AUTH_PROXY_API_TOKEN_ENABLED`). See `docs/note/api-token-auth-runbook.md` and `docs/note/decisions/0001-api-token-bearer-auth.md` |
| Phase API-2 | Web UI for issuing/revoking API tokens: `GET /me/tokens` → `/settings/security/tokens` (list, issue, revoke), linked from `/settings/security`. Session auth only, same `auth_method == "session"` guard as the Phase API-1 JSON API |
| Phase API-3 | Path-scope restriction for API tokens (R7 only — R6 "pairing codes" was evaluated and explicitly rejected, see [ADR 0002](docs/note/decisions/0002-path-scope-accepted-pairing-code-rejected.md)). A token issued with `path_prefix` can only reach request paths starting with that prefix; `auth_middleware` returns `403 insufficient_scope` otherwise. `path_prefix == NULL` (default) keeps full access, unchanged from Phase API-1 |

**Phase 4 ("Guest tokens") is NOT implemented**, despite being listed as done in older versions of this file. See "Guest Tokens — Not Yet Implemented" below.

---

## Guest Tokens — Not Yet Implemented

The spec describes a guest-token feature (time-limited, optionally password-protected shared links,
an `AuthContext::Guest` variant, a `guest_tokens` table, `POST /api/guest-token`, `GET/POST /guest-auth`).
**None of this exists in the codebase today.** Concretely, there is no `guest_token.rs` store, no
`guest_token.rs`/`guest_auth.rs` handlers, no `AuthContext` enum (auth state is a plain `AuthUser` struct
instead), no `guest_tokens` table/migration, and no `/api/guest-token` or `/guest-auth` routes.

What *does* exist as a placeholder: `Config` has `guest_token_secret` / `guest_token_api_key` fields
(parsed from `AUTH_PROXY_GUEST_TOKEN_SECRET` / `AUTH_PROXY_GUEST_TOKEN_API_KEY`), but nothing reads them.

If/when this feature is implemented, carry over these design points from the spec:
- `use_count` enforcement must be atomic SQL (`UPDATE ... WHERE use_count < max_uses RETURNING id`),
  not a separate SELECT+Rust comparison.
- Guest token errors (invalid, expired, wrong password) must always return 403, never redirect to `/login`,
  and must not distinguish "doesn't exist" from "wrong password" in the response.
- A guest auth password failure should have the same ~500ms delay pattern used elsewhere in this codebase
  for failed-credential timing consistency.
- `/api/guest-token` and `/guest-auth` will need to sit outside `auth_middleware` (in Axum 0.8, `layer()`
  applies to the fallback but not to explicitly defined routes — plan the router structure around this).

This section replaces several invariants that appeared in earlier versions of this file as if they were
already enforced in code; they were not (see ADR `docs/note/decisions/0001-api-token-bearer-auth.md` for
how this drift was found and tracked).

---

## Key Invariants — Never Violate These

**Migration files are append-only.**  
Never edit an existing file under `migrations/`. New schema changes always go in a new numbered file (e.g., `004_*.sql`). Always `ls migrations/` before creating a new one to find the correct next number.

**auth_middleware is the sole authentication gate.**  
No handler should perform its own session/token validation. All auth state arrives via `Extension<AuthUser>`.

**X-Auth-* headers must be stripped before any upstream contact.**  
This is the forgery prevention boundary. Do not remove this logic or move it downstream.

**Use `OsRng`, never `thread_rng`**, for session IDs, API token generation, TOTP secrets, device tokens.

**Argon2id operations must run inside `tokio::task::spawn_blocking`.**  
Direct async calls will block the executor.

**Timing attack mitigations must not be removed:**
- Login failure: 500ms delay before returning error
- Backup code verification: iterate all codes, no early return on match

**TOTP secrets are stored AES-256-GCM encrypted.**  
The key is `AUTH_PROXY_MFA_ENCRYPTION_KEY`. Never store plaintext secrets.

**Bearer token auth takes priority over session cookies, and its failures never redirect (Phase API-1).**  
In `auth_middleware`, the `Authorization: Bearer` check runs before the session cookie check. Once a Bearer header is present, the request is treated as an API client: on any failure, return the RFC 6750-style 401 JSON (with `WWW-Authenticate: Bearer`), never a 302 to `/login`. Token auth never sets `Set-Cookie`.

**`POST /api/tokens` and `DELETE /api/tokens/{id}` require session authentication, not token authentication.**  
Check `AuthUser.auth_method == "session"` inside the handler. Allowing a valid API token to mint or revoke other tokens would let a single leaked token escalate into unlimited further tokens.

**A path-scoped API token (`path_prefix` set) must be checked before the user is even looked up (Phase API-3, R7).**  
In `auth_middleware`, the scope check happens right after `ApiTokenStoreDb::verify` succeeds and before `state.users.get_by_id`. On mismatch, return `403 insufficient_scope` — never silently widen access, and never fall through to full access. `path_prefix == None` means unrestricted (Phase API-1 behavior), unchanged.

**Never compare `path_prefix` against a raw, un-normalized request path with plain `starts_with`.**  
`req.uri().path()` never collapses `..`, decodes percent-encoding, or treats `\` as a separator, but `reqwest`'s `Url::parse` (used when forwarding to the upstream in `handlers/proxy.rs`) does all three — including percent-encoded `%2e%2e` in any case combination, and treating a literal `\` exactly like `/` for special schemes (http/https). A prefix match on the raw path alone lets a request like `/sync/%2e%2e/admin` or `/sync/..\admin` pass a `/sync/` scope check while actually resolving to `/admin` upstream. `contains_dot_dot_segment` in `middleware/auth.rs` splits on both `/` and `\` and must run (and reject on any match) before the prefix comparison. Found and fixed via security review (two rounds) — see ADR 0002's addendum.

**`/admin/*` requires session authentication, not just `role == "admin"`.**  
Every handler in `src/handlers/admin/` checks `auth_user.role != "admin" || auth_user.auth_method != "session"`. API tokens carry the owner's real `role`, so without the `auth_method` check, a leaked API token belonging to an admin would grant full admin-panel access (create admins, reset any password, delete users) even though the token was only ever meant to authenticate calls to the proxied upstream app. This was found and fixed via security review — see `docs/note/decisions/0001-api-token-bearer-auth.md`.

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
| `AUTH_PROXY_API_TOKEN_ENABLED` | No | `false` | Enables Bearer API token auth (Phase API-1). Opt-in for backward compat |
| `AUTH_PROXY_API_TOKEN_DEFAULT_TTL_DAYS` | No | `0` | Default expiry (days) for newly issued API tokens. `0` = no expiry |
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
