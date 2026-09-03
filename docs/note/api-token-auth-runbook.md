# Runbook: API トークン認証（Phase API-1）実装手順書

**元提案**: [`docs/auth-proxy-api-token-proposal_v1.md`](../auth-proxy-api-token-proposal_v1.md)
**関連ADR**: [`decisions/0001-api-token-bearer-auth.md`](decisions/0001-api-token-bearer-auth.md)
**作成日**: 2026-09-03
**対象ブランチ**: `dev`
**ステータス**: 未着手（実装計画段階）

このドキュメントは、提案書の Phase API-1（R1・R2・R3・R5 = Bearer トークン認証の中核）を
実装するための具体的な手順書である。R4（Web UI）以降は別フェーズ・別runbookとする（後述）。

---

## 0. 着手前に必ず確認すること

### 0.1 【最優先・本提案とは無関係のブロッカー】現在 dev ブランチはビルドが失敗する

`cargo check` を実行すると `src/handlers/me.rs:119` で構文エラーになることを確認済み（
直近コミット `fbf2421 Update src/handlers/me.rs` 由来、`0e4d6ce` の "まだデプロイ後のテスト
はしていない" というメッセージとも符合する）。

```
error: unexpected closing delimiter: `}`
  --> src/handlers/me.rs:119:1
```

CLAUDE.md の運用ルール「`cargo build && cargo test` — confirm baseline is clean」を満たせない
状態なので、**この API トークン機能の実装に着手する前に、まず `me.rs` の構文エラーを別PRで
修正し、`cargo build`/`cargo test` がグリーンになることを確認すること。**
本 runbook の手順は、その前提が満たされた状態からの差分として書かれている。

### 0.2 CLAUDE.md の記述と実コードの乖離（実装者向け注意）

CLAUDE.md はアーキテクチャ節で `db.rs` / `session.rs`(SessionStore として) / `guest_token.rs` /
`guest_auth.rs` / `AuthContext` enum / migrations の `002_guest_tokens.sql` などに言及しているが、
**現在の dev ブランチにはこれらは存在しない**。実際の構成は以下の通り。

| CLAUDE.md の記述 | 実際 |
|---|---|
| `db.rs` | 存在しない。DB初期化・マイグレーション実行は `state.rs::AppState::new_internal` 内 |
| `session.rs`（SessionStore、Cookie検証） | `session.rs` は存在するが**インメモリ版で未使用の可能性が高い**（`HashMap`実装）。実際にセッション管理しているのは `sessions_db.rs::SessionStoreDb`（SQLite） |
| `guest_token.rs` / `guest_auth.rs` / Phase 4 完了 | **未実装**。`config.rs` に `guest_token_secret` / `guest_token_api_key` フィールドは存在するが、router・handlers 側に対応する実装がない |
| `AuthContext::Authenticated` / `AuthContext::Guest` enum | 存在しない。代わりに `middleware/admin.rs` 定義の `AuthUser` 構造体（`{id, username, role}`）を `Extension<AuthUser>` として使う、より単純な設計 |
| migrations: `001_init.sql`, `002_guest_tokens.sql`, `003_mfa.sql`... | 実際は `001_initial.sql`, `003_mfa.sql`, `004_mfa_add_attempt_count.sql`（**002が欠番**） |

→ 本 runbook は **実コードベースの構造**（`AuthUser` 構造体、`*_db.rs` 命名規則）に合わせて設計する。
CLAUDE.md のアーキテクチャ表を鵜呑みにしないこと。

### 0.3 マイグレーション番号

`ls migrations/` の結果、既存の最大番号は `004`。**新規マイグレーションは `005_api_tokens.sql`**
とする（CLAUDE.mdの規則通り、既存ファイルは一切編集しない）。

### 0.4 不足している依存クレート

`sha2` は `Cargo.toml` に未追加。提案のハッシュ方式（SHA-256）を実装するために追加が必要。
`hmac` は今回不要（HMAC ではなく単純な SHA-256 ダイジェストを使う設計のため）。

---

## 1. スコープ（このrunbookで実装する範囲）

提案書 §10 のフェーズ分割に従う。

| フェーズ | 内容 | 本runbookの対象か |
|---|---|---|
| **Phase API-1** | R1（Bearerミドルウェア）+ R2（`api_tokens`テーブル）+ R3（401 JSON応答）+ R5（`X-Auth-Method`） | **✅ 対象** |
| Phase API-2 | R4（トークン発行・失効のWeb UI、`/me/tokens`） | ❌ 別runbookで実施 |
| Phase API-3 | R6（ペアリングコード）+ R7（パススコープ制限） | ❌ 未着手・要ADR |
| Phase API-4 | R8（レート制限）+ R9（CLI）+ R10（管理画面） | ❌ 未着手・要ADR |

Phase API-1 が完了すると、`api_tokens` テーブルへの直接 INSERT でトークンを払い出し、
Bearer 認証で上流にアクセスできるようになる（timetrack 側のブロッカー解消条件、提案書 §10 参照）。
UI がないため運用は手作業になるが、それは Phase API-2 まで許容する設計判断（ADR参照）。

---

## 2. 変更対象ファイル

### 新規作成

| ファイル | 内容 |
|---|---|
| `migrations/005_api_tokens.sql` | `api_tokens` テーブル定義 |
| `src/api_tokens_db.rs` | `ApiTokenStoreDb`：トークン生成・検証・失効ストア（`users_db.rs`/`sessions_db.rs` と同じ命名規則） |

### 変更

| ファイル | 変更内容 |
|---|---|
| `Cargo.toml` | `sha2 = "0.10"` を追加 |
| `src/config.rs` | `api_token_enabled: bool`, `api_token_default_ttl_days: u32` を追加 |
| `src/state.rs` | `AppState` に `api_tokens: Arc<ApiTokenStoreDb>` を追加。`new_internal` / `test()` 両方で初期化 |
| `src/middleware/admin.rs` | `AuthUser` に `auth_method: String`（`"session"` / `"token"`）, `token_name: Option<String>` を追加 |
| `src/middleware/auth.rs` | 先頭に Bearer トークン判定を追加。ヘッダーストリップ対象に `x-auth-method` / `x-auth-token-name` を追加 |
| `src/handlers/mod.rs` | `pub mod api_tokens;` を追加 |
| `src/handlers/api_tokens.rs`（新規） | `GET/POST /api/tokens`, `DELETE /api/tokens/{id}` ハンドラー |
| `src/router.rs` | 上記3ルートを追加 |
| `src/lib.rs` | `pub mod api_tokens_db;` を追加 |
| `.env.auth-proxy.example` | `AUTH_PROXY_API_TOKEN_ENABLED`, `AUTH_PROXY_API_TOKEN_DEFAULT_TTL_DAYS` の説明を追加 |
| `CLAUDE.md` | Implemented Phases 表に `Phase API-1` を追記（完了後）。§0.2で指摘した既存の乖離修正は本タスクのスコープ外（別途Issue化を推奨） |

---

## 3. 実装手順

### 3.1 依存関係追加

`Cargo.toml` の `[dependencies]` に追加：

```toml
sha2 = "0.10"
```

### 3.2 マイグレーション `migrations/005_api_tokens.sql`

提案書 §5 R2 の DDL をそのまま採用する（追加のみ、既存テーブル無変更）。

```sql
CREATE TABLE IF NOT EXISTS api_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    token_hash    TEXT    NOT NULL UNIQUE,  -- SHA-256 hex（平文は保存しない）
    name          TEXT    NOT NULL,
    path_prefix   TEXT,                      -- Phase API-3 (R7) まで未使用。NULLのみ許容
    expires_at    TEXT,
    last_used_at  TEXT,
    revoked_at    TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id    ON api_tokens(user_id);
```

`path_prefix` カラムは Phase API-3 (R7) 向けに先行して用意するが、Phase API-1 の実装では
常に `NULL` を書き込み、検証ロジックでも参照しない（YAGNI に反しない範囲での先行スキーマ確保。
カラム追加は破壊的変更なので、後から追加するより今 NULL 許容で用意する方が安全という判断）。

### 3.3 `src/config.rs` の拡張

`Config` 構造体に追加：

```rust
pub api_token_enabled: bool,
pub api_token_default_ttl_days: u32, // 0 = 無期限
```

`from_env()` に追加（デフォルト `false` / `0` を厳守。提案書§6の「後方互換のためデフォルトfalse」
という設計思想通り）：

```rust
let api_token_enabled = std::env::var("AUTH_PROXY_API_TOKEN_ENABLED")
    .map(|v| v == "true" || v == "1")
    .unwrap_or(false);

let api_token_default_ttl_days: u32 = std::env::var("AUTH_PROXY_API_TOKEN_DEFAULT_TTL_DAYS")
    .unwrap_or_else(|_| "0".to_string())
    .parse()
    .unwrap_or(0);
```

`test_default()` にも両フィールドを追加すること（`api_token_enabled: true` にしてテストで
経路を有効化できるようにする）。

### 3.4 `src/api_tokens_db.rs`（新規）

`users_db.rs` / `sessions_db.rs` と同じ構造で実装する。

```rust
use sqlx::SqlitePool;
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use thiserror::Error;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiTokenRow {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub path_prefix: Option<String>,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Error)]
pub enum ApiTokenDbError {
    #[error("Database error: {0}")]
    DbError(#[from] sqlx::Error),
}

pub struct ApiTokenStoreDb {
    pool: SqlitePool,
}

impl ApiTokenStoreDb {
    pub fn new(pool: SqlitePool) -> Self { Self { pool } }

    /// 平文トークンを生成する。 `(plaintext, sha256_hex)` を返す。
    /// 乱数は既存方針通り OsRng を使用（thread_rng禁止）。
    pub fn generate_token() -> (String, String) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let plaintext = format!("apx_{}", URL_SAFE_NO_PAD.encode(bytes));
        let hash = Self::hash_token(&plaintext);
        (plaintext, hash)
    }

    pub fn hash_token(plaintext: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(plaintext.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// トークンを発行してDBに保存する。ttl_days=0 なら無期限。
    pub async fn create(
        &self, user_id: i64, name: &str, ttl_days: u32,
    ) -> Result<(ApiTokenRow, String), ApiTokenDbError> {
        let (plaintext, hash) = Self::generate_token();
        let expires_at = if ttl_days > 0 {
            Some((Utc::now() + chrono::Duration::days(ttl_days as i64)).to_rfc3339())
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO api_tokens (user_id, token_hash, name, expires_at) VALUES (?, ?, ?, ?)"
        )
        .bind(user_id).bind(&hash).bind(name).bind(&expires_at)
        .execute(&self.pool).await?;

        let row = sqlx::query_as::<_, ApiTokenRow>(
            "SELECT id, user_id, name, path_prefix, expires_at, last_used_at, revoked_at, created_at
             FROM api_tokens WHERE token_hash = ?"
        )
        .bind(&hash)
        .fetch_one(&self.pool).await?;

        Ok((row, plaintext))
    }

    /// ハッシュから有効なトークンを検証する。
    /// 失効済み・期限切れ・存在しない場合は None。
    pub async fn verify(&self, token_hash: &str) -> Result<Option<ApiTokenRow>, ApiTokenDbError> {
        let row = sqlx::query_as::<_, ApiTokenRow>(
            "SELECT id, user_id, name, path_prefix, expires_at, last_used_at, revoked_at, created_at
             FROM api_tokens
             WHERE token_hash = ?
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > datetime('now'))"
        )
        .bind(token_hash)
        .fetch_optional(&self.pool).await?;
        Ok(row)
    }

    /// last_used_at をスロットリング更新する（5分に1回まで）。
    /// 提案書§5 R1の注意事項：毎リクエストUPDATEはSQLite書き込みロック多発の原因になる。
    pub async fn touch_last_used(&self, id: i64) -> Result<(), ApiTokenDbError> {
        sqlx::query(
            "UPDATE api_tokens SET last_used_at = datetime('now')
             WHERE id = ? AND (last_used_at IS NULL OR last_used_at < datetime('now', '-5 minutes'))"
        )
        .bind(id)
        .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn list_for_user(&self, user_id: i64) -> Result<Vec<ApiTokenRow>, ApiTokenDbError> {
        let rows = sqlx::query_as::<_, ApiTokenRow>(
            "SELECT id, user_id, name, path_prefix, expires_at, last_used_at, revoked_at, created_at
             FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool).await?;
        Ok(rows)
    }

    /// 失効。所有者チェックは呼び出し側（ハンドラー）で行う。
    pub async fn revoke(&self, id: i64, user_id: i64) -> Result<bool, ApiTokenDbError> {
        let result = sqlx::query(
            "UPDATE api_tokens SET revoked_at = datetime('now')
             WHERE id = ? AND user_id = ? AND revoked_at IS NULL"
        )
        .bind(id).bind(user_id)
        .execute(&self.pool).await?;
        Ok(result.rows_affected() > 0)
    }
}
```

**実装上の注意点（レビュー観点）**:
- `verify()` は SELECT のみで `use_count` のような可変カウンタを扱わないため、CLAUDE.mdの
  「`use_count` はSQL側でアトミックに」というルールは本機能には直接該当しない（ゲストトークン
  固有のルール）。ただし `revoke()` は `revoked_at IS NULL` を WHERE 句に含めることで、
  二重失効や競合を避けている。
- `touch_last_used` の WHERE 句自体がアトミックな「5分以上経過していたら更新」条件になっており、
  Rust側で比較してからUPDATEする二段階処理ではない点に注意（提案書の推奨する緩和策と一致）。

### 3.5 `src/state.rs` の拡張

```rust
use crate::api_tokens_db::ApiTokenStoreDb;
// ...
pub struct AppState {
    // ...既存フィールド...
    pub api_tokens: Arc<ApiTokenStoreDb>,
}
```

`new_internal()` と `test()` の両方で `Arc::new(ApiTokenStoreDb::new(db.clone()))` を追加。
（`test()` を更新し忘れると既存テストが軒並みコンパイルエラーになるので要注意）

### 3.6 `AuthUser` の拡張（`src/middleware/admin.rs`）

```rust
#[derive(Clone)]
pub struct AuthUser {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub auth_method: String,        // "session" | "token"
    pub token_name: Option<String>, // トークン認証時のみ Some
}
```

**構築箇所は現状 `src/middleware/auth.rs` の1箇所のみ**（grep で事前確認すること）。
既存のセッション経路での構築を `auth_method: "session".to_string(), token_name: None` に更新する。

### 3.7 `src/middleware/auth.rs` の改修（本フェーズの中核）

現在のロジックの先頭に Bearer 判定を追加する。**処理順序が権限昇格防止の要**なので、
以下の順序を厳守すること（提案書§7.1・CLAUDE.mdの既存不変条件の両方に対応）。

```
1. クライアント由来の x-auth-* ヘッダーを全て除去
   （既存4種 + 新規2種: x-auth-method, x-auth-token-name）
2. api_token_enabled == true かつ Authorization: Bearer が存在する場合:
     a. トークンを検証
     b. 成功 → AuthUser構築（auth_method="token"）→ ヘッダー付与 → next.run() → return
     c. 失敗 → 401 JSON を即座に返す（next.run() を呼ばない。/login にリダイレクトしない）
3. 上記に該当しない場合: 既存のセッションCookie判定（従来通り）
     - 成功時は auth_method="session" をセットし、x-auth-method: session ヘッダーも付与する
     - 失敗時は従来通り何もせず next.run() で継続（下流ハンドラーが/loginへリダイレクト判断）
```

実装イメージ：

```rust
use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use crate::AppState;
use crate::middleware::{extract_session_id, admin::AuthUser};
use crate::api_tokens_db::ApiTokenStoreDb;

const BEARER_PREFIX: &str = "Bearer ";

/// トークン認証失敗時の統一レスポンス(RFC 6750準拠のerror語彙)
fn invalid_token_response() -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "invalid_token",
            "error_description": "The access token is invalid or has been revoked"
        })),
    ).into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer"),
    );
    resp
}

/// ヘッダー値として安全な文字列にサニタイズする(改行・制御文字除去)。
/// X-Auth-Token-Name はユーザー入力(トークン名)なのでヘッダーインジェクション対策必須。
fn sanitize_header_value(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    // 1. クライアント由来のX-Auth-*を全て除去(新規2種を含む)
    for h in ["x-auth-user", "x-auth-user-id", "x-auth-role", "x-auth-issuer",
              "x-auth-method", "x-auth-token-name"] {
        req.headers_mut().remove(h);
    }

    // 2. Bearerトークン判定(セッションCookie判定より先に行う)
    if state.config.api_token_enabled {
        if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix(BEARER_PREFIX) {
                    // Authorization: Bearer が存在する時点でAPIクライアント確定。
                    // 以降どの分岐でも 401 JSON を返す。302 /login にフォールバックしない。
                    let token_hash = ApiTokenStoreDb::hash_token(token);
                    let verified = state.api_tokens.verify(&token_hash).await.ok().flatten();

                    let Some(token_row) = verified else {
                        return invalid_token_response();
                    };
                    let Ok(Some(user)) = state.users.get_by_id(token_row.user_id).await else {
                        return invalid_token_response();
                    };

                    // last_used_at はスロットリング更新(失敗しても認証結果には影響させない)
                    let _ = state.api_tokens.touch_last_used(token_row.id).await;

                    let safe_token_name = sanitize_header_value(&token_row.name);

                    if let Ok(v) = HeaderValue::from_str(&user.username) {
                        req.headers_mut().insert("x-auth-user", v);
                    }
                    if let Ok(v) = HeaderValue::from_str(&user.id.to_string()) {
                        req.headers_mut().insert("x-auth-user-id", v);
                    }
                    if let Ok(v) = HeaderValue::from_str(&user.role) {
                        req.headers_mut().insert("x-auth-role", v);
                    }
                    if let Ok(v) = HeaderValue::from_str(&state.config.issuer_name) {
                        req.headers_mut().insert("x-auth-issuer", v);
                    }
                    req.headers_mut().insert("x-auth-method", HeaderValue::from_static("token"));
                    if let Ok(v) = HeaderValue::from_str(&safe_token_name) {
                        req.headers_mut().insert("x-auth-token-name", v);
                    }

                    req.extensions_mut().insert(AuthUser {
                        id: user.id,
                        username: user.username.clone(),
                        role: user.role.clone(),
                        auth_method: "token".to_string(),
                        token_name: Some(token_row.name.clone()),
                    });

                    return next.run(req).await;
                }
            }
        }
    }

    // 3. 既存のセッションCookie判定(従来通り)
    if let Ok(session_id) = extract_session_id(req.headers()) {
        if let Ok(Some(session)) = state.sessions.get(&session_id).await {
            if let Ok(Some(user)) = state.users.get_by_id(session.user_id).await {
                if let Ok(v) = HeaderValue::from_str(&user.username) {
                    req.headers_mut().insert("x-auth-user", v);
                }
                if let Ok(v) = HeaderValue::from_str(&session.user_id.to_string()) {
                    req.headers_mut().insert("x-auth-user-id", v);
                }
                if let Ok(v) = HeaderValue::from_str(&user.role) {
                    req.headers_mut().insert("x-auth-role", v);
                }
                if let Ok(v) = HeaderValue::from_str(&state.config.issuer_name) {
                    req.headers_mut().insert("x-auth-issuer", v);
                }
                req.headers_mut().insert("x-auth-method", HeaderValue::from_static("session"));

                req.extensions_mut().insert(AuthUser {
                    id: user.id,
                    username: user.username.clone(),
                    role: user.role.clone(),
                    auth_method: "session".to_string(),
                    token_name: None,
                });

                return next.run(req).await;
            }
        }
    }

    // 未認証。下流ハンドラー(proxy_handler等)が /login へのリダイレクトを判断する。
    next.run(req).await
}
```

**Set-Cookie を返さないこと**（提案書§5 R3）: 上記実装はトークン経路で `Set-Cookie` を
一切発行していないため、この要件は自然に満たされる。実装時にこの分岐へ誤って
`session.create()` 等を呼び足さないよう注意。

### 3.8 `POST /api/tokens` 系ハンドラー（`src/handlers/api_tokens.rs`、新規）

**最重要のセキュリティ要件（提案書§5 R4・§9「権限昇格の防止」）**:
トークン認証でこのエンドポイント群を叩けてはならない。`AuthUser.auth_method == "token"` の
場合は明示的に拒否する。

```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use serde::{Deserialize, Serialize};
use crate::AppState;
use crate::middleware::AuthUser;

/// トークン認証経路からのアクセスを拒否する。
/// 権限昇格の連鎖(盗まれたトークンで新規トークンを無限発行される)を防ぐガード。
fn require_session_auth(auth_user: &AuthUser) -> Result<(), Response> {
    if auth_user.auth_method != "session" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "insufficient_scope",
                "error_description": "Token issuance requires session authentication"
            })),
        ).into_response());
    }
    Ok(())
}

#[derive(Serialize)]
struct TokenSummary {
    id: i64,
    name: String,
    last_used_at: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    revoked: bool,
}

/// GET /api/tokens - 自分のトークン一覧(ハッシュは含めない)
pub async fn list_tokens(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(resp) = require_session_auth(&auth_user) { return resp; }

    let rows = state.api_tokens.list_for_user(auth_user.id).await.unwrap_or_default();
    let summaries: Vec<TokenSummary> = rows.into_iter().map(|r| TokenSummary {
        id: r.id, name: r.name, last_used_at: r.last_used_at,
        created_at: r.created_at, expires_at: r.expires_at,
        revoked: r.revoked_at.is_some(),
    }).collect();

    Json(summaries).into_response()
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    id: i64,
    name: String,
    token: String, // 平文。このレスポンスのみに含まれる
}

/// POST /api/tokens - 新規発行
pub async fn create_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(body): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_session_auth(&auth_user) { return resp; }

    let ttl_days = state.config.api_token_default_ttl_days;
    match state.api_tokens.create(auth_user.id, &body.name, ttl_days).await {
        Ok((row, plaintext)) => Json(CreateTokenResponse {
            id: row.id, name: row.name, token: plaintext,
        }).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// DELETE /api/tokens/{id} - 失効
pub async fn revoke_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if let Err(resp) = require_session_auth(&auth_user) { return resp; }

    // revoke()内部でuser_id一致を条件にしているため、他人のトークンは
    // rows_affected=0 となり、存在有無に関わらず404を返せる(情報漏洩防止)。
    match state.api_tokens.revoke(id, auth_user.id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
```

`require_session_auth` の戻り値型 `Result<(), Response>` はサンプルの簡略表記。実装時は
`axum::response::Response` を正しくインポートし、`impl IntoResponse` との整合を取ること
（コンパイル時に型調整が必要になる可能性が高い箇所）。

### 3.9 `src/router.rs` へのルート追加

```rust
.route("/api/tokens", get(handlers::api_tokens::list_tokens).post(handlers::api_tokens::create_token))
.route("/api/tokens/{id}", axum::routing::delete(handlers::api_tokens::revoke_token))
```

**重要**: これらのルートは既存の `/admin/*` 等と同様に、末尾の `.layer(auth_middleware)` の
対象内に置く（`auth_middleware` が `Extension<AuthUser>` をセットしないと、ハンドラー側の
`Extension<AuthUser>` 抽出が失敗して 500 になる）。CLAUDE.md が言及する「`/api/guest-token` は
`auth_middleware` の対象外」という axum 0.8 の `layer()`/`fallback()` の挙動上の注意点は、
**このエンドポイントには適用されない**（`/api/tokens` は明示ルートであり fallback ではないため、
通常通り `.layer()` が効く。ゲストトークン機能自体が現状未実装なので、実機で必ず動作確認すること）。

### 3.10 `src/lib.rs` / `src/handlers/mod.rs` へのモジュール登録

```rust
// lib.rs
pub mod api_tokens_db;

// handlers/mod.rs
pub mod api_tokens;
```

### 3.11 ドキュメント更新

`.env.auth-proxy.example` に追記：

```dotenv
# API トークン認証機能の有効化。デフォルト false(既存利用者への後方互換のため)
# AUTH_PROXY_API_TOKEN_ENABLED=true

# 発行するトークンのデフォルト有効期限(日数)。0または未設定で無期限
# AUTH_PROXY_API_TOKEN_DEFAULT_TTL_DAYS=0
```

`AUTH_PROXY_PAIRING_CODE_TTL_MINUTES` / `AUTH_PROXY_API_TOKEN_RATE_LIMIT` は
Phase API-3/4 まで追加しない(使われない環境変数をドキュメントに書くと運用者を混乱させるため)。

---

## 4. テスト計画（提案書§9 → 実装マッピング)

すべて `#[cfg(test)] mod tests` として各実装ファイル内に配置する(既存の慣習通り、
`tests/` ディレクトリは現状使われていない)。

| 提案書の観点 | テスト配置先 | 概要 |
|---|---|---|
| 有効なトークンで正しい `X-Auth-User-Id` が付与される | `middleware/auth.rs` | axum-test で `/`(fallback) にBearer付きリクエストを送り、上流モックへのヘッダーを検証 |
| 失効済み/期限切れ/存在しないトークンで401 | `api_tokens_db.rs::verify` の単体テスト + `middleware/auth.rs` の結合テスト | `revoked_at` セット済み・`expires_at`過去・未INSERTの3パターン |
| Bearer形式でない場合セッション認証にフォールバック | `middleware/auth.rs` | `Authorization: Basic ...` 等でセッションCookieが有効なら通ることを確認 |
| 302ではなく401、JSON、WWW-Authenticate付与 | `middleware/auth.rs` | レスポンスstatus・content-type・ヘッダーをアサート |
| **トークン認証成功時にSet-Cookieが返らない**(★重要) | `middleware/auth.rs` | レスポンスヘッダーに `set-cookie` が存在しないことを確認 |
| **Authorization: Bearer + X-Auth-Role: admin同時送信でも上流のロールは正しい**(★最重要) | `middleware/auth.rs` | クライアントヘッダーの除去 → 検証結果のロールで上書き、の順序を直接検証する回帰テスト。CLAUDE.mdの「処理順序を明示的にテストすること」に対応 |
| 一般ユーザーのトークンで`/admin/*`アクセス403 | `handlers/admin/dashboard.rs`等の既存テストに、token由来のAuthUserケースを追加 | `admin_middleware`は未配線(dead code)であり、各ハンドラー内のrole比較が効くことを利用 |
| トークン認証で`POST /api/tokens`を叩けない | `handlers/api_tokens.rs` | `auth_method="token"`のAuthUserで`require_session_auth`が403を返すことを確認 |
| 平文トークンは発行レスポンスのみ、一覧APIには含まれない | `handlers/api_tokens.rs` | `TokenSummary`に`token`フィールドが存在しないことは型で保証されるが、JSON出力の回帰テストも用意する |
| 他ユーザーのトークンを失効できない | `api_tokens_db.rs::revoke` | 別ユーザーIDで`revoke`を呼び`rows_affected=0`(false)になることを確認 |

R6(ペアリング)・R7(パススコープ)のテスト項目は Phase API-1 の対象外のため、本フェーズでは実装しない。

---

## 5. ロールアウト手順

1. `cargo build` / `cargo test` がゼロ警告でグリーンであることを確認(§0.1のブロッカー解消が前提)
2. `.env.auth-proxy` で `AUTH_PROXY_API_TOKEN_ENABLED` を**設定しない**状態でも既存動作が
   変わらないことを手動確認(後方互換性の確認、提案書§8)
3. 開発環境で `AUTH_PROXY_API_TOKEN_ENABLED=true` にし、`api_tokens` テーブルへ直接INSERT
   (または `POST /api/tokens` 経由)してトークンを払い出し、`curl` で以下を確認:
   ```bash
   curl -i -H "Authorization: Bearer apx_xxx" https://example.com/sync/v1/logs
   # → 上流に X-Auth-User / X-Auth-User-Id / X-Auth-Role / X-Auth-Method: token が渡ることを
   #   上流側ログ or モックサーバーで確認
   curl -i -H "Authorization: Bearer apx_invalid" https://example.com/sync/v1/logs
   # → 401 + JSON + WWW-Authenticate: Bearer
   ```
4. `RUST_LOG=debug` でトークン文字列が平文でログに出力されないことを確認(提案書§7.2)。
   現状 `tracing` の呼び出しにリクエストヘッダー全体をダンプする箇所がないか grep で確認。
5. マイグレーションが追加のみであることを最終確認(`005_api_tokens.sql`が既存テーブルに触れていないか)。

---

## 6. Definition of Done (Phase API-1)

- [ ] `cargo build` ゼロ警告
- [ ] `cargo test` 全パス(上記テスト計画の全項目を含む)
- [ ] 既存マイグレーションファイルを変更していない
- [ ] `auth_middleware`以外の場所でセッション/トークン検証を行っていない
- [ ] `X-Auth-*`(新規2種含む)のクライアント由来ヘッダー除去が維持されている
- [ ] 乱数生成に`OsRng`のみ使用(`thread_rng`不使用)
- [ ] トークン認証失敗は常に401、302リダイレクトなし
- [ ] `AUTH_PROXY_API_TOKEN_ENABLED`未設定時に既存動作へ影響なし
- [ ] `.env.auth-proxy.example` / CLAUDE.md Implemented Phases 表を更新

---

## 7. 次フェーズへの引き継ぎ事項

- **Phase API-2(R4 Web UI)**: `/me/tokens` → `/settings/security/tokens` のリダイレクト規約
  (提案書§5 R4)は既存の`handlers/me.rs`のパターンに倣うこと。ただし現在`me.rs`自体が
  壊れているため(§0.1)、まずそちらの健全化を待つ。
- **Phase API-3(R6/R7)**: パススコープ(`path_prefix`)のカラムは本フェーズで先行して
  スキーマに用意済み。検証ロジック追加のみで対応可能な設計にしてある。ペアリングコードは
  新規テーブル`pairing_codes`が必要(提案書§5 R6)。未認証エンドポイントになるため、
  タイミング攻撃対策を含め別ADRでレビューすること。
- **Phase API-4(R8/R9/R10)**: レート制限は「メモリ上のカウンタで十分」という提案書の判断
  (§5 R8)をADRとして正式に承認するかどうか、実装前に判断が必要。
