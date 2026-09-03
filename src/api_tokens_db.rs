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

const SELECT_COLUMNS: &str =
    "id, user_id, name, path_prefix, expires_at, last_used_at, revoked_at, created_at";

pub struct ApiTokenStoreDb {
    pool: SqlitePool,
}

impl ApiTokenStoreDb {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Generate a new plaintext token and its SHA-256 hex digest.
    /// Uses OsRng only (thread_rng is disallowed by project policy).
    pub fn generate_token() -> (String, String) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let plaintext = format!("apx_{}", URL_SAFE_NO_PAD.encode(bytes));
        let hash = Self::hash_token(&plaintext);
        (plaintext, hash)
    }

    /// Hash a token (including its `apx_` prefix) with SHA-256.
    /// SHA-256 (not Argon2id) is intentional: the token is a 256-bit random
    /// value, not a low-entropy human secret, so a slow KDF buys no real
    /// protection while adding latency to every request.
    pub fn hash_token(plaintext: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(plaintext.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Issue a new token for a user and persist its hash.
    /// `ttl_days == 0` means no expiration. `path_prefix == None` means the
    /// token can access every path (Phase API-1 behavior); `Some(prefix)`
    /// restricts it to paths starting with `prefix` (Phase API-3, R7).
    /// Returns the stored row together with the plaintext token, which is
    /// never persisted and must only be returned to the caller once.
    pub async fn create(
        &self,
        user_id: i64,
        name: &str,
        ttl_days: u32,
        path_prefix: Option<&str>,
    ) -> Result<(ApiTokenRow, String), ApiTokenDbError> {
        let (plaintext, hash) = Self::generate_token();
        let expires_at = if ttl_days > 0 {
            Some((Utc::now() + chrono::Duration::days(ttl_days as i64)).to_rfc3339())
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO api_tokens (user_id, token_hash, name, expires_at, path_prefix) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(&hash)
        .bind(name)
        .bind(&expires_at)
        .bind(path_prefix)
        .execute(&self.pool)
        .await?;

        let row = sqlx::query_as::<_, ApiTokenRow>(&format!(
            "SELECT {SELECT_COLUMNS} FROM api_tokens WHERE token_hash = ?"
        ))
        .bind(&hash)
        .fetch_one(&self.pool)
        .await?;

        Ok((row, plaintext))
    }

    /// Verify a token hash. Returns None if the token does not exist, is
    /// revoked, or has expired. This is a pure SELECT: `api_tokens` has no
    /// use-count semantics, so there is no compare-then-update race here.
    pub async fn verify(&self, token_hash: &str) -> Result<Option<ApiTokenRow>, ApiTokenDbError> {
        let row = sqlx::query_as::<_, ApiTokenRow>(&format!(
            "SELECT {SELECT_COLUMNS} FROM api_tokens
             WHERE token_hash = ?
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > datetime('now'))"
        ))
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Throttled last_used_at update: only writes if more than 5 minutes
    /// have passed since the last write, avoiding a write on every single
    /// request (SQLite write-lock contention). The condition is evaluated
    /// atomically in the WHERE clause, not via a separate SELECT+compare.
    pub async fn touch_last_used(&self, id: i64) -> Result<(), ApiTokenDbError> {
        sqlx::query(
            "UPDATE api_tokens SET last_used_at = datetime('now')
             WHERE id = ? AND (last_used_at IS NULL OR last_used_at < datetime('now', '-5 minutes'))",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_for_user(&self, user_id: i64) -> Result<Vec<ApiTokenRow>, ApiTokenDbError> {
        let rows = sqlx::query_as::<_, ApiTokenRow>(&format!(
            "SELECT {SELECT_COLUMNS} FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC"
        ))
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Revoke a token. The `user_id` match is enforced in SQL so a caller
    /// can never revoke another user's token, and the caller cannot
    /// distinguish "not yours" from "does not exist" (both return false).
    pub async fn revoke(&self, id: i64, user_id: i64) -> Result<bool, ApiTokenDbError> {
        let result = sqlx::query(
            "UPDATE api_tokens SET revoked_at = datetime('now')
             WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> (SqlitePool, ApiTokenStoreDb, i64) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let test_hash = "$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0";
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("alice")
            .bind(test_hash)
            .bind("user")
            .execute(&pool)
            .await
            .unwrap();

        let store = ApiTokenStoreDb::new(pool.clone());
        (pool, store, 1)
    }

    #[test]
    fn test_generate_token_has_prefix_and_is_unique() {
        let (t1, h1) = ApiTokenStoreDb::generate_token();
        let (t2, h2) = ApiTokenStoreDb::generate_token();
        assert!(t1.starts_with("apx_"));
        assert!(t2.starts_with("apx_"));
        assert_ne!(t1, t2);
        assert_ne!(h1, h2);
        // SHA-256 hex digest is 64 chars
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_token_deterministic() {
        let h1 = ApiTokenStoreDb::hash_token("apx_fixed");
        let h2 = ApiTokenStoreDb::hash_token("apx_fixed");
        assert_eq!(h1, h2);
    }

    #[tokio::test]
    async fn test_create_and_verify_token() {
        let (_pool, store, user_id) = setup_test_db().await;
        let (row, plaintext) = store.create(user_id, "Alice's MacBook", 0, None).await.unwrap();
        assert_eq!(row.user_id, user_id);
        assert!(row.expires_at.is_none());

        let hash = ApiTokenStoreDb::hash_token(&plaintext);
        let verified = store.verify(&hash).await.unwrap();
        assert!(verified.is_some());
        assert_eq!(verified.unwrap().id, row.id);
    }

    #[tokio::test]
    async fn test_verify_unknown_token_returns_none() {
        let (_pool, store, _user_id) = setup_test_db().await;
        let bogus_hash = ApiTokenStoreDb::hash_token("apx_never_issued");
        assert!(store.verify(&bogus_hash).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_verify_revoked_token_returns_none() {
        let (_pool, store, user_id) = setup_test_db().await;
        let (row, plaintext) = store.create(user_id, "Device", 0, None).await.unwrap();
        let hash = ApiTokenStoreDb::hash_token(&plaintext);

        assert!(store.revoke(row.id, user_id).await.unwrap());
        assert!(store.verify(&hash).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_verify_expired_token_returns_none() {
        let (pool, store, user_id) = setup_test_db().await;
        let (_row, plaintext) = store.create(user_id, "Device", 0, None).await.unwrap();
        let hash = ApiTokenStoreDb::hash_token(&plaintext);

        // Force expiry into the past directly.
        sqlx::query("UPDATE api_tokens SET expires_at = datetime('now', '-1 hour') WHERE token_hash = ?")
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();

        assert!(store.verify(&hash).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_revoke_wrong_user_fails() {
        let (pool, store, user_id) = setup_test_db().await;
        let test_hash = "$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0";
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("bob")
            .bind(test_hash)
            .bind("user")
            .execute(&pool)
            .await
            .unwrap();

        let (row, _plaintext) = store.create(user_id, "Alice's token", 0, None).await.unwrap();

        // bob (user_id=2) must not be able to revoke alice's token.
        let revoked = store.revoke(row.id, 2).await.unwrap();
        assert!(!revoked);

        let hash = ApiTokenStoreDb::hash_token(&_plaintext);
        assert!(store.verify(&hash).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_list_for_user_excludes_other_users() {
        let (pool, store, user_id) = setup_test_db().await;
        let test_hash = "$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0";
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("bob")
            .bind(test_hash)
            .bind("user")
            .execute(&pool)
            .await
            .unwrap();

        store.create(user_id, "Alice's token", 0, None).await.unwrap();
        store.create(2, "Bob's token", 0, None).await.unwrap();

        let alice_tokens = store.list_for_user(user_id).await.unwrap();
        assert_eq!(alice_tokens.len(), 1);
        assert_eq!(alice_tokens[0].name, "Alice's token");
    }

    #[tokio::test]
    async fn test_touch_last_used_sets_timestamp() {
        let (_pool, store, user_id) = setup_test_db().await;
        let (row, _plaintext) = store.create(user_id, "Device", 0, None).await.unwrap();
        assert!(row.last_used_at.is_none());

        store.touch_last_used(row.id).await.unwrap();

        let updated = store.list_for_user(user_id).await.unwrap();
        assert!(updated[0].last_used_at.is_some());
    }
}
