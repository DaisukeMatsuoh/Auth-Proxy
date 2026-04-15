use sqlx::SqlitePool;
use chrono::{DateTime, Utc};
use anyhow::Result;
use rand::RngCore;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub session_id: String,
    pub user_id: i64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum SessionDbError {
    #[error("Session not found")]
    NotFound,

    #[error("Database error: {0}")]
    DbError(#[from] sqlx::Error),
}

pub struct SessionStoreDb {
    pool: SqlitePool,
    ttl: Duration,
}

impl SessionStoreDb {
    pub fn new(pool: SqlitePool, ttl: Duration) -> Self {
        Self { pool, ttl }
    }

    /// Create a new session for a user
    pub async fn create(&self, user_id: i64) -> Result<String, SessionDbError> {
        // Generate session ID: 16 random bytes as hex
        let mut session_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut session_bytes);
        let session_id = hex::encode(session_bytes);

        // Calculate expiration time
        let expires_at = Utc::now() + chrono::Duration::from_std(self.ttl)
            .map_err(|_| SessionDbError::DbError(
                sqlx::Error::RowNotFound
            ))?;

        // Insert into database
        sqlx::query(
            "INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)"
        )
        .bind(&session_id)
        .bind(user_id)
        .bind(expires_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(session_id)
    }

    /// Get session by ID
    pub async fn get(&self, session_id: &str) -> Result<Option<SessionRow>, SessionDbError> {
        let now = Utc::now();

        let session = sqlx::query_as::<_, (String, i64, String)>(
            "SELECT session_id, user_id, expires_at FROM sessions WHERE session_id = ? AND expires_at > ?"
        )
        .bind(session_id)
        .bind(now.to_rfc3339())
        .fetch_optional(&self.pool)
        .await?;

        Ok(session.map(|(session_id, user_id, expires_at_str)| {
            let expires_at = DateTime::parse_from_rfc3339(&expires_at_str)
                .unwrap_or_else(|_| chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00+00:00").unwrap())
                .with_timezone(&Utc);

            SessionRow {
                session_id,
                user_id,
                expires_at,
            }
        }))
    }

    /// Remove session
    pub async fn remove(&self, session_id: &str) -> Result<(), SessionDbError> {
        sqlx::query("DELETE FROM sessions WHERE session_id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) -> Result<u64, SessionDbError> {
        let result = sqlx::query(
            "DELETE FROM sessions WHERE expires_at < datetime('now')"
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count active sessions
    pub async fn count_active(&self) -> Result<i64, SessionDbError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')"
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to setup test database with AppState
    async fn setup_test_db() -> (SqlitePool, SessionStoreDb) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();

        // Run migrations (same as AppState::test())
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .unwrap();

        // Insert a test user so we can create sessions for valid user_id
        let test_hash = "$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0";
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("testuser")
            .bind(test_hash)
            .bind("user")
            .execute(&pool)
            .await
            .unwrap();

        let store = SessionStoreDb::new(pool.clone(), Duration::from_secs(3600));
        (pool, store)
    }

    #[tokio::test]
    async fn test_session_creation() {
        let (_pool, store) = setup_test_db().await;

        // Create session for user_id=1 (inserted in setup)
        let session_id = store.create(1).await.unwrap();

        // Verify session ID properties
        assert!(!session_id.is_empty(), "Session ID should not be empty");
        assert_eq!(session_id.len(), 32, "Session ID should be 32 chars (hex encoded 16 bytes)");
        assert!(session_id.chars().all(|c| c.is_ascii_hexdigit()), "Session ID should be valid hex");
    }

    #[tokio::test]
    async fn test_session_create_and_retrieve() {
        let (_pool, store) = setup_test_db().await;

        // Create session
        let session_id = store.create(1).await.unwrap();

        // Retrieve session
        let session = store.get(&session_id).await.unwrap();
        assert!(session.is_some(), "Created session should be retrievable");

        let session = session.unwrap();
        assert_eq!(session.session_id, session_id, "Session ID should match");
        assert_eq!(session.user_id, 1, "User ID should match");
        assert!(session.expires_at > Utc::now(), "Session should not be expired");
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let (_pool, store) = setup_test_db().await;

        // Query nonexistent session
        let session = store.get("nonexistent_session_id").await.unwrap();
        assert!(session.is_none(), "Nonexistent session should return None");
    }

    #[tokio::test]
    async fn test_session_remove() {
        let (_pool, store) = setup_test_db().await;

        // Create session
        let session_id = store.create(1).await.unwrap();

        // Verify it exists
        let session = store.get(&session_id).await.unwrap();
        assert!(session.is_some(), "Session should exist before removal");

        // Remove session
        store.remove(&session_id).await.unwrap();

        // Verify it's gone
        let session = store.get(&session_id).await.unwrap();
        assert!(session.is_none(), "Session should not exist after removal");
    }

    #[tokio::test]
    async fn test_session_cleanup_expired() {
        let (pool, store) = setup_test_db().await;

        // Manually insert an expired session using SQLite's datetime function
        // This is an expired session that should be cleaned up
        sqlx::query("INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, datetime('now', '-1 hour'))")
            .bind("expired_session_id")
            .bind(1)
            .execute(&pool)
            .await
            .unwrap();

        // Create a valid (non-expired) session
        let valid_session_id = store.create(1).await.unwrap();

        // Verify both sessions exist
        let expired = store.get("expired_session_id").await.unwrap();
        let valid = store.get(&valid_session_id).await.unwrap();
        assert!(expired.is_none(), "Expired session should not be retrievable by get() (respects TTL)");
        assert!(valid.is_some(), "Valid session should be retrievable");

        // Clean up expired sessions
        let count = store.cleanup_expired().await.unwrap();
        assert_eq!(count, 1, "Cleanup should remove exactly 1 expired session");

        // Verify valid session still exists
        let valid_after = store.get(&valid_session_id).await.unwrap();
        assert!(valid_after.is_some(), "Valid session should still exist after cleanup");
    }

    #[tokio::test]
    async fn test_session_ttl_respected() {
        // Create store with very short TTL
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .unwrap();

        let test_hash = "$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0";
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("testuser")
            .bind(test_hash)
            .bind("user")
            .execute(&pool)
            .await
            .unwrap();

        let store = SessionStoreDb::new(pool, Duration::from_secs(1));

        // Create session
        let session_id = store.create(1).await.unwrap();

        // Session should be retrievable immediately
        let session = store.get(&session_id).await.unwrap();
        assert!(session.is_some(), "Session should be retrievable immediately after creation");

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Session should now be expired
        let session = store.get(&session_id).await.unwrap();
        assert!(session.is_none(), "Session should be expired after TTL passes");
    }
}
