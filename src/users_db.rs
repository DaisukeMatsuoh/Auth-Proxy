use sqlx::SqlitePool;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use anyhow::Result;
use thiserror::Error;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String, // "user" or "admin"
    pub totp_enabled: i32, // 0 or 1
}

#[derive(Debug, Error)]
pub enum UserDbError {
    #[error("User not found")]
    NotFound,

    #[error("Database error: {0}")]
    DbError(#[from] sqlx::Error),

    #[error("Invalid password hash")]
    InvalidHash,
}

pub struct UserStoreDb {
    pool: SqlitePool,
}

impl UserStoreDb {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Get user by username from database
    pub async fn get_by_username(&self, username: &str) -> Result<Option<UserRow>, UserDbError> {
        let user = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, password_hash, role, totp_enabled FROM users WHERE username = ?"
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Get user by ID from database
    pub async fn get_by_id(&self, id: i64) -> Result<Option<UserRow>, UserDbError> {
        let user = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, password_hash, role, totp_enabled FROM users WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Verify user credentials
    pub async fn verify(&self, username: &str, password: &str) -> Result<bool, UserDbError> {
        let user = self.get_by_username(username).await?;

        match user {
            Some(user) => {
                // Perform Argon2 verification
                let password_hash = PasswordHash::new(&user.password_hash)
                    .map_err(|_| UserDbError::InvalidHash)?;

                let argon2 = Argon2::default();
                match argon2.verify_password(password.as_bytes(), &password_hash) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            None => {
                // Timing attack mitigation: always perform Argon2 check
                // Use a dummy hash to prevent timing attacks
                let dummy_hash = PasswordHash::new(
                    "$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0"
                ).map_err(|_| UserDbError::InvalidHash)?;

                let argon2 = Argon2::default();
                let _ = argon2.verify_password(password.as_bytes(), &dummy_hash);

                Ok(false) // User doesn't exist
            }
        }
    }

    /// List all users
    pub async fn list_all(&self) -> Result<Vec<UserRow>, UserDbError> {
        let users = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, password_hash, role, totp_enabled FROM users ORDER BY username"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    /// Create a new user
    pub async fn create(&self, username: &str, password: &str, role: &str) -> Result<UserRow, UserDbError> {
        // Hash password using Argon2id
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::Argon2;

        let salt = SaltString::generate(argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| UserDbError::InvalidHash)?
            .to_string();

        // Insert into database
        sqlx::query(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"
        )
        .bind(username)
        .bind(&password_hash)
        .bind(role)
        .execute(&self.pool)
        .await?;

        // Retrieve and return the created user
        self.get_by_username(username)
            .await?
            .ok_or(UserDbError::NotFound)
    }

    /// Update user password
    pub async fn update_password(&self, id: i64, password: &str) -> Result<(), UserDbError> {
        // Hash password using Argon2id
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::Argon2;

        let salt = SaltString::generate(argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| UserDbError::InvalidHash)?
            .to_string();

        sqlx::query(
            "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
        )
        .bind(&password_hash)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete a user by ID
    pub async fn delete(&self, id: i64) -> Result<(), UserDbError> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to setup test database with AppState
    async fn setup_test_db() -> (SqlitePool, UserStoreDb) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();

        // Run migrations (same as AppState::test())
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .unwrap();

        let store = UserStoreDb::new(pool.clone());
        (pool, store)
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let (_pool, store) = setup_test_db().await;

        // Query nonexistent user
        let result = store.get_by_username("nonexistent").await.unwrap();
        assert!(result.is_none(), "Expected nonexistent user to return None");
    }

    #[tokio::test]
    async fn test_get_by_id_found() {
        let (pool, store) = setup_test_db().await;

        // Insert a test user with a valid hash
        let test_hash = "$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0";
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("testuser")
            .bind(test_hash)
            .bind("admin")
            .execute(&pool)
            .await
            .unwrap();

        let result = store.get_by_id(1).await.unwrap();
        assert!(result.is_some(), "Expected user with id=1 to be found");

        let user = result.unwrap();
        assert_eq!(user.username, "testuser", "Expected username to be 'testuser'");
        assert_eq!(user.role, "admin", "Expected role to be 'admin'");
        assert_eq!(user.password_hash, test_hash, "Expected valid hash to be stored");
    }

    #[tokio::test]
    async fn test_get_by_id_not_found() {
        let (_pool, store) = setup_test_db().await;

        // Query nonexistent ID
        let result = store.get_by_id(999).await.unwrap();
        assert!(result.is_none(), "Expected nonexistent id to return None");
    }

    #[tokio::test]
    async fn test_list_all_users() {
        let (pool, store) = setup_test_db().await;

        // Insert test users with valid hashes
        let test_hash = "$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0";

        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("alice")
            .bind(test_hash)
            .bind("user")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("bob")
            .bind(test_hash)
            .bind("admin")
            .execute(&pool)
            .await
            .unwrap();

        let users = store.list_all().await.unwrap();
        assert_eq!(users.len(), 2, "Expected 2 users in database");
        assert_eq!(users[0].username, "alice", "Expected first user to be alice");
        assert_eq!(users[1].username, "bob", "Expected second user to be bob");
        assert_eq!(users[0].role, "user", "Expected alice role to be 'user'");
        assert_eq!(users[1].role, "admin", "Expected bob role to be 'admin'");
    }

    #[tokio::test]
    async fn test_list_all_users_empty() {
        let (_pool, store) = setup_test_db().await;

        // List from empty database
        let users = store.list_all().await.unwrap();
        assert_eq!(users.len(), 0, "Expected empty user list");
    }
}
