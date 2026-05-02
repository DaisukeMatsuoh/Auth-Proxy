use crate::config::Config;
use crate::users_db::UserStoreDb;
use crate::sessions_db::SessionStoreDb;
use crate::users::UserStore;
use crate::mfa::MfaStore;
use sqlx::SqlitePool;
use std::sync::Arc;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: SqlitePool,
    pub users: Arc<UserStoreDb>,
    pub sessions: Arc<SessionStoreDb>,
    pub mfa: Arc<MfaStore>,
    pub http_client: reqwest::Client,
}

impl AppState {
    /// Create a new AppState with database pool
    pub async fn new(config: Arc<Config>) -> anyhow::Result<Self> {
        Self::new_internal(config, true).await
    }

    /// Create a new AppState without seeding users (used for init-admin command)
    pub async fn new_without_seed(config: Arc<Config>) -> anyhow::Result<Self> {
        Self::new_internal(config, false).await
    }

    /// Internal AppState creation
    async fn new_internal(config: Arc<Config>, should_seed: bool) -> anyhow::Result<Self> {
        // Ensure parent directory exists for database file
        if let Some(parent) = config.db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Create database URL with create flag
        // ?mode=rwc means: read, write, create file if not exists
        let db_url = format!("sqlite:{}?mode=rwc", config.db_path.display());

        // Create connection pool
        let db = SqlitePool::connect(&db_url).await?;

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&db)
            .await?;

        // Initialize stores
        let users = Arc::new(UserStoreDb::new(db.clone()));
        let sessions = Arc::new(SessionStoreDb::new(db.clone(), config.session_ttl));
        let mfa = Arc::new(MfaStore::new(db.clone(), config.mfa_encryption_key));

        // Seed initial users from APP_USERS environment variable (if requested)
        if should_seed {
            Self::seed_users(&db, &config.users_raw).await?;
        }

        let http_client = reqwest::Client::new();

        Ok(Self {
            config,
            db,
            users,
            sessions,
            mfa,
            http_client,
        })
    }

    /// Seed users from APP_USERS environment variable into database
    async fn seed_users(db: &SqlitePool, users_raw: &str) -> anyhow::Result<()> {
        // Parse APP_USERS format: "user1:hash1,user2:hash2"
        let user_store = UserStore::from_str(users_raw)?;

        // Get list of users from parsed format
        let users_list = user_store.list_all();

        for (username, hash) in users_list {
            // Insert or ignore if already exists
            sqlx::query(
                "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)"
            )
            .bind(&username)
            .bind(&hash)
            .bind("user") // Default role
            .execute(db)
            .await?;
        }

        Ok(())
    }

    #[cfg(test)]
    pub async fn test() -> anyhow::Result<Self> {
        let config = Arc::new(Config::test_default());

        // Create in-memory database for testing
        let db = SqlitePool::connect("sqlite::memory:").await?;

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&db)
            .await?;

        // Initialize stores
        let users = Arc::new(UserStoreDb::new(db.clone()));
        let sessions = Arc::new(SessionStoreDb::new(db.clone(), config.session_ttl));
        let mfa = Arc::new(MfaStore::new(db.clone(), config.mfa_encryption_key));

        // Seed test users
        Self::seed_users(&db, &config.users_raw).await?;

        Ok(Self {
            config,
            db,
            users,
            sessions,
            mfa,
            http_client: reqwest::Client::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_state_creation() {
        let state = AppState::test().await;
        assert!(state.is_ok());
    }
}
