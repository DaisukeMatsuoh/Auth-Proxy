use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub users_raw: String,
    pub session_secret: String,
    pub serve_path: PathBuf,
    pub listen_addr: SocketAddr,
    pub session_ttl: Duration,
    // Phase 3: SQLite & リバースプロキシ
    pub db_path: PathBuf,
    pub upstream_url: String,
    pub issuer_name: String,
    // Phase 3a: MFA
    pub mfa_encryption_key: [u8; 32],
    // Phase 4: ゲストトークン
    pub guest_token_secret: String,
    pub guest_token_api_key: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnv(String),

    #[error("Invalid address: {0}")]
    InvalidAddr(String),

    #[error("Path does not exist: {0}")]
    PathNotFound(PathBuf),

    #[error("Invalid TTL hours: {0}")]
    InvalidTtl(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl Config {
    /// Load minimal config for CLI commands (only DB path)
    /// This is used by commands like init-admin that don't need full server config
    pub fn from_env_cli_only() -> Result<PathBuf, ConfigError> {
        // Load .env file if it exists
        let _ = dotenvy::dotenv();

        // Only load DB path (optional, defaults to auth_proxy.db)
        let db_path_str = std::env::var("APP_DB_PATH")
            .unwrap_or_else(|_| "auth_proxy.db".to_string());
        let db_path = PathBuf::from(&db_path_str);

        Ok(db_path)
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        let _ = dotenvy::dotenv();

        // Fetch environment variables with sensible defaults
        // For init-admin: APP_USERS can be a dummy value since DB will be empty
        let users_raw = std::env::var("APP_USERS")
            .unwrap_or_else(|_| "dummy:$argon2id$v=19$m=19456,t=2,p=1$sQzYp8k4PCQ3nwNJ7V2Eqg$/1fN7a+8Z6K0L3M9N5O1P2Q3R4S5T6U7V8W9X0Y1".to_string());

        let session_secret = std::env::var("APP_SESSION_SECRET")
            .unwrap_or_else(|_| "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

        let serve_path_str = std::env::var("APP_SERVE_PATH")
            .map_err(|_| ConfigError::MissingEnv("APP_SERVE_PATH".to_string()))?;
        let serve_path = PathBuf::from(&serve_path_str);

        // Verify that the serve path exists
        if !serve_path.exists() {
            return Err(ConfigError::PathNotFound(serve_path));
        }

        let listen_addr_str = std::env::var("APP_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let listen_addr = listen_addr_str.parse::<SocketAddr>()
            .map_err(|_| ConfigError::InvalidAddr(listen_addr_str))?;

        let ttl_hours: u64 = std::env::var("APP_SESSION_TTL_HOURS")
            .unwrap_or_else(|_| "8".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidTtl(
                std::env::var("APP_SESSION_TTL_HOURS").unwrap_or_default()
            ))?;
        let session_ttl = Duration::from_secs(ttl_hours * 3600);

        // Phase 3: SQLite and reverse proxy configuration
        let db_path_str = std::env::var("APP_DB_PATH")
            .unwrap_or_else(|_| "auth_proxy.db".to_string());
        let db_path = PathBuf::from(&db_path_str);

        let upstream_url = std::env::var("APP_UPSTREAM_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        let issuer_name = std::env::var("APP_ISSUER_NAME")
            .unwrap_or_else(|_| "auth-proxy".to_string());

        // Phase 4: Guest token configuration (with defaults)
        let guest_token_secret = std::env::var("APP_GUEST_TOKEN_SECRET")
            .unwrap_or_else(|_| "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

        let guest_token_api_key = std::env::var("APP_GUEST_TOKEN_API_KEY")
            .unwrap_or_else(|_| "your-secret-api-key-here".to_string());

        // Phase 3a: MFA encryption key (required)
        let key_hex = std::env::var("APP_MFA_ENCRYPTION_KEY")
            .unwrap_or_else(|_| "0000000000000000000000000000000000000000000000000000000000000000".to_string());
        let key_bytes = hex::decode(&key_hex)
            .map_err(|_| ConfigError::MissingEnv("APP_MFA_ENCRYPTION_KEY must be valid hex".to_string()))?;
        if key_bytes.len() != 32 {
            return Err(ConfigError::MissingEnv(
                "APP_MFA_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)".to_string()
            ));
        }
        let mut mfa_encryption_key = [0u8; 32];
        mfa_encryption_key.copy_from_slice(&key_bytes);

        Ok(Config {
            users_raw,
            session_secret,
            serve_path,
            listen_addr,
            session_ttl,
            db_path,
            upstream_url,
            issuer_name,
            mfa_encryption_key,
            guest_token_secret,
            guest_token_api_key,
        })
    }

    pub fn test_default() -> Self {
        Config {
            users_raw: "testuser:$argon2id$v=19$m=19456,t=2,p=1$eW9vdGlzcGFzcw$VT2kfB6K4/HQp9YC8K7ZhFXxe7viFVzTwFNXnSg7vj0"
                .to_string(),
            session_secret: "test_secret_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            serve_path: PathBuf::from("/tmp"),
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            session_ttl: Duration::from_secs(8 * 3600),
            db_path: PathBuf::from(":memory:"),
            upstream_url: "http://127.0.0.1:3000".to_string(),
            issuer_name: "Test Issuer".to_string(),
            mfa_encryption_key: [0u8; 32],
            guest_token_secret: "test_guest_secret_0123456789abcdef0123456789abcdef"
                .to_string(),
            guest_token_api_key: "test_guest_api_key_0123456789abcdef0123456789abcdef"
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::test_default();
        assert!(!config.users_raw.is_empty());
        assert!(!config.session_secret.is_empty());
        assert_eq!(config.session_ttl, Duration::from_secs(8 * 3600));
        assert_eq!(config.listen_addr.to_string(), "127.0.0.1:8080");
    }
}
