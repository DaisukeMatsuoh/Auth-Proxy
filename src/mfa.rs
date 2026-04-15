use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng}};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Utc, Duration};
use rand::rngs::OsRng;
use rand::RngCore;
use sqlx::SqlitePool;
use totp_rs::{TOTP, Algorithm, Secret};
use anyhow::Result;

pub struct MfaStore {
    pool:           SqlitePool,
    encryption_key: [u8; 32],
}

impl MfaStore {
    pub fn new(pool: SqlitePool, encryption_key: [u8; 32]) -> Self {
        MfaStore {
            pool,
            encryption_key,
        }
    }

    /// Encrypt plaintext using AES-256-GCM
    fn encrypt(&self, plaintext: &str) -> Result<String> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("encrypt error: {}", e))?;
        let combined = [nonce.as_slice(), &ciphertext].concat();
        Ok(BASE64.encode(combined))
    }

    /// Decrypt Base64-encoded ciphertext
    fn decrypt(&self, encoded: &str) -> Result<String> {
        let bytes = BASE64.decode(encoded)?;
        if bytes.len() < 12 {
            return Err(anyhow::anyhow!("invalid ciphertext"));
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(12);
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("decrypt error: {}", e))?;
        Ok(String::from_utf8(plaintext)?)
    }

    /// Generate a new TOTP secret (Base32) and return (secret, otpauth_uri)
    pub fn generate_totp_secret(&self, username: &str, issuer: &str) -> Result<(String, String)> {
        let mut secret_bytes = [0u8; 20];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);

        let totp = TOTP::new(
            Algorithm::SHA1, 6, 1, 30,
            Secret::Encoded(secret_b32.clone()).to_bytes()?,
            Some(issuer.to_string()),
            username.to_string(),
        )?;
        let uri = totp.get_url();
        Ok((secret_b32, uri))
    }

    /// Verify a TOTP code against a Base32-encoded secret
    pub fn verify_totp_code(&self, secret_b32: &str, code: &str) -> bool {
        let Ok(totp) = TOTP::new(
            Algorithm::SHA1, 6, 1, 30,
            Secret::Encoded(secret_b32.to_string()).to_bytes().unwrap_or_default(),
            None, String::new(),
        ) else { return false };
        totp.check_current(code).unwrap_or(false)
    }

    /// Enable TOTP for a user (stores encrypted secret)
    pub async fn enable_totp(&self, user_id: i64, secret_b32: &str) -> Result<()> {
        let encrypted = self.encrypt(secret_b32)?;
        sqlx::query(
            "UPDATE users SET totp_secret_enc = ?, totp_enabled = 1, updated_at = datetime('now')
             WHERE id = ?"
        ).bind(&encrypted)
         .bind(user_id)
         .execute(&self.pool).await?;
        Ok(())
    }

    /// Disable TOTP for a user (transaction: clear secret, delete backup codes and device tokens)
    pub async fn disable_totp(&self, user_id: i64) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "UPDATE users SET totp_secret_enc = NULL, totp_enabled = 0, updated_at = datetime('now')
             WHERE id = ?"
        ).bind(user_id)
         .execute(&mut *tx).await?;

        sqlx::query("DELETE FROM mfa_backup_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx).await?;

        sqlx::query("DELETE FROM mfa_device_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx).await?;

        sqlx::query("DELETE FROM mfa_pending_sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx).await?;

        tx.commit().await?;
        Ok(())
    }

    /// Verify TOTP code for a user (checks totp_enabled and decrypts secret)
    pub async fn verify_totp_for_user(&self, user_id: i64, code: &str) -> Result<bool> {
        let row = sqlx::query_as::<_, (Option<String>, i32)>(
            "SELECT totp_secret_enc, totp_enabled FROM users WHERE id = ?"
        ).bind(user_id)
         .fetch_optional(&self.pool).await?;

        let Some((enc_opt, totp_enabled)) = row else { return Ok(false) };
        if totp_enabled == 0 { return Ok(false) }
        let Some(enc) = enc_opt else { return Ok(false) };
        let secret_b32 = self.decrypt(&enc)?;
        Ok(self.verify_totp_code(&secret_b32, code))
    }

    /// Generate 8 backup codes (xxxx-xxxx-xxxx format), delete existing, return plaintext codes
    pub async fn generate_backup_codes(&self, user_id: i64) -> Result<Vec<String>> {
        // Delete existing codes
        sqlx::query("DELETE FROM mfa_backup_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool).await?;

        // Helper to generate single 4-char part
        fn generate_part() -> String {
            const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
            let part: Vec<u8> = (0..4)
                .map(|_| {
                    let idx = (OsRng.next_u32() as usize) % CHARSET.len();
                    CHARSET[idx]
                })
                .collect();
            String::from_utf8(part).unwrap()
        }

        // Generate 8 codes (xxxx-xxxx-xxxx format)
        let mut codes = Vec::new();
        for _ in 0..8 {
            let code = format!("{}-{}-{}", generate_part(), generate_part(), generate_part());
            codes.push(code);
        }

        // Hash and insert
        for code in &codes {
            // Store normalized version (without hyphens) for consistency with verify
            let normalized = code.replace('-', "").to_lowercase();
            let code_to_hash = normalized.clone();
            let hash_result = tokio::task::spawn_blocking(move || {
                use argon2::PasswordHasher;
                let argon2 = Argon2::default();
                match argon2.hash_password(code_to_hash.as_bytes(), &argon2::password_hash::SaltString::generate(OsRng)) {
                    Ok(hash) => Ok(hash.to_string()),
                    Err(e) => Err(anyhow::anyhow!("hash error: {}", e)),
                }
            }).await?;

            if let Ok(hash) = hash_result {
                sqlx::query(
                    "INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (?, ?)"
                ).bind(user_id)
                 .bind(&hash)
                 .execute(&self.pool).await?;
            }
        }

        Ok(codes)
    }

    /// Verify a backup code (full-loop timing attack mitigation, mark as used if match)
    /// Accepts input with or without hyphens (e.g., "abcd-efgh-ijkl" or "abcdefghijkl")
    pub async fn verify_backup_code(&self, user_id: i64, code: &str) -> Result<bool> {
        let rows = sqlx::query_as::<_, (i64, String)>(
            "SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = ? AND used_at IS NULL"
        ).bind(user_id)
         .fetch_all(&self.pool).await?;

        // Normalize input: remove hyphens and convert to lowercase for comparison
        let normalized_input = code.replace('-', "").to_lowercase();
        let mut found_id: Option<i64> = None;
        let mut matched = false;

        for (id, hash) in rows {
            let input_to_verify = normalized_input.clone();
            let result = tokio::task::spawn_blocking(move || {
                use argon2::{PasswordVerifier, password_hash::PasswordHash};
                let argon2 = Argon2::default();
                if let Ok(hash_obj) = PasswordHash::new(&hash) {
                    // Verify against normalized input (without hyphens)
                    argon2.verify_password(input_to_verify.as_bytes(), &hash_obj).is_ok()
                } else {
                    false
                }
            }).await?;

            if result && !matched {
                matched = true;
                found_id = Some(id);
            }
        }

        if matched && found_id.is_some() {
            let id = found_id.unwrap();
            sqlx::query(
                "UPDATE mfa_backup_codes SET used_at = datetime('now') WHERE id = ?"
            ).bind(id)
             .execute(&self.pool).await?;
        }

        Ok(matched)
    }

    /// Create a pending MFA session (5-minute expiry)
    pub async fn create_pending_session(&self, user_id: i64) -> Result<String> {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let expires_at = Utc::now() + Duration::minutes(5);
        sqlx::query(
            "INSERT INTO mfa_pending_sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(&token)
         .bind(user_id)
         .bind(expires_at.to_rfc3339())
         .execute(&self.pool).await?;
        Ok(token)
    }

    /// Verify a pending MFA session (check expiry), return (user_id, attempt_count)
    pub async fn verify_pending_session(&self, token: &str) -> Option<(i64, u32)> {
        sqlx::query_as::<_, (i64, i32)>(
            "SELECT user_id, attempt_count FROM mfa_pending_sessions WHERE token = ? AND expires_at > datetime('now')"
        ).bind(token)
         .fetch_optional(&self.pool)
         .await
         .ok()
         .flatten()
         .map(|(user_id, attempt_count)| (user_id, attempt_count as u32))
    }

    /// Delete a pending MFA session
    pub async fn delete_pending_session(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM mfa_pending_sessions WHERE token = ?")
            .bind(token)
            .execute(&self.pool).await?;
        Ok(())
    }

    /// Increment attempt count for a pending session
    /// Returns true if locked out (attempt >= 5), false if still allowed
    pub async fn increment_attempt(&self, token: &str) -> Result<bool> {
        // Increment attempt count
        sqlx::query("UPDATE mfa_pending_sessions SET attempt_count = attempt_count + 1 WHERE token = ?")
            .bind(token)
            .execute(&self.pool).await?;

        // Get updated count
        let row = sqlx::query_as::<_, (i32,)>(
            "SELECT attempt_count FROM mfa_pending_sessions WHERE token = ?"
        ).bind(token)
         .fetch_optional(&self.pool).await?;

        if let Some((count,)) = row {
            if count >= 5 {
                // Lockout: delete the session
                self.delete_pending_session(token).await?;
                Ok(true)  // Locked out
            } else {
                Ok(false)  // Still allowed
            }
        } else {
            // Session already deleted (expired, etc.)
            Ok(true)
        }
    }

    /// Create a device token (30-day expiry)
    pub async fn create_device_token(&self, user_id: i64) -> Result<String> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let expires_at = Utc::now() + Duration::days(30);
        sqlx::query(
            "INSERT INTO mfa_device_tokens (token, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(&token)
         .bind(user_id)
         .bind(expires_at.to_rfc3339())
         .execute(&self.pool).await?;
        Ok(token)
    }

    /// Verify a device token (check both token and user_id match, and not expired)
    pub async fn verify_device_token(&self, token: &str, user_id: i64) -> bool {
        let row = sqlx::query_scalar::<_, i64>(
            "SELECT user_id FROM mfa_device_tokens WHERE token = ? AND user_id = ? AND expires_at > datetime('now')"
        ).bind(token)
         .bind(user_id)
         .fetch_optional(&self.pool)
         .await;

        matches!(row, Ok(Some(_)))
    }

    /// Delete a specific device token
    pub async fn delete_device_token(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM mfa_device_tokens WHERE token = ?")
            .bind(token)
            .execute(&self.pool).await?;
        Ok(())
    }

    /// Delete all device tokens for a user
    pub async fn delete_all_device_tokens(&self, user_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM mfa_device_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool).await?;
        Ok(())
    }

    /// Clean up expired sessions and device tokens
    pub async fn cleanup_expired(&self) -> Result<()> {
        sqlx::query("DELETE FROM mfa_pending_sessions WHERE expires_at < datetime('now')")
            .execute(&self.pool).await?;
        sqlx::query("DELETE FROM mfa_device_tokens WHERE expires_at < datetime('now')")
            .execute(&self.pool).await?;
        Ok(())
    }

    /// Get count of unused backup codes for a user
    pub async fn backup_code_count(&self, user_id: i64) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = ? AND used_at IS NULL"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_mfa_store() -> (MfaStore, i64) {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();

        // Initialize schema
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                totp_secret_enc TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"
        ).execute(&pool).await.unwrap();

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mfa_backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                code_hash TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"
        ).execute(&pool).await.unwrap();

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mfa_pending_sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"
        ).execute(&pool).await.unwrap();

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mfa_device_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"
        ).execute(&pool).await.unwrap();

        let store = MfaStore::new(pool.clone(), [0u8; 32]);

        // Create test user
        let user_id = sqlx::query(
            "INSERT INTO users (username, password_hash, role) VALUES ('testuser', 'hash', 'user')"
        ).execute(&pool).await.unwrap().last_insert_rowid();

        (store, user_id)
    }

    #[tokio::test]
    async fn test_generate_totp_secret_returns_base32_and_uri() {
        let (store, _) = test_mfa_store().await;
        let (secret, uri) = store.generate_totp_secret("alice", "test-proxy").unwrap();

        assert!(!secret.is_empty());
        assert!(secret.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));

        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("alice"));
        assert!(uri.contains("test-proxy"));
    }

    #[tokio::test]
    async fn test_totp_verify_correct_code() {
        let (store, user_id) = test_mfa_store().await;
        let (secret, _) = store.generate_totp_secret("alice", "test").unwrap();
        store.enable_totp(user_id, &secret).await.unwrap();

        use totp_rs::{TOTP, Algorithm, Secret};
        let totp = TOTP::new(
            Algorithm::SHA1, 6, 1, 30,
            Secret::Encoded(secret).to_bytes().unwrap(),
            None, String::new(),
        ).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(store.verify_totp_for_user(user_id, &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_totp_verify_wrong_code() {
        let (store, user_id) = test_mfa_store().await;
        let (secret, _) = store.generate_totp_secret("alice", "test").unwrap();
        store.enable_totp(user_id, &secret).await.unwrap();
        assert!(!store.verify_totp_for_user(user_id, "000000").await.unwrap());
    }

    #[tokio::test]
    async fn test_encryption_roundtrip() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = MfaStore::new(pool, [42u8; 32]);
        let original = "JBSWY3DPEHPK3PXP";
        let encrypted = store.encrypt(original).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(original, decrypted);
        let encrypted2 = store.encrypt(original).unwrap();
        assert_ne!(encrypted, encrypted2);
    }

    #[tokio::test]
    async fn test_generate_backup_codes_creates_8_codes() {
        let (store, user_id) = test_mfa_store().await;
        let codes = store.generate_backup_codes(user_id).await.unwrap();
        assert_eq!(codes.len(), 8);
        for code in &codes {
            // Format: xxxx-xxxx-xxxx (12 chars + 2 hyphens)
            assert_eq!(code.len(), 14);
            let parts: Vec<&str> = code.split('-').collect();
            assert_eq!(parts.len(), 3);
            for part in parts {
                assert_eq!(part.len(), 4);
                assert!(part.chars().all(|c| c.is_ascii_alphanumeric()));
            }
        }
    }

    #[tokio::test]
    async fn test_backup_code_verify_success_and_marks_used() {
        let (store, user_id) = test_mfa_store().await;
        let codes = store.generate_backup_codes(user_id).await.unwrap();
        let code = &codes[0];

        assert!(store.verify_backup_code(user_id, code).await.unwrap());
        assert!(!store.verify_backup_code(user_id, code).await.unwrap());
    }

    #[tokio::test]
    async fn test_backup_code_wrong_code_fails() {
        let (store, user_id) = test_mfa_store().await;
        store.generate_backup_codes(user_id).await.unwrap();
        assert!(!store.verify_backup_code(user_id, "00000000").await.unwrap());
    }

    #[tokio::test]
    async fn test_generate_backup_codes_replaces_existing() {
        let (store, user_id) = test_mfa_store().await;
        let codes1 = store.generate_backup_codes(user_id).await.unwrap();
        let codes2 = store.generate_backup_codes(user_id).await.unwrap();
        assert!(!store.verify_backup_code(user_id, &codes1[0]).await.unwrap());
        assert!(store.verify_backup_code(user_id, &codes2[0]).await.unwrap());
    }

    #[tokio::test]
    async fn test_pending_session_lifecycle() {
        let (store, user_id) = test_mfa_store().await;
        let token = store.create_pending_session(user_id).await.unwrap();

        assert_eq!(store.verify_pending_session(&token).await, Some((user_id, 0)));

        store.delete_pending_session(&token).await.unwrap();
        assert_eq!(store.verify_pending_session(&token).await, None);
    }

    #[tokio::test]
    async fn test_pending_session_expired() {
        let (store, user_id) = test_mfa_store().await;
        sqlx::query(
            "INSERT INTO mfa_pending_sessions (token, user_id, expires_at)
             VALUES ('expired_token', ?, datetime('now', '-1 minute'))"
        ).bind(user_id)
         .execute(&store.pool).await.unwrap();
        assert_eq!(store.verify_pending_session("expired_token").await, None);
    }

    #[tokio::test]
    async fn test_device_token_lifecycle() {
        let (store, user_id) = test_mfa_store().await;
        let token = store.create_device_token(user_id).await.unwrap();

        assert!(store.verify_device_token(&token, user_id).await);
        assert!(!store.verify_device_token(&token, user_id + 1).await);

        store.delete_device_token(&token).await.unwrap();
        assert!(!store.verify_device_token(&token, user_id).await);
    }

    #[tokio::test]
    async fn test_delete_all_device_tokens() {
        let (store, user_id) = test_mfa_store().await;
        let token1 = store.create_device_token(user_id).await.unwrap();
        let token2 = store.create_device_token(user_id).await.unwrap();

        store.delete_all_device_tokens(user_id).await.unwrap();

        assert!(!store.verify_device_token(&token1, user_id).await);
        assert!(!store.verify_device_token(&token2, user_id).await);
    }

    #[tokio::test]
    async fn test_disable_totp_clears_all_mfa_data() {
        let (store, user_id) = test_mfa_store().await;
        let (secret, _) = store.generate_totp_secret("alice", "test").unwrap();
        store.enable_totp(user_id, &secret).await.unwrap();
        store.generate_backup_codes(user_id).await.unwrap();
        store.create_device_token(user_id).await.unwrap();

        store.disable_totp(user_id).await.unwrap();

        assert!(!store.verify_totp_for_user(user_id, "000000").await.unwrap());
        let backup_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = ?"
        ).bind(user_id)
         .fetch_one(&store.pool).await.unwrap();
        assert_eq!(backup_count.0, 0);
        let device_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mfa_device_tokens WHERE user_id = ?"
        ).bind(user_id)
         .fetch_one(&store.pool).await.unwrap();
        assert_eq!(device_count.0, 0);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let (store, user_id) = test_mfa_store().await;
        sqlx::query(
            "INSERT INTO mfa_pending_sessions (token, user_id, expires_at)
             VALUES ('old_pending', ?, datetime('now', '-10 minutes'))"
        ).bind(user_id)
         .execute(&store.pool).await.unwrap();
        sqlx::query(
            "INSERT INTO mfa_device_tokens (token, user_id, expires_at)
             VALUES ('old_device', ?, datetime('now', '-1 day'))"
        ).bind(user_id)
         .execute(&store.pool).await.unwrap();

        store.create_pending_session(user_id).await.unwrap();
        store.create_device_token(user_id).await.unwrap();

        store.cleanup_expired().await.unwrap();

        let pending_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mfa_pending_sessions"
        ).fetch_one(&store.pool).await.unwrap();
        assert_eq!(pending_count.0, 1);

        let device_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mfa_device_tokens"
        ).fetch_one(&store.pool).await.unwrap();
        assert_eq!(device_count.0, 1);
    }

    #[tokio::test]
    async fn test_increment_attempt_returns_false_until_fifth() {
        let (store, user_id) = test_mfa_store().await;
        let token = store.create_pending_session(user_id).await.unwrap();

        // First 4 attempts should return false (not locked out)
        for i in 1..=4 {
            let locked_out = store.increment_attempt(&token).await.unwrap();
            assert!(!locked_out);

            // Verify attempt count
            let (_, attempt_count) = store.verify_pending_session(&token).await.unwrap();
            assert_eq!(attempt_count, i);
        }
    }

    #[tokio::test]
    async fn test_increment_attempt_lockout_on_fifth() {
        let (store, user_id) = test_mfa_store().await;
        let token = store.create_pending_session(user_id).await.unwrap();

        // First 4 attempts
        for _ in 0..4 {
            store.increment_attempt(&token).await.unwrap();
        }

        // 5th attempt should lock out and delete session
        let locked_out = store.increment_attempt(&token).await.unwrap();
        assert!(locked_out);

        // Session should be deleted
        assert_eq!(store.verify_pending_session(&token).await, None);
    }

    #[tokio::test]
    async fn test_backup_code_input_with_and_without_hyphens() {
        let (store, user_id) = test_mfa_store().await;
        let codes = store.generate_backup_codes(user_id).await.unwrap();
        let code_with_hyphens = &codes[0]; // Format: xxxx-xxxx-xxxx

        // Should work with hyphens
        assert!(store.verify_backup_code(user_id, code_with_hyphens).await.unwrap());

        // Generate new codes for second test
        let codes = store.generate_backup_codes(user_id).await.unwrap();
        let code_with_hyphens = &codes[0];

        // Remove hyphens and try again
        let code_without_hyphens = code_with_hyphens.replace('-', "");
        assert!(store.verify_backup_code(user_id, &code_without_hyphens).await.unwrap());
    }

    #[tokio::test]
    async fn test_backup_code_consumed_cannot_be_reused() {
        let (store, user_id) = test_mfa_store().await;
        let codes = store.generate_backup_codes(user_id).await.unwrap();
        let code = &codes[0];

        // First use succeeds
        assert!(store.verify_backup_code(user_id, code).await.unwrap());

        // Second use fails
        assert!(!store.verify_backup_code(user_id, code).await.unwrap());

        // Also fails with hyphens removed
        let code_no_hyphen = code.replace('-', "");
        assert!(!store.verify_backup_code(user_id, &code_no_hyphen).await.unwrap());
    }
}
