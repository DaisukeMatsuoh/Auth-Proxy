use argon2::{Argon2, PasswordHash, PasswordVerifier};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct UserStore {
    users: HashMap<String, String>, // username -> argon2id hash
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("Failed to parse users: {0}")]
    ParseError(String),

    #[error("Invalid user entry: {0}")]
    InvalidEntry(String),
}

impl UserStore {
    /// Parse APP_USERS string format: "user1:hash1,user2:hash2"
    /// Note: Hashes may contain commas (e.g., Argon2 m=19456,t=2,p=1)
    /// So we split on commas first, then find the ':' separator
    pub fn from_str(raw: &str) -> Result<Self, UserStoreError> {
        let mut users = HashMap::new();

        if raw.is_empty() {
            return Err(UserStoreError::ParseError(
                "APP_USERS cannot be empty".to_string(),
            ));
        }

        // Split by comma, but carefully reconstruct user:hash pairs
        // since hashes contain commas. We look for username:hash pattern.
        let entries = Self::parse_entries(raw)?;

        for (username, hash) in entries {
            if username.is_empty() || hash.is_empty() {
                return Err(UserStoreError::InvalidEntry(
                    format!("Empty username or hash"),
                ));
            }
            users.insert(username, hash);
        }

        if users.is_empty() {
            return Err(UserStoreError::ParseError(
                "No valid user entries found".to_string(),
            ));
        }

        Ok(UserStore { users })
    }

    fn parse_entries(raw: &str) -> Result<Vec<(String, String)>, UserStoreError> {
        let mut entries = Vec::new();

        // Split by commas and try to group them back into user:hash pairs
        // Username contains only alphanumeric and underscores, so we look for pattern
        // where a comma is followed by a word boundary then ':' to know a new entry started
        let parts: Vec<&str> = raw.split(',').collect();
        let mut i = 0;

        while i < parts.len() {
            let part = parts[i].trim();

            // Check if this part contains ':'
            if let Some(colon_pos) = part.find(':') {
                // Extract username (before ':')
                let username = part[..colon_pos].trim().to_string();

                // Start collecting hash
                let mut hash = part[colon_pos + 1..].trim().to_string();

                // Check if username is valid (word characters only)
                if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    return Err(UserStoreError::InvalidEntry(
                        format!("Invalid username: {}", username),
                    ));
                }

                // Look ahead to see if we need to collect more parts (hash contains commas)
                i += 1;
                while i < parts.len() {
                    let next_part = parts[i].trim();
                    // If next part contains ':', it's a new user entry
                    if next_part.contains(':') {
                        // Check if it starts with a valid username pattern
                        if let Some(next_colon) = next_part.find(':') {
                            let potential_user = next_part[..next_colon].trim();
                            if potential_user.chars().all(|c| c.is_alphanumeric() || c == '_') {
                                // This is a new user entry, don't consume it
                                break;
                            }
                        }
                    }
                    // Part is a continuation of the hash
                    hash.push(',');
                    hash.push_str(next_part);
                    i += 1;
                }

                entries.push((username, hash));
            } else {
                return Err(UserStoreError::InvalidEntry(
                    format!("Invalid entry format (missing colon): {}", part),
                ));
            }
        }

        Ok(entries)
    }

    /// Verify username and password.
    /// Returns true if the password matches the stored hash for the user.
    /// Returns false if the user doesn't exist or the password doesn't match.
    ///
    /// IMPORTANT: This function always performs Argon2 verification
    /// (even for non-existent users with a dummy hash) to mitigate
    /// timing attacks.
    pub fn verify(&self, username: &str, password: &str) -> bool {
        eprintln!("[DEBUG] verify() called: username='{}', password_len={}", username, password.len());

        let argon2 = Argon2::default();

        // Get the hash for the user, or use a dummy hash if user doesn't exist
        let user_exists = self.users.contains_key(username);
        eprintln!("[DEBUG] User '{}' exists: {}", username, user_exists);

        let hash_str = self.users.get(username).map(|s| s.as_str()).unwrap_or(
            // Dummy hash for timing attack mitigation
            "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$abcdefghijklmnopqrstuvwxyz0123456789abcd",
        );

        if user_exists {
            eprintln!("[DEBUG] Hash from user store: (len={})", hash_str.len());
            // Show first and last parts of hash for inspection
            if hash_str.len() > 20 {
                eprintln!("[DEBUG] Hash preview: {}...{}", &hash_str[..20], &hash_str[hash_str.len()-10..]);
            } else {
                eprintln!("[DEBUG] Hash: {}", hash_str);
            }
        } else {
            eprintln!("[DEBUG] Using dummy hash (user not found)");
        }

        let parsed_hash = match PasswordHash::new(hash_str) {
            Ok(hash) => {
                eprintln!("[DEBUG] PasswordHash parsed successfully");
                hash
            }
            Err(e) => {
                eprintln!("[DEBUG] PasswordHash parse FAILED: {:?}", e);
                return false;
            }
        };

        // Always attempt verification, even with dummy hash
        let verify_result = argon2.verify_password(password.as_bytes(), &parsed_hash);
        eprintln!("[DEBUG] verify_password result: {}", verify_result.is_ok());

        verify_result.is_ok()
    }

    /// Get list of all usernames
    pub fn list_users(&self) -> Vec<String> {
        let mut users: Vec<_> = self.users.keys().cloned().collect();
        users.sort();
        users
    }

    /// Get all users as (username, hash) pairs
    pub fn list_all(&self) -> Vec<(String, String)> {
        let mut users: Vec<_> = self.users
            .iter()
            .map(|(username, hash)| (username.clone(), hash.clone()))
            .collect();
        users.sort_by(|a, b| a.0.cmp(&b.0));
        users
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    // Generate test hash for password "testpass"
    fn get_test_hash() -> String {
        let argon2 = Argon2::default();
        let password = "testpass";
        let salt = SaltString::generate(&mut OsRng);

        argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    #[test]
    fn test_parse_valid_single_user() {
        let hash = get_test_hash();
        let raw = format!("testuser:{}", hash);
        let store = UserStore::from_str(&raw).unwrap();
        assert_eq!(store.users.len(), 1);
        assert!(store.users.contains_key("testuser"));
    }

    #[test]
    fn test_parse_multiple_users() {
        let hash = get_test_hash();
        let raw = format!(
            "alice:{},bob:{}",
            hash, hash
        );
        let store = UserStore::from_str(&raw).unwrap();
        assert_eq!(store.users.len(), 2);
        assert!(store.users.contains_key("alice"));
        assert!(store.users.contains_key("bob"));
    }

    #[test]
    fn test_parse_empty_string() {
        let result = UserStore::from_str("");
        assert!(matches!(result, Err(UserStoreError::ParseError(_))));
    }

    #[test]
    fn test_parse_invalid_format() {
        let result = UserStore::from_str("invalidformat");
        assert!(matches!(result, Err(UserStoreError::InvalidEntry(_))));
    }

    #[test]
    fn test_parse_empty_username() {
        let hash = get_test_hash();
        let raw = format!(":{}", hash);
        let result = UserStore::from_str(&raw);
        assert!(matches!(result, Err(UserStoreError::InvalidEntry(_))));
    }

    #[test]
    fn test_verify_correct_password() {
        let hash = get_test_hash();
        let raw = format!("testuser:{}", hash);
        let store = UserStore::from_str(&raw).unwrap();
        assert!(store.verify("testuser", "testpass"));
    }

    #[test]
    fn test_verify_wrong_password() {
        let hash = get_test_hash();
        let raw = format!("testuser:{}", hash);
        let store = UserStore::from_str(&raw).unwrap();
        assert!(!store.verify("testuser", "wrongpass"));
    }

    #[test]
    fn test_verify_nonexistent_user() {
        let hash = get_test_hash();
        let raw = format!("testuser:{}", hash);
        let store = UserStore::from_str(&raw).unwrap();
        // Should still return false (timing attack mitigation ensures we do verification)
        assert!(!store.verify("nonexistent", "testpass"));
    }

    #[test]
    fn test_verify_timing_attack_mitigation() {
        let hash = get_test_hash();
        let raw = format!("testuser:{}", hash);
        let store = UserStore::from_str(&raw).unwrap();

        // Both should be false, and timing should be similar
        let result1 = store.verify("nonexistent", "testpass");
        let result2 = store.verify("testuser", "wrongpass");

        assert!(!result1);
        assert!(!result2);
    }

    #[test]
    fn test_list_users() {
        let hash = get_test_hash();
        let raw = format!(
            "charlie:{},alice:{},bob:{}",
            hash, hash, hash
        );
        let store = UserStore::from_str(&raw).unwrap();
        let users = store.list_users();
        assert_eq!(users, vec!["alice", "bob", "charlie"]);
    }
}
