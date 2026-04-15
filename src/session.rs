use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub username: String,
    pub created_at: Instant,
    pub expires_at: Instant,
}

impl SessionEntry {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        SessionStore {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Create a new session and return the session ID (32-char hex string)
    pub fn create(&self, username: String) -> String {
        let mut random_bytes = [0u8; 16]; // 128 bits
        OsRng.fill_bytes(&mut random_bytes);
        let session_id = hex::encode(random_bytes);

        let now = Instant::now();
        let entry = SessionEntry {
            username,
            created_at: now,
            expires_at: now + self.ttl,
        };

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), entry);

        session_id
    }

    /// Get a session if it exists and is not expired
    pub fn get(&self, session_id: &str) -> Option<SessionEntry> {
        let sessions = self.sessions.lock().unwrap();
        match sessions.get(session_id) {
            Some(entry) if !entry.is_expired() => Some(entry.clone()),
            _ => None,
        }
    }

    /// Remove a session
    pub fn remove(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }

    /// Clean up expired sessions (call periodically from background task)
    pub fn cleanup_expired(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, entry| !entry.is_expired());
    }

    /// Get count of active sessions (for testing/debugging)
    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        let sessions = self.sessions.lock().unwrap();
        sessions.values().filter(|e| !e.is_expired()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let session_id = store.create("testuser".to_string());

        // Session ID should be 32-char hex (16 bytes = 128 bits)
        assert_eq!(session_id.len(), 32);
        assert!(session_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_get_existing_session() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let session_id = store.create("testuser".to_string());

        let entry = store.get(&session_id).unwrap();
        assert_eq!(entry.username, "testuser");
    }

    #[test]
    fn test_get_nonexistent_session() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let result = store.get("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_session() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let session_id = store.create("testuser".to_string());

        assert!(store.get(&session_id).is_some());
        store.remove(&session_id);
        assert!(store.get(&session_id).is_none());
    }

    #[test]
    fn test_session_expiration() {
        let store = SessionStore::new(Duration::from_millis(100));
        let session_id = store.create("testuser".to_string());

        assert!(store.get(&session_id).is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));
        assert!(store.get(&session_id).is_none());
    }

    #[test]
    fn test_cleanup_expired() {
        let store = SessionStore::new(Duration::from_millis(100));
        let _session_id1 = store.create("user1".to_string());
        let _session_id2 = store.create("user2".to_string());

        assert_eq!(store.session_count(), 2);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        store.cleanup_expired();
        assert_eq!(store.session_count(), 0);
    }

    #[test]
    fn test_multiple_sessions_same_user() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let session_id1 = store.create("testuser".to_string());
        let session_id2 = store.create("testuser".to_string());

        assert_ne!(session_id1, session_id2);
        assert!(store.get(&session_id1).is_some());
        assert!(store.get(&session_id2).is_some());
    }

    #[test]
    fn test_session_store_clone() {
        let store1 = SessionStore::new(Duration::from_secs(3600));
        let session_id = store1.create("testuser".to_string());

        let store2 = store1.clone();
        // Both should see the same session (Arc internally)
        assert!(store2.get(&session_id).is_some());
    }
}
