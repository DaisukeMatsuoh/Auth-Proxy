// Middleware modules
pub mod auth;
pub mod admin;

// Re-export key types
pub use admin::AuthUser;

// Session cookie extraction utilities used by handlers
use axum::http::HeaderMap;
use crate::AppError;

/// Extract session_id from Cookie header
pub fn extract_session_id(headers: &HeaderMap) -> Result<String, AppError> {
    if let Some(cookie_header) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Parse cookies separated by ";"
            for cookie in cookie_str.split(';') {
                let trimmed = cookie.trim();
                if trimmed.starts_with("session_id=") {
                    if let Some(value) = trimmed.strip_prefix("session_id=") {
                        if !value.is_empty() {
                            return Ok(value.to_string());
                        }
                    }
                }
            }
        }
    }

    Err(AppError::Unauthorized)
}
