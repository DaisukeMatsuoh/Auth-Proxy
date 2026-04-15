use crate::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;

/// POST /logout - Handle logout
pub async fn post_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // Try to extract session_id from Cookie header and remove from store
    if let Some(cookie_header) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            if let Some(session_id) = extract_session_id(cookie_str) {
                let _ = state.sessions.remove(&session_id).await;
            }
        }
    }

    // Clear the session cookie on the client side (Max-Age=0)
    (
        StatusCode::SEE_OTHER,
        [
            (
                axum::http::header::SET_COOKIE,
                HeaderValue::from_static(
                    "session_id=; Max-Age=0; HttpOnly; Secure; Path=/; SameSite=Strict"
                ),
            ),
            (
                axum::http::header::LOCATION,
                HeaderValue::from_static("/login"),
            ),
        ],
        "",
    )
        .into_response()
}

/// Extract session_id from Cookie header value
fn extract_session_id(cookie_str: &str) -> Option<String> {
    for cookie in cookie_str.split(';') {
        let trimmed = cookie.trim();
        if trimmed.starts_with("session_id=") {
            let value = trimmed.strip_prefix("session_id=")?;
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}
