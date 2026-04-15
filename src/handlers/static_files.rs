use crate::{AppError, AppState};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Response};
use axum::http::Uri;
use std::path::PathBuf;
use tokio::fs;

/// GET /* - Serve static files (authenticated users only)
pub async fn serve_static_files(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response<Body>, AppError> {
    // Extract session_id from Cookie header
    let session_id = extract_session_id(&headers)?;

    // Validate session
    let _session = state
        .sessions
        .get(&session_id)
        .await
        .map_err(|_| AppError::SessionNotFound)?
        .ok_or(AppError::SessionNotFound)?;

    // Extract path from URI
    let mut path = uri.path().to_string();

    // Remove leading slash
    if path.starts_with('/') {
        path = path[1..].to_string();
    }

    // Default to index.html
    if path.is_empty() {
        path = "index.html".to_string();
    }

    // Prevent directory traversal
    let request_path = PathBuf::from(&path);
    if request_path.components().any(|c| c.as_os_str() == "..") {
        return Err(AppError::NotFound);
    }

    // Construct full file path
    let mut full_path = state.config.serve_path.clone();
    full_path.push(&request_path);

    // Determine content type based on file extension
    let content_type = match request_path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    };

    // Read file as bytes (supports both text and binary)
    let contents = fs::read(&full_path)
        .await
        .map_err(|_| AppError::NotFound)?;

    // Build response
    let response = Response::builder()
        .header(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static(content_type),
        )
        .body(Body::from(contents))
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(response)
}

/// Extract session_id from Cookie header value
fn extract_session_id(headers: &HeaderMap) -> Result<String, AppError> {
    if let Some(cookie_header) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
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
