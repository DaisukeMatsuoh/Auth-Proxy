use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use std::path::PathBuf;
use crate::AppState;
use crate::middleware::AuthUser;

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailers"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "host"
    )
}

/// Fallback handler: serves static files (if APP_SERVE_PATH set) or proxies to upstream
pub async fn proxy_handler(
    State(state): State<AppState>,
    req: Request,
) -> Response {
    // Require authentication (AuthUser extension is set by auth_middleware on valid session)
    if req.extensions().get::<AuthUser>().is_none() {
        return Redirect::to("/login").into_response();
    }

    // If serve_path is configured, try to serve a matching static file first
    if let Some(serve_path) = &state.config.serve_path {
        let uri_path = req.uri().path();
        let rel = uri_path.trim_start_matches('/');
        let rel = if rel.is_empty() { "index.html" } else { rel };

        let request_path = PathBuf::from(rel);
        // Prevent directory traversal
        if !request_path.components().any(|c| c.as_os_str() == "..") {
            let full_path = serve_path.join(&request_path);
            if full_path.is_file() {
                return serve_file(&full_path).await;
            }
        }
    }

    // Forward to upstream (upstream_url is guaranteed Some when serve_path is None,
    // enforced by startup validation in config.rs)
    if state.config.upstream_url.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    forward_to_upstream(state, req).await
}

async fn serve_file(path: &std::path::Path) -> Response {
    let content_type = match path.extension().and_then(|ext| ext.to_str()) {
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

    match tokio::fs::read(path).await {
        Ok(contents) => Response::builder()
            .header(axum::http::header::CONTENT_TYPE, content_type)
            .body(Body::from(contents))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn forward_to_upstream(state: AppState, req: Request) -> Response {
    // Clone parts we need before consuming body
    let method_bytes = req.method().as_str().as_bytes().to_vec();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let mut req_headers = reqwest::header::HeaderMap::new();
    for (name, value) in req.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            req_headers.insert(n, v);
        }
    }

    // Consume body (limit 100 MB)
    let body = match axum::body::to_bytes(req.into_body(), 100 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let upstream_url = state.config.upstream_url.as_deref().unwrap_or("");
    let upstream_base = upstream_url.trim_end_matches('/');
    let target_url = format!("{}{}", upstream_base, path_and_query);

    let method = match reqwest::Method::from_bytes(&method_bytes) {
        Ok(m) => m,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let upstream_resp = match state
        .http_client
        .request(method, &target_url)
        .headers(req_headers)
        .body(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Upstream request failed: {}", e);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);

    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_resp.headers() {
        if !is_hop_by_hop(name.as_str()) {
            builder = builder.header(name, value);
        }
    }

    let resp_body = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    builder
        .body(Body::from(resp_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
