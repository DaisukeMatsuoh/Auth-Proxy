use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use crate::AppState;
use crate::api_tokens_db::ApiTokenStoreDb;
use crate::middleware::{extract_session_id, admin::AuthUser};

const BEARER_PREFIX: &str = "Bearer ";

/// Client-facing X-Auth-* headers. Always stripped from incoming requests
/// before any auth decision is made, to prevent forgery. Must be kept in
/// sync with every header this middleware ever sets below.
const X_AUTH_HEADERS: [&str; 6] = [
    "x-auth-user",
    "x-auth-user-id",
    "x-auth-role",
    "x-auth-issuer",
    "x-auth-method",
    "x-auth-token-name",
];

/// RFC 6750-flavored 401 for API clients. Never used for the session/cookie
/// path: browsers get a 302 to /login instead, handled downstream.
fn invalid_token_response() -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "invalid_token",
            "error_description": "The access token is invalid or has been revoked"
        })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

/// Strip control/newline characters before a user-supplied value (token
/// name) is placed into an HTTP header, to prevent header injection.
fn sanitize_header_value(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// RFC 6750-flavored 403 for a token restricted to a path scope it doesn't
/// cover (Phase API-3, R7). Distinct from `invalid_token_response`: the
/// token itself is valid, it just isn't allowed to reach this path.
fn insufficient_scope_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "insufficient_scope",
            "error_description": "This token is not permitted to access this path"
        })),
    )
        .into_response()
}

/// Extract session ID from cookies and attach X-Auth-* headers
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    // Remove any X-Auth-* headers from the client to prevent spoofing.
    // This must run before any auth branch below, including the token one.
    for header_name in X_AUTH_HEADERS {
        req.headers_mut().remove(header_name);
    }

    // Bearer token authentication takes priority over session cookies.
    // Presence of "Authorization: Bearer" marks this as an API client
    // request: on failure we must return 401 JSON, never a 302 redirect.
    if state.config.api_token_enabled {
        if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix(BEARER_PREFIX) {
                    let token_hash = ApiTokenStoreDb::hash_token(token);

                    let Ok(Some(token_row)) = state.api_tokens.verify(&token_hash).await else {
                        return invalid_token_response();
                    };

                    // Path-scope restriction (Phase API-3, R7). Checked before
                    // fetching the user so a scoped-out request costs one
                    // fewer DB round trip.
                    if let Some(prefix) = &token_row.path_prefix {
                        if !req.uri().path().starts_with(prefix.as_str()) {
                            return insufficient_scope_response();
                        }
                    }

                    let Ok(Some(user)) = state.users.get_by_id(token_row.user_id).await else {
                        return invalid_token_response();
                    };

                    // Best-effort, throttled bookkeeping; must never affect
                    // the auth decision itself.
                    let _ = state.api_tokens.touch_last_used(token_row.id).await;

                    let safe_token_name = sanitize_header_value(&token_row.name);

                    if let Ok(v) = HeaderValue::from_str(&user.username) {
                        req.headers_mut().insert("x-auth-user", v);
                    }
                    if let Ok(v) = HeaderValue::from_str(&user.id.to_string()) {
                        req.headers_mut().insert("x-auth-user-id", v);
                    }
                    if let Ok(v) = HeaderValue::from_str(&user.role) {
                        req.headers_mut().insert("x-auth-role", v);
                    }
                    if let Ok(v) = HeaderValue::from_str(&state.config.issuer_name) {
                        req.headers_mut().insert("x-auth-issuer", v);
                    }
                    req.headers_mut()
                        .insert("x-auth-method", HeaderValue::from_static("token"));
                    if let Ok(v) = HeaderValue::from_str(&safe_token_name) {
                        req.headers_mut().insert("x-auth-token-name", v);
                    }

                    req.extensions_mut().insert(AuthUser {
                        id: user.id,
                        username: user.username.clone(),
                        role: user.role.clone(),
                        auth_method: "token".to_string(),
                        token_name: Some(token_row.name.clone()),
                    });

                    // Token auth is stateless: no Set-Cookie is ever issued
                    // on this path.
                    return next.run(req).await;
                }
            }
        }
    }

    // Try to extract session_id from cookies
    if let Ok(session_id) = extract_session_id(req.headers()) {
        // Fetch session from database
        if let Ok(Some(session)) = state.sessions.get(&session_id).await {
            // Session is valid, fetch user details
            if let Ok(Some(user)) = state.users.get_by_id(session.user_id).await {
                // Add X-Auth-* headers
                if let Ok(username_val) = HeaderValue::from_str(&user.username) {
                    req.headers_mut().insert("x-auth-user", username_val);
                }

                if let Ok(user_id_val) = HeaderValue::from_str(&session.user_id.to_string()) {
                    req.headers_mut().insert("x-auth-user-id", user_id_val);
                }

                if let Ok(role_val) = HeaderValue::from_str(&user.role) {
                    req.headers_mut().insert("x-auth-role", role_val);
                }

                if let Ok(issuer_val) = HeaderValue::from_str(&state.config.issuer_name) {
                    req.headers_mut().insert("x-auth-issuer", issuer_val);
                }

                req.headers_mut()
                    .insert("x-auth-method", HeaderValue::from_static("session"));

                // Set Extension<AuthUser> for handlers that need it
                let auth_user = AuthUser {
                    id: user.id,
                    username: user.username.clone(),
                    role: user.role.clone(),
                    auth_method: "session".to_string(),
                    token_name: None,
                };
                let mut req = req;
                req.extensions_mut().insert(auth_user);

                return next.run(req).await;
            }
        }
    }

    // No valid session, continue with request as-is
    // The downstream handler will decide if authentication is required
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware::from_fn_with_state, routing::get, Router};
    use axum_test::TestServer;
    use crate::api_tokens_db::ApiTokenStoreDb as TokenStore;
    use crate::config::Config;
    use crate::mfa::MfaStore;
    use crate::sessions_db::SessionStoreDb;
    use crate::users_db::UserStoreDb;
    use sqlx::SqlitePool;
    use std::sync::Arc;

    /// Echo back the X-Auth-* headers that reached the "upstream" handler,
    /// as JSON. This is what proxy_handler would forward verbatim, so
    /// asserting on this echo is equivalent to asserting on what the
    /// upstream service actually receives.
    async fn echo_auth_headers(req: Request) -> Response {
        let mut out = serde_json::Map::new();
        for name in X_AUTH_HEADERS {
            if let Some(v) = req.headers().get(name) {
                out.insert(
                    name.to_string(),
                    serde_json::Value::String(v.to_str().unwrap_or("").to_string()),
                );
            }
        }
        Json(serde_json::Value::Object(out)).into_response()
    }

    async fn build_state(api_token_enabled: bool) -> AppState {
        let mut config = Config::test_default();
        config.api_token_enabled = api_token_enabled;
        let config = Arc::new(config);

        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();

        AppState {
            users: Arc::new(UserStoreDb::new(db.clone())),
            sessions: Arc::new(SessionStoreDb::new(db.clone(), config.session_ttl)),
            mfa: Arc::new(MfaStore::new(db.clone(), config.mfa_encryption_key)),
            api_tokens: Arc::new(TokenStore::new(db.clone())),
            http_client: reqwest::Client::new(),
            db,
            config,
        }
    }

    fn test_server(state: AppState) -> TestServer {
        let app = Router::new()
            .route("/echo", get(echo_auth_headers))
            .route("/sync/echo", get(echo_auth_headers))
            .layer(from_fn_with_state(state.clone(), auth_middleware))
            .with_state(state);
        TestServer::new(app)
    }

    #[tokio::test]
    async fn test_no_credentials_sets_no_auth_headers() {
        let state = build_state(true).await;
        let server = test_server(state);

        let response = server.get("/echo").await;
        response.assert_status_ok();
        let body = response.json::<serde_json::Value>();
        assert_eq!(body, serde_json::json!({}));
    }

    #[tokio::test]
    async fn test_valid_session_sets_session_headers() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let session_id = state.sessions.create(user.id).await.unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("cookie", format!("session_id={session_id}"))
            .await;

        response.assert_status_ok();
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["x-auth-user"], "alice");
        assert_eq!(body["x-auth-user-id"], user.id.to_string());
        assert_eq!(body["x-auth-role"], "user");
        assert_eq!(body["x-auth-method"], "session");
        assert!(body.get("x-auth-token-name").is_none());
    }

    #[tokio::test]
    async fn test_valid_token_sets_token_headers_and_no_set_cookie() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let (_row, plaintext) = state.api_tokens.create(user.id, "Alice's MacBook", 0, None).await.unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("authorization", format!("Bearer {plaintext}"))
            .await;

        response.assert_status_ok();
        assert!(!response.contains_header("set-cookie"));
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["x-auth-user"], "alice");
        assert_eq!(body["x-auth-method"], "token");
        assert_eq!(body["x-auth-token-name"], "Alice's MacBook");
    }

    /// Phase API-3 (R7): a token scoped to /sync/ can reach paths under it.
    #[tokio::test]
    async fn test_scoped_token_can_access_its_prefix() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let (_row, plaintext) = state
            .api_tokens
            .create(user.id, "Sync-only device", 0, Some("/sync/"))
            .await
            .unwrap();
        let server = test_server(state);

        let response = server
            .get("/sync/echo")
            .add_header("authorization", format!("Bearer {plaintext}"))
            .await;

        response.assert_status_ok();
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["x-auth-user"], "alice");
    }

    /// Phase API-3 (R7) ★most important: a token scoped to /sync/ must be
    /// rejected outside that prefix, with 403 insufficient_scope — not a
    /// silent pass-through and not the generic invalid_token 401.
    #[tokio::test]
    async fn test_scoped_token_rejected_outside_its_prefix() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let (_row, plaintext) = state
            .api_tokens
            .create(user.id, "Sync-only device", 0, Some("/sync/"))
            .await
            .unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("authorization", format!("Bearer {plaintext}"))
            .await;

        response.assert_status_forbidden();
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["error"], "insufficient_scope");
    }

    /// A token with no path_prefix (None) keeps Phase API-1 behavior: full access.
    #[tokio::test]
    async fn test_unscoped_token_can_access_any_path() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let (_row, plaintext) = state.api_tokens.create(user.id, "Full-access device", 0, None).await.unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("authorization", format!("Bearer {plaintext}"))
            .await;
        response.assert_status_ok();

        let response = server
            .get("/sync/echo")
            .add_header("authorization", format!("Bearer {plaintext}"))
            .await;
        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_invalid_token_returns_401_json_with_www_authenticate() {
        let state = build_state(true).await;
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("authorization", "Bearer apx_this_was_never_issued")
            .await;

        response.assert_status_unauthorized();
        response.assert_header("www-authenticate", "Bearer");
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["error"], "invalid_token");
    }

    #[tokio::test]
    async fn test_revoked_token_returns_401_not_redirect() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let (row, plaintext) = state.api_tokens.create(user.id, "Device", 0, None).await.unwrap();
        state.api_tokens.revoke(row.id, user.id).await.unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("authorization", format!("Bearer {plaintext}"))
            .await;

        response.assert_status_unauthorized();
    }

    #[tokio::test]
    async fn test_disabled_feature_ignores_bearer_header() {
        // AUTH_PROXY_API_TOKEN_ENABLED=false must fully preserve legacy
        // behavior: a Bearer header is neither validated nor rejected, it
        // simply falls through to the (absent) session check.
        let state = build_state(false).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let (_row, plaintext) = state.api_tokens.create(user.id, "Device", 0, None).await.unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("authorization", format!("Bearer {plaintext}"))
            .await;

        // Falls through to "no valid session" -> handler still runs, but
        // with no X-Auth-* headers set (not a 401 JSON error either).
        response.assert_status_ok();
        let body = response.json::<serde_json::Value>();
        assert_eq!(body, serde_json::json!({}));
    }

    /// ★ Most important test in this module (see CLAUDE.md invariant:
    /// "processing order must be explicitly tested"). A client cannot use
    /// a valid low-privilege token to smuggle in an elevated role by also
    /// sending X-Auth-Role directly: client-supplied X-Auth-* headers must
    /// be stripped before the token's real role is looked up and set.
    #[tokio::test]
    async fn test_token_auth_ignores_client_supplied_role_header() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let (_row, plaintext) = state.api_tokens.create(user.id, "Device", 0, None).await.unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("authorization", format!("Bearer {plaintext}"))
            .add_header("x-auth-role", "admin")
            .add_header("x-auth-user", "root")
            .await;

        response.assert_status_ok();
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["x-auth-role"], "user");
        assert_eq!(body["x-auth-user"], "alice");
    }

    /// Same escalation attempt via the session-cookie path.
    #[tokio::test]
    async fn test_session_auth_ignores_client_supplied_role_header() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let session_id = state.sessions.create(user.id).await.unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("cookie", format!("session_id={session_id}"))
            .add_header("x-auth-role", "admin")
            .await;

        response.assert_status_ok();
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["x-auth-role"], "user");
    }

    #[tokio::test]
    async fn test_non_bearer_authorization_falls_back_to_session() {
        let state = build_state(true).await;
        let user = state.users.create("alice", "hunter2", "user").await.unwrap();
        let session_id = state.sessions.create(user.id).await.unwrap();
        let server = test_server(state);

        let response = server
            .get("/echo")
            .add_header("cookie", format!("session_id={session_id}"))
            .add_header("authorization", "Basic dXNlcjpwYXNz")
            .await;

        response.assert_status_ok();
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["x-auth-method"], "session");
    }
}
