use crate::{AppError, AppState};
use axum::extract::State;
use axum::http::{StatusCode, HeaderMap};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// GET / - Show login form if no session, otherwise redirect to static files
pub async fn get_login(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Check if user has a valid session
    if let Some(cookie_header) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Parse cookies to find session_id
            for cookie in cookie_str.split(';') {
                let trimmed = cookie.trim();
                if trimmed.starts_with("session_id=") {
                    if let Some(value) = trimmed.strip_prefix("session_id=") {
                        // Check if session exists (async)
                        if let Ok(Some(_)) = state.sessions.get(value).await {
                            return Redirect::to("/").into_response();
                        }
                    }
                }
            }
        }
    }

    // No valid session, show login form
    Html(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Login</title>
    <style>
        body { font-family: sans-serif; max-width: 400px; margin: 100px auto; }
        form { display: flex; flex-direction: column; }
        input { margin: 10px 0; padding: 8px; }
        button { padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>Login</h1>
    <form method="post" action="/login">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>

        <button type="submit">Login</button>
    </form>
</body>
</html>"#,
    ).into_response()
}

/// POST /login - Handle login form submission
pub async fn post_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(credentials): Form<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Verify user credentials
    match state.users.verify(&credentials.username, &credentials.password).await {
        Ok(true) => {
            // Credentials valid, get user_id
        }
        Ok(false) => {
            // Invalid credentials
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            return Ok((
                StatusCode::UNAUTHORIZED,
                Html(
                    r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Login Failed</title>
</head>
<body>
    <h1>Login Failed</h1>
    <p>Invalid username or password.</p>
    <a href="/">Back to login</a>
</body>
</html>"#,
                ),
            )
                .into_response());
        }
        Err(_e) => {
            // Database error
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>500 Internal Server Error</h1>"),
            )
                .into_response());
        }
    }

    // Get user to obtain user_id and check MFA status
    let user = match state.users.get_by_username(&credentials.username).await {
        Ok(Some(user)) => user,
        _ => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>500 Internal Server Error</h1>"),
            )
                .into_response());
        }
    };

    // Check if MFA is enabled for this user
    let totp_enabled = sqlx::query_scalar::<_, i32>(
        "SELECT totp_enabled FROM users WHERE id = ?"
    ).bind(user.id)
     .fetch_optional(&state.db).await
     .unwrap_or(Some(0))
     .unwrap_or(0);

    // If MFA is disabled, create normal session
    if totp_enabled == 0 {
        let session_id = match state.sessions.create(user.id).await {
            Ok(id) => id,
            Err(_e) => {
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html("<h1>500 Internal Server Error</h1>"),
                )
                    .into_response());
            }
        };

        let ttl_secs = state.config.session_ttl.as_secs();
        let cookie_value = format!(
            "session_id={}; Max-Age={}; HttpOnly; Secure; Path=/; SameSite=Strict",
            session_id, ttl_secs
        );

        return Ok((
            [(
                axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&cookie_value)
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
            )],
            axum::response::Redirect::to("/"),
        )
            .into_response());
    }

    // MFA is enabled: check for device token
    let device_token = headers.get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            for cookie in cookie_str.split(';') {
                let trimmed = cookie.trim();
                if let Some(value) = trimmed.strip_prefix("device_token=") {
                    return Some(value.to_string());
                }
            }
            None
        });

    // If valid device token exists, skip MFA
    if let Some(token) = &device_token {
        if state.mfa.verify_device_token(token, user.id).await {
            let session_id = match state.sessions.create(user.id).await {
                Ok(id) => id,
                Err(_e) => {
                    return Ok((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Html("<h1>500 Internal Server Error</h1>"),
                    )
                        .into_response());
                }
            };

            let ttl_secs = state.config.session_ttl.as_secs();
            let cookie_value = format!(
                "session_id={}; Max-Age={}; HttpOnly; Secure; Path=/; SameSite=Strict",
                session_id, ttl_secs
            );

            return Ok((
                [(
                    axum::http::header::SET_COOKIE,
                    axum::http::HeaderValue::from_str(&cookie_value)
                        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
                )],
                axum::response::Redirect::to("/"),
            )
                .into_response());
        }
    }

    // MFA required: create pending session
    let pending_token = match state.mfa.create_pending_session(user.id).await {
        Ok(token) => token,
        Err(_e) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>500 Internal Server Error</h1>"),
            )
                .into_response());
        }
    };

    let pending_cookie_value = format!(
        "mfa_pending={}; Max-Age=300; HttpOnly; Secure; Path=/; SameSite=Strict",
        pending_token
    );

    Ok((
        [(
            axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&pending_cookie_value)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
        )],
        axum::response::Redirect::to("/mfa/verify"),
    )
        .into_response())
}
