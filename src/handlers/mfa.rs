use crate::{AppError, AppState};
use axum::extract::{State, Query};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

/// GET /mfa/verify - Show TOTP/Backup code form
pub async fn show_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Extract mfa_pending cookie
    let pending_token = headers.get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            for cookie in cookie_str.split(';') {
                let trimmed = cookie.trim();
                if let Some(value) = trimmed.strip_prefix("mfa_pending=") {
                    return Some(value.to_string());
                }
            }
            None
        });

    if pending_token.is_none() {
        return Redirect::to("/login").into_response();
    }

    // Verify pending session
    if state.mfa.verify_pending_session(&pending_token.unwrap()).await.is_none() {
        return Redirect::to("/login").into_response();
    }

    let next = params.get("next").map(|s| s.as_str()).unwrap_or("/");
    let error = params.get("error").is_some();

    let error_html = if error {
        r#"<p class="text-sm text-red-500 mb-3">コードが正しくありません</p>"#
    } else {
        ""
    };

    Html(
        format!(
            r#"<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 flex items-center justify-center">
  <div class="bg-white rounded-2xl shadow-md p-8 w-full max-w-sm">
    <div class="flex items-center gap-2 mb-6">
      <span class="text-2xl">🔐</span>
      <span class="text-lg font-semibold text-gray-700">{}</span>
    </div>
    <h1 class="text-xl font-bold text-gray-800 mb-2">二段階認証</h1>
    <p class="text-sm text-gray-500 mb-6">認証アプリに表示されている6桁のコードを入力してください</p>
    {}
    <form method="POST" action="/mfa/verify">
      <input type="hidden" name="next" value="{}">
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 mb-1">認証コード</label>
        <input type="text" name="code" inputmode="numeric" pattern="[0-9]*"
               maxlength="8"
               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm
                      focus:outline-none focus:ring-2 focus:ring-blue-500
                      tracking-widest text-center text-lg"
               autofocus required>
      </div>
      <div class="flex items-center mb-4">
        <input type="checkbox" name="remember_device" id="remember_device"
               class="mr-2">
        <label for="remember_device" class="text-sm text-gray-600">
          このデバイスを30日間記憶する
        </label>
      </div>
      <button type="submit"
              class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium
                     py-2 px-4 rounded-lg text-sm transition-colors">
        確認する
      </button>
    </form>
    <div class="mt-4 text-center">
      <a href="/mfa/backup?next={}" class="text-sm text-blue-600 hover:underline">
        バックアップコードを使う
      </a>
    </div>
  </div>
</body>
</html>"#,
            state.config.issuer_name,
            state.config.issuer_name,
            error_html,
            next,
            next,
        )
    ).into_response()
}

#[derive(Deserialize)]
pub struct MfaVerifyRequest {
    pub code: String,
    pub remember_device: Option<String>,
    pub next: Option<String>,
}

/// POST /mfa/verify - Verify TOTP or backup code
pub async fn handle_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaVerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Extract mfa_pending cookie
    let pending_token = headers.get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            for cookie in cookie_str.split(';') {
                let trimmed = cookie.trim();
                if let Some(value) = trimmed.strip_prefix("mfa_pending=") {
                    return Some(value.to_string());
                }
            }
            None
        })
        .ok_or(AppError::Unauthorized)?;

    // Verify pending session and get attempt count
    let (user_id, _attempt_count) = state.mfa.verify_pending_session(&pending_token).await
        .ok_or(AppError::Unauthorized)?;

    let next = form.next.as_deref().unwrap_or("/");
    if !next.starts_with('/') {
        return Err(AppError::Unauthorized);
    }

    // Try TOTP verification
    if state.mfa.verify_totp_for_user(user_id, &form.code).await.unwrap_or(false) {
        // TOTP verified
        state.mfa.delete_pending_session(&pending_token).await.ok();

        let session_id = state.sessions.create(user_id).await.map_err(|_| AppError::InternalError("session creation failed".to_string()))?;
        let ttl_secs = state.config.session_ttl.as_secs();

        let mut response = Response::default();

        {
            let headers = response.headers_mut();
            // Delete mfa_pending cookie
            let pending_cookie = format!("mfa_pending=; Max-Age=0; HttpOnly; Secure; Path=/; SameSite=Strict");
            headers.insert(axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&pending_cookie)
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")));

            // Issue session_id cookie
            let session_cookie = format!("session_id={}; Max-Age={}; HttpOnly; Secure; Path=/; SameSite=Strict", session_id, ttl_secs);
            headers.insert(axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&session_cookie)
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")));

            // If remember_device is checked, issue device_token
            if form.remember_device.as_deref() == Some("on") {
                let device_token = state.mfa.create_device_token(user_id).await
                    .map_err(|_| AppError::InternalError("device token creation failed".to_string()))?;
                let device_cookie = format!("device_token={}; Max-Age=2592000; HttpOnly; Secure; Path=/; SameSite=Strict", device_token);
                headers.insert(axum::http::header::SET_COOKIE,
                    axum::http::HeaderValue::from_str(&device_cookie)
                        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")));
            }

            headers.insert(axum::http::header::LOCATION, axum::http::HeaderValue::from_str(next)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("/")));
        }

        *response.status_mut() = axum::http::StatusCode::SEE_OTHER;
        return Ok(response);
    }

    // Try backup code verification
    if state.mfa.verify_backup_code(user_id, &form.code).await.unwrap_or(false) {
        // Backup code verified
        state.mfa.delete_pending_session(&pending_token).await.ok();

        let session_id = state.sessions.create(user_id).await.map_err(|_| AppError::InternalError("session creation failed".to_string()))?;
        let ttl_secs = state.config.session_ttl.as_secs();

        let mut response = Response::default();

        {
            let headers = response.headers_mut();
            // Delete mfa_pending cookie
            let pending_cookie = format!("mfa_pending=; Max-Age=0; HttpOnly; Secure; Path=/; SameSite=Strict");
            headers.insert(axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&pending_cookie)
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")));

            // Issue session_id cookie
            let session_cookie = format!("session_id={}; Max-Age={}; HttpOnly; Secure; Path=/; SameSite=Strict", session_id, ttl_secs);
            headers.insert(axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&session_cookie)
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")));

            headers.insert(axum::http::header::LOCATION, axum::http::HeaderValue::from_str(next)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("/")));
        }

        *response.status_mut() = axum::http::StatusCode::SEE_OTHER;
        return Ok(response);
    }

    // Invalid code: increment attempt and check for lockout
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    match state.mfa.increment_attempt(&pending_token).await {
        Ok(true) => {
            // Locked out (5 failed attempts)
            Ok((
                axum::http::StatusCode::LOCKED,
                Html(
                    r#"<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>ロック</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 flex items-center justify-center">
  <div class="bg-white rounded-2xl shadow-md p-8 w-full max-w-sm">
    <h1 class="text-xl font-bold text-red-600 mb-4">🔒 認証失敗が多すぎます</h1>
    <p class="text-gray-700 mb-4">セキュリティのため、一時的にアクセスがロックされています。数分後に再度ログインしてください。</p>
    <a href="/login" class="text-blue-600 hover:underline">ログインページに戻る</a>
  </div>
</body>
</html>"#
                ),
            ).into_response())
        }
        Ok(false) => {
            // Still allowed, show error
            let next_param = if next == "/" { String::new() } else { format!("?next={}", next) };
            Ok(Redirect::to(&format!("/mfa/verify{}?error=true", next_param)).into_response())
        }
        Err(_) => {
            // Database error
            Err(AppError::InternalError("attempt tracking failed".to_string()))
        }
    }
}

/// GET /mfa/backup - Show backup code form
pub async fn show_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let pending_token = headers.get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            for cookie in cookie_str.split(';') {
                let trimmed = cookie.trim();
                if let Some(value) = trimmed.strip_prefix("mfa_pending=") {
                    return Some(value.to_string());
                }
            }
            None
        });

    if pending_token.is_none() || state.mfa.verify_pending_session(&pending_token.unwrap()).await.is_none() {
        return Redirect::to("/login").into_response();
    }

    let next = params.get("next").map(|s| s.as_str()).unwrap_or("/");

    Html(
        format!(
            r#"<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 flex items-center justify-center">
  <div class="bg-white rounded-2xl shadow-md p-8 w-full max-w-sm">
    <div class="flex items-center gap-2 mb-6">
      <span class="text-2xl">🔐</span>
      <span class="text-lg font-semibold text-gray-700">{}</span>
    </div>
    <h1 class="text-xl font-bold text-gray-800 mb-2">バックアップコード</h1>
    <p class="text-sm text-gray-500 mb-6">保存してあるバックアップコードを入力してください</p>
    <form method="POST" action="/mfa/backup">
      <input type="hidden" name="next" value="{}">
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 mb-1">コード</label>
        <input type="text" name="code" inputmode="numeric" pattern="[0-9]*"
               maxlength="8"
               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm
                      focus:outline-none focus:ring-2 focus:ring-blue-500
                      text-center text-lg"
               autofocus required>
      </div>
      <button type="submit"
              class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium
                     py-2 px-4 rounded-lg text-sm transition-colors">
        確認する
      </button>
    </form>
  </div>
</body>
</html>"#,
            state.config.issuer_name,
            state.config.issuer_name,
            next,
        )
    ).into_response()
}

#[derive(Deserialize)]
pub struct MfaBackupRequest {
    pub code: String,
    pub next: Option<String>,
}

/// POST /mfa/backup - Verify backup code
pub async fn handle_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaBackupRequest>,
) -> Result<impl IntoResponse, AppError> {
    let pending_token = headers.get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            for cookie in cookie_str.split(';') {
                let trimmed = cookie.trim();
                if let Some(value) = trimmed.strip_prefix("mfa_pending=") {
                    return Some(value.to_string());
                }
            }
            None
        })
        .ok_or(AppError::Unauthorized)?;

    let (user_id, _attempt_count) = state.mfa.verify_pending_session(&pending_token).await
        .ok_or(AppError::Unauthorized)?;

    let next = form.next.as_deref().unwrap_or("/");
    if !next.starts_with('/') {
        return Err(AppError::Unauthorized);
    }

    if !state.mfa.verify_backup_code(user_id, &form.code).await.unwrap_or(false) {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Increment attempt and check for lockout
        match state.mfa.increment_attempt(&pending_token).await {
            Ok(true) => {
                // Locked out (5 failed attempts)
                return Ok((
                    axum::http::StatusCode::LOCKED,
                    Html(
                        r#"<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>ロック</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 flex items-center justify-center">
  <div class="bg-white rounded-2xl shadow-md p-8 w-full max-w-sm">
    <h1 class="text-xl font-bold text-red-600 mb-4">🔒 認証失敗が多すぎます</h1>
    <p class="text-gray-700 mb-4">セキュリティのため、一時的にアクセスがロックされています。数分後に再度ログインしてください。</p>
    <a href="/login" class="text-blue-600 hover:underline">ログインページに戻る</a>
  </div>
</body>
</html>"#
                    ),
                ).into_response());
            }
            Ok(false) => {
                // Still allowed
                return Err(AppError::InvalidCredentials);
            }
            Err(_) => {
                // Database error
                return Err(AppError::InternalError("attempt tracking failed".to_string()));
            }
        }
    }

    state.mfa.delete_pending_session(&pending_token).await.ok();

    let session_id = state.sessions.create(user_id).await
        .map_err(|_| AppError::InternalError("session creation failed".to_string()))?;
    let ttl_secs = state.config.session_ttl.as_secs();

    let mut response: Response = Response::default();

    {
        let headers = response.headers_mut();
        let pending_cookie = format!("mfa_pending=; Max-Age=0; HttpOnly; Secure; Path=/; SameSite=Strict");
        headers.insert(axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&pending_cookie)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")));

        let session_cookie = format!("session_id={}; Max-Age={}; HttpOnly; Secure; Path=/; SameSite=Strict", session_id, ttl_secs);
        headers.insert(axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&session_cookie)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")));

        headers.insert(axum::http::header::LOCATION, axum::http::HeaderValue::from_str(next)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("/")));
    }

    *response.status_mut() = axum::http::StatusCode::SEE_OTHER;
    Ok(response)
}
