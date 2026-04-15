use crate::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use serde::Deserialize;

// Helper to extract user_id from session
async fn get_user_id_from_session(state: &AppState, headers: &HeaderMap) -> Option<i64> {
    let session_id = headers.get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            for cookie in cookie_str.split(';') {
                let trimmed = cookie.trim();
                if let Some(value) = trimmed.strip_prefix("session_id=") {
                    return Some(value.to_string());
                }
            }
            None
        })?;

    state.sessions.get(&session_id).await.ok()?.map(|s| s.user_id)
}

/// GET /settings/mfa - Show MFA settings page
pub async fn show_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_id = match get_user_id_from_session(&state, &headers).await {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };

    // Get user info
    let user = match state.users.get_by_id(user_id).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/login").into_response(),
    };

    // Check MFA status
    let totp_enabled = sqlx::query_scalar::<_, i32>(
        "SELECT totp_enabled FROM users WHERE id = ?"
    ).bind(user_id)
     .fetch_optional(&state.db).await
     .unwrap_or(None)
     .unwrap_or(0);

    let backup_count = if totp_enabled == 1 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = ? AND used_at IS NULL"
        ).bind(user_id)
         .fetch_optional(&state.db).await
         .unwrap_or(None)
         .unwrap_or(0)
    } else {
        0
    };

    let mfa_status_html = if totp_enabled == 1 {
        format!(
            r#"<div class="bg-green-50 border border-green-200 rounded-lg p-4 mb-4">
  <p class="text-green-700 font-semibold">✓ 二段階認証が有効です</p>
  <p class="text-sm text-green-600">バックアップコード残数: {} 個</p>
</div>"#,
            backup_count
        )
    } else {
        r#"<div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
  <p class="text-yellow-700 font-semibold">⚠ 二段階認証が無効です</p>
</div>"#.to_string()
    };

    let buttons_html = if totp_enabled == 1 {
        format!(
            r#"<form method="POST" action="/settings/mfa/revoke-devices" class="mb-3">
    <button type="submit" class="w-full bg-gray-600 hover:bg-gray-700 text-white font-medium py-2 px-4 rounded-lg text-sm transition-colors">
      すべてのデバイス記憶を削除
    </button>
  </form>
  <form method="POST" action="/settings/mfa/disable" class="mb-3">
    <div class="mb-3">
      <label class="block text-sm font-medium text-gray-700 mb-1">パスワード確認</label>
      <input type="password" name="password" required class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
    </div>
    <button type="submit" class="w-full bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-lg text-sm transition-colors">
      二段階認証を無効化
    </button>
  </form>"#
        )
    } else {
        r#"<form method="POST" action="/settings/mfa/setup/start">
    <button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white font-medium py-2 px-4 rounded-lg text-sm transition-colors">
      二段階認証を設定
    </button>
  </form>"#.to_string()
    };

    Html(
        format!(
            r#"<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MFA設定 - {}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 py-8">
  <div class="max-w-2xl mx-auto">
    <div class="bg-white rounded-lg shadow-md p-8">
      <h1 class="text-3xl font-bold text-gray-800 mb-8">二段階認証設定</h1>

      <div class="mb-8">
        <h2 class="text-lg font-semibold text-gray-700 mb-4">ユーザー情報</h2>
        <p class="text-gray-600">ユーザー: <strong>{}</strong></p>
      </div>

      <div class="mb-8">
        <h2 class="text-lg font-semibold text-gray-700 mb-4">ステータス</h2>
        {}
      </div>

      <div class="mb-8">
        <h2 class="text-lg font-semibold text-gray-700 mb-4">操作</h2>
        {}
      </div>

      <div class="mt-8 text-center">
        <a href="/" class="text-blue-600 hover:underline">ホームに戻る</a>
      </div>
    </div>
  </div>
</body>
</html>"#,
            state.config.issuer_name,
            user.username,
            mfa_status_html,
            buttons_html,
        )
    ).into_response()
}

/// POST /settings/mfa/setup/start - Begin TOTP setup
pub async fn start_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_id = match get_user_id_from_session(&state, &headers).await {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };

    let user = match state.users.get_by_id(user_id).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/login").into_response(),
    };

    // Generate TOTP secret
    let (secret_b32, otpauth_uri) = match state.mfa.generate_totp_secret(&user.username, &state.config.issuer_name) {
        Ok((s, u)) => (s, u),
        Err(_) => return Redirect::to("/settings/mfa").into_response(),
    };

    // Generate QR code
    let qr_svg = match qrcode::QrCode::new(otpauth_uri.as_bytes()) {
        Ok(code) => code.render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .build(),
        Err(_) => return Redirect::to("/settings/mfa").into_response(),
    };

    Html(
        format!(
            r#"<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>二段階認証セットアップ</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 py-8">
  <div class="max-w-2xl mx-auto">
    <div class="bg-white rounded-lg shadow-md p-8">
      <h1 class="text-3xl font-bold text-gray-800 mb-8">二段階認証のセットアップ</h1>

      <div class="mb-8">
        <h2 class="text-lg font-semibold text-gray-700 mb-4">ステップ 1: QRコードをスキャン</h2>
        <p class="text-gray-600 mb-4">認証アプリ (Google Authenticator, Authy など) でこのQRコードをスキャンしてください。</p>
        <div class="bg-gray-100 rounded-lg p-4 text-center mb-4">
          {}
        </div>
      </div>

      <div class="mb-8">
        <h2 class="text-lg font-semibold text-gray-700 mb-4">ステップ 2: 手動入力（QRコードが使えない場合）</h2>
        <p class="text-gray-600 mb-2">以下のシークレットキーを入力してください:</p>
        <code class="block bg-gray-100 p-3 rounded-lg text-center font-mono text-lg">{}</code>
      </div>

      <div class="mb-8">
        <h2 class="text-lg font-semibold text-gray-700 mb-4">ステップ 3: 確認コード入力</h2>
        <form method="POST" action="/settings/mfa/setup/confirm">
          <input type="hidden" name="secret" value="{}">
          <div class="mb-4">
            <label class="block text-sm font-medium text-gray-700 mb-1">認証アプリに表示されている6桁のコード</label>
            <input type="text" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6"
                   class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 text-center text-lg"
                   autofocus required>
          </div>
          <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg text-sm transition-colors">
            確認
          </button>
        </form>
      </div>

      <div class="mt-8 text-center">
        <a href="/settings/mfa" class="text-blue-600 hover:underline">キャンセル</a>
      </div>
    </div>
  </div>
</body>
</html>"#,
            qr_svg,
            secret_b32,
            secret_b32,
        )
    ).into_response()
}

#[derive(Deserialize)]
pub struct SetupConfirmRequest {
    pub secret: String,
    pub code: String,
}

/// POST /settings/mfa/setup/confirm - Confirm TOTP setup
pub async fn confirm_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SetupConfirmRequest>,
) -> impl IntoResponse {
    let user_id = match get_user_id_from_session(&state, &headers).await {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };

    // Verify TOTP code
    if !state.mfa.verify_totp_code(&form.secret, &form.code) {
        return Html(
            r#"<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>エラー</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 flex items-center justify-center">
  <div class="bg-white rounded-lg shadow-md p-8 w-full max-w-sm">
    <h1 class="text-xl font-bold text-gray-800 mb-4">エラー</h1>
    <p class="text-red-600 mb-4">確認コードが正しくありません。</p>
    <a href="/settings/mfa/setup/start" class="text-blue-600 hover:underline">戻る</a>
  </div>
</body>
</html>"#
        ).into_response();
    }

    // Enable TOTP
    if let Err(_) = state.mfa.enable_totp(user_id, &form.secret).await {
        return Redirect::to("/settings/mfa").into_response();
    }

    // Generate backup codes
    let codes = match state.mfa.generate_backup_codes(user_id).await {
        Ok(codes) => codes,
        Err(_) => return Redirect::to("/settings/mfa").into_response(),
    };

    let codes_html = codes.iter()
        .map(|c| format!("<span>{}</span>", c))
        .collect::<Vec<_>>()
        .join("");

    Html(
        format!(
            r#"<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>セットアップ完了</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-50 py-8">
  <div class="max-w-2xl mx-auto">
    <div class="bg-white rounded-lg shadow-md p-8">
      <h1 class="text-3xl font-bold text-green-600 mb-8">✓ セットアップ完了</h1>

      <div class="mb-8 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
        <p class="text-yellow-800 font-semibold mb-2">⚠ 重要</p>
        <p class="text-yellow-700">以下のバックアップコードは今後二度と表示されません。必ず安全な場所に保存してください。</p>
      </div>

      <div class="mb-8">
        <h2 class="text-lg font-semibold text-gray-700 mb-4">バックアップコード（8個）</h2>
        <div class="grid grid-cols-2 gap-2 bg-gray-50 rounded-lg p-4 font-mono text-sm">
          {}
        </div>
      </div>

      <div class="flex gap-4">
        <a href="/settings/mfa" class="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg text-center transition-colors">
          完了
        </a>
      </div>
    </div>
  </div>
</body>
</html>"#,
            codes_html,
        )
    ).into_response()
}

#[derive(Deserialize)]
pub struct DisableMfaRequest {
    pub password: String,
}

/// POST /settings/mfa/disable - Disable MFA
pub async fn disable_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DisableMfaRequest>,
) -> impl IntoResponse {
    let user_id = match get_user_id_from_session(&state, &headers).await {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };

    let user = match state.users.get_by_id(user_id).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/login").into_response(),
    };

    // Verify password
    if !state.users.verify(&user.username, &form.password).await.unwrap_or(false) {
        return Html("<h1>400 Bad Request</h1><p>パスワードが正しくありません。</p>").into_response();
    }

    // Disable TOTP
    if let Err(_) = state.mfa.disable_totp(user_id).await {
        return Redirect::to("/settings/mfa").into_response();
    }

    Redirect::to("/settings/mfa").into_response()
}

/// POST /settings/mfa/revoke-devices - Revoke all device tokens
pub async fn revoke_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_id = match get_user_id_from_session(&state, &headers).await {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };

    if let Err(_) = state.mfa.delete_all_device_tokens(user_id).await {
        return Redirect::to("/settings/mfa").into_response();
    }

    Redirect::to("/settings/mfa").into_response()
}

pub mod security;
