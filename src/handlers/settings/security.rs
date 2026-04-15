// Security settings handlers - Phase 3a-2
// Handles password changes and MFA backup code regeneration

use crate::AppState;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
    http::StatusCode,
    Extension,
    Form,
};
use serde::Deserialize;
use std::time::Duration;
use tokio::task::spawn_blocking;
use crate::middleware::AuthUser;

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct RegenerateBackupCodesForm {
    pub current_password: String,
}

/// GET /settings/security - Show security settings page
pub async fn show(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Html<String>, StatusCode> {
    // Get user info
    let user = state.users.get_by_id(auth_user.id)
        .await
        .ok()
        .flatten()
        .ok_or(StatusCode::NOT_FOUND)?;

    // Get backup code count
    let unused_count = state.mfa.backup_code_count(auth_user.id)
        .await
        .unwrap_or(0);

    let totp_enabled = user.totp_enabled == 1;

    // Build MFA section based on status
    let mfa_section = if totp_enabled {
        format!(
            r#"<section class="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">
    <div class="flex items-center gap-2 mb-1">
      <h2 class="text-lg font-semibold text-gray-700">二段階認証 (MFA)</h2>
      <span class="text-xs bg-green-100 text-green-700 font-medium px-2 py-0.5 rounded-full">
        ✅ 有効
      </span>
    </div>
    <p class="text-sm text-gray-500 mb-4">
      バックアップコード残数: {} / 8
    </p>
    <div class="flex flex-col gap-2">
      <a href="/settings/security/mfa/backup-codes/regenerate"
         class="inline-block text-center bg-gray-100 hover:bg-gray-200 text-gray-700
                font-medium py-2 px-4 rounded-lg text-sm transition-colors">
        バックアップコードを再発行する
      </a>
      <form method="POST" action="/settings/security/mfa/revoke-devices">
        <button type="submit"
                class="w-full bg-gray-100 hover:bg-gray-200 text-gray-700
                       font-medium py-2 px-4 rounded-lg text-sm transition-colors">
          デバイス記憶をすべて削除する
        </button>
      </form>
      <form method="POST" action="/settings/security/mfa/disable">
        <button type="submit"
                class="w-full bg-red-50 hover:bg-red-100 text-red-700
                       font-medium py-2 px-4 rounded-lg text-sm transition-colors">
          MFAを無効化する
        </button>
      </form>
    </div>
  </section>"#,
            unused_count
        )
    } else {
        r#"<section class="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">
    <div class="flex items-center gap-2 mb-1">
      <h2 class="text-lg font-semibold text-gray-700">二段階認証 (MFA)</h2>
      <span class="text-xs bg-gray-100 text-gray-500 font-medium px-2 py-0.5 rounded-full">
        ❌ 無効
      </span>
    </div>
    <p class="text-sm text-gray-500 mb-4">
      MFAを有効にするとアカウントのセキュリティが向上します。
    </p>
    <form method="POST" action="/settings/security/mfa/setup/start">
      <button type="submit"
              class="inline-block bg-blue-600 hover:bg-blue-700 text-white
                     font-medium py-2 px-4 rounded-lg text-sm transition-colors">
        MFAを有効化する
      </button>
    </form>
  </section>"#
            .to_string()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Security Settings</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 40px 20px; }}
        h1 {{ font-size: 24px; font-weight: bold; color: #1f2937; margin-bottom: 32px; }}
        section {{ background: white; border-radius: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #e5e7eb; padding: 24px; margin-bottom: 24px; }}
        h2 {{ font-size: 18px; font-weight: 600; color: #374151; margin-bottom: 16px; }}
        p {{ font-size: 14px; color: #6b7280; margin-bottom: 16px; }}
        a {{ color: #3b82f6; text-decoration: none; cursor: pointer; }}
        a:hover {{ text-decoration: underline; }}
        .inline-block {{ display: inline-block; background: #f3f4f6; color: #374151; font-weight: 500; padding: 8px 16px; border-radius: 8px; transition: background 0.2s; }}
        .inline-block:hover {{ background: #e5e7eb; }}
        button {{ width: 100%; background: #f3f4f6; color: #374151; font-weight: 500; padding: 8px 16px; border-radius: 8px; border: none; cursor: pointer; transition: background 0.2s; }}
        button:hover {{ background: #e5e7eb; }}
        form {{ display: contents; }}
        .flex {{ display: flex; }}
        .flex-col {{ flex-direction: column; }}
        .gap-2 {{ gap: 8px; }}
        .items-center {{ align-items: center; }}
        .rounded-full {{ border-radius: 9999px; }}
        .bg-green-100 {{ background: #dcfce7; }}
        .text-green-700 {{ color: #15803d; }}
        .bg-gray-100 {{ background: #f3f4f6; }}
        .text-gray-700 {{ color: #374151; }}
        .text-gray-500 {{ color: #6b7280; }}
        .bg-gray-200:hover {{ background: #e5e7eb; }}
        .bg-red-50 {{ background: #fef2f2; }}
        .text-red-700 {{ color: #b91c1c; }}
        .bg-red-100:hover {{ background: #fee2e2; }}
        .bg-blue-600 {{ background: #2563eb; }}
        .text-white {{ color: white; }}
        .bg-blue-700:hover {{ background: #1d4ed8; }}
        .text-xs {{ font-size: 12px; }}
        .text-sm {{ font-size: 14px; }}
        .text-lg {{ font-size: 18px; }}
        .font-medium {{ font-weight: 500; }}
        .font-semibold {{ font-weight: 600; }}
        .px-2 {{ padding-left: 8px; padding-right: 8px; }}
        .px-4 {{ padding-left: 16px; padding-right: 16px; }}
        .py-2 {{ padding-top: 8px; padding-bottom: 8px; }}
        .py-0.5 {{ padding-top: 2px; padding-bottom: 2px; }}
        .mb-1 {{ margin-bottom: 4px; }}
        .mb-4 {{ margin-bottom: 16px; }}
        .mb-8 {{ margin-bottom: 32px; }}
        .mt-2 {{ margin-top: 8px; }}
        .w-full {{ width: 100%; }}
        .shadow-sm {{ box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
        .border {{ border: 1px solid #e5e7eb; }}
        .border-gray-100 {{ border-color: #f3f4f6; }}
        .rounded-2xl {{ border-radius: 16px; }}
        .rounded-lg {{ border-radius: 8px; }}
        .transition-colors {{ transition: background-color 0.2s; }}
        .hover\:bg-gray-200:hover {{ background: #e5e7eb; }}
        .hover\:bg-red-100:hover {{ background: #fee2e2; }}
        .hover\:bg-blue-700:hover {{ background: #1d4ed8; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 セキュリティ設定</h1>

        <section>
            <h2>🔑 パスワード</h2>
            <a href="/settings/security/password" class="inline-block">
                パスワードを変更する
            </a>
        </section>

        {}
    </div>
</body>
</html>"#,
        mfa_section
    );

    Ok(Html(html))
}

/// GET /settings/security/password - Show password change form
pub async fn show_password(
    Extension(_auth_user): Extension<AuthUser>,
) -> Html<String> {
    let issuer_name = std::env::var("APP_ISSUER_NAME")
        .unwrap_or_else(|_| "Auth Proxy".to_string());

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Change Password</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
        .form-box {{ background: white; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); padding: 32px; width: 100%; max-width: 400px; }}
        .header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 24px; }}
        .header-icon {{ font-size: 24px; }}
        .header-text {{ font-size: 18px; font-weight: 600; color: #374151; }}
        h1 {{ font-size: 20px; font-weight: bold; color: #1f2937; margin-bottom: 24px; }}
        .form-group {{ margin-bottom: 16px; }}
        label {{ display: block; font-size: 14px; font-weight: 500; color: #374151; margin-bottom: 4px; }}
        input {{ width: 100%; padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; }}
        input:focus {{ outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }}
        .button-group {{ display: flex; gap: 12px; margin-top: 24px; }}
        .button-group a, .button-group button {{ flex: 1; padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; text-align: center; text-decoration: none; font-weight: 500; transition: background 0.2s; }}
        .button-group a {{ background: #f3f4f6; color: #374151; }}
        .button-group a:hover {{ background: #e5e7eb; }}
        .button-group button {{ background: #2563eb; color: white; }}
        .button-group button:hover {{ background: #1d4ed8; }}
        .error {{ color: #dc2626; font-size: 14px; margin-bottom: 16px; padding: 12px; background: #fee2e2; border-radius: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="form-box">
            <div class="header">
                <span class="header-icon">🔑</span>
                <span class="header-text">{}</span>
            </div>
            <h1>パスワードを変更する</h1>
            <form method="POST" action="/settings/security/password">
                <div class="form-group">
                    <label for="current_password">現在のパスワード</label>
                    <input type="password" id="current_password" name="current_password" required autofocus>
                </div>
                <div class="form-group">
                    <label for="new_password">新しいパスワード</label>
                    <input type="password" id="new_password" name="new_password" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">新しいパスワード（確認）</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                <div class="button-group">
                    <a href="/settings/security">キャンセル</a>
                    <button type="submit">変更する</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>"#,
        issuer_name
    );

    Html(html)
}

/// POST /settings/security/password - Handle password change
pub async fn handle_password(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Form(form): Form<ChangePasswordForm>,
) -> Result<Response, StatusCode> {
    // Validate new password
    if form.new_password.len() < 8 {
        return Ok(error_password_form(&auth_user, "新しいパスワードは8文字以上で入力してください").into_response());
    }

    if form.new_password != form.confirm_password {
        return Ok(error_password_form(&auth_user, "パスワードが一致しません").into_response());
    }

    // Verify current password
    let username = auth_user.username.clone();
    let current_password = form.current_password.clone();
    let state_clone = state.clone();

    let verify_result = spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            state_clone.users.verify(&username, &current_password)
                .await
                .unwrap_or(false)
        })
    })
    .await
    .unwrap_or(false);

    if !verify_result {
        tokio::time::sleep(Duration::from_millis(500)).await;
        return Ok(error_password_form(&auth_user, "現在のパスワードが正しくありません").into_response());
    }

    // Update password
    if let Err(_) = state.users.update_password(auth_user.id, &form.new_password).await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Redirect::to("/settings/security").into_response())
}

/// GET /settings/security/mfa/backup-codes/regenerate - Show regenerate confirmation form
pub async fn show_regenerate_backup_codes(
    Extension(_auth_user): Extension<AuthUser>,
) -> Html<String> {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Regenerate Backup Codes</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
        .form-box {{ background: white; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); padding: 32px; width: 100%; max-width: 400px; }}
        h1 {{ font-size: 20px; font-weight: bold; color: #1f2937; margin-bottom: 8px; }}
        p {{ font-size: 14px; color: #6b7280; margin-bottom: 24px; }}
        .form-group {{ margin-bottom: 16px; }}
        label {{ display: block; font-size: 14px; font-weight: 500; color: #374151; margin-bottom: 4px; }}
        input {{ width: 100%; padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; }}
        input:focus {{ outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }}
        .button-group {{ display: flex; gap: 12px; margin-top: 24px; }}
        .button-group a, .button-group button {{ flex: 1; padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; text-align: center; text-decoration: none; font-weight: 500; transition: background 0.2s; }}
        .button-group a {{ background: #f3f4f6; color: #374151; }}
        .button-group a:hover {{ background: #e5e7eb; }}
        .button-group button {{ background: #2563eb; color: white; }}
        .button-group button:hover {{ background: #1d4ed8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="form-box">
            <h1>バックアップコードを再発行する</h1>
            <p>
                再発行すると現在のバックアップコードは全て無効になります。
                確認のため現在のパスワードを入力してください。
            </p>
            <form method="POST" action="/settings/security/mfa/backup-codes/regenerate">
                <div class="form-group">
                    <label for="current_password">現在のパスワード</label>
                    <input type="password" id="current_password" name="current_password" required autofocus>
                </div>
                <div class="button-group">
                    <a href="/settings/security">キャンセル</a>
                    <button type="submit">再発行する</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>"#
    );

    Html(html)
}

/// POST /settings/security/mfa/backup-codes/regenerate - Generate new backup codes
pub async fn handle_regenerate_backup_codes(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Form(form): Form<RegenerateBackupCodesForm>,
) -> Result<Response, StatusCode> {
    // Verify current password
    let username = auth_user.username.clone();
    let password = form.current_password.clone();
    let state_clone = state.clone();

    let verify_result = spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            state_clone.users.verify(&username, &password)
                .await
                .unwrap_or(false)
        })
    })
    .await
    .unwrap_or(false);

    if !verify_result {
        tokio::time::sleep(Duration::from_millis(500)).await;
        return Ok(Redirect::to("/settings/security?error=backup_regenerate_failed").into_response());
    }

    // Generate new backup codes
    let codes = state.mfa.generate_backup_codes(auth_user.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build display of backup codes
    let codes_html = codes.iter()
        .map(|code| format!("<span>{}</span>", code))
        .collect::<Vec<_>>()
        .join("\n");

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - New Backup Codes</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
        .form-box {{ background: white; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); padding: 32px; width: 100%; max-width: 400px; }}
        h1 {{ font-size: 20px; font-weight: bold; color: #1f2937; margin-bottom: 8px; }}
        .warning {{ background: #fef3c7; border: 1px solid #fcd34d; border-radius: 8px; padding: 12px; margin-bottom: 16px; }}
        .warning-text {{ font-size: 14px; color: #92400e; font-weight: 500; }}
        .codes-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; background: #f5f5f5; border-radius: 8px; padding: 16px; margin: 16px 0; font-family: monospace; font-size: 13px; }}
        .codes-grid span {{ padding: 8px; background: white; border-radius: 4px; text-align: center; }}
        a {{ display: block; width: 100%; text-align: center; background: #2563eb; color: white; font-weight: 500; padding: 8px 16px; border-radius: 8px; border: none; cursor: pointer; text-decoration: none; transition: background 0.2s; margin-top: 24px; }}
        a:hover {{ background: #1d4ed8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="form-box">
            <h1>新しいバックアップコード</h1>
            <div class="warning">
                <p class="warning-text">⚠️ この画面を閉じると再表示できません</p>
                <p class="warning-text" style="margin-top: 4px;">必ず安全な場所に保存してください。</p>
            </div>
            <div class="codes-grid">
                {}
            </div>
            <a href="/settings/security">完了</a>
        </div>
    </div>
</body>
</html>"#,
        codes_html
    );

    Ok(Html(html).into_response())
}

// Helper function to show password form with error
fn error_password_form(_auth_user: &AuthUser, error_message: &str) -> Html<String> {
    let issuer_name = std::env::var("APP_ISSUER_NAME")
        .unwrap_or_else(|_| "Auth Proxy".to_string());

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Change Password</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
        .form-box {{ background: white; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); padding: 32px; width: 100%; max-width: 400px; }}
        .header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 24px; }}
        .header-icon {{ font-size: 24px; }}
        .header-text {{ font-size: 18px; font-weight: 600; color: #374151; }}
        h1 {{ font-size: 20px; font-weight: bold; color: #1f2937; margin-bottom: 24px; }}
        .form-group {{ margin-bottom: 16px; }}
        label {{ display: block; font-size: 14px; font-weight: 500; color: #374151; margin-bottom: 4px; }}
        input {{ width: 100%; padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; }}
        input:focus {{ outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }}
        .button-group {{ display: flex; gap: 12px; margin-top: 24px; }}
        .button-group a, .button-group button {{ flex: 1; padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; text-align: center; text-decoration: none; font-weight: 500; transition: background 0.2s; }}
        .button-group a {{ background: #f3f4f6; color: #374151; }}
        .button-group a:hover {{ background: #e5e7eb; }}
        .button-group button {{ background: #2563eb; color: white; }}
        .button-group button:hover {{ background: #1d4ed8; }}
        .error {{ color: #dc2626; font-size: 14px; margin-bottom: 16px; padding: 12px; background: #fee2e2; border-radius: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="form-box">
            <div class="header">
                <span class="header-icon">🔑</span>
                <span class="header-text">{}</span>
            </div>
            <h1>パスワードを変更する</h1>
            <p class="error">{}</p>
            <form method="POST" action="/settings/security/password">
                <div class="form-group">
                    <label for="current_password">現在のパスワード</label>
                    <input type="password" id="current_password" name="current_password" required autofocus>
                </div>
                <div class="form-group">
                    <label for="new_password">新しいパスワード</label>
                    <input type="password" id="new_password" name="new_password" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">新しいパスワード（確認）</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                <div class="button-group">
                    <a href="/settings/security">キャンセル</a>
                    <button type="submit">変更する</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>"#,
        issuer_name,
        error_message
    );

    Html(html)
}
