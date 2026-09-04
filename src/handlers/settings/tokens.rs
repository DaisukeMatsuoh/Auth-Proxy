// API token management UI - Phase API-2
// Session-auth only web UI on top of the Phase API-1 ApiTokenStoreDb.
// Mirrors the security.rs page style (inline CSS, no JS/fetch).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Extension, Form,
};
use serde::Deserialize;
use crate::AppState;
use crate::middleware::AuthUser;
use crate::api_tokens_db::ApiTokenDbError;
use crate::handlers::api_tokens::require_session_auth;

const PAGE_STYLE: &str = r#"
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 700px; margin: 0 auto; padding: 40px 20px; }
        h1 { font-size: 24px; font-weight: bold; color: #1f2937; margin-bottom: 24px; }
        section { background: white; border-radius: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #e5e7eb; padding: 24px; margin-bottom: 24px; }
        h2 { font-size: 18px; font-weight: 600; color: #374151; margin-bottom: 16px; }
        p { font-size: 14px; color: #6b7280; margin-bottom: 12px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { text-align: left; padding: 8px 4px; border-bottom: 1px solid #e5e7eb; }
        th { color: #6b7280; font-weight: 500; }
        .muted { color: #9ca3af; }
        .empty { color: #9ca3af; font-size: 14px; padding: 16px 0; }
        input[type="text"] { width: 100%; padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; margin-bottom: 12px; }
        button, .btn { background: #2563eb; color: white; font-weight: 500; padding: 8px 16px; border-radius: 8px; border: none; cursor: pointer; font-size: 14px; }
        button:hover, .btn:hover { background: #1d4ed8; }
        .btn-danger { background: #fef2f2; color: #b91c1c; padding: 4px 10px; font-size: 13px; }
        .btn-danger:hover { background: #fee2e2; }
        .warning { background: #fef3c7; border: 1px solid #fcd34d; border-radius: 8px; padding: 12px; margin-bottom: 16px; font-size: 14px; color: #92400e; }
        code.token { display: block; background: #f3f4f6; border-radius: 8px; padding: 12px; font-family: monospace; font-size: 13px; word-break: break-all; margin-bottom: 16px; }
        .inline-block { display: inline-block; background: #f3f4f6; color: #374151; font-weight: 500; padding: 8px 16px; border-radius: 8px; text-decoration: none; margin-top: 8px; }
        .inline-block:hover { background: #e5e7eb; }
        form.inline { display: inline; }
"#;

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - {title}</title>
    <style>{PAGE_STYLE}</style>
</head>
<body>
    <div class="container">
        {body}
    </div>
</body>
</html>"#
    )
}

/// GET /settings/security/tokens - list tokens and show the issue form
pub async fn show(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    if let Err(resp) = require_session_auth(&auth_user) {
        return resp;
    }

    let rows = state.api_tokens.list_for_user(auth_user.id).await.unwrap_or_default();

    let rows_html = if rows.is_empty() {
        r#"<tr><td colspan="5" class="empty">まだトークンがありません</td></tr>"#.to_string()
    } else {
        rows.iter()
            .map(|r| {
                let name = html_escape::encode_text(&r.name);
                let last_used = r.last_used_at.as_deref().unwrap_or("未使用");
                let action = if r.revoked_at.is_some() {
                    r#"<span class="muted">失効済み</span>"#.to_string()
                } else {
                    format!(
                        r#"<form class="inline" method="POST" action="/settings/security/tokens/{}/revoke" onsubmit="return confirm('このトークンを失効させますか?この操作は取り消せません。');">
                            <button type="submit" class="btn-danger">失効</button>
                        </form>"#,
                        r.id
                    )
                };
                let scope = r.path_prefix.as_deref()
                    .map(|p| format!("<code>{}</code>", html_escape::encode_text(p)))
                    .unwrap_or_else(|| r#"<span class="muted">全パス</span>"#.to_string());
                format!(
                    r#"<tr><td>{name}</td><td>{scope}</td><td>{last_used}</td><td>{}</td><td>{action}</td></tr>"#,
                    r.created_at
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let body = format!(
        r#"<h1>🔑 API トークン</h1>

        <section>
            <h2>発行済みトークン</h2>
            <table>
                <thead><tr><th>名前</th><th>スコープ</th><th>最終利用</th><th>作成日</th><th></th></tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
        </section>

        <section>
            <h2>新しいトークンを発行</h2>
            <p>ブラウザ以外のクライアント(デスクトップアプリ・CLI・CI等)から認証するためのトークンを発行します。</p>
            <form method="POST" action="/settings/security/tokens">
                <input type="text" name="name" placeholder="例: Alice の MacBook" required maxlength="200">
                <input type="text" name="path_prefix" placeholder="例: /sync/ (空欄で全パスにアクセス可能)" maxlength="200">
                <button type="submit">トークンを発行</button>
            </form>
        </section>

        <a href="/settings/security" class="inline-block">← セキュリティ設定に戻る</a>"#
    );

    Html(page("API トークン", &body)).into_response()
}

#[derive(Deserialize)]
pub struct CreateTokenForm {
    pub name: String,
    #[serde(default)]
    pub path_prefix: String,
}

/// POST /settings/security/tokens - issue a new token and show it once
pub async fn create(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Form(form): Form<CreateTokenForm>,
) -> Response {
    if let Err(resp) = require_session_auth(&auth_user) {
        return resp;
    }

    let name = form.name.trim();
    if name.is_empty() {
        return Redirect::to("/settings/security/tokens").into_response();
    }

    let ttl_days = state.config.api_token_default_ttl_days;
    let (_row, plaintext) = match state
        .api_tokens
        .create(auth_user.id, name, ttl_days, Some(&form.path_prefix))
        .await
    {
        Ok(v) => v,
        Err(ApiTokenDbError::InvalidPathPrefix(msg)) => {
            let body = format!(
                r#"<h1>エラー</h1><p>{}</p><a href="/settings/security/tokens" class="inline-block">戻る</a>"#,
                html_escape::encode_text(&msg)
            );
            return Html(page("エラー", &body)).into_response();
        }
        Err(ApiTokenDbError::DbError(_)) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // The plaintext token is never stored and can never be shown again, so it
    // is rendered directly in this response rather than via a redirect (a
    // redirect would put it in the browser's history/URL and risk leaking it
    // via a Referer header).
    let body = format!(
        r#"<h1>✅ トークンを発行しました</h1>

        <section>
            <div class="warning">⚠ この画面を閉じると二度と表示できません。今すぐコピーして安全な場所に保管してください。</div>
            <code class="token">{}</code>
            <a href="/settings/security/tokens" class="inline-block">完了</a>
        </section>"#,
        html_escape::encode_text(&plaintext)
    );

    Html(page("トークンを発行しました", &body)).into_response()
}

/// POST /settings/security/tokens/{id}/revoke - revoke a token
pub async fn revoke(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = require_session_auth(&auth_user) {
        return resp;
    }

    let _ = state.api_tokens.revoke(id, auth_user.id).await;
    Redirect::to("/settings/security/tokens").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;

    fn session_user(id: i64) -> AuthUser {
        AuthUser {
            id,
            username: "alice".to_string(),
            role: "user".to_string(),
            auth_method: "session".to_string(),
            token_name: None,
        }
    }

    fn token_user(id: i64) -> AuthUser {
        AuthUser {
            id,
            username: "alice".to_string(),
            role: "user".to_string(),
            auth_method: "token".to_string(),
            token_name: Some("some-token".to_string()),
        }
    }

    #[tokio::test]
    async fn test_show_empty_list() {
        let state = AppState::test().await.unwrap();
        let response = show(State(state), Extension(session_user(1))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("まだトークンがありません"));
    }

    #[tokio::test]
    async fn test_show_rejects_token_auth() {
        let state = AppState::test().await.unwrap();
        let response = show(State(state), Extension(token_user(1))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_returns_plaintext_token_once() {
        let state = AppState::test().await.unwrap();
        let response = create(
            State(state.clone()),
            Extension(session_user(1)),
            Form(CreateTokenForm { name: "My Device".to_string(), path_prefix: String::new() }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("apx_"));

        // The list page must never expose the plaintext or the hash.
        let list_response = show(State(state), Extension(session_user(1))).await;
        let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX).await.unwrap();
        let list_html = String::from_utf8(list_body.to_vec()).unwrap();
        assert!(list_html.contains("My Device"));
        assert!(!list_html.contains("apx_"));
    }

    #[tokio::test]
    async fn test_create_rejects_token_auth() {
        let state = AppState::test().await.unwrap();
        let response = create(
            State(state),
            Extension(token_user(1)),
            Form(CreateTokenForm { name: "Backdoor".to_string(), path_prefix: String::new() }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_escapes_html_in_token_name() {
        let state = AppState::test().await.unwrap();
        create(
            State(state.clone()),
            Extension(session_user(1)),
            Form(CreateTokenForm { name: r#"<script>alert(1)</script>"#.to_string(), path_prefix: String::new() }),
        )
        .await;

        let list_response = show(State(state), Extension(session_user(1))).await;
        let body = axum::body::to_bytes(list_response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[tokio::test]
    async fn test_revoke_cannot_revoke_other_users_token() {
        let state = AppState::test().await.unwrap();
        state.users.create("bob", "password123", "user").await.unwrap();
        let (row, _plaintext) = state.api_tokens.create(1, "Alice's token", 0, None).await.unwrap();

        // bob (user_id=2) attempts to revoke alice's token via the UI handler.
        let response = revoke(State(state.clone()), Extension(session_user(2)), Path(row.id)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let verified = state
            .api_tokens
            .verify(&crate::api_tokens_db::ApiTokenStoreDb::hash_token(&_plaintext))
            .await
            .unwrap();
        assert!(verified.is_some(), "token must still be active; bob must not be able to revoke it");
    }

    #[tokio::test]
    async fn test_revoke_rejects_token_auth() {
        let state = AppState::test().await.unwrap();
        let response = revoke(State(state), Extension(token_user(1)), Path(1)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
