// Admin-wide API token visibility - Phase API-4 (R10), ADR 0003.
// Scope is deliberately limited to "list every token, revoke any token" --
// no broader admin UX changes.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    Extension,
};
use crate::{AppState, middleware::AuthUser};

/// GET /admin/tokens - list every user's API tokens
pub async fn get_admin_tokens(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    if auth_user.role != "admin" || auth_user.auth_method != "session" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1>".to_string()),
        )
            .into_response();
    }

    let tokens = state.api_tokens.list_all().await.unwrap_or_default();

    let rows = if tokens.is_empty() {
        r#"<tr><td colspan="6" style="text-align:center;color:#9ca3af;">トークンはまだ発行されていません</td></tr>"#.to_string()
    } else {
        tokens
            .iter()
            .map(|t| {
                let username = html_escape::encode_text(&t.username);
                let name = html_escape::encode_text(&t.name);
                let scope = t
                    .path_prefix
                    .as_deref()
                    .map(|p| format!("<code>{}</code>", html_escape::encode_text(p)))
                    .unwrap_or_else(|| r#"<span style="color:#9ca3af;">全パス</span>"#.to_string());
                let last_used = t.last_used_at.as_deref().unwrap_or("未使用");
                let action = if t.revoked_at.is_some() {
                    r#"<span style="color:#9ca3af;">失効済み</span>"#.to_string()
                } else {
                    format!(
                        r#"<form method="POST" action="/admin/tokens/{}/revoke" style="display:inline;" onsubmit="return confirm('このトークンを失効させますか?この操作は取り消せません。');">
                            <button type="submit" style="background:#dc2626;">失効</button>
                        </form>"#,
                        t.id
                    )
                };
                format!(
                    "<tr><td>{username}</td><td>{name}</td><td>{scope}</td><td>{last_used}</td><td>{}</td><td>{action}</td></tr>",
                    t.created_at
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - API Tokens</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: white; border-bottom: 1px solid #ddd; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        header h1 {{ margin: 0; font-size: 24px; color: #333; }}
        nav {{ margin-top: 15px; }}
        nav a {{ display: inline-block; margin-right: 20px; color: #0066cc; text-decoration: none; }}
        nav a:hover {{ text-decoration: underline; }}
        .user-info {{ float: right; margin-top: 15px; color: #666; }}
        .user-info a {{ color: #0066cc; text-decoration: none; }}
        table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #f0f0f0; padding: 12px; text-align: left; border-bottom: 2px solid #ddd; }}
        td {{ padding: 12px; border-bottom: 1px solid #ddd; }}
        button {{ padding: 6px 12px; color: white; border: none; border-radius: 4px; cursor: pointer; }}
    </style>
</head>
<body>
    <header>
        <h1>API トークン管理(全ユーザー)</h1>
        <nav>
            <a href="/admin">Dashboard</a>
            <a href="/admin/users">User Management</a>
        </nav>
        <div class="user-info">
            Logged in as: <strong>{}</strong> | <a href="/logout">Logout</a>
        </div>
    </header>

    <div class="container">
        <table>
            <thead>
                <tr>
                    <th>ユーザー</th>
                    <th>名前</th>
                    <th>スコープ</th>
                    <th>最終利用</th>
                    <th>作成日</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
</body>
</html>"#,
        html_escape::encode_text(&auth_user.username)
    );

    Html(html).into_response()
}

/// POST /admin/tokens/{id}/revoke - revoke any user's token
///
/// Uses `ApiTokenStoreDb::revoke_any`, which performs no ownership check.
/// This is safe ONLY because this handler is gated the same way every
/// other `/admin/*` handler is (session-authenticated admin). Do not reuse
/// `revoke_any` from a non-admin-gated context.
pub async fn post_admin_token_revoke(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if auth_user.role != "admin" || auth_user.auth_method != "session" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1>".to_string()),
        )
            .into_response();
    }

    let _ = state.api_tokens.revoke_any(id).await;
    Redirect::to("/admin/tokens").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;

    fn admin_session() -> AuthUser {
        AuthUser {
            id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            auth_method: "session".to_string(),
            token_name: None,
        }
    }

    fn admin_token() -> AuthUser {
        AuthUser {
            id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            auth_method: "token".to_string(),
            token_name: Some("leaked".to_string()),
        }
    }

    fn regular_user_session() -> AuthUser {
        AuthUser {
            id: 2,
            username: "alice".to_string(),
            role: "user".to_string(),
            auth_method: "session".to_string(),
            token_name: None,
        }
    }

    #[tokio::test]
    async fn test_get_admin_tokens_rejects_token_authenticated_admin() {
        let state = AppState::test().await.unwrap();
        let response = get_admin_tokens(State(state), Extension(admin_token()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_admin_tokens_rejects_non_admin() {
        let state = AppState::test().await.unwrap();
        let response = get_admin_tokens(State(state), Extension(regular_user_session()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_admin_tokens_shows_other_users_tokens() {
        let state = AppState::test().await.unwrap();
        let alice = state.users.create("alice", "password123", "user").await.unwrap();
        state.api_tokens.create(alice.id, "Alice's device", 0, None).await.unwrap();

        let response = get_admin_tokens(State(state), Extension(admin_session()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("alice"));
        assert!(html.contains("Alice's device"));
    }

    #[tokio::test]
    async fn test_post_admin_token_revoke_rejects_token_authenticated_admin() {
        let state = AppState::test().await.unwrap();
        let response = post_admin_token_revoke(State(state), Extension(admin_token()), Path(1))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_post_admin_token_revoke_rejects_non_admin() {
        let state = AppState::test().await.unwrap();
        let response = post_admin_token_revoke(State(state), Extension(regular_user_session()), Path(1))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_post_admin_token_revoke_revokes_any_users_token() {
        let state = AppState::test().await.unwrap();
        let alice = state.users.create("alice", "password123", "user").await.unwrap();
        let (row, plaintext) = state.api_tokens.create(alice.id, "Alice's device", 0, None).await.unwrap();

        let response = post_admin_token_revoke(State(state.clone()), Extension(admin_session()), Path(row.id))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let hash = crate::api_tokens_db::ApiTokenStoreDb::hash_token(&plaintext);
        assert!(state.api_tokens.verify(&hash).await.unwrap().is_none());
    }
}
