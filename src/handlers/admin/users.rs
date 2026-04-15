use crate::{AppState, middleware::AuthUser};
use axum::{
    extract::{State, Path},
    response::{Html, IntoResponse, Redirect, Response},
    http::StatusCode,
    Extension,
    Form,
};
use serde::Deserialize;
use std::time::Duration;
use tokio::task::spawn_blocking;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub confirm_password: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct DisableMfaForm {
    pub admin_password: String,
}

fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.len() < 3 {
        return Err("Username must be at least 3 characters");
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err("Username can only contain letters, numbers, and underscores");
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters");
    }
    Ok(())
}

/// GET /admin/users - List all users
pub async fn get_users(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    // Admin role check
    if auth_user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1>"),
        ).into_response();
    }

    let users = state.users.list_all()
        .await
        .ok()
        .unwrap_or_default();

    let user_rows = users.iter().map(|user| {
        let delete_disabled = if user.id == auth_user.id { "disabled" } else { "" };

        // MFA アイコン
        let mfa_icon = if user.totp_enabled == 1 {
            r#"<span title="MFA有効">🔐</span>"#
        } else {
            r#"<span title="MFA無効" style="color:#9ca3af;">—</span>"#
        };

        // MFA無効化ボタンは、totp_enabled == true かつ自分自身でない場合のみ表示
        let mfa_button = if user.totp_enabled == 1 && user.id != auth_user.id {
            format!(
                r#"<a href="/admin/users/{}/disable-mfa" style="background:#dc2626;color:white;padding:6px 12px;text-decoration:none;border-radius:4px;margin-left:10px;">MFA無効化</a>"#,
                user.id
            )
        } else {
            String::new()
        };

        format!(
            "<tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>
                    <a href=\"/admin/users/{}/edit\">Change Password</a>
                    <form method=\"POST\" action=\"/admin/users/{}/delete\" style=\"display:inline;\" onsubmit=\"return confirm('Delete user {}?');\">
                        <button type=\"submit\" {} style=\"background:#cc0000;margin-left:10px;\">Delete</button>
                    </form>
                    {}
                </td>
            </tr>",
            user.id, user.username, mfa_icon, user.id, user.id, user.username, delete_disabled, mfa_button
        )
    }).collect::<Vec<_>>().join("");

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - User Management</title>
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
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        button {{ padding: 6px 12px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background: #0052a3; }}
        button:disabled {{ background: #ccc; cursor: not-allowed; }}
        .actions {{ margin-bottom: 20px; }}
        .actions a {{ display: inline-block; padding: 10px 20px; background: #0066cc; color: white; text-decoration: none; border-radius: 4px; }}
        .actions a:hover {{ text-decoration: none; background: #0052a3; }}
    </style>
</head>
<body>
    <header>
        <h1>User Management</h1>
        <nav>
            <a href="/admin">Dashboard</a>
            <a href="/admin/users/new">Add User</a>
        </nav>
        <div class="user-info">
            Logged in as: <strong>{}</strong> | <a href="/logout">Logout</a>
        </div>
    </header>

    <div class="container">
        <div class="actions">
            <a href="/admin/users/new">+ Add New User</a>
        </div>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>MFA</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>
</body>
</html>"#,
        auth_user.username,
        user_rows
    );

    Html(html).into_response()
}

/// GET /admin/users/new - Show create user form
pub async fn get_user_new(
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    // Admin role check
    if auth_user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1>"),
        ).into_response();
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Create User</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        header {{ background: white; border-bottom: 1px solid #ddd; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        header h1 {{ margin: 0; font-size: 24px; color: #333; }}
        nav {{ margin-top: 15px; }}
        nav a {{ display: inline-block; margin-right: 20px; color: #0066cc; text-decoration: none; }}
        nav a:hover {{ text-decoration: underline; }}
        .user-info {{ float: right; margin-top: 15px; color: #666; }}
        .user-info a {{ color: #0066cc; text-decoration: none; }}
        form {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; color: #333; font-weight: 500; }}
        input, select {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }}
        input:focus, select:focus {{ outline: none; border-color: #0066cc; box-shadow: 0 0 0 3px rgba(0,102,204,0.1); }}
        button {{ background: #0066cc; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #0052a3; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <header>
        <h1>Create New User</h1>
        <nav>
            <a href="/admin">Dashboard</a>
            <a href="/admin/users">User List</a>
        </nav>
        <div class="user-info">
            Logged in as: <strong>{}</strong> | <a href="/logout">Logout</a>
        </div>
    </header>

    <div class="container">
        <form method="POST" action="/admin/users/new">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required minlength="3">
                <small>3+ characters, alphanumeric and underscores only</small>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required minlength="8">
                <small>8+ characters</small>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
            </div>
            <div class="form-group">
                <label for="role">Role:</label>
                <select id="role" name="role" required>
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <button type="submit">Create User</button>
            <a href="/admin/users" style="margin-left:10px;">Cancel</a>
        </form>
    </div>
</body>
</html>"#,
        auth_user.username
    );

    Html(html).into_response()
}

/// POST /admin/users/new - Create a new user
pub async fn post_user_new(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Form(req): Form<CreateUserRequest>,
) -> impl IntoResponse {
    // Admin role check
    if auth_user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1>"),
        ).into_response();
    }

    // Validation
    if let Err(msg) = validate_username(&req.username) {
        return Html(format!(
            "<h1>Error</h1><p>{}</p><a href=\"/admin/users/new\">Back</a>",
            msg
        ))
            .into_response();
    }

    if let Err(msg) = validate_password(&req.password) {
        return Html(format!(
            "<h1>Error</h1><p>{}</p><a href=\"/admin/users/new\">Back</a>",
            msg
        ))
            .into_response();
    }

    if req.password != req.confirm_password {
        return Html(
            "<h1>Error</h1><p>Passwords do not match</p><a href=\"/admin/users/new\">Back</a>"
        )
            .into_response();
    }

    // Create user
    match state.users.create(&req.username, &req.password, &req.role).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(_) => Html(
            "<h1>Error</h1><p>Failed to create user (username may already exist)</p><a href=\"/admin/users/new\">Back</a>"
        )
            .into_response(),
    }
}

/// GET /admin/users/:id/edit - Show password change form
pub async fn get_user_edit(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    // Admin role check
    if auth_user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1>"),
        ).into_response();
    }

    let user = match state.users.get_by_id(id).await {
        Ok(Some(user)) => user,
        _ => {
            return Html(
                "<h1>Error</h1><p>User not found</p><a href=\"/admin/users\">Back</a>"
            )
                .into_response();
        }
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Change Password</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        header {{ background: white; border-bottom: 1px solid #ddd; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        header h1 {{ margin: 0; font-size: 24px; color: #333; }}
        nav {{ margin-top: 15px; }}
        nav a {{ display: inline-block; margin-right: 20px; color: #0066cc; text-decoration: none; }}
        nav a:hover {{ text-decoration: underline; }}
        .user-info {{ float: right; margin-top: 15px; color: #666; }}
        .user-info a {{ color: #0066cc; text-decoration: none; }}
        form {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; color: #333; font-weight: 500; }}
        input {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }}
        input:focus {{ outline: none; border-color: #0066cc; box-shadow: 0 0 0 3px rgba(0,102,204,0.1); }}
        button {{ background: #0066cc; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #0052a3; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <header>
        <h1>Change Password for {}</h1>
        <nav>
            <a href="/admin">Dashboard</a>
            <a href="/admin/users">User List</a>
        </nav>
        <div class="user-info">
            Logged in as: <strong>{}</strong> | <a href="/logout">Logout</a>
        </div>
    </header>

    <div class="container">
        <form method="POST" action="/admin/users/{}/edit">
            <div class="form-group">
                <label>Username (read-only):</label>
                <input type="text" value="{}" disabled>
            </div>
            <div class="form-group">
                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password" required minlength="8">
                <small>8+ characters</small>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
            </div>
            <button type="submit">Change Password</button>
            <a href="/admin/users" style="margin-left:10px;">Cancel</a>
        </form>
    </div>
</body>
</html>"#,
        user.username,
        auth_user.username,
        id,
        user.username
    );

    Html(html).into_response()
}

/// POST /admin/users/:id/edit - Update user password
pub async fn post_user_edit(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    Form(req): Form<UpdatePasswordRequest>,
) -> impl IntoResponse {
    // Admin role check
    if auth_user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1>"),
        ).into_response();
    }

    // Validation
    if let Err(msg) = validate_password(&req.new_password) {
        return Html(format!(
            "<h1>Error</h1><p>{}</p><a href=\"/admin/users\">Back</a>",
            msg
        ))
            .into_response();
    }

    if req.new_password != req.confirm_password {
        return Html(
            "<h1>Error</h1><p>Passwords do not match</p><a href=\"/admin/users\">Back</a>"
        )
            .into_response();
    }

    // Update password
    match state.users.update_password(id, &req.new_password).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(_) => Html(
            "<h1>Error</h1><p>Failed to update password</p><a href=\"/admin/users\">Back</a>"
        )
            .into_response(),
    }
}

/// POST /admin/users/:id/delete - Delete a user
pub async fn post_user_delete(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    // Admin role check
    if auth_user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1>"),
        ).into_response();
    }

    // Prevent self-deletion
    if id == auth_user.id {
        return Html(
            "<h1>Error</h1><p>You cannot delete your own account</p><a href=\"/admin/users\">Back</a>"
        )
            .into_response();
    }

    // Delete user
    match state.users.delete(id).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(_) => Html(
            "<h1>Error</h1><p>Failed to delete user</p><a href=\"/admin/users\">Back</a>"
        )
            .into_response(),
    }
}

/// GET /admin/users/:id/disable-mfa - Show MFA disable confirmation form
pub async fn show_disable_mfa(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Result<Html<String>, StatusCode> {
    // Admin role check
    if auth_user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    // Get target user
    let target = state.users.get_by_id(id)
        .await
        .ok()
        .flatten()
        .ok_or(StatusCode::NOT_FOUND)?;

    // Cannot disable own MFA from admin panel
    if id == auth_user.id {
        return Err(StatusCode::BAD_REQUEST);
    }

    // If MFA not enabled, silently redirect
    if target.totp_enabled == 0 {
        return Err(StatusCode::SEE_OTHER);
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Disable MFA</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        header {{ background: white; border-bottom: 1px solid #ddd; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        header h1 {{ margin: 0; font-size: 24px; color: #333; }}
        nav {{ margin-top: 15px; }}
        nav a {{ display: inline-block; margin-right: 20px; color: #0066cc; text-decoration: none; }}
        nav a:hover {{ text-decoration: underline; }}
        .user-info {{ float: right; margin-top: 15px; color: #666; }}
        .user-info a {{ color: #0066cc; text-decoration: none; }}
        .warning-box {{ background: #fffbeb; border: 1px solid #fcd34d; border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
        .warning-box p {{ margin: 8px 0; font-size: 14px; color: #92400e; }}
        .warning-box p:first-child {{ font-weight: 600; margin-bottom: 12px; }}
        .warning-box ul {{ margin: 12px 0 0 20px; font-size: 14px; color: #92400e; }}
        .warning-box li {{ margin: 4px 0; }}
        form {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; color: #333; font-weight: 500; }}
        input {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }}
        input:focus {{ outline: none; border-color: #0066cc; box-shadow: 0 0 0 3px rgba(0,102,204,0.1); }}
        .button-group {{ display: flex; gap: 10px; margin-top: 30px; }}
        .button-group a, .button-group button {{ flex: 1; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; text-align: center; text-decoration: none; }}
        .button-group a {{ background: #f0f0f0; color: #333; }}
        .button-group a:hover {{ background: #e0e0e0; }}
        .button-group button {{ background: #dc2626; color: white; }}
        .button-group button:hover {{ background: #b91c1c; }}
        .error {{ color: #dc2626; font-size: 14px; margin-bottom: 16px; }}
    </style>
</head>
<body>
    <header>
        <h1>Disable MFA</h1>
        <nav>
            <a href="/admin">Dashboard</a>
            <a href="/admin/users">User List</a>
        </nav>
        <div class="user-info">
            Logged in as: <strong>{}</strong> | <a href="/logout">Logout</a>
        </div>
    </header>

    <div class="container">
        <div class="warning-box">
            <p>⚠️ この操作は取り消せません</p>
            <p>
                <strong>{}</strong> のMFAを無効化すると、以下が全て削除されます:
            </p>
            <ul>
                <li>TOTPシークレット</li>
                <li>バックアップコード（全件）</li>
                <li>デバイス記憶トークン（全件）</li>
            </ul>
            <p style="margin-top: 12px;">
                対象ユーザーは次回ログイン時にTOTPを求められなくなります。
                無効化後、ユーザー自身が再度MFAを有効化するよう案内してください。
            </p>
        </div>

        <form method="POST" action="/admin/users/{}/disable-mfa">
            <div class="form-group">
                <label for="admin_password">管理者パスワード（操作の確認）</label>
                <input type="password" id="admin_password" name="admin_password" required autofocus>
            </div>
            <div class="button-group">
                <a href="/admin/users">キャンセル</a>
                <button type="submit">MFAを無効化する</button>
            </div>
        </form>
    </div>
</body>
</html>"#,
        auth_user.username,
        target.username,
        id
    );

    Ok(Html(html))
}

/// POST /admin/users/:id/disable-mfa - Disable MFA for a user
pub async fn handle_disable_mfa(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<i64>,
    Form(form): Form<DisableMfaForm>,
) -> Result<Response, StatusCode> {
    // Admin role check
    if auth_user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    // Get target user
    let target = state.users.get_by_id(id)
        .await
        .ok()
        .flatten()
        .ok_or(StatusCode::NOT_FOUND)?;

    // Cannot disable own MFA from admin panel
    if id == auth_user.id {
        return Err(StatusCode::BAD_REQUEST);
    }

    // If MFA not enabled, silently redirect
    if target.totp_enabled == 0 {
        return Ok(Redirect::to("/admin/users").into_response());
    }

    // Verify admin password
    let admin_username = auth_user.username.clone();
    let password_to_verify = form.admin_password.clone();

    let verify_result = spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            state.users.verify(&admin_username, &password_to_verify)
                .await
                .unwrap_or(false)
        })
    })
    .await
    .unwrap_or(false);

    if !verify_result {
        // Wrong password - add delay to prevent timing attacks
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Return error form
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Disable MFA</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        header {{ background: white; border-bottom: 1px solid #ddd; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        header h1 {{ margin: 0; font-size: 24px; color: #333; }}
        nav {{ margin-top: 15px; }}
        nav a {{ display: inline-block; margin-right: 20px; color: #0066cc; text-decoration: none; }}
        nav a:hover {{ text-decoration: underline; }}
        .user-info {{ float: right; margin-top: 15px; color: #666; }}
        .user-info a {{ color: #0066cc; text-decoration: none; }}
        .warning-box {{ background: #fffbeb; border: 1px solid #fcd34d; border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
        .warning-box p {{ margin: 8px 0; font-size: 14px; color: #92400e; }}
        .warning-box p:first-child {{ font-weight: 600; margin-bottom: 12px; }}
        .warning-box ul {{ margin: 12px 0 0 20px; font-size: 14px; color: #92400e; }}
        .warning-box li {{ margin: 4px 0; }}
        form {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; color: #333; font-weight: 500; }}
        input {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }}
        input:focus {{ outline: none; border-color: #0066cc; box-shadow: 0 0 0 3px rgba(0,102,204,0.1); }}
        .button-group {{ display: flex; gap: 10px; margin-top: 30px; }}
        .button-group a, .button-group button {{ flex: 1; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; text-align: center; text-decoration: none; }}
        .button-group a {{ background: #f0f0f0; color: #333; }}
        .button-group a:hover {{ background: #e0e0e0; }}
        .button-group button {{ background: #dc2626; color: white; }}
        .button-group button:hover {{ background: #b91c1c; }}
        .error {{ color: #dc2626; font-size: 14px; margin-bottom: 16px; padding: 12px; background: #fee2e2; border-radius: 4px; }}
    </style>
</head>
<body>
    <header>
        <h1>Disable MFA</h1>
        <nav>
            <a href="/admin">Dashboard</a>
            <a href="/admin/users">User List</a>
        </nav>
        <div class="user-info">
            Logged in as: <strong>{}</strong> | <a href="/logout">Logout</a>
        </div>
    </header>

    <div class="container">
        <div class="warning-box">
            <p>⚠️ この操作は取り消せません</p>
            <p>
                <strong>{}</strong> のMFAを無効化すると、以下が全て削除されます:
            </p>
            <ul>
                <li>TOTPシークレット</li>
                <li>バックアップコード（全件）</li>
                <li>デバイス記憶トークン（全件）</li>
            </ul>
            <p style="margin-top: 12px;">
                対象ユーザーは次回ログイン時にTOTPを求められなくなります。
                無効化後、ユーザー自身が再度MFAを有効化するよう案内してください。
            </p>
        </div>

        <form method="POST" action="/admin/users/{}/disable-mfa">
            <div class="error">管理者パスワードが正しくありません</div>
            <div class="form-group">
                <label for="admin_password">管理者パスワード（操作の確認）</label>
                <input type="password" id="admin_password" name="admin_password" required autofocus>
            </div>
            <div class="button-group">
                <a href="/admin/users">キャンセル</a>
                <button type="submit">MFAを無効化する</button>
            </div>
        </form>
    </div>
</body>
</html>"#,
            auth_user.username,
            target.username,
            id
        );

        return Ok(Html(html).into_response());
    }

    // Password correct - disable MFA
    if let Err(_) = state.mfa.disable_totp(id).await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Redirect::to("/admin/users").into_response())
}
