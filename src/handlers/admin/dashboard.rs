use crate::{AppState, middleware::AuthUser};
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    http::StatusCode,
    Extension,
};

/// GET /admin - Dashboard with statistics
pub async fn get_dashboard(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    // Admin role check
    if auth_user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 Forbidden</h1><p>You do not have permission to access this resource.</p>"),
        ).into_response();
    }

    // Get user count
    let user_count = state.users.list_all()
        .await
        .ok()
        .map(|users| users.len())
        .unwrap_or(0);

    // Get active session count
    let session_count = state.sessions.count_active()
        .await
        .ok()
        .unwrap_or(0);

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Auth Proxy - Dashboard</title>
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
        .user-info a:hover {{ text-decoration: underline; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ color: #666; font-size: 14px; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-card .number {{ font-size: 48px; color: #0066cc; font-weight: bold; }}
        .actions {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .actions h2 {{ font-size: 18px; margin-bottom: 15px; }}
        .actions a, .actions button {{
            display: inline-block;
            padding: 10px 20px;
            margin-right: 10px;
            margin-bottom: 10px;
            background: #0066cc;
            color: white;
            text-decoration: none;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }}
        .actions a:hover, .actions button:hover {{ background: #0052a3; }}
    </style>
</head>
<body>
    <header>
        <h1>Auth Proxy Dashboard</h1>
        <nav>
            <a href="/admin/users">User Management</a>
            <a href="/admin/users/new">Add User</a>
        </nav>
        <div class="user-info">
            Logged in as: <strong>{}</strong> | <a href="/logout">Logout</a>
        </div>
    </header>

    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <h3>Total Users</h3>
                <div class="number">{}</div>
            </div>
            <div class="stat-card">
                <h3>Active Sessions</h3>
                <div class="number">{}</div>
            </div>
        </div>

        <div class="actions">
            <h2>Quick Actions</h2>
            <a href="/admin/users">View All Users</a>
            <a href="/admin/users/new">Create New User</a>
        </div>
    </div>
</body>
</html>"#,
        auth_user.username,
        user_count,
        session_count
    );

    Html(html).into_response()
}
