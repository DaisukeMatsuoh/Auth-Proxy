use axum::{
    extract::State,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use crate::AppState;

/// AuthUser extension passed by auth middleware
#[derive(Clone)]
pub struct AuthUser {
    pub id: i64,
    pub username: String,
    pub role: String,
}

/// Admin middleware: checks if user has admin role
pub async fn admin_middleware(
    State(_state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    next: Next,
) -> Response {
    // Check if user is admin
    if auth_user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            "<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
  <h1>403 Forbidden</h1>
  <p>You do not have permission to access this resource.</p>
  <a href=\"/\">Back to home</a>
</body>
</html>"
        )
            .into_response();
    }

    // User is admin, proceed
    next.run(Default::default()).await
}
