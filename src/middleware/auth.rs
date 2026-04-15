use axum::{
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};
use crate::AppState;
use crate::middleware::{extract_session_id, admin::AuthUser};

/// Extract session ID from cookies and attach X-Auth-* headers
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    // Remove any X-Auth-* headers from the client to prevent spoofing
    req.headers_mut().remove("x-auth-user");
    req.headers_mut().remove("x-auth-user-id");
    req.headers_mut().remove("x-auth-role");
    req.headers_mut().remove("x-auth-issuer");

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

                // Set Extension<AuthUser> for handlers that need it
                let auth_user = AuthUser {
                    id: user.id,
                    username: user.username.clone(),
                    role: user.role.clone(),
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
