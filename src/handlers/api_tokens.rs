use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use crate::AppState;
use crate::api_tokens_db::ApiTokenDbError;
use crate::middleware::auth::insufficient_scope_response;
use crate::middleware::AuthUser;

/// Reject requests authenticated via API token. Token issuance/revocation
/// must stay behind session auth only: allowing a token to mint or revoke
/// other tokens would create a privilege-escalation chain from a single
/// leaked token.
pub(crate) fn require_session_auth(auth_user: &AuthUser) -> Result<(), Response> {
    if auth_user.auth_method != "session" {
        return Err(insufficient_scope_response(
            "Token issuance and management require session authentication",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
pub struct TokenSummary {
    pub id: i64,
    pub name: String,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked: bool,
    pub path_prefix: Option<String>,
}

/// GET /api/tokens - list the current user's tokens (never includes hashes)
pub async fn list_tokens(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    if let Err(resp) = require_session_auth(&auth_user) {
        return resp;
    }

    let rows = state
        .api_tokens
        .list_for_user(auth_user.id)
        .await
        .unwrap_or_default();

    let summaries: Vec<TokenSummary> = rows
        .into_iter()
        .map(|r| TokenSummary {
            id: r.id,
            name: r.name,
            last_used_at: r.last_used_at,
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked: r.revoked_at.is_some(),
            path_prefix: r.path_prefix,
        })
        .collect();

    Json(summaries).into_response()
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    /// Optional path-scope prefix (Phase API-3, R7). `None`/blank = full access.
    #[serde(default)]
    pub path_prefix: Option<String>,
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub id: i64,
    pub name: String,
    /// Plaintext token. Present only in this response; never retrievable again.
    pub token: String,
    pub path_prefix: Option<String>,
}

/// POST /api/tokens - issue a new token
pub async fn create_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(body): Json<CreateTokenRequest>,
) -> Response {
    if let Err(resp) = require_session_auth(&auth_user) {
        return resp;
    }

    if body.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "name must not be empty"
            })),
        )
            .into_response();
    }

    let ttl_days = state.config.api_token_default_ttl_days;
    match state
        .api_tokens
        .create(auth_user.id, &body.name, ttl_days, body.path_prefix.as_deref())
        .await
    {
        Ok((row, plaintext)) => (
            StatusCode::CREATED,
            Json(CreateTokenResponse {
                id: row.id,
                name: row.name,
                token: plaintext,
                path_prefix: row.path_prefix,
            }),
        )
            .into_response(),
        Err(ApiTokenDbError::InvalidPathPrefix(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": msg
            })),
        )
            .into_response(),
        Err(ApiTokenDbError::DbError(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// DELETE /api/tokens/{id} - revoke a token
///
/// Ownership is enforced in ApiTokenStoreDb::revoke (user_id must match),
/// so "not yours" and "does not exist" both surface as 404 here, avoiding
/// an enumeration oracle over other users' token IDs.
pub async fn revoke_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = require_session_auth(&auth_user) {
        return resp;
    }

    match state.api_tokens.revoke(id, auth_user.id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_user() -> AuthUser {
        AuthUser {
            id: 1,
            username: "alice".to_string(),
            role: "user".to_string(),
            auth_method: "session".to_string(),
            token_name: None,
        }
    }

    fn token_user() -> AuthUser {
        AuthUser {
            id: 1,
            username: "alice".to_string(),
            role: "user".to_string(),
            auth_method: "token".to_string(),
            token_name: Some("Alice's MacBook".to_string()),
        }
    }

    #[test]
    fn test_require_session_auth_allows_session() {
        assert!(require_session_auth(&session_user()).is_ok());
    }

    #[test]
    fn test_require_session_auth_rejects_token() {
        assert!(require_session_auth(&token_user()).is_err());
    }

    #[tokio::test]
    async fn test_create_token_with_path_prefix_round_trips() {
        let state = AppState::test().await.unwrap();
        let response = create_token(
            State(state),
            Extension(session_user()),
            Json(CreateTokenRequest {
                name: "Sync-only device".to_string(),
                path_prefix: Some("/sync/".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["path_prefix"], "/sync/");
    }

    #[tokio::test]
    async fn test_create_token_rejects_invalid_path_prefix() {
        let state = AppState::test().await.unwrap();
        let response = create_token(
            State(state),
            Extension(session_user()),
            Json(CreateTokenRequest {
                name: "Bad prefix".to_string(),
                path_prefix: Some("sync".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
