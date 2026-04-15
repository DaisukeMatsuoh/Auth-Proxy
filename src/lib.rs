pub mod config;
pub mod state;
pub mod session;
pub mod users;
pub mod users_db;
pub mod sessions_db;
pub mod mfa;
pub mod handlers;
pub mod middleware;
pub mod cli;
pub mod router;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

// Re-export AppState from state module
pub use state::AppState;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Session not found")]
    SessionNotFound,

    #[error("File not found")]
    NotFound,

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Config error: {0}")]
    ConfigError(#[from] config::ConfigError),

    #[error("User store error: {0}")]
    UserStoreError(#[from] users::UserStoreError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AppError::SessionNotFound => (StatusCode::UNAUTHORIZED, "Session expired or not found"),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found"),
            AppError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
            AppError::ConfigError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error"),
            AppError::UserStoreError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "User store error"),
            AppError::IoError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "IO error"),
        };

        (status, error_message).into_response()
    }
}
