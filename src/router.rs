use axum::{
    routing::{get, post},
    middleware::from_fn_with_state,
    Router,
};
use crate::{
    handlers,
    middleware,
    AppState,
};

/// Build the main application router
///
/// Route structure:
/// - /login, /logout: authentication (no auth_middleware)
/// - /admin/*: admin panel (role check performed in handlers)
/// - /*: fallback proxy handler (auth_middleware)
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Authentication routes (no middleware)
        .route("/login", get(handlers::login::get_login).post(handlers::login::post_login))
        .route("/logout", post(handlers::logout::post_logout))
        // MFA verification routes (mfa_pending cookie protected, not auth_middleware)
        .route("/mfa/verify", get(handlers::mfa::show_verify).post(handlers::mfa::handle_verify))
        .route("/mfa/backup", get(handlers::mfa::show_backup).post(handlers::mfa::handle_backup))
        // Admin routes (role check performed in each handler)
        .route("/admin", get(handlers::admin::get_dashboard))
        .route("/admin/users", get(handlers::admin::get_users))
        .route("/admin/users/new", get(handlers::admin::get_user_new).post(handlers::admin::post_user_new))
        .route("/admin/users/{id}/edit", get(handlers::admin::get_user_edit).post(handlers::admin::post_user_edit))
        .route("/admin/users/{id}/delete", post(handlers::admin::post_user_delete))
        .route("/admin/users/{id}/disable-mfa", get(handlers::admin::show_disable_mfa).post(handlers::admin::handle_disable_mfa))
        // Admin-wide API token visibility (Phase API-4, R10)
        .route("/admin/tokens", get(handlers::admin::get_admin_tokens))
        .route("/admin/tokens/{id}/revoke", post(handlers::admin::post_admin_token_revoke))
        // Security settings routes (Phase 3a-2)
        .route("/settings/security", get(handlers::settings::security::show))
        .route("/settings/security/password", get(handlers::settings::security::show_password).post(handlers::settings::security::handle_password))
        .route("/settings/security/mfa/setup/start", post(handlers::settings::start_setup))
        .route("/settings/security/mfa/setup/confirm", post(handlers::settings::confirm_setup))
        .route("/settings/security/mfa/disable", post(handlers::settings::disable_mfa))
        .route("/settings/security/mfa/revoke-devices", post(handlers::settings::revoke_devices))
        .route("/settings/security/mfa/backup-codes/regenerate", get(handlers::settings::security::show_regenerate_backup_codes).post(handlers::settings::security::handle_regenerate_backup_codes))
        // API token management UI (Phase API-2). Session-auth only, enforced
        // inside each handler (see require_session_auth) for the same reason
        // as /api/tokens above.
        .route("/settings/security/tokens", get(handlers::settings::tokens::show).post(handlers::settings::tokens::create))
        .route("/settings/security/tokens/{id}/revoke", post(handlers::settings::tokens::revoke))
        // Legacy MFA settings routes (backward compatibility)
        .route("/settings/mfa", get(handlers::settings::show_mfa))
        .route("/settings/mfa/setup/start", post(handlers::settings::start_setup))
        .route("/settings/mfa/setup/confirm", post(handlers::settings::confirm_setup))
        .route("/settings/mfa/disable", post(handlers::settings::disable_mfa))
        .route("/settings/mfa/revoke-devices", post(handlers::settings::revoke_devices))
        // Public API: /me (stable user settings URLs for upstream app integration - Phase Me)
        .route("/me", get(handlers::me::redirect_to_security))
        .route("/me/password", get(handlers::me::redirect_to_password))
        .route("/me/mfa", get(handlers::me::redirect_to_mfa))
        .route("/me/devices", get(handlers::me::redirect_to_devices))
        .route("/me/tokens", get(handlers::me::redirect_to_tokens))
        // API token management (Phase API-1). Session-auth only; enforced
        // inside each handler via AuthUser::auth_method, not at the router
        // level, since both session and token requests reach the same
        // auth_middleware-protected routes.
        .route("/api/tokens", get(handlers::api_tokens::list_tokens).post(handlers::api_tokens::create_token))
        .route("/api/tokens/{id}", axum::routing::delete(handlers::api_tokens::revoke_token))
        // Fallback route: static files (if APP_SERVE_PATH set) then upstream proxy
        .fallback(handlers::proxy::proxy_handler)
        // Apply auth middleware to all routes except /login, /logout, /mfa/*, and some explicit routes
        .layer(from_fn_with_state(state.clone(), middleware::auth::auth_middleware))
        .with_state(state)
}
