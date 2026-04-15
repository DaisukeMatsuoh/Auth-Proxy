pub mod login;
pub mod logout;
pub mod static_files;
pub mod proxy;
pub mod admin;
pub mod mfa;
pub mod settings;

// Re-export main handlers for convenience
pub use login::{get_login, post_login};
pub use logout::post_logout;
pub use static_files::serve_static_files;
pub use proxy::proxy_handler;
pub use mfa::{show_verify, handle_verify, show_backup, handle_backup};
pub use settings::{show_mfa, start_setup, confirm_setup, disable_mfa, revoke_devices};
