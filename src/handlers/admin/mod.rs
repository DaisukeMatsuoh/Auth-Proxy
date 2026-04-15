// Admin handlers
pub mod dashboard;
pub mod users;

pub use dashboard::get_dashboard;
pub use users::{
    get_users,
    get_user_new,
    post_user_new,
    get_user_edit,
    post_user_edit,
    post_user_delete,
    show_disable_mfa,
    handle_disable_mfa,
};
