use crate::config::Config;
use crate::state::AppState;
use std::sync::Arc;

pub async fn handle_list() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment
    let config = Config::from_env()?;
    let config = Arc::new(config);

    // Initialize database state
    let state = AppState::new(config).await?;

    // Get all users from database
    let users = state.users.list_all().await?;

    // Display users
    println!("Registered users:");
    for user in users {
        let role_badge = match user.role.as_str() {
            "admin" => "👑",
            _ => "👤",
        };
        println!("  {} {}", role_badge, user.username);
    }

    Ok(())
}
