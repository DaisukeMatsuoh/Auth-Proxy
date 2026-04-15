use crate::config::Config;
use crate::state::AppState;
use std::sync::Arc;

pub async fn handle_verify(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment
    let config = Config::from_env()?;
    let config = Arc::new(config);

    // Initialize database state
    let state = AppState::new(config).await?;

    // Read password securely (hidden input)
    let password = rpassword::prompt_password("Password: ")?.trim().to_string();

    // Verify credentials via database
    let result = state.users.verify(username, &password).await?;

    if result {
        println!("✅ Password OK");
    } else {
        println!("❌ Password NG");
    }

    Ok(())
}
