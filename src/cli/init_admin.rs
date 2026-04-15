use crate::config::Config;
use crate::AppState;
use dotenvy;
use rpassword::prompt_password;
use std::sync::Arc;
use std::io::{self, Write};

/// Initialize the first admin user interactively
///
/// This command:
/// 1. Checks if any users exist in the database
/// 2. If users exist, returns an error
/// 3. If no users, prompts for admin username and password
/// 4. Creates the admin user with role 'admin'
pub async fn handle_init_admin() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration (without loading .env for CLI-only operations)
    let _ = dotenvy::dotenv();
    let config = Arc::new(Config::from_env()?);

    // Create AppState without seeding default users
    let state = AppState::new_without_seed(config.clone()).await?;

    // Check if any users already exist
    let users = state.users.list_all().await?;
    if !users.is_empty() {
        eprintln!("Error: Database already contains {} user(s). Cannot create initial admin when users exist.", users.len());
        return Err("Users already exist in database".into());
    }

    println!("Create initial admin user");
    println!();

    // Prompt for username
    print!("Username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    // Validate username
    if username.len() < 3 {
        eprintln!("Error: Username must be at least 3 characters");
        return Err("Invalid username".into());
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        eprintln!("Error: Username can only contain letters, numbers, and underscores");
        return Err("Invalid username".into());
    }

    // Prompt for password (hidden input)
    let password = prompt_password("Password: ")?;

    // Validate password
    if password.len() < 8 {
        eprintln!("Error: Password must be at least 8 characters");
        return Err("Invalid password".into());
    }

    // Prompt for confirmation
    let confirm = prompt_password("Confirm:  ")?;

    if password != confirm {
        eprintln!("Error: Passwords do not match");
        return Err("Password mismatch".into());
    }

    // Create the admin user (hashing is done by create() method)
    // Pass plaintext password, not hash
    state.users.create(&username, &password, "admin").await?;

    println!("Admin user '{}' created.", username);
    Ok(())
}
