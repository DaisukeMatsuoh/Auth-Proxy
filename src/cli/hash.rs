use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;
use std::io::{self, Write};

pub async fn handle_hash() -> Result<(), Box<dyn std::error::Error>> {
    // Read username from stdin
    print!("Username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();

    if username.is_empty() {
        return Err("Username cannot be empty".into());
    }

    eprintln!("[DEBUG] Username entered: '{}' (len={})", username, username.len());

    // Read password securely (hidden input)
    let password = rpassword::prompt_password("Password: ")?.trim().to_string();

    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }

    eprintln!("[DEBUG] Password entered: (len={}, first_char={:?})", password.len(), password.chars().next());

    // Generate Argon2id hash
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {}", e))?;

    eprintln!("[DEBUG] Hash generated successfully");
    eprintln!("[DEBUG] Output format: .env compatible");

    // Output in single-quoted format for .env file
    // Single quotes prevent shell variable expansion of $ characters in the hash
    println!("APP_USERS='{}:{}\'", username, password_hash);

    Ok(())
}
