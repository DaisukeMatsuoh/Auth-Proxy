// API token CLI subcommand - Phase API-4 (R9), ADR 0003.
//
// Design constraint: never accept an existing token or password as a CLI
// argument. `create` only ever prints a freshly-generated token out; it
// never takes one in as input, so there is no secret-in-argv/shell-history
// exposure on this side. The printed plaintext is a one-time display, same
// contract as the Web UI (Phase API-2) and JSON API (Phase API-1).

use crate::config::Config;
use crate::state::AppState;
use std::sync::Arc;

pub async fn handle_token_list(username: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(Config::from_env()?);
    let state = AppState::new(config).await?;

    let user_id_filter = match &username {
        Some(name) => match state.users.get_by_username(name).await? {
            Some(user) => Some(user.id),
            None => {
                eprintln!("Error: no such user '{name}'");
                return Ok(());
            }
        },
        None => None,
    };

    let tokens = state.api_tokens.list_all().await?;
    let tokens: Vec<_> = tokens
        .into_iter()
        .filter(|t| user_id_filter.is_none_or(|id| t.user_id == id))
        .collect();

    if tokens.is_empty() {
        println!("No tokens found.");
        return Ok(());
    }

    println!("{:<6} {:<15} {:<25} {:<12} {:<20} {}", "ID", "USER", "NAME", "SCOPE", "LAST USED", "STATUS");
    for t in tokens {
        let scope = t.path_prefix.as_deref().unwrap_or("(full access)");
        let last_used = t.last_used_at.as_deref().unwrap_or("never");
        let status = if t.revoked_at.is_some() { "revoked" } else { "active" };
        println!(
            "{:<6} {:<15} {:<25} {:<12} {:<20} {}",
            t.id, t.username, t.name, scope, last_used, status
        );
    }

    Ok(())
}

pub async fn handle_token_revoke(id: i64) -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(Config::from_env()?);
    let state = AppState::new(config).await?;

    if state.api_tokens.revoke_any(id).await? {
        println!("Token {id} revoked.");
    } else {
        eprintln!("Error: no active token with id {id}");
    }

    Ok(())
}

pub async fn handle_token_create(
    username: String,
    name: String,
    path_prefix: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(Config::from_env()?);
    let ttl_days = config.api_token_default_ttl_days;
    let state = AppState::new(config).await?;

    let user = match state.users.get_by_username(&username).await? {
        Some(user) => user,
        None => {
            eprintln!("Error: no such user '{username}'");
            return Ok(());
        }
    };

    let (row, plaintext) = state
        .api_tokens
        .create(user.id, &name, ttl_days, path_prefix.as_deref())
        .await?;

    println!("Token created for '{username}' (id={}).", row.id);
    println!();
    println!("  {plaintext}");
    println!();
    println!("This is the only time the plaintext token will be shown -- copy it now.");
    println!("If this output is captured by a CI system, make sure the log is masked.");

    Ok(())
}
