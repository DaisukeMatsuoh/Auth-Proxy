// API token CLI subcommand - Phase API-4 (R9), ADR 0003.
//
// Design constraint: never accept an existing token or password as a CLI
// argument. `create` only ever prints a freshly-generated token out; it
// never takes one in as input, so there is no secret-in-argv/shell-history
// exposure on this side. The printed plaintext is a one-time display, same
// contract as the Web UI (Phase API-2) and JSON API (Phase API-1).
//
// Every failure path here returns `Err(...)` rather than printing to
// stderr and returning `Ok(())`. This CLI exists specifically to be driven
// by scripts/CI (see ADR 0003, R9) checking the process exit code; a
// silent `Ok(())` on "no such user" or "no active token with that id"
// would make automation believe an operation succeeded when it did not.

use crate::config::Config;
use crate::state::AppState;
use std::sync::Arc;

async fn build_state() -> Result<AppState, Box<dyn std::error::Error>> {
    let config = Arc::new(Config::from_env()?);
    Ok(AppState::new(config).await?)
}

pub async fn handle_token_list(username: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let state = build_state().await?;

    println!("{:<6} {:<15} {:<25} {:<12} {:<20} {}", "ID", "USER", "NAME", "SCOPE", "LAST USED", "STATUS");

    if let Some(name) = &username {
        // A user filter is given: go straight to the indexed per-user query
        // (ApiTokenStoreDb::list_for_user) instead of joining every user's
        // tokens via list_all() and discarding all but one user's rows.
        let user = match state.users.get_by_username(name).await? {
            Some(user) => user,
            None => return Err(format!("no such user '{name}'").into()),
        };

        let tokens = state.api_tokens.list_for_user(user.id).await?;
        if tokens.is_empty() {
            println!("No tokens found.");
            return Ok(());
        }
        for t in tokens {
            print_token_row(t.id, name, &t.name, t.path_prefix.as_deref(), t.last_used_at.as_deref(), t.revoked_at.is_some());
        }
    } else {
        let tokens = state.api_tokens.list_all().await?;
        if tokens.is_empty() {
            println!("No tokens found.");
            return Ok(());
        }
        for t in tokens {
            print_token_row(
                t.token.id,
                &t.username,
                &t.token.name,
                t.token.path_prefix.as_deref(),
                t.token.last_used_at.as_deref(),
                t.token.revoked_at.is_some(),
            );
        }
    }

    Ok(())
}

fn print_token_row(id: i64, username: &str, name: &str, path_prefix: Option<&str>, last_used_at: Option<&str>, revoked: bool) {
    let scope = path_prefix.unwrap_or("(full access)");
    let last_used = last_used_at.unwrap_or("never");
    let status = if revoked { "revoked" } else { "active" };
    println!("{id:<6} {username:<15} {name:<25} {scope:<12} {last_used:<20} {status}");
}

pub async fn handle_token_revoke(id: i64) -> Result<(), Box<dyn std::error::Error>> {
    let state = build_state().await?;

    if state.api_tokens.revoke_any(id).await? {
        println!("Token {id} revoked.");
        Ok(())
    } else {
        Err(format!("no active token with id {id}").into())
    }
}

pub async fn handle_token_create(
    username: String,
    name: String,
    path_prefix: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = build_state().await?;
    let ttl_days = state.config.api_token_default_ttl_days;

    let user = match state.users.get_by_username(&username).await? {
        Some(user) => user,
        None => return Err(format!("no such user '{username}'").into()),
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
