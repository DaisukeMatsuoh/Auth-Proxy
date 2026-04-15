use auth_proxy::{config::Config, AppState, cli, router};
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber;

#[derive(Parser, Debug)]
#[command(name = "auth-proxy")]
#[command(about = "Authentication proxy server for static HTML files", long_about = None)]
enum Cli {
    /// Start the server (default)
    Serve,

    /// Initialize the first admin user
    InitAdmin,

    /// Generate Argon2id hash for a password
    Hash,

    /// Verify a password for a user
    Verify {
        /// Username to verify
        username: String,
    },

    /// List registered usernames
    List,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing_subscriber::filter::LevelFilter::INFO.into()),
        )
        .init();

    // Parse CLI arguments
    let args = Cli::parse();

    match args {
        Cli::Serve => {
            serve().await?;
        }
        Cli::InitAdmin => {
            cli::handle_init_admin().await?;
        }
        Cli::Hash => {
            cli::handle_hash().await?;
        }
        Cli::Verify { username } => {
            cli::handle_verify(&username).await?;
        }
        Cli::List => {
            cli::handle_list().await?;
        }
    }

    Ok(())
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment
    let config = Config::from_env()?;
    let listen_addr = config.listen_addr;
    tracing::info!("Config loaded: listening on {}", listen_addr);

    // Create app state with database
    let config = Arc::new(config);
    let state = AppState::new(config.clone()).await?;
    tracing::info!("Database initialized and migrations applied");

    // Background task: clean up expired sessions every 10 minutes
    {
        let sessions = state.sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                match sessions.cleanup_expired().await {
                    Ok(n) if n > 0 => tracing::info!("Cleaned up {} expired sessions", n),
                    Err(e) => tracing::error!("Session cleanup error: {}", e),
                    _ => {}
                }
            }
        });
    }

    // Background task: clean up expired MFA sessions and device tokens every 10 minutes
    {
        let mfa = state.mfa.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                if let Err(e) = mfa.cleanup_expired().await {
                    tracing::error!("MFA cleanup error: {}", e);
                }
            }
        });
    }

    tracing::info!("Server startup complete. Ready to accept connections.");

    // Build Axum router
    let app = router::build_router(state);

    // Create TCP listener
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("Server listening on {}", listen_addr);

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Signal handler for graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received CTRL+C signal");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM signal");
        }
    }

    tracing::info!("Server shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_state_creation() {
        let config = Arc::new(Config::test_default());
        let state = AppState::new(config).await;
        assert!(state.is_ok());
    }
}
