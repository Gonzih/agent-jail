use agent_jail::api::create_router;
use agent_jail::config::Config;
use agent_jail::state::AppState;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("agent_jail=info,tower_http=info")),
        )
        .init();

    let config = Config::from_env();
    tracing::info!(
        host = %config.host,
        port = %config.port,
        data_dir = %config.data_dir.display(),
        "Starting agent-jail service"
    );

    let state = AppState::new(config.clone());

    // Load persisted jails
    match state.load_from_disk().await {
        Ok(count) => {
            if count > 0 {
                tracing::info!(count, "Loaded jails from disk");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to load jails from disk");
        }
    }

    let app = create_router(Arc::clone(&state));

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "Listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
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
        _ = ctrl_c => tracing::info!("Ctrl+C received"),
        _ = terminate => tracing::info!("SIGTERM received"),
    }
}
