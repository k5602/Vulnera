//! Vulnera Rust - Main application entry point

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, signal};

use vulnera_rust::{
    Config,
    application::{AnalysisServiceImpl, CacheServiceImpl, ReportServiceImpl},
    infrastructure::{
        cache::file_cache::FileCacheRepository, parsers::ParserFactory,
        repositories::AggregatingVulnerabilityRepository,
    },
    init_tracing,
    presentation::{AppState, create_router},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = Config::load().unwrap_or_else(|_| {
        eprintln!("Failed to load configuration, using defaults");
        Config::default()
    });

    // Initialize tracing
    init_tracing(&config.logging)?;

    tracing::info!("Starting Vulnera Rust server...");
    tracing::info!(
        "Configuration loaded: server={}:{}",
        config.server.host,
        config.server.port
    );

    // Initialize infrastructure services
    let cache_repository = Arc::new(FileCacheRepository::new(
        config.cache.directory.clone(),
        Duration::from_secs(config.cache.ttl_hours * 3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repository));
    let parser_factory = Arc::new(ParserFactory::new());
    let vulnerability_repository = Arc::new(AggregatingVulnerabilityRepository::new());
    let analysis_service = Arc::new(AnalysisServiceImpl::new(
        parser_factory,
        vulnerability_repository,
        cache_service.clone(),
    ));
    let report_service = Arc::new(ReportServiceImpl::new());

    // Create application state
    let app_state = AppState {
        analysis_service,
        cache_service,
        report_service,
    };

    // Create router
    let app = create_router(app_state);

    // Create server address
    let addr = SocketAddr::new(config.server.host.parse()?, config.server.port);

    tracing::info!("Server listening on {}", addr);
    tracing::info!("API documentation available at http://{}/docs", addr);

    // Start server with graceful shutdown
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Handle graceful shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}
