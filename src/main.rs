//! Vulnera Rust - Main application entry point

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, signal};

use vulnera_rust::{
    Config,
    application::{
        AnalysisServiceImpl, CacheServiceImpl, PopularPackageServiceImpl, ReportServiceImpl,
    },
    infrastructure::{
        api_clients::{ghsa::GhsaClient, nvd::NvdClient, osv::OsvClient},
        cache::file_cache::FileCacheRepository,
        parsers::ParserFactory,
        repositories::AggregatingVulnerabilityRepository,
        repository_source::GitHubRepositoryClient,
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

    // Create API clients
    let osv_client = Arc::new(OsvClient::default());
    let nvd_client = Arc::new(NvdClient::new(
        config.apis.nvd.base_url.clone(),
        config.apis.nvd.api_key.clone(),
    ));
    let ghsa_token_opt = config.apis.ghsa.token.clone().filter(|t| !t.is_empty());
    if ghsa_token_opt.is_none() {
        tracing::info!(
            "GHSA token not provided; GitHub advisories lookups will be skipped unless provided via environment."
        );
    }
    let ghsa_client = Arc::new(GhsaClient::new(
        ghsa_token_opt.unwrap_or_default(),
        config.apis.ghsa.graphql_url.clone(),
    ));

    let vulnerability_repository = Arc::new(AggregatingVulnerabilityRepository::new(
        osv_client,
        nvd_client,
        ghsa_client,
    ));

    let analysis_service = Arc::new(AnalysisServiceImpl::new(
        parser_factory.clone(),
        vulnerability_repository.clone(),
        cache_service.clone(),
    ));
    let report_service = Arc::new(ReportServiceImpl::new());
    // GitHub repository analysis components (stub wiring)
    let github_client = Arc::new(
        GitHubRepositoryClient::from_token(
            config.apis.github.token.clone(),
            Some(config.apis.github.base_url.clone()),
            config.apis.github.timeout_seconds,
            config.apis.github.reuse_ghsa_token,
        ).await.unwrap_or_else(|e| {
            tracing::warn!(error=?e, "Failed to init GitHubRepositoryClient, repository analysis disabled");
            GitHubRepositoryClient::new(
                octocrab::Octocrab::builder().build().expect("octocrab build"),
                "https://api.github.com".into(),
                false,
                10,
            )
        })
    );
    let repository_analysis_service: Option<
        Arc<dyn vulnera_rust::application::RepositoryAnalysisService>,
    > = Some(Arc::new(
        vulnera_rust::application::RepositoryAnalysisServiceImpl::new(
            github_client.clone(),
            vulnerability_repository.clone(),
            parser_factory.clone(),
            Arc::new(config.clone()),
        ),
    ));

    // Create popular package service with config
    let config_arc = Arc::new(config.clone());
    let popular_package_service = Arc::new(PopularPackageServiceImpl::new(
        vulnerability_repository.clone(),
        cache_service.clone(),
        config_arc,
    ));

    // Create application state
    let app_state = AppState {
        analysis_service,
        cache_service,
        report_service,
        vulnerability_repository,
        popular_package_service,
        repository_analysis_service,
    };

    // Create router
    let app = create_router(app_state, &config);

    // Create server address
    let addr = SocketAddr::new(config.server.host.parse()?, config.server.port);

    tracing::info!("Server listening on {}", addr);
    if config.server.enable_docs {
        tracing::info!("API documentation available at http://{}/docs", addr);
    } else {
        tracing::info!("API documentation disabled (enable_docs=false)");
    }

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
