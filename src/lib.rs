//! Vulnera Rust - A comprehensive vulnerability analysis API
//!
//! This crate provides a Domain-Driven Design (DDD) architecture for analyzing
//! software dependencies across multiple programming language ecosystems.

use std::{sync::Arc, time::Duration};

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod logging;
pub mod presentation;

pub use config::Config;
pub use logging::init_tracing;

use application::{
    AnalysisServiceImpl, CacheServiceImpl, PopularPackageServiceImpl, ReportServiceImpl,
    VersionResolutionServiceImpl,
};
use infrastructure::{
    api_clients::{ghsa::GhsaClient, nvd::NvdClient, osv::OsvClient},
    cache::file_cache::FileCacheRepository,
    parsers::ParserFactory,
    registries::MultiplexRegistryClient,
    repositories::AggregatingVulnerabilityRepository,
    repository_source::GitHubRepositoryClient,
};
use presentation::{AppState, create_router};

/// Create the application with the given configuration
pub async fn create_app(config: Config) -> Result<axum::Router, Box<dyn std::error::Error>> {
    // Initialize infrastructure services
    let cache_repository = Arc::new(FileCacheRepository::new(
        config.cache.directory.clone(),
        Duration::from_secs(config.cache.ttl_hours * 3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repository));
    let parser_factory = Arc::new(ParserFactory::new());

    // Create API clients
    let osv_client = Arc::new(OsvClient);
    let nvd_client = Arc::new(NvdClient::new(
        config.apis.nvd.base_url.clone(),
        config.apis.nvd.api_key.clone(),
    ));
    let ghsa_token_opt = config.apis.ghsa.token.clone().filter(|t| !t.is_empty());
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
        &config,
    ));
    let report_service = Arc::new(ReportServiceImpl::new());

    // GitHub repository analysis components
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
    let repository_analysis_service: Option<Arc<dyn application::RepositoryAnalysisService>> =
        Some(Arc::new(application::RepositoryAnalysisServiceImpl::new(
            github_client.clone(),
            vulnerability_repository.clone(),
            parser_factory.clone(),
            Arc::new(config.clone()),
        )));

    // Create popular package service with config
    let config_arc = Arc::new(config.clone());
    let popular_package_service = Arc::new(PopularPackageServiceImpl::new(
        vulnerability_repository.clone(),
        cache_service.clone(),
        config_arc,
    ));

    // Create version resolution service
    let registry_client = Arc::new(MultiplexRegistryClient::new());
    let version_resolution_service = Arc::new(VersionResolutionServiceImpl::new_with_cache(
        registry_client,
        cache_service.clone(),
    ));

    // Create application state
    let app_state = AppState {
        analysis_service,
        cache_service,
        report_service,
        vulnerability_repository,
        popular_package_service,
        repository_analysis_service,
        version_resolution_service,
    };

    // Create router
    Ok(create_router(app_state, &config))
}
