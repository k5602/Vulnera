#[cfg(test)]
mod tests {
    use crate::{
        application::errors::VulnerabilityError,
        application::{AnalysisServiceImpl, CacheServiceImpl, PopularPackageServiceImpl, ReportServiceImpl},
        domain::Package,
        infrastructure::{
            api_clients::traits::{RawVulnerability, VulnerabilityApiClient},
            cache::file_cache::FileCacheRepository,
            parsers::ParserFactory,
            repositories::AggregatingVulnerabilityRepository,
        },
        presentation::{AppState, create_router},
    };
    use async_trait::async_trait;
    use axum::http::StatusCode;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    // Mock API client for testing
    struct MockApiClient;

    #[async_trait]
    impl VulnerabilityApiClient for MockApiClient {
        async fn query_vulnerabilities(
            &self,
            _package: &Package,
        ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
            Ok(vec![])
        }

        async fn get_vulnerability_details(
            &self,
            _id: &str,
        ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
            Ok(None)
        }
    }

    fn dummy_state() -> AppState {
        let cache_repo = Arc::new(FileCacheRepository::new(
            std::path::PathBuf::from(".vulnera_cache_test"),
            Duration::from_secs(60),
        ));
        let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
        let parser_factory = Arc::new(ParserFactory::new());

        // Create mock API clients
        let mock_client = Arc::new(MockApiClient);
        let vuln_repo = Arc::new(AggregatingVulnerabilityRepository::new(
            mock_client.clone(),
            mock_client.clone(),
            mock_client,
        ));

        let analysis_service = Arc::new(AnalysisServiceImpl::new(
            parser_factory,
            vuln_repo.clone(),
            cache_service.clone(),
        ));
        let report_service = Arc::new(ReportServiceImpl::new());
        
        // Create popular package service with test config
        let config = Arc::new(crate::Config::default());
        let popular_package_service = Arc::new(PopularPackageServiceImpl::new(
            vuln_repo.clone(),
            cache_service.clone(),
            config,
        ));
        
        AppState {
            analysis_service,
            cache_service,
            report_service,
            vulnerability_repository: vuln_repo,
            popular_package_service,
        }
    }

    #[tokio::test]
    async fn docs_disabled_returns_404() {
        let mut config = crate::Config::default();
        config.server.enable_docs = false;
        let app = create_router(dummy_state(), &config);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/docs")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn docs_enabled_returns_ok() {
        let mut config = crate::Config::default();
        config.server.enable_docs = true;
        let app = create_router(dummy_state(), &config);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/docs")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        //note: Swagger UI may redirect (303) before serving index depending on version
        assert!(
            matches!(response.status(), StatusCode::OK | StatusCode::SEE_OTHER),
            "unexpected status: {}",
            response.status()
        );
    }
}
