#[cfg(test)]
mod tests {
    use crate::{
        application::{AnalysisServiceImpl, CacheServiceImpl, ReportServiceImpl},
        infrastructure::{
            cache::file_cache::FileCacheRepository, parsers::ParserFactory,
            repositories::AggregatingVulnerabilityRepository,
        },
        presentation::{AppState, create_router},
    };
    use axum::http::StatusCode;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn dummy_state() -> AppState {
        let cache_repo = Arc::new(FileCacheRepository::new(
            std::path::PathBuf::from(".vulnera_cache_test"),
            Duration::from_secs(60),
        ));
        let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
        let parser_factory = Arc::new(ParserFactory::new());
        let vuln_repo = Arc::new(AggregatingVulnerabilityRepository::new());
        let analysis_service = Arc::new(AnalysisServiceImpl::new(
            parser_factory,
            vuln_repo,
            cache_service.clone(),
        ));
        let report_service = Arc::new(ReportServiceImpl::new());
        AppState {
            analysis_service,
            cache_service,
            report_service,
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
        // Swagger UI may redirect (303) before serving index depending on version
        assert!(
            matches!(response.status(), StatusCode::OK | StatusCode::SEE_OTHER),
            "unexpected status: {}",
            response.status()
        );
    }
}
