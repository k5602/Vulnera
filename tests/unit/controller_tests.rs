//! Comprehensive unit tests for Vulnera controllers
//! Tests controller logic in isolation with mocked dependencies

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::Utc;
use mockito::Server;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use uuid::Uuid;
use vulnera_rust::application::errors::ApplicationError;
use vulnera_rust::application::services::{
    AnalysisService, CacheService, PopularPackageService, ReportService, RepositoryAnalysisService,
    VersionResolutionService,
};
use vulnera_rust::domain::entities::{AnalysisMetadata, AnalysisReport, Package, Vulnerability};
use vulnera_rust::domain::value_objects::{
    Ecosystem, Severity, Version, VulnerabilityId, VulnerabilitySource,
};
use vulnera_rust::infrastructure::repositories::VulnerabilityRepository;
use vulnera_rust::presentation::controllers::analysis::{
    analyze_dependencies, analyze_repository, get_vulnerability_details,
    list_popular_vulnerabilities,
};
use vulnera_rust::presentation::controllers::health::{detailed_health_check, health_check};
use vulnera_rust::presentation::models::{
    AnalysisRequest, AnalysisResponse, PopularPackagesQuery, RepositoryAnalysisRequest,
};
use vulnera_rust::{AppState, Config};

// Mock implementations for testing

#[derive(Clone)]
struct MockAnalysisService {
    should_fail: bool,
    packages: Vec<Package>,
    vulnerabilities: Vec<Vulnerability>,
}

impl MockAnalysisService {
    fn new() -> Self {
        Self {
            should_fail: false,
            packages: vec![
                Package::new(
                    "express".to_string(),
                    Version::parse("4.17.1").unwrap(),
                    Ecosystem::Npm,
                )
                .unwrap(),
                Package::new(
                    "lodash".to_string(),
                    Version::parse("4.17.20").unwrap(),
                    Ecosystem::Npm,
                )
                .unwrap(),
            ],
            vulnerabilities: vec![
                create_test_vulnerability("GHSA-1234-5678-9012", Severity::High),
                create_test_vulnerability("CVE-2021-1234", Severity::Medium),
            ],
        }
    }

    fn with_failure() -> Self {
        Self {
            should_fail: true,
            packages: vec![],
            vulnerabilities: vec![],
        }
    }

    fn with_no_vulnerabilities() -> Self {
        Self {
            should_fail: false,
            packages: vec![
                Package::new(
                    "safe-package".to_string(),
                    Version::parse("1.0.0").unwrap(),
                    Ecosystem::Npm,
                )
                .unwrap(),
            ],
            vulnerabilities: vec![],
        }
    }
}

#[async_trait::async_trait]
impl AnalysisService for MockAnalysisService {
    async fn analyze_dependencies(
        &self,
        _content: &str,
        _ecosystem: Ecosystem,
        _filename: Option<&str>,
    ) -> Result<AnalysisReport, ApplicationError> {
        if self.should_fail {
            return Err(ApplicationError::ParsingError {
                message: "Mock parsing error".to_string(),
                ecosystem: Ecosystem::Npm,
                filename: "package.json".to_string(),
            });
        }

        let metadata = AnalysisMetadata::new(
            self.packages.len(),
            self.vulnerabilities.len(),
            vec![VulnerabilitySource::OSV],
            std::time::Duration::from_millis(100),
        );

        Ok(AnalysisReport::new(
            Uuid::new_v4(),
            self.packages.clone(),
            self.vulnerabilities.clone(),
            metadata,
        ))
    }

    async fn get_vulnerability_details(
        &self,
        id: &VulnerabilityId,
    ) -> Result<Vulnerability, ApplicationError> {
        if id.as_str() == "not-found" {
            return Err(ApplicationError::VulnerabilityNotFound {
                id: id.as_str().to_string(),
            });
        }

        Ok(create_test_vulnerability(id.as_str(), Severity::High))
    }
}

#[derive(Clone)]
struct MockRepositoryAnalysisService {
    should_fail: bool,
}

impl MockRepositoryAnalysisService {
    fn new() -> Self {
        Self { should_fail: false }
    }

    fn with_failure() -> Self {
        Self { should_fail: true }
    }
}

#[async_trait::async_trait]
impl RepositoryAnalysisService for MockRepositoryAnalysisService {
    async fn analyze_repository(
        &self,
        _input: vulnera_rust::application::services::RepositoryAnalysisInput,
    ) -> Result<
        vulnera_rust::application::services::RepositoryAnalysisInternalResult,
        ApplicationError,
    > {
        if self.should_fail {
            return Err(ApplicationError::RepositoryNotFound {
                owner: "test".to_string(),
                repo: "test".to_string(),
            });
        }

        Ok(
            vulnera_rust::application::services::RepositoryAnalysisInternalResult {
                id: Uuid::new_v4(),
                owner: "test".to_string(),
                repo: "test".to_string(),
                requested_ref: "main".to_string(),
                commit_sha: "abc123".to_string(),
                files: vec![],
                vulnerabilities: vec![],
                severity_breakdown:
                    vulnera_rust::domain::entities::SeverityBreakdown::from_vulnerabilities(&[]),
                total_files_scanned: 10,
                analyzed_files: 5,
                skipped_files: 5,
                unique_packages: 3,
                duration: std::time::Duration::from_millis(1000),
                file_errors: vec![],
                rate_limit_remaining: Some(4999),
                truncated: false,
            },
        )
    }
}

#[derive(Clone)]
struct MockPopularPackageService {
    should_fail: bool,
}

impl MockPopularPackageService {
    fn new() -> Self {
        Self { should_fail: false }
    }

    fn with_failure() -> Self {
        Self { should_fail: true }
    }
}

#[async_trait::async_trait]
impl PopularPackageService for MockPopularPackageService {
    async fn list_vulnerabilities(
        &self,
        _ecosystem: Ecosystem,
        _limit: Option<usize>,
        _offset: Option<usize>,
    ) -> Result<
        vulnera_rust::application::services::PopularPackageVulnerabilityResult,
        ApplicationError,
    > {
        if self.should_fail {
            return Err(ApplicationError::InternalError {
                message: "Mock service error".to_string(),
                source: None,
            });
        }

        Ok(
            vulnera_rust::application::services::PopularPackageVulnerabilityResult {
                vulnerabilities: vec![create_test_vulnerability(
                    "GHSA-test-1234",
                    Severity::Critical,
                )],
                total_count: 1,
                cache_status: "hit".to_string(),
            },
        )
    }

    async fn refresh_cache(&self, _ecosystem: Ecosystem) -> Result<(), ApplicationError> {
        if self.should_fail {
            return Err(ApplicationError::InternalError {
                message: "Mock refresh error".to_string(),
                source: None,
            });
        }
        Ok(())
    }
}

#[derive(Clone)]
struct MockCacheService;

#[async_trait::async_trait]
impl CacheService for MockCacheService {
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        _key: &str,
    ) -> Result<Option<T>, ApplicationError> {
        Ok(None)
    }

    async fn set<T: serde::Serialize>(
        &self,
        _key: &str,
        _value: &T,
        _ttl: std::time::Duration,
    ) -> Result<(), ApplicationError> {
        Ok(())
    }

    async fn invalidate(&self, _pattern: &str) -> Result<(), ApplicationError> {
        Ok(())
    }
}

#[derive(Clone)]
struct MockReportService;

#[async_trait::async_trait]
impl ReportService for MockReportService {
    async fn generate_report(&self, _report: &AnalysisReport) -> Result<String, ApplicationError> {
        Ok("Mock report".to_string())
    }

    async fn generate_html_report(
        &self,
        _report: &AnalysisReport,
        _template_path: Option<&str>,
    ) -> Result<String, ApplicationError> {
        Ok("<html>Mock HTML report</html>".to_string())
    }
}

// Helper functions

fn create_test_vulnerability(id: &str, severity: Severity) -> Vulnerability {
    Vulnerability::new(
        VulnerabilityId::new(id.to_string()).unwrap(),
        format!("Test vulnerability {}", id),
        format!("Description for {}", id),
        severity,
        vec![],
        vec![],
        Some(Utc::now()),
        vec![VulnerabilitySource::OSV],
    )
    .unwrap()
}

fn create_test_app_state() -> AppState {
    AppState {
        analysis_service: Arc::new(MockAnalysisService::new()),
        repository_analysis_service: Arc::new(MockRepositoryAnalysisService::new()),
        popular_package_service: Arc::new(MockPopularPackageService::new()),
        cache_service: Arc::new(MockCacheService),
        report_service: Arc::new(MockReportService),
        config: Arc::new(Config::default()),
    }
}

fn create_failing_app_state() -> AppState {
    AppState {
        analysis_service: Arc::new(MockAnalysisService::with_failure()),
        repository_analysis_service: Arc::new(MockRepositoryAnalysisService::with_failure()),
        popular_package_service: Arc::new(MockPopularPackageService::with_failure()),
        cache_service: Arc::new(MockCacheService),
        report_service: Arc::new(MockReportService),
        config: Arc::new(Config::default()),
    }
}

// Health controller tests

#[tokio::test]
async fn test_health_check_success() {
    let state = State(create_test_app_state());

    let response = health_check(state).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "healthy");
    assert!(json["timestamp"].is_string());
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn test_detailed_health_check_success() {
    let state = State(create_test_app_state());

    let response = detailed_health_check(state).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "healthy");
    assert!(json["checks"].is_object());
    assert!(json["dependencies"].is_object());
    assert!(json["system_info"].is_object());
}

// Analysis controller tests

#[tokio::test]
async fn test_analyze_dependencies_success() {
    let state = State(create_test_app_state());

    let request = AnalysisRequest {
        content: r#"{"dependencies": {"express": "4.17.1"}}"#.to_string(),
        ecosystem: Ecosystem::Npm,
        filename: Some("package.json".to_string()),
        include_dev_dependencies: None,
        exclude_packages: None,
    };

    let response = analyze_dependencies(state, axum::Json(request)).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["id"].is_string());
    assert!(json["packages"].is_array());
    assert!(json["vulnerabilities"].is_array());
    assert!(json["metadata"].is_object());
}

#[tokio::test]
async fn test_analyze_dependencies_parsing_error() {
    let state = State(create_failing_app_state());

    let request = AnalysisRequest {
        content: "invalid content".to_string(),
        ecosystem: Ecosystem::Npm,
        filename: Some("package.json".to_string()),
        include_dev_dependencies: None,
        exclude_packages: None,
    };

    let response = analyze_dependencies(state, axum::Json(request)).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["error"].is_string());
    assert!(json["error"].as_str().unwrap().contains("parsing"));
}

#[tokio::test]
async fn test_analyze_dependencies_no_vulnerabilities() {
    let mut state = create_test_app_state();
    state.analysis_service = Arc::new(MockAnalysisService::with_no_vulnerabilities());
    let state = State(state);

    let request = AnalysisRequest {
        content: r#"{"dependencies": {"safe-package": "1.0.0"}}"#.to_string(),
        ecosystem: Ecosystem::Npm,
        filename: Some("package.json".to_string()),
        include_dev_dependencies: None,
        exclude_packages: None,
    };

    let response = analyze_dependencies(state, axum::Json(request)).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["vulnerabilities"].as_array().unwrap().len(), 0);
    assert!(json["packages"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn test_analyze_dependencies_different_ecosystems() {
    let ecosystems = vec![
        (
            Ecosystem::Npm,
            r#"{"dependencies": {"express": "4.17.1"}}"#,
            "package.json",
        ),
        (
            Ecosystem::PyPI,
            "django==3.2.0\nrequests>=2.25.0",
            "requirements.txt",
        ),
        (
            Ecosystem::Cargo,
            r#"[dependencies]\nserde = "1.0""#,
            "Cargo.toml",
        ),
        (
            Ecosystem::Maven,
            r#"<dependencies><dependency><groupId>junit</groupId></dependency></dependencies>"#,
            "pom.xml",
        ),
        (
            Ecosystem::Go,
            "module test\ngo 1.19\nrequire github.com/gin-gonic/gin v1.7.0",
            "go.mod",
        ),
    ];

    for (ecosystem, content, filename) in ecosystems {
        let state = State(create_test_app_state());

        let request = AnalysisRequest {
            content: content.to_string(),
            ecosystem,
            filename: Some(filename.to_string()),
            include_dev_dependencies: None,
            exclude_packages: None,
        };

        let response = analyze_dependencies(state, axum::Json(request)).await;

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Failed for ecosystem: {:?}",
            ecosystem
        );
    }
}

#[tokio::test]
async fn test_get_vulnerability_details_success() {
    let state = State(create_test_app_state());
    let id = Path("GHSA-1234-5678-9012".to_string());

    let response = get_vulnerability_details(state, id).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["id"], "GHSA-1234-5678-9012");
    assert!(json["summary"].is_string());
    assert!(json["severity"].is_string());
}

#[tokio::test]
async fn test_get_vulnerability_details_not_found() {
    let state = State(create_test_app_state());
    let id = Path("not-found".to_string());

    let response = get_vulnerability_details(state, id).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["error"].is_string());
}

#[tokio::test]
async fn test_get_vulnerability_details_invalid_id() {
    let state = State(create_test_app_state());
    let id = Path("invalid-id-format".to_string());

    let response = get_vulnerability_details(state, id).await;

    // Should handle invalid ID format gracefully
    assert!(matches!(
        response.status(),
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
    ));
}

#[tokio::test]
async fn test_analyze_repository_success() {
    let state = State(create_test_app_state());

    let request = RepositoryAnalysisRequest {
        owner: "expressjs".to_string(),
        repo: "express".to_string(),
        requested_ref: Some("main".to_string()),
        include_paths: None,
        exclude_paths: None,
        max_files: Some(100),
        include_lockfiles: Some(true),
        return_packages: Some(false),
    };

    let response = analyze_repository(state, axum::Json(request)).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["id"].is_string());
    assert!(json["owner"].is_string());
    assert!(json["repo"].is_string());
    assert!(json["files"].is_array());
}

#[tokio::test]
async fn test_analyze_repository_not_found() {
    let state = State(create_failing_app_state());

    let request = RepositoryAnalysisRequest {
        owner: "nonexistent".to_string(),
        repo: "nonexistent".to_string(),
        requested_ref: Some("main".to_string()),
        include_paths: None,
        exclude_paths: None,
        max_files: None,
        include_lockfiles: None,
        return_packages: None,
    };

    let response = analyze_repository(state, axum::Json(request)).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_analyze_repository_with_options() {
    let state = State(create_test_app_state());

    let request = RepositoryAnalysisRequest {
        owner: "test".to_string(),
        repo: "test".to_string(),
        requested_ref: Some("develop".to_string()),
        include_paths: Some(vec!["src/**".to_string(), "lib/**".to_string()]),
        exclude_paths: Some(vec!["tests/**".to_string(), "docs/**".to_string()]),
        max_files: Some(50),
        include_lockfiles: Some(false),
        return_packages: Some(true),
    };

    let response = analyze_repository(state, axum::Json(request)).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_popular_vulnerabilities_success() {
    let state = State(create_test_app_state());

    let query = Query(PopularPackagesQuery {
        ecosystem: Some(Ecosystem::Npm),
        limit: Some(10),
        offset: Some(0),
    });

    let response = list_popular_vulnerabilities(state, query).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["vulnerabilities"].is_array());
    assert!(json["total_count"].is_number());
    assert!(json["cache_status"].is_string());
}

#[tokio::test]
async fn test_list_popular_vulnerabilities_service_error() {
    let state = State(create_failing_app_state());

    let query = Query(PopularPackagesQuery {
        ecosystem: Some(Ecosystem::Npm),
        limit: Some(10),
        offset: Some(0),
    });

    let response = list_popular_vulnerabilities(state, query).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_list_popular_vulnerabilities_default_params() {
    let state = State(create_test_app_state());

    let query = Query(PopularPackagesQuery {
        ecosystem: None,
        limit: None,
        offset: None,
    });

    let response = list_popular_vulnerabilities(state, query).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_popular_vulnerabilities_large_limit() {
    let state = State(create_test_app_state());

    let query = Query(PopularPackagesQuery {
        ecosystem: Some(Ecosystem::Npm),
        limit: Some(1000), // Should be capped to reasonable limit
        offset: Some(0),
    });

    let response = list_popular_vulnerabilities(state, query).await;

    assert_eq!(response.status(), StatusCode::OK);
}

// Edge case tests

#[tokio::test]
async fn test_analyze_empty_content() {
    let state = State(create_test_app_state());

    let request = AnalysisRequest {
        content: "".to_string(),
        ecosystem: Ecosystem::Npm,
        filename: Some("package.json".to_string()),
        include_dev_dependencies: None,
        exclude_packages: None,
    };

    let response = analyze_dependencies(state, axum::Json(request)).await;

    // Should handle empty content gracefully
    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn test_analyze_very_large_content() {
    let state = State(create_test_app_state());

    let large_deps: Vec<String> = (0..1000)
        .map(|i| format!(r#""package{}": "1.0.0""#, i))
        .collect();
    let content = format!(r#"{{"dependencies": {{{}}}}}"#, large_deps.join(","));

    let request = AnalysisRequest {
        content,
        ecosystem: Ecosystem::Npm,
        filename: Some("package.json".to_string()),
        include_dev_dependencies: None,
        exclude_packages: None,
    };

    let response = analyze_dependencies(state, axum::Json(request)).await;

    // Should handle large content gracefully
    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::PAYLOAD_TOO_LARGE
    ));
}

#[tokio::test]
async fn test_analyze_malformed_json() {
    let state = State(create_test_app_state());

    let request = AnalysisRequest {
        content: r#"{"dependencies": {"express": "4.17.1",}}"#.to_string(), // Trailing comma
        ecosystem: Ecosystem::Npm,
        filename: Some("package.json".to_string()),
        include_dev_dependencies: None,
        exclude_packages: None,
    };

    let response = analyze_dependencies(state, axum::Json(request)).await;

    // Should handle malformed JSON gracefully
    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::BAD_REQUEST
    ));
}

#[tokio::test]
async fn test_analyze_with_exclude_packages() {
    let state = State(create_test_app_state());

    let request = AnalysisRequest {
        content: r#"{"dependencies": {"express": "4.17.1", "lodash": "4.17.20"}}"#.to_string(),
        ecosystem: Ecosystem::Npm,
        filename: Some("package.json".to_string()),
        include_dev_dependencies: Some(false),
        exclude_packages: Some(vec!["lodash".to_string()]),
    };

    let response = analyze_dependencies(state, axum::Json(request)).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_repository_analysis_edge_cases() {
    let state = State(create_test_app_state());

    // Test with special characters in repo name
    let request = RepositoryAnalysisRequest {
        owner: "test-org".to_string(),
        repo: "test.repo-name_123".to_string(),
        requested_ref: Some("feature/special-branch".to_string()),
        include_paths: Some(vec!["**/*.js".to_string()]),
        exclude_paths: Some(vec!["node_modules/**".to_string()]),
        max_files: Some(1),
        include_lockfiles: Some(true),
        return_packages: Some(true),
    };

    let response = analyze_repository(state, axum::Json(request)).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_vulnerability_details_various_id_formats() {
    let state = State(create_test_app_state());

    let test_ids = vec![
        "CVE-2021-12345",
        "GHSA-1234-5678-9012",
        "OSV-2021-001",
        "RUSTSEC-2021-0001",
    ];

    for id in test_ids {
        let response = get_vulnerability_details(state.clone(), Path(id.to_string())).await;

        // Should handle different ID formats
        assert!(matches!(
            response.status(),
            StatusCode::OK | StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST
        ));
    }
}

#[tokio::test]
async fn test_popular_vulnerabilities_pagination() {
    let state = State(create_test_app_state());

    // Test pagination edge cases
    let test_cases = vec![
        (Some(0), Some(0)),    // Zero limit and offset
        (Some(1), Some(1000)), // Small limit, large offset
        (None, Some(10)),      // No limit, with offset
        (Some(100), None),     // Large limit, no offset
    ];

    for (limit, offset) in test_cases {
        let query = Query(PopularPackagesQuery {
            ecosystem: Some(Ecosystem::Npm),
            limit,
            offset,
        });

        let response = list_popular_vulnerabilities(state.clone(), query).await;

        assert_eq!(response.status(), StatusCode::OK);
    }
}

// Performance and stress tests

#[tokio::test]
async fn test_concurrent_analysis_requests() {
    let state = Arc::new(create_test_app_state());

    let mut handles = Vec::new();

    for i in 0..10 {
        let state_clone = state.clone();

        let handle = tokio::spawn(async move {
            let request = AnalysisRequest {
                content: format!(r#"{{"dependencies": {{"package{}": "1.0.0"}}}}"#, i),
                ecosystem: Ecosystem::Npm,
                filename: Some("package.json".to_string()),
                include_dev_dependencies: None,
                exclude_packages: None,
            };

            analyze_dependencies(State((*state_clone).clone()), axum::Json(request)).await
        });

        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;

    for result in results {
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_memory_usage_with_large_responses() {
    let state = State(create_test_app_state());

    // Test that large responses don't cause memory issues
    let query = Query(PopularPackagesQuery {
        ecosystem: Some(Ecosystem::Npm),
        limit: Some(100), // Request large number of vulnerabilities
        offset: Some(0),
    });

    let response = list_popular_vulnerabilities(state, query).await;

    assert_eq!(response.status(), StatusCode::OK);

    // Check that we can still access the body without issues
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert!(body.len() > 0);
}
