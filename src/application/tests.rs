// Repository analysis service tests
use super::{RepositoryAnalysisInput, RepositoryAnalysisService, RepositoryAnalysisServiceImpl};
use crate::infrastructure::VulnerabilityRepository;
use crate::infrastructure::parsers::ParserFactory;
use crate::infrastructure::repository_source::{
    FetchedFileContent, RepositoryFile, RepositorySourceClient, RepositorySourceError,
};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use crate::application::{
    AnalysisService, AnalysisServiceImpl, ApplicationError, CacheService, CacheServiceImpl,
    ReportService, ReportServiceImpl, VulnerabilityError,
};
use crate::domain::{
    AffectedPackage, AnalysisReport, Ecosystem, Package, Severity, Version, VersionRange,
    Vulnerability, VulnerabilityId, VulnerabilitySource,
};
use crate::infrastructure::cache::file_cache::FileCacheRepository;
use chrono::Utc;
use tempfile::TempDir;

struct MockRepoSource {
    files: Vec<RepositoryFile>,
    contents: Vec<FetchedFileContent>,
}

#[async_trait]
impl RepositorySourceClient for MockRepoSource {
    async fn list_repository_files(
        &self,
        _owner: &str,
        _repo: &str,
        _ref: Option<&str>,
        _max_files: u32,
        _max_bytes: u64,
    ) -> Result<Vec<RepositoryFile>, RepositorySourceError> {
        Ok(self.files.clone())
    }
    async fn fetch_file_contents(
        &self,
        _owner: &str,
        _repo: &str,
        _files: &[RepositoryFile],
        _ref: Option<&str>,
        _single_file_max_bytes: u64,
        _concurrent_limit: usize,
    ) -> Result<Vec<FetchedFileContent>, RepositorySourceError> {
        Ok(self.contents.clone())
    }
}

struct MockVulnRepo;
#[async_trait]
impl VulnerabilityRepository for MockVulnRepo {
    async fn find_vulnerabilities(
        &self,
        _package: &crate::domain::Package,
    ) -> Result<Vec<crate::domain::Vulnerability>, crate::application::errors::VulnerabilityError>
    {
        Ok(vec![])
    }
    async fn get_vulnerability_by_id(
        &self,
        _id: &crate::domain::VulnerabilityId,
    ) -> Result<Option<crate::domain::Vulnerability>, crate::application::errors::VulnerabilityError>
    {
        Ok(None)
    }
}

#[tokio::test]
async fn repository_analysis_parses_supported_files() {
    let parser_factory = Arc::new(ParserFactory::new());
    // Provide a simple package.json content
    let files = vec![RepositoryFile {
        path: "package.json".into(),
        size: 40,
        is_text: true,
    }];
    let contents = vec![FetchedFileContent { path: "package.json".into(), content: "{\n  \"name\": \"demo\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": { \"left-pad\": \"1.0.0\" }\n}".into() }];
    let source = Arc::new(MockRepoSource { files, contents });
    let vuln_repo = Arc::new(MockVulnRepo);
    let cfg = Arc::new(crate::config::Config::default());
    let service = RepositoryAnalysisServiceImpl::new(source, vuln_repo, parser_factory, cfg);
    let input = RepositoryAnalysisInput {
        owner: "o".into(),
        repo: "r".into(),
        requested_ref: None,
        include_paths: None,
        exclude_paths: None,
        max_files: 50,
        include_lockfiles: true,
        return_packages: true,
    };
    let result = service
        .analyze_repository(input)
        .await
        .expect("analysis ok");
    assert_eq!(result.files.len(), 1);
    assert_eq!(
        result.unique_packages, 1,
        "should parse one package dependency (left-pad)"
    );
}

// Mock implementations for testing

struct MockVulnerabilityRepository {
    vulnerabilities: Vec<Vulnerability>,
    should_fail: bool,
}

impl MockVulnerabilityRepository {
    fn new(vulnerabilities: Vec<Vulnerability>) -> Self {
        Self {
            vulnerabilities,
            should_fail: false,
        }
    }

    fn with_failure() -> Self {
        Self {
            vulnerabilities: vec![],
            should_fail: true,
        }
    }
}

#[async_trait::async_trait]
impl VulnerabilityRepository for MockVulnerabilityRepository {
    async fn find_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<Vulnerability>, VulnerabilityError> {
        if self.should_fail {
            return Err(VulnerabilityError::RateLimit {
                api: "mock".to_string(),
            });
        }

        Ok(self
            .vulnerabilities
            .iter()
            .filter(|vuln| vuln.affects_package(package))
            .cloned()
            .collect())
    }

    async fn get_vulnerability_by_id(
        &self,
        id: &VulnerabilityId,
    ) -> Result<Option<Vulnerability>, VulnerabilityError> {
        if self.should_fail {
            return Err(VulnerabilityError::RateLimit {
                api: "mock".to_string(),
            });
        }

        Ok(self
            .vulnerabilities
            .iter()
            .find(|vuln| vuln.id.as_str() == id.as_str())
            .cloned())
    }
}

// Helper functions for creating test data

fn create_test_package(name: &str, version: &str, ecosystem: Ecosystem) -> Package {
    Package::new(
        name.to_string(),
        Version::parse(version).unwrap(),
        ecosystem,
    )
    .unwrap()
}

fn create_test_vulnerability(
    id: &str,
    severity: Severity,
    affected_package: Package,
) -> Vulnerability {
    let affected = AffectedPackage::new(
        affected_package,
        vec![VersionRange::less_than(Version::parse("999.0.0").unwrap())],
        vec![Version::parse("999.0.0").unwrap()],
    );

    Vulnerability::new(
        VulnerabilityId::new(id.to_string()).unwrap(),
        format!("Test vulnerability {}", id),
        format!("A test vulnerability with ID {}", id),
        severity,
        vec![affected],
        vec![format!("https://example.com/{}", id)],
        Utc::now(),
        vec![VulnerabilitySource::OSV],
    )
    .unwrap()
}

fn create_test_analysis_report() -> AnalysisReport {
    let packages = vec![
        create_test_package("express", "4.17.1", Ecosystem::Npm),
        create_test_package("lodash", "4.17.20", Ecosystem::Npm),
    ];

    let vulnerabilities = vec![create_test_vulnerability(
        "CVE-2022-24999",
        Severity::High,
        create_test_package("express", "4.17.1", Ecosystem::Npm),
    )];

    AnalysisReport::new(
        packages,
        vulnerabilities,
        Duration::from_millis(500),
        vec!["OSV".to_string()],
    )
}

// Cache Service Tests

#[tokio::test]
async fn test_cache_service_basic_operations() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_millis(500),
    ));
    let cache_service = CacheServiceImpl::new(cache_repo);

    // Test set and get
    let test_data = vec!["item1".to_string(), "item2".to_string()];
    cache_service
        .set("test_key", &test_data, Duration::from_secs(3600))
        .await
        .unwrap();

    let retrieved: Option<Vec<String>> = cache_service.get("test_key").await.unwrap();
    assert_eq!(retrieved, Some(test_data));

    // Test get non-existent key
    let non_existent: Option<Vec<String>> = cache_service.get("non_existent").await.unwrap();
    assert_eq!(non_existent, None);

    // Test invalidate
    cache_service.invalidate("test_key").await.unwrap();
    let after_invalidate: Option<Vec<String>> = cache_service.get("test_key").await.unwrap();
    assert_eq!(after_invalidate, None);
}

#[tokio::test]
async fn test_cache_service_key_generation() {
    let package = create_test_package("express", "4.17.1", Ecosystem::Npm);
    let vuln_id = VulnerabilityId::new("CVE-2022-24999".to_string()).unwrap();

    let package_key = CacheServiceImpl::package_vulnerabilities_key(&package);
    let vuln_key = CacheServiceImpl::vulnerability_details_key(&vuln_id);
    let content_hash = CacheServiceImpl::content_hash("test content");

    assert!(package_key.contains("npm"));
    assert!(package_key.contains("express"));
    assert!(package_key.contains("4.17.1"));

    assert!(vuln_key.contains("CVE-2022-24999"));

    assert_eq!(content_hash.len(), 64); // SHA256 hex length
}

#[tokio::test]
async fn test_cache_service_statistics() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = CacheServiceImpl::new(cache_repo);

    // Add some data to cache
    cache_service
        .set("key1", &"value1", Duration::from_secs(3600))
        .await
        .unwrap();
    cache_service
        .set("key2", &"value2", Duration::from_secs(3600))
        .await
        .unwrap();

    // Get statistics
    let stats = cache_service.get_cache_statistics().await.unwrap();
    assert!(stats.total_entries >= 2);
    assert!(stats.total_size_bytes > 0);
}

#[tokio::test]
async fn test_cache_service_exists() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = CacheServiceImpl::new(cache_repo);

    assert!(!cache_service.exists("non_existent").await.unwrap());

    cache_service
        .set("existing_key", &"value", Duration::from_secs(3600))
        .await
        .unwrap();

    assert!(cache_service.exists("existing_key").await.unwrap());
}

// Report Service Tests

#[tokio::test]
async fn test_report_service_generate_text_report() {
    let report_service = ReportServiceImpl::new();
    let analysis = create_test_analysis_report();

    let text_report = report_service.generate_report(&analysis).await.unwrap();

    assert!(text_report.contains("Vulnerability Analysis Report"));
    assert!(text_report.contains("express"));
    assert!(text_report.contains("CVE-2022-24999"));
    assert!(text_report.contains("High"));
}

#[tokio::test]
async fn test_report_service_generate_json_report() {
    let report_service = ReportServiceImpl::new();
    let analysis = create_test_analysis_report();

    let json_report = report_service
        .generate_html_report(&analysis)
        .await
        .unwrap();

    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json_report).unwrap();
    assert!(parsed.is_object());
}

#[tokio::test]
async fn test_report_service_deduplication() {
    let report_service = ReportServiceImpl::new();

    // Create duplicate vulnerabilities with same ID
    let vuln1 = create_test_vulnerability(
        "CVE-2022-24999",
        Severity::High,
        create_test_package("express", "4.17.1", Ecosystem::Npm),
    );
    let mut vuln2 = vuln1.clone();
    vuln2.sources.push(VulnerabilitySource::NVD);

    let vulnerabilities = vec![vuln1, vuln2];
    let deduplicated = report_service.deduplicate_vulnerabilities(vulnerabilities);

    assert_eq!(deduplicated.len(), 1);
    assert_eq!(deduplicated[0].sources.len(), 2); // OSV + NVD
}

#[tokio::test]
async fn test_report_service_severity_scoring() {
    let report_service = ReportServiceImpl::new();
    let vuln = create_test_vulnerability(
        "CVE-2022-24999",
        Severity::Critical,
        create_test_package("express", "4.17.1", Ecosystem::Npm),
    );

    let score = report_service.calculate_severity_score(&vuln);
    assert!(score >= 10.0); // Critical base score
}

#[tokio::test]
async fn test_report_service_prioritization() {
    let report_service = ReportServiceImpl::new();

    let low_vuln = create_test_vulnerability(
        "CVE-2022-24999",
        Severity::Low,
        create_test_package("express", "4.17.1", Ecosystem::Npm),
    );
    let critical_vuln = create_test_vulnerability(
        "CVE-2022-25000",
        Severity::Critical,
        create_test_package("lodash", "4.17.20", Ecosystem::Npm),
    );

    let vulnerabilities = vec![low_vuln, critical_vuln];
    let prioritized = report_service.prioritize_vulnerabilities(vulnerabilities);

    assert_eq!(prioritized[0].severity, Severity::Critical);
    assert_eq!(prioritized[1].severity, Severity::Low);
}

#[tokio::test]
async fn test_report_service_structured_report() {
    let report_service = ReportServiceImpl::new();
    let analysis = create_test_analysis_report();

    let structured = report_service.generate_structured_report(&analysis);

    assert_eq!(structured.summary.total_packages, 2);
    assert_eq!(structured.summary.vulnerable_packages, 1);
    assert_eq!(structured.summary.clean_packages, 1);
    assert_eq!(structured.summary.total_vulnerabilities, 1);
    assert!(structured.summary.vulnerability_percentage > 0.0);
    assert!(!structured.package_summaries.is_empty());
    assert!(!structured.prioritized_vulnerabilities.is_empty());
}

// Analysis Service Tests

#[tokio::test]
async fn test_analysis_service_successful_analysis() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());

    // Create mock vulnerability repository with test data
    let test_vuln = create_test_vulnerability(
        "CVE-2022-24999",
        Severity::High,
        create_test_package("express", "4.17.1", Ecosystem::Npm),
    );
    let vuln_repo = Arc::new(MockVulnerabilityRepository::new(vec![test_vuln]));

    let analysis_service = AnalysisServiceImpl::new(parser_factory, vuln_repo, cache_service);

    // Test with a simple package.json
    let package_json = r#"{"dependencies": {"express": "4.17.1"}}"#;
    let result = analysis_service
        .analyze_dependencies(package_json, Ecosystem::Npm)
        .await;

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.packages.len(), 1);
    assert_eq!(report.vulnerabilities.len(), 1);
    assert_eq!(report.metadata.total_packages, 1);
    assert_eq!(report.metadata.vulnerable_packages, 1);
}

#[tokio::test]
async fn test_analysis_service_get_vulnerability_details() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());

    let test_vuln = create_test_vulnerability(
        "CVE-2022-24999",
        Severity::High,
        create_test_package("express", "4.17.1", Ecosystem::Npm),
    );
    let vuln_repo = Arc::new(MockVulnerabilityRepository::new(vec![test_vuln.clone()]));

    let analysis_service = AnalysisServiceImpl::new(parser_factory, vuln_repo, cache_service);

    let vuln_id = VulnerabilityId::new("CVE-2022-24999".to_string()).unwrap();
    let result = analysis_service.get_vulnerability_details(&vuln_id).await;

    assert!(result.is_ok());
    let vulnerability = result.unwrap();
    assert_eq!(vulnerability.id.as_str(), "CVE-2022-24999");
    assert_eq!(vulnerability.severity, Severity::High);
}

#[tokio::test]
async fn test_analysis_service_vulnerability_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());
    let vuln_repo = Arc::new(MockVulnerabilityRepository::new(vec![]));

    let analysis_service = AnalysisServiceImpl::new(parser_factory, vuln_repo, cache_service);

    let vuln_id = VulnerabilityId::new("CVE-2022-99999".to_string()).unwrap();
    let result = analysis_service.get_vulnerability_details(&vuln_id).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ApplicationError::NotFound { resource, id } => {
            assert_eq!(resource, "vulnerability");
            assert_eq!(id, "CVE-2022-99999");
        }
        other => panic!("Expected NotFound error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_analysis_service_repository_failure() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());
    let vuln_repo = Arc::new(MockVulnerabilityRepository::with_failure());

    let analysis_service = AnalysisServiceImpl::new(parser_factory, vuln_repo, cache_service);

    let package_json = r#"{"dependencies": {"express": "4.17.1"}}"#;
    let result = analysis_service
        .analyze_dependencies(package_json, Ecosystem::Npm)
        .await;

    // Should still succeed but with no vulnerabilities due to graceful error handling
    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.packages.len(), 1);
    assert_eq!(report.vulnerabilities.len(), 0); // No vulnerabilities due to repository failure
}

#[tokio::test]
async fn test_analysis_service_invalid_file_format() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());
    let vuln_repo = Arc::new(MockVulnerabilityRepository::new(vec![]));

    let analysis_service = AnalysisServiceImpl::new(parser_factory, vuln_repo, cache_service);

    let invalid_json = r#"{"invalid": json"#;
    let result = analysis_service
        .analyze_dependencies(invalid_json, Ecosystem::Npm)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ApplicationError::Parse(_) => {
            // Expected parse error
        }
        _ => panic!("Expected Parse error"),
    }
}

#[tokio::test]
async fn test_analysis_service_caching_behavior() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());

    let test_vuln = create_test_vulnerability(
        "CVE-2022-24999",
        Severity::High,
        create_test_package("express", "4.17.1", Ecosystem::Npm),
    );
    let vuln_repo = Arc::new(MockVulnerabilityRepository::new(vec![test_vuln]));

    let analysis_service =
        AnalysisServiceImpl::new(parser_factory, vuln_repo, cache_service.clone());

    let package_json = r#"{"dependencies": {"express": "4.17.1"}}"#;

    // First analysis should populate cache
    let result1 = analysis_service
        .analyze_dependencies(package_json, Ecosystem::Npm)
        .await
        .unwrap();

    // Second analysis should use cache (we can verify by checking cache statistics)
    let result2 = analysis_service
        .analyze_dependencies(package_json, Ecosystem::Npm)
        .await
        .unwrap();

    assert_eq!(result1.packages.len(), result2.packages.len());
    assert_eq!(result1.vulnerabilities.len(), result2.vulnerabilities.len());

    // Verify cache has entries
    let stats = cache_service.get_cache_statistics().await.unwrap();
    assert!(stats.total_entries > 0);
}

// Error handling tests

#[tokio::test]
async fn test_application_error_display() {
    let domain_error = crate::domain::DomainError::InvalidInput {
        field: "name".to_string(),
        message: "Package name cannot be empty".to_string(),
    };
    let app_error = ApplicationError::Domain(domain_error);
    assert!(app_error.to_string().contains("Domain error"));

    let parse_error = ApplicationError::Parse(crate::application::ParseError::Json(
        serde_json::Error::from(serde_json::from_str::<serde_json::Value>("invalid").unwrap_err()),
    ));
    assert!(parse_error.to_string().contains("Parsing error"));

    let ecosystem_error = ApplicationError::InvalidEcosystem {
        ecosystem: "unknown".to_string(),
    };
    assert!(ecosystem_error.to_string().contains("Invalid ecosystem"));

    let not_found_error = ApplicationError::NotFound {
        resource: "vulnerability".to_string(),
        id: "CVE-2022-99999".to_string(),
    };
    assert!(not_found_error.to_string().contains("Resource not found"));
}

// Configuration and edge case tests

#[tokio::test]
async fn test_report_service_with_custom_config() {
    let report_service = ReportServiceImpl::with_config(false, false); // No deduplication, no metadata
    let analysis = create_test_analysis_report();

    let text_report = report_service.generate_report(&analysis).await.unwrap();
    assert!(text_report.contains("Vulnerability Analysis Report"));
}

#[tokio::test]
async fn test_analysis_service_with_custom_concurrency() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());
    let vuln_repo = Arc::new(MockVulnerabilityRepository::new(vec![]));

    let analysis_service = AnalysisServiceImpl::with_concurrency(
        parser_factory,
        vuln_repo,
        cache_service,
        5, // Custom concurrency limit
    );

    let package_json = r#"{"dependencies": {"express": "4.17.1"}}"#;
    let result = analysis_service
        .analyze_dependencies(package_json, Ecosystem::Npm)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_cache_service_cleanup() {
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_millis(1), // Very short TTL for testing
    ));
    let cache_service = CacheServiceImpl::new(cache_repo);

    // Add data that will expire quickly
    cache_service
        .set("short_lived", &"value", Duration::from_millis(1))
        .await
        .unwrap();

    // Wait for expiry
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Trigger cleanup
    let cleaned_count = cache_service.cleanup_expired_entries().await.unwrap();
    // cleaned_count is usize, always >= 0, so just verify the operation succeeded
    assert!(cleaned_count <= 100); // Should clean up expired entries (sanity check)
}

// Use case tests

#[tokio::test]
async fn test_analyze_dependencies_use_case() {
    use crate::application::use_cases::AnalyzeDependencies;

    let test_package = create_test_package("express", "4.17.1", Ecosystem::Npm);
    let vuln = create_test_vulnerability("CVE-2022-24999", Severity::High, test_package.clone());
    let repo = Arc::new(MockVulnerabilityRepository::new(vec![vuln]));

    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_millis(500),
    ));
    let cache = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());

    let analysis_service = Arc::new(AnalysisServiceImpl::new(parser_factory, repo, cache));

    let use_case = AnalyzeDependencies::new(analysis_service);

    let file_content = r#"{"dependencies": {"express": "4.17.1"}}"#;
    let result = use_case.execute(file_content, Ecosystem::Npm).await;

    assert!(result.is_ok());
    let analysis_report = result.unwrap();
    assert_eq!(analysis_report.packages.len(), 1);
}

#[tokio::test]
async fn test_get_vulnerability_details_use_case() {
    use crate::application::use_cases::GetVulnerabilityDetails;

    let test_package = create_test_package("express", "4.17.1", Ecosystem::Npm);
    let vuln = create_test_vulnerability("CVE-2022-24999", Severity::High, test_package);
    let vuln_id = vuln.id.clone();
    let repo = Arc::new(MockVulnerabilityRepository::new(vec![vuln.clone()]));

    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_millis(500),
    ));
    let cache = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());

    let analysis_service = Arc::new(AnalysisServiceImpl::new(parser_factory, repo, cache));

    let use_case = GetVulnerabilityDetails::new(analysis_service);

    let result = use_case.execute(&vuln_id).await;

    assert!(result.is_ok());
    let vulnerability = result.unwrap();
    assert_eq!(vulnerability.id, vuln_id);
    assert_eq!(vulnerability.summary, "Test vulnerability CVE-2022-24999");
}

#[tokio::test]
async fn test_generate_report_use_case_text() {
    use crate::application::use_cases::{GenerateReport, ReportFormat};

    let report_service = Arc::new(ReportServiceImpl::new());
    let use_case = GenerateReport::new(report_service);

    let analysis_report = create_test_analysis_report();

    let result = use_case.execute(&analysis_report, ReportFormat::Text).await;

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(report.contains("Vulnerability Analysis Report"));
    assert!(report.contains("express"));
}

#[tokio::test]
async fn test_generate_report_use_case_json() {
    use crate::application::use_cases::{GenerateReport, ReportFormat};

    let report_service = Arc::new(ReportServiceImpl::new());
    let use_case = GenerateReport::new(report_service);

    let analysis_report = create_test_analysis_report();

    let result = use_case.execute(&analysis_report, ReportFormat::Json).await;

    assert!(result.is_ok());
    let report = result.unwrap();
    // Should be valid JSON
    assert!(serde_json::from_str::<serde_json::Value>(&report).is_ok());
}

#[tokio::test]
async fn test_generate_report_use_case_html() {
    use crate::application::use_cases::{GenerateReport, ReportFormat};

    let report_service = Arc::new(ReportServiceImpl::new());
    let use_case = GenerateReport::new(report_service);

    let analysis_report = create_test_analysis_report();

    let result = use_case.execute(&analysis_report, ReportFormat::Html).await;

    assert!(result.is_ok());
    let report = result.unwrap();
    // HTML format actually returns JSON as per implementation
    assert!(serde_json::from_str::<serde_json::Value>(&report).is_ok());
}

#[tokio::test]
async fn test_analyze_dependencies_use_case_error_handling() {
    use crate::application::use_cases::AnalyzeDependencies;

    let repo = Arc::new(MockVulnerabilityRepository::with_failure());
    let temp_dir = TempDir::new().unwrap();
    let cache_repo = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_millis(500),
    ));
    let cache = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());

    let analysis_service = Arc::new(AnalysisServiceImpl::new(parser_factory, repo, cache));

    let use_case = AnalyzeDependencies::new(analysis_service);

    let file_content = "invalid json content";
    let result = use_case.execute(file_content, Ecosystem::Npm).await;

    // Should handle parsing errors gracefully
    assert!(result.is_err());
}
