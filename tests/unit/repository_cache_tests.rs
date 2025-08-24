//! Comprehensive repository and cache tests
//! Tests repository patterns, caching behavior, and data persistence

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;
use uuid::Uuid;
use vulnera_rust::application::errors::ApplicationError;
use vulnera_rust::application::services::{CacheService, CacheStatistics};
use vulnera_rust::domain::entities::{Package, Vulnerability};
use vulnera_rust::domain::value_objects::{
    Ecosystem, Severity, Version, VulnerabilityId, VulnerabilitySource,
};
use vulnera_rust::infrastructure::api_clients::traits::VulnerabilityApiClient;
use vulnera_rust::infrastructure::cache::file_cache::FileCacheRepository;
use vulnera_rust::infrastructure::repositories::{
    AggregatingVulnerabilityRepository, VulnerabilityRepository,
};

// Mock implementations for testing

#[derive(Clone)]
struct MockVulnerabilityClient {
    vulnerabilities: Vec<Vulnerability>,
    should_fail: bool,
    delay: Option<Duration>,
}

impl MockVulnerabilityClient {
    fn new(vulnerabilities: Vec<Vulnerability>) -> Self {
        Self {
            vulnerabilities,
            should_fail: false,
            delay: None,
        }
    }

    fn with_failure() -> Self {
        Self {
            vulnerabilities: vec![],
            should_fail: true,
            delay: None,
        }
    }

    fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

#[async_trait::async_trait]
impl VulnerabilityApiClient for MockVulnerabilityClient {
    async fn find_vulnerabilities(
        &self,
        packages: &[Package],
    ) -> Result<Vec<Vulnerability>, ApplicationError> {
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }

        if self.should_fail {
            return Err(ApplicationError::NetworkError {
                message: "Mock network error".to_string(),
                source: None,
            });
        }

        // Return vulnerabilities that match the requested packages
        let matching_vulns: Vec<Vulnerability> = self
            .vulnerabilities
            .iter()
            .filter(|vuln| {
                packages.iter().any(|pkg| {
                    vuln.affected_packages.iter().any(|affected| {
                        affected.package.name == pkg.name
                            && affected.package.ecosystem == pkg.ecosystem
                    })
                })
            })
            .cloned()
            .collect();

        Ok(matching_vulns)
    }

    async fn get_vulnerability_by_id(
        &self,
        id: &VulnerabilityId,
    ) -> Result<Option<Vulnerability>, ApplicationError> {
        if self.should_fail {
            return Err(ApplicationError::NetworkError {
                message: "Mock network error".to_string(),
                source: None,
            });
        }

        let vuln = self.vulnerabilities.iter().find(|v| v.id == *id).cloned();

        Ok(vuln)
    }
}

// Helper functions

fn create_test_vulnerability(id: &str, package_name: &str, ecosystem: Ecosystem) -> Vulnerability {
    let package = Package::new(
        package_name.to_string(),
        Version::parse("1.0.0").unwrap(),
        ecosystem,
    )
    .unwrap();

    let affected_package =
        vulnera_rust::domain::entities::AffectedPackage::new(package, vec![], vec![]);

    Vulnerability::new(
        VulnerabilityId::new(id.to_string()).unwrap(),
        format!("Test vulnerability for {}", package_name),
        format!("Description for vulnerability {}", id),
        Severity::High,
        vec![affected_package],
        vec![],
        Some(Utc::now()),
        vec![VulnerabilitySource::OSV],
    )
    .unwrap()
}

fn create_test_package(name: &str, version: &str, ecosystem: Ecosystem) -> Package {
    Package::new(
        name.to_string(),
        Version::parse(version).unwrap(),
        ecosystem,
    )
    .unwrap()
}

// File Cache Repository Tests

#[tokio::test]
async fn test_file_cache_basic_operations() {
    let temp_dir = TempDir::new().unwrap();
    let cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());

    let key = "test_key";
    let value = serde_json::json!({
        "test": "data",
        "number": 42
    });

    // Test set operation
    let result = cache.set(key, &value, Duration::from_secs(3600)).await;
    assert!(result.is_ok());

    // Test get operation
    let retrieved: Option<serde_json::Value> = cache.get(key).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), value);

    // Test non-existent key
    let non_existent: Option<serde_json::Value> = cache.get("non_existent").await.unwrap();
    assert!(non_existent.is_none());
}

#[tokio::test]
async fn test_file_cache_ttl_expiration() {
    let temp_dir = TempDir::new().unwrap();
    let cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());

    let key = "ttl_test";
    let value = serde_json::json!({"data": "expires_soon"});

    // Set with short TTL
    cache
        .set(key, &value, Duration::from_millis(100))
        .await
        .unwrap();

    // Should be available immediately
    let retrieved: Option<serde_json::Value> = cache.get(key).await.unwrap();
    assert!(retrieved.is_some());

    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Should be expired
    let expired: Option<serde_json::Value> = cache.get(key).await.unwrap();
    assert!(expired.is_none());
}

#[tokio::test]
async fn test_file_cache_concurrent_access() {
    let temp_dir = TempDir::new().unwrap();
    let cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_string_lossy().to_string(),
    ));

    let mut handles = Vec::new();

    // Spawn multiple tasks to write and read concurrently
    for i in 0..10 {
        let cache_clone = cache.clone();
        let handle = tokio::spawn(async move {
            let key = format!("concurrent_key_{}", i);
            let value = serde_json::json!({"id": i, "data": format!("test_data_{}", i)});

            // Write
            cache_clone
                .set(&key, &value, Duration::from_secs(3600))
                .await
                .unwrap();

            // Read back
            let retrieved: Option<serde_json::Value> = cache_clone.get(&key).await.unwrap();
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap()["id"], i);
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    futures::future::join_all(handles).await;
}

#[tokio::test]
async fn test_file_cache_large_values() {
    let temp_dir = TempDir::new().unwrap();
    let cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());

    // Create a large value (1MB of data)
    let large_data = "x".repeat(1_000_000);
    let large_value = serde_json::json!({
        "large_field": large_data,
        "metadata": {"size": "1MB"}
    });

    let key = "large_value_test";

    // Should handle large values
    let result = cache
        .set(key, &large_value, Duration::from_secs(3600))
        .await;
    assert!(result.is_ok());

    let retrieved: Option<serde_json::Value> = cache.get(key).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(
        retrieved.unwrap()["large_field"].as_str().unwrap().len(),
        1_000_000
    );
}

#[tokio::test]
async fn test_file_cache_special_characters_in_keys() {
    let temp_dir = TempDir::new().unwrap();
    let cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());

    let special_keys = vec![
        "key/with/slashes",
        "key:with:colons",
        "key@with@symbols",
        "key with spaces",
        "key-with-dashes",
        "key_with_underscores",
        "key.with.dots",
        "key|with|pipes",
        "key#with#hashes",
        "key%with%percent",
    ];

    for (i, key) in special_keys.iter().enumerate() {
        let value = serde_json::json!({"key": key, "index": i});

        let result = cache.set(key, &value, Duration::from_secs(3600)).await;
        assert!(result.is_ok(), "Failed to set key: {}", key);

        let retrieved: Option<serde_json::Value> = cache.get(key).await.unwrap();
        assert!(retrieved.is_some(), "Failed to get key: {}", key);
        assert_eq!(retrieved.unwrap()["key"], *key);
    }
}

#[tokio::test]
async fn test_file_cache_invalidation() {
    let temp_dir = TempDir::new().unwrap();
    let cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());

    // Set multiple related keys
    let keys = vec![
        "prefix:key1",
        "prefix:key2",
        "prefix:key3",
        "other:key1",
        "other:key2",
    ];

    for key in &keys {
        let value = serde_json::json!({"key": key});
        cache
            .set(key, &value, Duration::from_secs(3600))
            .await
            .unwrap();
    }

    // Verify all keys exist
    for key in &keys {
        let retrieved: Option<serde_json::Value> = cache.get(key).await.unwrap();
        assert!(retrieved.is_some());
    }

    // Invalidate with pattern
    cache.invalidate("prefix:*").await.unwrap();

    // Check that prefix keys are gone but others remain
    for key in &keys {
        let retrieved: Option<serde_json::Value> = cache.get(key).await.unwrap();
        if key.starts_with("prefix:") {
            assert!(retrieved.is_none(), "Key {} should be invalidated", key);
        } else {
            assert!(retrieved.is_some(), "Key {} should still exist", key);
        }
    }
}

#[tokio::test]
async fn test_file_cache_error_handling() {
    // Test with invalid directory path
    let invalid_path = "/non/existent/path/that/should/fail";
    let cache = FileCacheRepository::new(invalid_path.to_string());

    let key = "test_key";
    let value = serde_json::json!({"test": "data"});

    // Should handle write errors gracefully
    let result = cache.set(key, &value, Duration::from_secs(3600)).await;
    assert!(result.is_err());

    // Should handle read errors gracefully
    let result: Result<Option<serde_json::Value>, ApplicationError> = cache.get(key).await;
    assert!(result.is_err() || result.unwrap().is_none());
}

// Aggregating Vulnerability Repository Tests

#[tokio::test]
async fn test_aggregating_repository_single_client() {
    let vuln1 = create_test_vulnerability("OSV-2021-001", "express", Ecosystem::Npm);
    let vuln2 = create_test_vulnerability("OSV-2021-002", "lodash", Ecosystem::Npm);

    let client = MockVulnerabilityClient::new(vec![vuln1.clone(), vuln2.clone()]);
    let repository = AggregatingVulnerabilityRepository::new(vec![Arc::new(client)], 3);

    let packages = vec![
        create_test_package("express", "4.17.1", Ecosystem::Npm),
        create_test_package("lodash", "4.17.20", Ecosystem::Npm),
    ];

    let result = repository.find_vulnerabilities(&packages).await;
    assert!(result.is_ok());

    let vulnerabilities = result.unwrap();
    assert_eq!(vulnerabilities.len(), 2);
}

#[tokio::test]
async fn test_aggregating_repository_multiple_clients() {
    let osv_vuln = create_test_vulnerability("OSV-2021-001", "express", Ecosystem::Npm);
    let nvd_vuln = create_test_vulnerability("CVE-2021-1234", "express", Ecosystem::Npm);
    let ghsa_vuln = create_test_vulnerability("GHSA-1234-5678", "express", Ecosystem::Npm);

    let osv_client = MockVulnerabilityClient::new(vec![osv_vuln.clone()]);
    let nvd_client = MockVulnerabilityClient::new(vec![nvd_vuln.clone()]);
    let ghsa_client = MockVulnerabilityClient::new(vec![ghsa_vuln.clone()]);

    let repository = AggregatingVulnerabilityRepository::new(
        vec![
            Arc::new(osv_client),
            Arc::new(nvd_client),
            Arc::new(ghsa_client),
        ],
        3,
    );

    let packages = vec![create_test_package("express", "4.17.1", Ecosystem::Npm)];

    let result = repository.find_vulnerabilities(&packages).await;
    assert!(result.is_ok());

    let vulnerabilities = result.unwrap();
    assert_eq!(vulnerabilities.len(), 3); // All three sources should return vulnerabilities
}

#[tokio::test]
async fn test_aggregating_repository_deduplication() {
    // Create same vulnerability from multiple sources
    let mut vuln1 = create_test_vulnerability("GHSA-1234-5678", "express", Ecosystem::Npm);
    let mut vuln2 = create_test_vulnerability("GHSA-1234-5678", "express", Ecosystem::Npm);

    // Different sources
    vuln1.sources = vec![VulnerabilitySource::OSV];
    vuln2.sources = vec![VulnerabilitySource::GHSA];

    let client1 = MockVulnerabilityClient::new(vec![vuln1]);
    let client2 = MockVulnerabilityClient::new(vec![vuln2]);

    let repository =
        AggregatingVulnerabilityRepository::new(vec![Arc::new(client1), Arc::new(client2)], 3);

    let packages = vec![create_test_package("express", "4.17.1", Ecosystem::Npm)];

    let result = repository.find_vulnerabilities(&packages).await;
    assert!(result.is_ok());

    let vulnerabilities = result.unwrap();
    assert_eq!(vulnerabilities.len(), 1); // Should be deduplicated
    assert_eq!(vulnerabilities[0].sources.len(), 2); // Should merge sources
}

#[tokio::test]
async fn test_aggregating_repository_partial_failure() {
    let good_vuln = create_test_vulnerability("OSV-2021-001", "express", Ecosystem::Npm);

    let good_client = MockVulnerabilityClient::new(vec![good_vuln.clone()]);
    let failing_client = MockVulnerabilityClient::with_failure();

    let repository = AggregatingVulnerabilityRepository::new(
        vec![Arc::new(good_client), Arc::new(failing_client)],
        3,
    );

    let packages = vec![create_test_package("express", "4.17.1", Ecosystem::Npm)];

    let result = repository.find_vulnerabilities(&packages).await;
    assert!(result.is_ok()); // Should succeed despite partial failure

    let vulnerabilities = result.unwrap();
    assert_eq!(vulnerabilities.len(), 1); // Should get results from good client
}

#[tokio::test]
async fn test_aggregating_repository_all_clients_fail() {
    let failing_client1 = MockVulnerabilityClient::with_failure();
    let failing_client2 = MockVulnerabilityClient::with_failure();

    let repository = AggregatingVulnerabilityRepository::new(
        vec![Arc::new(failing_client1), Arc::new(failing_client2)],
        3,
    );

    let packages = vec![create_test_package("express", "4.17.1", Ecosystem::Npm)];

    let result = repository.find_vulnerabilities(&packages).await;
    assert!(result.is_ok()); // Should succeed but return empty results

    let vulnerabilities = result.unwrap();
    assert_eq!(vulnerabilities.len(), 0);
}

#[tokio::test]
async fn test_aggregating_repository_concurrency_limiting() {
    let vuln = create_test_vulnerability("OSV-2021-001", "express", Ecosystem::Npm);

    // Create client with delay to test concurrency
    let slow_client =
        MockVulnerabilityClient::new(vec![vuln]).with_delay(Duration::from_millis(100));

    let repository = AggregatingVulnerabilityRepository::new(
        vec![Arc::new(slow_client)],
        2, // Limit concurrency to 2
    );

    let packages = vec![
        create_test_package("express", "4.17.1", Ecosystem::Npm),
        create_test_package("lodash", "4.17.20", Ecosystem::Npm),
        create_test_package("react", "17.0.2", Ecosystem::Npm),
    ];

    let start = std::time::Instant::now();
    let result = repository.find_vulnerabilities(&packages).await;
    let duration = start.elapsed();

    assert!(result.is_ok());

    // With concurrency limit of 2 and 3 packages with 100ms delay each,
    // it should take at least 200ms (100ms for first 2, then 100ms for the third)
    assert!(duration.as_millis() >= 150); // Allow some tolerance
}

#[tokio::test]
async fn test_aggregating_repository_get_vulnerability_by_id() {
    let vuln = create_test_vulnerability("GHSA-1234-5678", "express", Ecosystem::Npm);
    let client = MockVulnerabilityClient::new(vec![vuln.clone()]);

    let repository = AggregatingVulnerabilityRepository::new(vec![Arc::new(client)], 3);

    let id = VulnerabilityId::new("GHSA-1234-5678".to_string()).unwrap();
    let result = repository.get_vulnerability_by_id(&id).await;

    assert!(result.is_ok());
    let found_vuln = result.unwrap();
    assert!(found_vuln.is_some());
    assert_eq!(found_vuln.unwrap().id, id);
}

#[tokio::test]
async fn test_aggregating_repository_vulnerability_not_found() {
    let client = MockVulnerabilityClient::new(vec![]); // Empty client

    let repository = AggregatingVulnerabilityRepository::new(vec![Arc::new(client)], 3);

    let id = VulnerabilityId::new("GHSA-NOT-FOUND".to_string()).unwrap();
    let result = repository.get_vulnerability_by_id(&id).await;

    assert!(result.is_ok());
    let found_vuln = result.unwrap();
    assert!(found_vuln.is_none());
}

// Cache Service Integration Tests

#[tokio::test]
async fn test_cache_service_with_file_backend() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());
    let cache_service =
        vulnera_rust::application::services::CacheServiceImpl::new(Arc::new(file_cache));

    let key = "cache_service_test";
    let value = serde_json::json!({
        "packages": ["express", "lodash"],
        "timestamp": "2023-01-01T00:00:00Z"
    });

    // Test set
    let result = cache_service
        .set(key, &value, Duration::from_secs(3600))
        .await;
    assert!(result.is_ok());

    // Test get
    let retrieved: Option<serde_json::Value> = cache_service.get(key).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), value);

    // Test invalidate
    cache_service.invalidate("cache_service_*").await.unwrap();

    let after_invalidate: Option<serde_json::Value> = cache_service.get(key).await.unwrap();
    assert!(after_invalidate.is_none());
}

#[tokio::test]
async fn test_cache_service_key_generation() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());
    let cache_service =
        vulnera_rust::application::services::CacheServiceImpl::new(Arc::new(file_cache));

    // Test package vulnerabilities key
    let key = cache_service.package_vulnerabilities_key(&create_test_package(
        "express",
        "4.17.1",
        Ecosystem::Npm,
    ));
    assert!(key.contains("package_vulns"));
    assert!(key.contains("express"));
    assert!(key.contains("4.17.1"));
    assert!(key.contains("npm"));

    // Test vulnerability details key
    let vuln_id = VulnerabilityId::new("GHSA-1234-5678".to_string()).unwrap();
    let details_key = cache_service.vulnerability_details_key(&vuln_id);
    assert!(details_key.contains("vuln_details"));
    assert!(details_key.contains("GHSA-1234-5678"));

    // Test content hash
    let content = "test content for hashing";
    let hash = cache_service.content_hash(content);
    assert_eq!(hash.len(), 64); // SHA256 hex length

    // Same content should produce same hash
    let hash2 = cache_service.content_hash(content);
    assert_eq!(hash, hash2);

    // Different content should produce different hash
    let hash3 = cache_service.content_hash("different content");
    assert_ne!(hash, hash3);
}

#[tokio::test]
async fn test_cache_service_statistics() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());
    let cache_service =
        vulnera_rust::application::services::CacheServiceImpl::new(Arc::new(file_cache));

    // Populate cache with some data
    for i in 0..5 {
        let key = format!("stats_test_{}", i);
        let value = serde_json::json!({"id": i});
        cache_service
            .set(&key, &value, Duration::from_secs(3600))
            .await
            .unwrap();
    }

    // Test exists method
    let exists = cache_service.exists("stats_test_0").await.unwrap();
    assert!(exists);

    let not_exists = cache_service.exists("non_existent_key").await.unwrap();
    assert!(!not_exists);

    // Test cache statistics
    let stats = cache_service.get_cache_statistics().await.unwrap();
    println!("Cache statistics: {:?}", stats);
    // Note: Actual values depend on implementation
}

#[tokio::test]
async fn test_cache_service_preload_vulnerabilities() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());
    let cache_service =
        vulnera_rust::application::services::CacheServiceImpl::new(Arc::new(file_cache));

    let vulnerabilities = vec![
        create_test_vulnerability("GHSA-1234-5678", "express", Ecosystem::Npm),
        create_test_vulnerability("CVE-2021-1234", "lodash", Ecosystem::Npm),
    ];

    // Test preload
    let result = cache_service
        .preload_vulnerabilities(&vulnerabilities)
        .await;
    assert!(result.is_ok());

    // Verify vulnerabilities are cached
    for vuln in &vulnerabilities {
        let key = cache_service.vulnerability_details_key(&vuln.id);
        let cached: Option<Vulnerability> = cache_service.get(&key).await.unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().id, vuln.id);
    }
}

#[tokio::test]
async fn test_cache_service_cleanup_expired_entries() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());
    let cache_service =
        vulnera_rust::application::services::CacheServiceImpl::new(Arc::new(file_cache));

    // Add entries with different TTLs
    cache_service
        .set(
            "short_ttl",
            &json!({"data": "expires_soon"}),
            Duration::from_millis(50),
        )
        .await
        .unwrap();
    cache_service
        .set(
            "long_ttl",
            &json!({"data": "expires_later"}),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    // Wait for short TTL to expire
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run cleanup
    let result = cache_service.cleanup_expired_entries().await;
    assert!(result.is_ok());

    // Check that expired entry is gone but non-expired remains
    let short_result: Option<serde_json::Value> = cache_service.get("short_ttl").await.unwrap();
    assert!(short_result.is_none());

    let long_result: Option<serde_json::Value> = cache_service.get("long_ttl").await.unwrap();
    assert!(long_result.is_some());
}

#[tokio::test]
async fn test_cache_service_invalidate_ecosystem_cache() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());
    let cache_service =
        vulnera_rust::application::services::CacheServiceImpl::new(Arc::new(file_cache));

    // Cache packages from different ecosystems
    let npm_package = create_test_package("express", "4.17.1", Ecosystem::Npm);
    let cargo_package = create_test_package("serde", "1.0.0", Ecosystem::Cargo);

    let npm_key = cache_service.package_vulnerabilities_key(&npm_package);
    let cargo_key = cache_service.package_vulnerabilities_key(&cargo_package);

    cache_service
        .set(
            &npm_key,
            &json!({"vulns": ["npm-vuln"]}),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
    cache_service
        .set(
            &cargo_key,
            &json!({"vulns": ["cargo-vuln"]}),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    // Invalidate only npm ecosystem
    let result = cache_service
        .invalidate_ecosystem_cache(Ecosystem::Npm)
        .await;
    assert!(result.is_ok());

    // Check that npm cache is invalidated but cargo cache remains
    let npm_result: Option<serde_json::Value> = cache_service.get(&npm_key).await.unwrap();
    assert!(npm_result.is_none());

    let cargo_result: Option<serde_json::Value> = cache_service.get(&cargo_key).await.unwrap();
    assert!(cargo_result.is_some());
}

// Performance and stress tests

#[tokio::test]
async fn test_repository_performance_with_many_packages() {
    let vulns: Vec<Vulnerability> = (0..100)
        .map(|i| {
            create_test_vulnerability(&format!("OSV-2021-{:03}", i), "express", Ecosystem::Npm)
        })
        .collect();

    let client = MockVulnerabilityClient::new(vulns);
    let repository = AggregatingVulnerabilityRepository::new(vec![Arc::new(client)], 5);

    let packages: Vec<Package> = (0..50)
        .map(|i| create_test_package(&format!("package{}", i), "1.0.0", Ecosystem::Npm))
        .collect();

    let start = std::time::Instant::now();
    let result = repository.find_vulnerabilities(&packages).await;
    let duration = start.elapsed();

    assert!(result.is_ok());
    println!("Performance test completed in {:?}", duration);
    assert!(duration.as_secs() < 10); // Should complete within reasonable time
}

#[tokio::test]
async fn test_cache_performance_with_large_dataset() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = FileCacheRepository::new(temp_dir.path().to_string_lossy().to_string());

    let start = std::time::Instant::now();

    // Write many entries
    for i in 0..1000 {
        let key = format!("perf_test_{}", i);
        let value = serde_json::json!({
            "id": i,
            "data": format!("test_data_{}", i),
            "timestamp": Utc::now().to_rfc3339()
        });

        file_cache
            .set(&key, &value, Duration::from_secs(3600))
            .await
            .unwrap();
    }

    let write_duration = start.elapsed();

    // Read all entries back
    let read_start = std::time::Instant::now();
    for i in 0..1000 {
        let key = format!("perf_test_{}", i);
        let result: Option<serde_json::Value> = file_cache.get(&key).await.unwrap();
        assert!(result.is_some());
    }

    let read_duration = read_start.elapsed();

    println!(
        "Cache performance - Write: {:?}, Read: {:?}",
        write_duration, read_duration
    );
    assert!(write_duration.as_secs() < 30);
    assert!(read_duration.as_secs() < 10);
}

#[tokio::test]
async fn test_concurrent_repository_and_cache_operations() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_string_lossy().to_string(),
    ));
    let cache_service = Arc::new(vulnera_rust::application::services::CacheServiceImpl::new(
        file_cache,
    ));

    let vuln = create_test_vulnerability("OSV-2021-001", "express", Ecosystem::Npm);
    let client = Arc::new(MockVulnerabilityClient::new(vec![vuln]));
    let repository = Arc::new(AggregatingVulnerabilityRepository::new(vec![client], 3));

    let mut handles = Vec::new();

    // Spawn tasks that use both repository and cache
    for i in 0..10 {
        let repo_clone = repository.clone();
        let cache_clone = cache_service.clone();

        let handle = tokio::spawn(async move {
            let package = create_test_package(&format!("package{}", i), "1.0.0", Ecosystem::Npm);

            // Check cache first
            let cache_key = cache_clone.package_vulnerabilities_key(&package);
            let cached: Option<Vec<Vulnerability>> = cache_clone.get(&cache_key).await.unwrap();

            if cached.is_none() {
                // Query repository
                let vulns = repo_clone.find_vulnerabilities(&[package]).await.unwrap();

                // Cache results
                cache_clone
                    .set(&cache_key, &vulns, Duration::from_secs(3600))
                    .await
                    .unwrap();
            }
        });

        handles.push(handle);
    }

    // Wait for all operations to complete
    futures::future::join_all(handles).await;
}
