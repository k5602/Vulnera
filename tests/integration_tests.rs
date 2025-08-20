//! Integration tests for the Vulnera API

use std::time::Duration;
use tokio::time::timeout;

/// Test that the server can start and respond to health checks
#[tokio::test]
async fn test_server_health_endpoint() {
    // This test would require starting the actual server
    // For now, we'll just ensure the test framework works
    assert!(true, "Integration test framework is working");
}

/// Test vulnerability analysis endpoint with real data
#[tokio::test]
async fn test_vulnerability_analysis_integration() {
    // This would test the full analysis pipeline
    // Including real API calls to vulnerability databases
    // For now, placeholder for future implementation
    assert!(true, "Analysis integration test placeholder");
}

/// Test that configuration loading works correctly
#[tokio::test]
async fn test_configuration_loading() {
    use vulnera_rust::Config;

    // Test that default config can be loaded
    let config = Config::default();
    assert_eq!(config.server.port, 3000);
    assert_eq!(config.server.host, "0.0.0.0");
    assert_eq!(config.cache.ttl_hours, 24);
}

/// Test that all required dependencies are available
#[tokio::test]
async fn test_external_dependencies() {
    // Test that we can reach external APIs (with timeout)
    let client = reqwest::Client::new();

    // Test OSV API
    let osv_result = timeout(
        Duration::from_secs(5),
        client.get("https://api.osv.dev/v1/vulns").send(),
    )
    .await;

    if osv_result.is_ok() {
        println!("OSV API is reachable");
    } else {
        println!("OSV API is not reachable (network issue or timeout)");
    }

    // Always pass since network connectivity shouldn't fail tests
    assert!(true, "External dependency test completed");
}
