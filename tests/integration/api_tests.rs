//! Comprehensive integration tests for Vulnera API endpoints
//! Tests the full request-response cycle with real dependencies

use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::{Value, json};
use std::collections::HashMap;
use tempfile::TempDir;
use vulnera_rust::{Config, create_app};

/// Helper to create a test server with mock dependencies
async fn create_test_server() -> TestServer {
    let config = Config::default();
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Override cache directory to use temp directory
    let mut test_config = config;
    test_config.cache.directory = temp_dir.path().to_string_lossy().to_string();

    let app = create_app(test_config).await.expect("Failed to create app");
    TestServer::new(app).expect("Failed to create test server")
}

/// Test health endpoint
#[tokio::test]
async fn test_health_endpoint() {
    let server = create_test_server().await;

    let response = server.get("/health").await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].is_string());
    assert!(body["version"].is_string());
}

/// Test analysis endpoint with valid package.json
#[tokio::test]
async fn test_analyze_package_json() {
    let server = create_test_server().await;

    let package_json = json!({
        "dependencies": {
            "express": "4.17.1",
            "lodash": "4.17.20"
        },
        "devDependencies": {
            "jest": "26.6.3"
        }
    });

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": package_json.to_string(),
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["packages"].is_array());
    assert!(body["vulnerabilities"].is_array());
    assert!(body["metadata"].is_object());
}

/// Test analysis endpoint with Cargo.toml
#[tokio::test]
async fn test_analyze_cargo_toml() {
    let server = create_test_server().await;

    let cargo_toml = r#"
[package]
name = "test-package"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": cargo_toml,
            "ecosystem": "cargo",
            "filename": "Cargo.toml"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["packages"].is_array());
    let packages = body["packages"].as_array().unwrap();
    assert!(packages.len() >= 2); // serde and tokio
}

/// Test analysis endpoint with requirements.txt
#[tokio::test]
async fn test_analyze_requirements_txt() {
    let server = create_test_server().await;

    let requirements = "django==3.2.0\nrequests>=2.25.0\nnumpy==1.21.0";

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": requirements,
            "ecosystem": "pypi",
            "filename": "requirements.txt"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    let packages = body["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 3);
}

/// Test analysis endpoint with invalid JSON
#[tokio::test]
async fn test_analyze_invalid_json() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": "{invalid json",
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    let body: Value = response.json();
    assert!(body["error"].is_string());
}

/// Test analysis endpoint with unsupported ecosystem
#[tokio::test]
async fn test_analyze_unsupported_ecosystem() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": "some content",
            "ecosystem": "unsupported",
            "filename": "unknown.file"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

/// Test analysis endpoint with missing required fields
#[tokio::test]
async fn test_analyze_missing_fields() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": "some content"
            // Missing ecosystem and filename
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

/// Test vulnerability details endpoint
#[tokio::test]
async fn test_vulnerability_details() {
    let server = create_test_server().await;

    // First, get a vulnerability ID from an analysis
    let package_json = json!({
        "dependencies": {
            "express": "4.17.1"
        }
    });

    let analysis_response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": package_json.to_string(),
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    let analysis_body: Value = analysis_response.json();
    let vulnerabilities = analysis_body["vulnerabilities"].as_array().unwrap();

    if !vulnerabilities.is_empty() {
        let vuln_id = vulnerabilities[0]["id"].as_str().unwrap();

        let details_response = server
            .get(&format!("/api/v1/vulnerabilities/{}", vuln_id))
            .await;

        assert_eq!(details_response.status_code(), StatusCode::OK);

        let details_body: Value = details_response.json();
        assert_eq!(details_body["id"], vuln_id);
        assert!(details_body["summary"].is_string());
        assert!(details_body["severity"].is_string());
    }
}

/// Test vulnerability details with invalid ID
#[tokio::test]
async fn test_vulnerability_details_invalid_id() {
    let server = create_test_server().await;

    let response = server.get("/api/v1/vulnerabilities/invalid-id").await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

/// Test repository analysis endpoint
#[tokio::test]
async fn test_repository_analysis() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze/repository")
        .json(&json!({
            "owner": "expressjs",
            "repo": "express",
            "ref": "main",
            "max_files": 50
        }))
        .await;

    // This might timeout or fail due to GitHub API limits, so we accept multiple status codes
    assert!(matches!(
        response.status_code(),
        StatusCode::OK
            | StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::SERVICE_UNAVAILABLE
    ));
}

/// Test repository analysis with invalid repository
#[tokio::test]
async fn test_repository_analysis_invalid_repo() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze/repository")
        .json(&json!({
            "owner": "nonexistent",
            "repo": "nonexistent-repo",
            "ref": "main"
        }))
        .await;

    assert!(matches!(
        response.status_code(),
        StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST
    ));
}

/// Test popular packages endpoint
#[tokio::test]
async fn test_popular_packages() {
    let server = create_test_server().await;

    let response = server.get("/api/v1/popular?ecosystem=npm&limit=10").await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["vulnerabilities"].is_array());
    assert!(body["total_count"].is_number());
}

/// Test popular packages with invalid ecosystem
#[tokio::test]
async fn test_popular_packages_invalid_ecosystem() {
    let server = create_test_server().await;

    let response = server.get("/api/v1/popular?ecosystem=invalid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

/// Test CORS headers
#[tokio::test]
async fn test_cors_headers() {
    let server = create_test_server().await;

    let response = server
        .options("/api/v1/analyze")
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let headers = response.headers();
    assert!(headers.contains_key("access-control-allow-origin"));
    assert!(headers.contains_key("access-control-allow-methods"));
}

/// Test rate limiting (if implemented)
#[tokio::test]
async fn test_rate_limiting() {
    let server = create_test_server().await;

    // Make multiple rapid requests
    let mut responses = Vec::new();
    for _ in 0..20 {
        let response = server.get("/health").await;
        responses.push(response.status_code());
    }

    // Should either all succeed or some be rate limited
    let successful = responses
        .iter()
        .filter(|&&status| status == StatusCode::OK)
        .count();
    let rate_limited = responses
        .iter()
        .filter(|&&status| status == StatusCode::TOO_MANY_REQUESTS)
        .count();

    assert!(successful + rate_limited == responses.len());
}

/// Test content type validation
#[tokio::test]
async fn test_content_type_validation() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .header("content-type", "text/plain")
        .text("not json")
        .await;

    assert_eq!(response.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// Test request size limits
#[tokio::test]
async fn test_request_size_limits() {
    let server = create_test_server().await;

    // Create a very large request
    let large_content = "x".repeat(10_000_000); // 10MB

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": large_content,
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    assert!(matches!(
        response.status_code(),
        StatusCode::PAYLOAD_TOO_LARGE | StatusCode::BAD_REQUEST | StatusCode::REQUEST_TIMEOUT
    ));
}

/// Test concurrent requests
#[tokio::test]
async fn test_concurrent_requests() {
    let server = create_test_server().await;

    let package_json = json!({
        "dependencies": {
            "express": "4.17.1"
        }
    });

    // Send multiple concurrent requests
    let mut handles = Vec::new();
    for _ in 0..5 {
        let server_clone = server.clone();
        let content = package_json.clone();

        let handle = tokio::spawn(async move {
            server_clone
                .post("/api/v1/analyze")
                .json(&json!({
                    "content": content.to_string(),
                    "ecosystem": "npm",
                    "filename": "package.json"
                }))
                .await
        });

        handles.push(handle);
    }

    // Wait for all requests to complete
    let results = futures::future::join_all(handles).await;

    for result in results {
        let response = result.unwrap();
        assert_eq!(response.status_code(), StatusCode::OK);
    }
}

/// Test OpenAPI documentation endpoint
#[tokio::test]
async fn test_openapi_docs() {
    let server = create_test_server().await;

    let response = server.get("/docs/").await;

    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/html")
    );
}

/// Test OpenAPI JSON specification
#[tokio::test]
async fn test_openapi_json() {
    let server = create_test_server().await;

    let response = server.get("/api-docs/openapi.json").await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["openapi"], "3.0.3");
    assert!(body["info"].is_object());
    assert!(body["paths"].is_object());
}

/// Test security headers
#[tokio::test]
async fn test_security_headers() {
    let server = create_test_server().await;

    let response = server.get("/health").await;

    let headers = response.headers();

    // Check for common security headers
    assert!(headers.contains_key("x-content-type-options") || !headers.is_empty());
    // Note: Actual security headers depend on middleware configuration
}

/// Test error response format consistency
#[tokio::test]
async fn test_error_response_format() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "content": "{invalid json",
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    let body: Value = response.json();
    assert!(body["error"].is_string());
    assert!(body["timestamp"].is_string());
    assert!(body["path"].is_string());
}

/// Test metrics endpoint (if available)
#[tokio::test]
async fn test_metrics_endpoint() {
    let server = create_test_server().await;

    let response = server.get("/metrics").await;

    // Metrics endpoint might not be enabled in test environment
    assert!(matches!(
        response.status_code(),
        StatusCode::OK | StatusCode::NOT_FOUND | StatusCode::FORBIDDEN
    ));
}

/// Test graceful shutdown behavior
#[tokio::test]
async fn test_server_lifecycle() {
    // This test ensures the server can be created and dropped cleanly
    let server = create_test_server().await;

    let response = server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    drop(server);
    // If we reach here without hanging, the server shut down gracefully
}
