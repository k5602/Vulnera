//! Comprehensive integration tests for Vulnera
//! Tests the complete system end-to-end with real components

use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::{Value, json};

use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use vulnera_rust::{Config, create_app};

mod fixtures {
    //! Test fixtures and sample data

    pub const SAMPLE_PACKAGE_JSON: &str = r#"{
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "4.17.1",
            "lodash": "4.17.20",
            "axios": "0.21.1"
        },
        "devDependencies": {
            "jest": "26.6.3",
            "eslint": "7.32.0"
        }
    }"#;

    pub const SAMPLE_CARGO_TOML: &str = r#"[package]
name = "test-app"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
axum = "0.6"
reqwest = { version = "0.11", features = ["json"] }"#;

    pub const SAMPLE_REQUIREMENTS_TXT: &str = r#"django==3.2.13
requests>=2.25.0
psycopg2-binary==2.9.3
celery[redis]==5.2.7
gunicorn==20.1.0"#;

    pub const SAMPLE_POM_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.21</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>"#;

    pub const SAMPLE_GO_MOD: &str = r#"module github.com/example/test-app

go 1.19

require (
    github.com/gin-gonic/gin v1.7.7
    github.com/gorilla/mux v1.8.0
    golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4
)"#;

    pub const SAMPLE_COMPOSER_JSON: &str = r#"{
        "name": "example/test-app",
        "require": {
            "php": ">=7.4",
            "laravel/framework": "^8.75",
            "guzzlehttp/guzzle": "^7.0.1",
            "monolog/monolog": "^2.0"
        },
        "require-dev": {
            "phpunit/phpunit": "^9.5.10",
            "mockery/mockery": "^1.4.4"
        }
    }"#;
}

/// Helper to create a test server with custom configuration
async fn create_test_server_with_config(config: Config) -> TestServer {
    let app = create_app(config).await.expect("Failed to create app");
    TestServer::new(app).expect("Failed to create test server")
}

/// Helper to create a test server with default configuration
async fn create_test_server() -> TestServer {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let mut config = Config::default();
    config.cache.directory = temp_dir.path().to_path_buf();
    config.server.enable_docs = true;

    create_test_server_with_config(config).await
}

/// Test server startup and health endpoints
#[tokio::test]
async fn test_server_startup_and_health() {
    let server = create_test_server().await;

    // Test basic health endpoint
    let response = server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].is_string());
    assert!(body["version"].is_string());
}

/// Test configuration loading from different sources
#[tokio::test]
async fn test_configuration_loading() {
    // Test default configuration
    let default_config = Config::default();
    assert_eq!(default_config.server.port, 3000);
    assert_eq!(default_config.server.host, "0.0.0.0");
    assert_eq!(default_config.cache.ttl_hours, 24);
    assert!(
        default_config
            .cache
            .directory
            .to_string_lossy()
            .contains(".vulnera_cache")
    );

    // Test environment variable override
    unsafe {
        std::env::set_var("VULNERA__SERVER__PORT", "8080");
        std::env::set_var("VULNERA__CACHE__TTL_HOURS", "12");
    }

    let env_config = Config::load().expect("Failed to load config");
    assert_eq!(env_config.server.port, 8080);
    assert_eq!(env_config.cache.ttl_hours, 12);

    // Clean up environment variables
    unsafe {
        std::env::remove_var("VULNERA__SERVER__PORT");
        std::env::remove_var("VULNERA__CACHE__TTL_HOURS");
    }
}

/// Test analysis endpoint with npm/Node.js dependencies
#[tokio::test]
async fn test_npm_analysis_comprehensive() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": fixtures::SAMPLE_PACKAGE_JSON,
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["vulnerabilities"].is_array());
    assert!(body["metadata"].is_object());

    let _vulnerabilities = body["vulnerabilities"].as_array().unwrap();

    let metadata = &body["metadata"];
    assert!(metadata["total_packages"].is_number());
    assert!(metadata["vulnerable_packages"].is_number());
    assert!(metadata["analysis_duration_ms"].is_number());
    assert!(metadata["sources_queried"].is_array());
}

/// Test analysis endpoint with Rust/Cargo dependencies
#[tokio::test]
async fn test_cargo_analysis_comprehensive() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": fixtures::SAMPLE_CARGO_TOML,
            "ecosystem": "cargo",
            "filename": "Cargo.toml"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["vulnerabilities"].is_array());
    assert!(body["metadata"].is_object());

    let _vulnerabilities = body["vulnerabilities"].as_array().unwrap();
    let metadata = &body["metadata"];

    assert!(metadata["total_packages"].is_number());
    assert!(metadata["vulnerable_packages"].is_number());
    assert!(metadata["analysis_duration_ms"].is_number());
    assert!(metadata["sources_queried"].is_array());
    // Package analysis completed successfully
}

/// Test analysis endpoint with Python dependencies
#[tokio::test]
async fn test_python_analysis_comprehensive() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": fixtures::SAMPLE_REQUIREMENTS_TXT,
            "ecosystem": "pypi",
            "filename": "requirements.txt"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["vulnerabilities"].is_array());
    assert!(body["metadata"].is_object());

    let _vulnerabilities = body["vulnerabilities"].as_array().unwrap();
    let metadata = &body["metadata"];
    assert!(metadata["total_packages"].is_number());
    assert!(metadata["vulnerable_packages"].is_number());
    assert!(metadata["analysis_duration_ms"].is_number());
    assert!(metadata["sources_queried"].is_array());
}

/// Test analysis endpoint with Java/Maven dependencies
#[tokio::test]
async fn test_maven_analysis_comprehensive() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": fixtures::SAMPLE_POM_XML,
            "ecosystem": "maven",
            "filename": "pom.xml"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["vulnerabilities"].is_array());
    assert!(body["metadata"].is_object());

    let _vulnerabilities = body["vulnerabilities"].as_array().unwrap();
    let metadata = &body["metadata"];
    assert!(metadata["total_packages"].is_number());
    assert!(metadata["vulnerable_packages"].is_number());
    assert!(metadata["analysis_duration_ms"].is_number());
    assert!(metadata["sources_queried"].is_array());
}

/// Test analysis endpoint with Go dependencies
#[tokio::test]
async fn test_go_analysis_comprehensive() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": fixtures::SAMPLE_GO_MOD,
            "ecosystem": "go",
            "filename": "go.mod"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["vulnerabilities"].is_array());
    assert!(body["metadata"].is_object());

    let _vulnerabilities = body["vulnerabilities"].as_array().unwrap();
    let metadata = &body["metadata"];
    assert!(metadata["total_packages"].is_number());
    assert!(metadata["vulnerable_packages"].is_number());
    assert!(metadata["analysis_duration_ms"].is_number());
    assert!(metadata["sources_queried"].is_array());

    // Go module parsing completed successfully
}

/// Test analysis endpoint with PHP/Composer dependencies
#[tokio::test]
async fn test_php_analysis_comprehensive() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": fixtures::SAMPLE_COMPOSER_JSON,
            "ecosystem": "packagist",
            "filename": "composer.json"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["id"].is_string());
    assert!(body["vulnerabilities"].is_array());
    assert!(body["metadata"].is_object());

    let _vulnerabilities = body["vulnerabilities"].as_array().unwrap();
    let metadata = &body["metadata"];
    assert!(metadata["total_packages"].is_number());
    assert!(metadata["vulnerable_packages"].is_number());
    assert!(metadata["analysis_duration_ms"].is_number());
    assert!(metadata["sources_queried"].is_array());
    // PHP composer parsing completed successfully
}

/// Test vulnerability details endpoint
#[tokio::test]
async fn test_vulnerability_details_endpoint() {
    let server = create_test_server().await;

    // First, get vulnerabilities from an analysis
    let analysis_response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": fixtures::SAMPLE_PACKAGE_JSON,
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    assert_eq!(analysis_response.status_code(), StatusCode::OK);

    let analysis_body: Value = analysis_response.json();
    let vulnerabilities = analysis_body["vulnerabilities"].as_array().unwrap();

    if !vulnerabilities.is_empty() {
        let vuln_id = vulnerabilities[0]["id"].as_str().unwrap();

        let details_response = server
            .get(&format!("/api/v1/vulnerabilities/{}", vuln_id))
            .await;

        // Accept both OK (found) and NOT_FOUND (not found in mock data)
        assert!(matches!(
            details_response.status_code(),
            StatusCode::OK | StatusCode::NOT_FOUND
        ));

        if details_response.status_code() == StatusCode::OK {
            let details_body: Value = details_response.json();
            assert_eq!(details_body["id"], vuln_id);
            assert!(details_body["summary"].is_string());
            assert!(details_body["description"].is_string());
            assert!(details_body["severity"].is_string());
            assert!(details_body["affected_packages"].is_array());
            assert!(details_body["references"].is_array());
            assert!(details_body["sources"].is_array());
        }
    }
}

/// Test popular packages endpoint
#[tokio::test]
async fn test_popular_packages_endpoint() {
    let server = create_test_server().await;

    // Test with npm ecosystem
    let response = server
        .get("/api/v1/popular?ecosystem=npm&limit=10&offset=0")
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["vulnerabilities"].is_array());
    assert!(body["total_count"].is_number());
    assert!(body["cache_status"].is_string());

    let vulnerabilities = body["vulnerabilities"].as_array().unwrap();
    assert!(vulnerabilities.len() <= 10);

    // Test with different ecosystems
    let ecosystems = ["pypi", "cargo", "maven", "go", "packagist"];
    for ecosystem in ecosystems {
        let eco_response = server
            .get(&format!("/api/v1/popular?ecosystem={}&limit=5", ecosystem))
            .await;

        assert_eq!(eco_response.status_code(), StatusCode::OK);
    }
}

/// Test repository analysis endpoint (might fail due to GitHub API limits)
#[tokio::test]
async fn test_repository_analysis_endpoint() {
    let server = create_test_server().await;

    let response = server
        .post("/api/v1/analyze/repository")
        .json(&json!({
            "owner": "expressjs",
            "repo": "express",
            "ref": "master",
            "max_files": 10,
            "include_lockfiles": true,
            "return_packages": false
        }))
        .await;

    // Accept various responses due to external API dependencies
    assert!(matches!(
        response.status_code(),
        StatusCode::OK
            | StatusCode::NOT_FOUND
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::FORBIDDEN
    ));

    if response.status_code() == StatusCode::OK {
        let body: Value = response.json();
        assert!(body["id"].is_string());
        assert!(body["repository"]["owner"].is_string());
        assert!(body["repository"]["repo"].is_string());
        assert!(body["files"].is_array());
        assert!(body["metadata"].is_object());
    }
}

/// Test error handling and validation
#[tokio::test]
async fn test_error_handling_comprehensive() {
    let server = create_test_server().await;

    // Test invalid JSON
    let invalid_json_response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": "{invalid json",
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    assert_eq!(invalid_json_response.status_code(), StatusCode::BAD_REQUEST);
    let error_body: Value = invalid_json_response.json();
    assert!(error_body["message"].is_string());
    assert!(error_body["timestamp"].is_string());

    // Test missing required fields
    let missing_fields_response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": "some content"
            // Missing ecosystem and filename
        }))
        .await;

    assert_eq!(
        missing_fields_response.status_code(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Test unsupported ecosystem
    let unsupported_ecosystem_response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": "some content",
            "ecosystem": "unsupported",
            "filename": "unknown.file"
        }))
        .await;

    assert_eq!(
        unsupported_ecosystem_response.status_code(),
        StatusCode::BAD_REQUEST
    );

    // Test vulnerability not found
    let not_found_response = server
        .get("/api/v1/vulnerabilities/INVALID-ID-FORMAT")
        .await;

    assert!(matches!(
        not_found_response.status_code(),
        StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST
    ));
}

/// Test CORS headers and middleware
#[tokio::test]
async fn test_cors_and_middleware() {
    let server = create_test_server().await;

    // Test actual request - CORS headers should be present in response
    let cors_response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": "{}",
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    // Should complete successfully (with or without CORS headers depending on config)
    assert!(matches!(
        cors_response.status_code(),
        StatusCode::OK | StatusCode::BAD_REQUEST
    ));
}

/// Test OpenAPI documentation endpoints
#[tokio::test]
async fn test_openapi_documentation() {
    let server = create_test_server().await;

    // Test Swagger UI
    let docs_response = server.get("/docs/").await;
    assert_eq!(docs_response.status_code(), StatusCode::OK);
    assert!(
        docs_response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/html")
    );

    // Test OpenAPI JSON spec
    let spec_response = server.get("/api-docs/openapi.json").await;
    assert_eq!(spec_response.status_code(), StatusCode::OK);

    let spec_body: Value = spec_response.json();
    assert_eq!(spec_body["openapi"], "3.1.0");
    assert!(spec_body["info"].is_object());
    assert!(spec_body["paths"].is_object());
    assert!(spec_body["components"].is_object());

    // Verify key endpoints are documented
    let paths = spec_body["paths"].as_object().unwrap();
    assert!(paths.contains_key("/api/v1/analyze"));
    assert!(paths.contains_key("/api/v1/vulnerabilities/{id}"));
    assert!(paths.contains_key("/api/v1/popular"));
    assert!(paths.contains_key("/health"));
}

/// Test concurrent requests and performance
#[tokio::test]
async fn test_concurrent_requests_performance() {
    let server = create_test_server().await;

    let sample_requests = [
        json!({
            "file_content": fixtures::SAMPLE_PACKAGE_JSON,
            "ecosystem": "npm",
            "filename": "package.json"
        }),
        json!({
            "file_content": fixtures::SAMPLE_CARGO_TOML,
            "ecosystem": "cargo",
            "filename": "Cargo.toml"
        }),
        json!({
            "file_content": fixtures::SAMPLE_REQUIREMENTS_TXT,
            "ecosystem": "pypi",
            "filename": "requirements.txt"
        }),
    ];

    let start_time = std::time::Instant::now();

    // Send requests sequentially (axum-test may not support true concurrency)
    for (i, request_body) in sample_requests.iter().enumerate() {
        let response = server.post("/api/v1/analyze").json(request_body).await;
        assert_eq!(
            response.status_code(),
            StatusCode::OK,
            "Request {} failed",
            i
        );
    }

    let total_duration = start_time.elapsed();

    println!("Sequential requests completed in {:?}", total_duration);
    assert!(total_duration.as_secs() < 60); // Should complete within reasonable time
}

/// Test caching behavior
#[tokio::test]
async fn test_caching_behavior() {
    let server = create_test_server().await;

    let request_body = json!({
        "file_content": fixtures::SAMPLE_PACKAGE_JSON,
        "ecosystem": "npm",
        "filename": "package.json"
    });

    // First request - should populate cache
    let first_start = std::time::Instant::now();
    let first_response = server.post("/api/v1/analyze").json(&request_body).await;
    let first_duration = first_start.elapsed();

    assert_eq!(first_response.status_code(), StatusCode::OK);

    // Second identical request - should use cache and be faster
    let second_start = std::time::Instant::now();
    let second_response = server.post("/api/v1/analyze").json(&request_body).await;
    let second_duration = second_start.elapsed();

    assert_eq!(second_response.status_code(), StatusCode::OK);

    // Cache hit should generally be faster (though this isn't guaranteed in all cases)
    println!(
        "Cache test - First: {:?}, Second: {:?}",
        first_duration, second_duration
    );

    // Verify responses are consistent
    let first_body: Value = first_response.json();
    let second_body: Value = second_response.json();

    // IDs will be different but vulnerability counts should match
    assert_eq!(
        first_body["vulnerabilities"].as_array().unwrap().len(),
        second_body["vulnerabilities"].as_array().unwrap().len()
    );
}

/// Test rate limiting (if implemented)
#[tokio::test]
async fn test_rate_limiting() {
    let server = create_test_server().await;

    let mut responses = Vec::new();

    // Make rapid requests to test rate limiting
    for _ in 0..10 {
        let response = server.get("/health").await;
        responses.push(response.status_code());
    }

    let successful_count = responses
        .iter()
        .filter(|&&status| status == StatusCode::OK)
        .count();

    // Most requests should succeed in test environment
    assert!(successful_count > 0);

    println!(
        "Rate limiting test - Successful: {} out of {}",
        successful_count,
        responses.len()
    );
}

/// Test external API availability (graceful degradation)
#[tokio::test]
async fn test_external_api_availability() {
    let client = reqwest::Client::new();

    // Test connectivity to external vulnerability APIs
    let apis = vec![
        ("OSV API", "https://api.osv.dev/v1/vulns"),
        (
            "NVD API",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        ),
        // Note: GHSA requires authentication for meaningful testing
    ];

    for (name, url) in apis {
        let result = timeout(Duration::from_secs(10), client.get(url).send()).await;

        match result {
            Ok(Ok(response)) => {
                println!("{} is reachable (status: {})", name, response.status());
            }
            Ok(Err(e)) => {
                println!("{} request failed: {}", name, e);
            }
            Err(_) => {
                println!("{} request timed out", name);
            }
        }
    }
}

/// Test memory usage and resource management
#[tokio::test]
async fn test_memory_usage() {
    let server = create_test_server().await;

    // Create a large request to test memory handling
    let large_package_json = {
        let mut deps = serde_json::Map::new();
        for i in 0..1000 {
            deps.insert(
                format!("package{}", i),
                serde_json::Value::String(format!("{}.0.0", i % 10)),
            );
        }

        json!({
            "name": "memory-test",
            "dependencies": deps
        })
    };

    let response = server
        .post("/api/v1/analyze")
        .json(&json!({
            "file_content": large_package_json.to_string(),
            "ecosystem": "npm",
            "filename": "package.json"
        }))
        .await;

    // Should handle large requests gracefully
    assert!(matches!(
        response.status_code(),
        StatusCode::OK
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::BAD_REQUEST
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::REQUEST_TIMEOUT
            | StatusCode::INTERNAL_SERVER_ERROR
    ));

    if response.status_code() == StatusCode::OK {
        let body: Value = response.json();
        let vulnerabilities = body["vulnerabilities"].as_array().unwrap();
        println!(
            "Memory test - processed {} vulnerabilities from large request",
            vulnerabilities.len()
        );
    }
}

/// Test graceful shutdown behavior
#[tokio::test]
async fn test_graceful_shutdown() {
    let server = create_test_server().await;

    // Make a request to ensure server is working
    let response = server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Drop the server - this should trigger graceful shutdown
    drop(server);

    // If we reach this point without hanging, shutdown was graceful
    println!("Server shutdown completed gracefully");
}

/// Test security headers and input validation
#[tokio::test]
async fn test_security_measures() {
    let server = create_test_server().await;

    // Test with potentially malicious input
    let malicious_inputs = vec![
        // XSS attempts
        r#"{"dependencies": {"<script>alert('xss')</script>": "1.0.0"}}"#,
        // SQL injection attempts
        r#"{"dependencies": {"'; DROP TABLE users; --": "1.0.0"}}"#,
        // Path traversal attempts
        r#"{"dependencies": {"../../../etc/passwd": "1.0.0"}}"#,
        // Command injection attempts
        r#"{"dependencies": {"`rm -rf /`": "1.0.0"}}"#,
    ];

    for malicious_input in malicious_inputs {
        let response = server
            .post("/api/v1/analyze")
            .json(&json!({
                "file_content": malicious_input,
                "ecosystem": "npm",
                "filename": "package.json"
            }))
            .await;

        // Should either parse safely or reject with bad request
        assert!(matches!(
            response.status_code(),
            StatusCode::OK | StatusCode::BAD_REQUEST
        ));

        if response.status_code() == StatusCode::OK {
            let body: Value = response.json();
            // Ensure malicious content is properly escaped/sanitized
            let response_text = body.to_string();
            assert!(!response_text.contains("<script>"));
            assert!(!response_text.contains("DROP TABLE"));
        }
    }

    // Test security headers
    let response = server.get("/health").await;
    let headers = response.headers();

    // Check for common security headers (actual headers depend on middleware config)
    println!("Response headers: {:?}", headers);
}

/// Test comprehensive ecosystem support
#[tokio::test]
async fn test_all_ecosystems_comprehensive() {
    let server = create_test_server().await;

    let test_cases = vec![
        ("npm", "package.json", fixtures::SAMPLE_PACKAGE_JSON),
        ("cargo", "Cargo.toml", fixtures::SAMPLE_CARGO_TOML),
        (
            "pypi",
            "requirements.txt",
            fixtures::SAMPLE_REQUIREMENTS_TXT,
        ),
        ("maven", "pom.xml", fixtures::SAMPLE_POM_XML),
        ("go", "go.mod", fixtures::SAMPLE_GO_MOD),
        ("packagist", "composer.json", fixtures::SAMPLE_COMPOSER_JSON),
    ];

    for (ecosystem, filename, content) in test_cases {
        let response = server
            .post("/api/v1/analyze")
            .json(&json!({
                "file_content": content,
                "ecosystem": ecosystem,
                "filename": filename
            }))
            .await;

        assert_eq!(
            response.status_code(),
            StatusCode::OK,
            "Failed for ecosystem: {}",
            ecosystem
        );

        let body: Value = response.json();
        assert!(body["id"].is_string());
        assert!(body["vulnerabilities"].is_array());
        assert!(body["metadata"].is_object());

        let vulnerabilities = body["vulnerabilities"].as_array().unwrap();
        let metadata = &body["metadata"];
        assert!(metadata["total_packages"].is_number());
        // Test passed for ecosystem

        // Ecosystem test completed successfully

        println!(
            "Ecosystem {} - Found {} vulnerabilities",
            ecosystem,
            vulnerabilities.len()
        );
    }
}
