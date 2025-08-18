# Essential Rust Crates Research

## HTTP Client - reqwest

### Overview
Reqwest is an ergonomic, async HTTP client for Rust with excellent performance and ease of use.

### Key Features
- Async/await support with Tokio
- JSON serialization/deserialization
- Connection pooling
- Timeout support
- Retry mechanisms
- TLS support

### Usage Example
```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Deserialize)]
struct ApiResponse {
    data: Vec<String>,
}

async fn fetch_data() -> Result<ApiResponse, reqwest::Error> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    
    let response = client
        .get("https://api.example.com/data")
        .header("User-Agent", "vulnera-rust/1.0")
        .send()
        .await?;
    
    response.json::<ApiResponse>().await
}
```

## OpenAPI Documentation - utoipa

### Overview
Utoipa provides compile-time OpenAPI specification generation for Rust web applications.

### Key Features
- Compile-time OpenAPI spec generation
- Integration with Axum, Actix-web, Warp
- Automatic schema derivation
- Interactive Swagger UI
- Type-safe API documentation

### Usage Example
```rust
use utoipa::{OpenApi, ToSchema};
use serde::{Deserialize, Serialize};

#[derive(OpenApi)]
#[openapi(
    paths(analyze_dependencies, get_vulnerability),
    components(schemas(AnalysisRequest, AnalysisResponse, Vulnerability))
)]
struct ApiDoc;

#[derive(Serialize, Deserialize, ToSchema)]
struct AnalysisRequest {
    /// The dependency file content
    #[schema(example = "express@4.17.1\nlodash@4.17.21")]
    file_content: String,
    /// The ecosystem type
    #[schema(example = "npm")]
    ecosystem: String,
}

#[derive(Serialize, ToSchema)]
struct AnalysisResponse {
    /// List of found vulnerabilities
    vulnerabilities: Vec<Vulnerability>,
    /// Analysis metadata
    metadata: AnalysisMetadata,
}

#[utoipa::path(
    post,
    path = "/api/v1/analyze",
    request_body = AnalysisRequest,
    responses(
        (status = 200, description = "Analysis completed successfully", body = AnalysisResponse),
        (status = 400, description = "Invalid request format"),
        (status = 500, description = "Internal server error")
    )
)]
async fn analyze_dependencies(
    Json(request): Json<AnalysisRequest>
) -> Result<Json<AnalysisResponse>, StatusCode> {
    // Implementation
}
```

## Error Handling - anyhow & thiserror

### anyhow - Application Error Handling
```rust
use anyhow::{Context, Result};

async fn process_file(path: &str) -> Result<String> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read file: {}", path))?;
    
    let parsed = parse_dependencies(&content)
        .context("Failed to parse dependency file")?;
    
    Ok(parsed)
}
```

### thiserror - Library Error Types
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VulnerabilityError {
    #[error("Network request failed: {0}")]
    Network(#[from] reqwest::Error),
    
    #[error("JSON parsing failed: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Cache operation failed: {0}")]
    Cache(#[from] std::io::Error),
    
    #[error("Invalid ecosystem: {ecosystem}")]
    InvalidEcosystem { ecosystem: String },
    
    #[error("Rate limit exceeded for API: {api}")]
    RateLimit { api: String },
}
```

## Async Utilities - tokio & futures

### Tokio Features
```toml
[dependencies]
tokio = { version = "1.0", features = [
    "rt-multi-thread",  # Multi-threaded runtime
    "net",              # TCP/UDP networking
    "fs",               # File system operations
    "time",             # Timers and timeouts
    "sync",             # Synchronization primitives
    "macros",           # #[tokio::main] and #[tokio::test]
] }
```

### Concurrent Processing
```rust
use tokio::time::{timeout, Duration};
use futures::future::join_all;

async fn analyze_packages_concurrently(packages: Vec<Package>) -> Vec<Result<VulnerabilityReport, VulnerabilityError>> {
    let tasks = packages.into_iter().map(|package| {
        timeout(Duration::from_secs(30), analyze_single_package(package))
    });
    
    let results = join_all(tasks).await;
    
    results.into_iter().map(|result| {
        match result {
            Ok(Ok(report)) => Ok(report),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(VulnerabilityError::Timeout),
        }
    }).collect()
}
```

## Configuration - config

### Configuration Management
```rust
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub cache: CacheConfig,
    pub apis: ApiConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct CacheConfig {
    pub directory: String,
    pub ttl_hours: u64,
    pub max_size_mb: u64,
}

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub nvd_api_key: Option<String>,
    pub github_token: Option<String>,
    pub request_timeout_secs: u64,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let s = Config::builder()
            .add_source(File::with_name("config/default"))
            .add_source(File::with_name("config/local").required(false))
            .add_source(Environment::with_prefix("VULNERA"))
            .build()?;

        s.try_deserialize()
    }
}
```

## Logging and Tracing - tracing

### Structured Logging
```rust
use tracing::{info, warn, error, instrument, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracing() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "vulnera=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[instrument(skip(client), fields(package_name = %package.name))]
async fn fetch_vulnerabilities(
    client: &VulnerabilityClient,
    package: &Package,
) -> Result<Vec<Vulnerability>, VulnerabilityError> {
    let span = Span::current();
    span.record("package_version", &package.version);
    
    info!("Starting vulnerability analysis");
    
    let start = std::time::Instant::now();
    let result = client.query_vulnerabilities(package).await;
    let duration = start.elapsed();
    
    match &result {
        Ok(vulns) => {
            info!(
                vulnerability_count = vulns.len(),
                duration_ms = duration.as_millis(),
                "Vulnerability analysis completed"
            );
        }
        Err(e) => {
            error!(
                error = %e,
                duration_ms = duration.as_millis(),
                "Vulnerability analysis failed"
            );
        }
    }
    
    result
}
```

## File System Operations - tokio-fs

### Async File Operations
```rust
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::path::Path;

async fn save_cache_entry(key: &str, data: &[u8]) -> Result<(), std::io::Error> {
    let cache_dir = Path::new(".cache");
    fs::create_dir_all(cache_dir).await?;
    
    let file_path = cache_dir.join(format!("{}.json", key));
    let mut file = fs::File::create(file_path).await?;
    file.write_all(data).await?;
    file.sync_all().await?;
    
    Ok(())
}

async fn load_cache_entry(key: &str) -> Result<Vec<u8>, std::io::Error> {
    let file_path = Path::new(".cache").join(format!("{}.json", key));
    let mut file = fs::File::open(file_path).await?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await?;
    Ok(contents)
}
```

## Testing - tokio-test

### Async Testing
```rust
use tokio_test::{assert_ok, assert_err, task};

#[tokio::test]
async fn test_vulnerability_analysis() {
    let client = VulnerabilityClient::new();
    let package = Package {
        name: "express".to_string(),
        version: "4.17.1".to_string(),
        ecosystem: Ecosystem::Npm,
    };
    
    let result = client.analyze_package(&package).await;
    assert_ok!(&result);
    
    let vulnerabilities = result.unwrap();
    assert!(!vulnerabilities.is_empty());
}

#[tokio::test]
async fn test_rate_limiting() {
    let mut client = VulnerabilityClient::new();
    
    // Make multiple rapid requests
    let tasks = (0..10).map(|_| {
        let package = Package::default();
        client.analyze_package(&package)
    });
    
    let results = futures::future::join_all(tasks).await;
    
    // Verify rate limiting is working
    assert!(results.iter().all(|r| r.is_ok()));
}
```

## Complete Cargo.toml

```toml
[package]
name = "vulnera-rust"
version = "0.1.0"
edition = "2024"

[dependencies]
# Web framework
axum = { version = "0.8.4", features = ["macros"] }
axum-valid = "0.24.0"
axum-prometheus = "0.9.0"
axum_doc = "0.1.1"
axum-restful = "0.5.0"
tower = "0.5.2"
tower-http = { version = "0.5.2", features = ["cors", "trace"] }

# Async runtime
tokio = { version = "1.47.1", features = ["full"] }
futures = "0.3.31"
axum-tasks = "0.1.0"
axum-tasks-derive = "0.1.0"

# HTTP client
reqwest = { version = "0.12.23", features = ["json", "stream"] }

# Serialization
serde = { version = "1.0.219", features = ["derive"] }
axum-serde = "0.9.0"
serde_json = "1.0.142"

# OpenAPI documentation
utoipa = { version = "5.4.0", features = ["axum_extras"] }
utoipa-swagger-ui = { version = "9.0.2", features = ["axum"] }

# Error handling
anyhow = "1.0.99"
thiserror = "2.0.15"

# Configuration
config = "0.15.14"

# Logging and tracing
tracing = "0.1.40"
tracing-subscriber = { version = "0.3.18", features = ["env-filter"] }

# Time handling
chrono = { version = "0.4.40", features = ["serde"] }

# UUID generation
uuid = { version = "1.18.0", features = ["v4", "serde"] }

# Hashing for cache keys
sha2 = "0.10.8"
hex = "0.4.3"

# File parsing
toml = "0.9.5"
serde_yaml = "0.9.34"

[dev-dependencies]
tokio-test = "0.4.4"
mockito = "1.7.0"
tempfile = "3.20"
axum-test = "17.3.0"
axum-webtools = "0.1.30"
```