//! Configuration management

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub cache: CacheConfig,
    pub apis: ApiConfig,
    pub logging: LoggingConfig,
    pub recommendations: RecommendationsConfig,
    pub popular_packages: Option<PopularPackagesConfig>,
}

/// Popular packages configuration for vulnerability listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopularPackagesConfig {
    pub cache_ttl_hours: Option<u64>,
    pub npm: Option<Vec<PackageConfig>>,
    pub pypi: Option<Vec<PackageConfig>>,
    pub maven: Option<Vec<PackageConfig>>,
    pub cargo: Option<Vec<PackageConfig>>,
    pub go: Option<Vec<PackageConfig>>,
    pub packagist: Option<Vec<PackageConfig>>,
}

/// Individual package configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageConfig {
    pub name: String,
    pub version: String,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
    /// Whether to expose interactive API docs (Swagger UI). Should be false in hardened production.
    pub enable_docs: bool,
    /// Global request timeout in seconds applied at the HTTP layer.
    pub request_timeout_seconds: u64,
    /// Allowed CORS origins. Use ["*"] to allow any (development only). Empty vector -> no external origins.
    pub allowed_origins: Vec<String>,
    /// Security configuration
    pub security: SecurityConfig,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Whether to enforce HTTPS redirects (redirect HTTP to HTTPS)
    pub enforce_https: bool,
    /// Whether to enable security headers
    pub enable_security_headers: bool,
    /// Whether to sanitize error messages in production
    pub sanitize_errors: bool,
    /// HSTS max age in seconds (31536000 = 1 year)
    pub hsts_max_age: u64,
    /// Whether to include subdomains in HSTS
    pub hsts_include_subdomains: bool,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub directory: PathBuf,
    pub ttl_hours: u64,
}

/// External API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub nvd: NvdConfig,
    pub ghsa: GhsaConfig,
    pub github: GitHubConfig,
}

/// NVD API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout_seconds: u64,
    pub rate_limit_per_30s: u32,
}

/// GitHub Security Advisories configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhsaConfig {
    pub graphql_url: String,
    pub token: Option<String>,
    pub timeout_seconds: u64,
}

/// GitHub repository analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    pub base_url: String,
    pub token: Option<String>,
    pub reuse_ghsa_token: bool,
    pub timeout_seconds: u64,
    pub max_concurrent_file_fetches: usize,
    pub max_files_scanned: usize,
    pub max_total_bytes: u64,
    pub max_single_file_bytes: u64,
    pub backoff_initial_ms: u64,
    pub backoff_max_retries: u32,
    pub backoff_jitter: bool,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

/// Recommendations configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationsConfig {
    pub max_version_queries_per_request: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3000,
                workers: None,
                enable_docs: true,
                request_timeout_seconds: 30,
                allowed_origins: vec!["*".to_string()],
                security: SecurityConfig {
                    enforce_https: false, // Disabled by default for development
                    enable_security_headers: true,
                    sanitize_errors: false, // Show detailed errors in development
                    hsts_max_age: 31536000, // 1 year
                    hsts_include_subdomains: true,
                },
            },
            cache: CacheConfig {
                directory: PathBuf::from(".vulnera_cache"),
                ttl_hours: 24,
            },
            apis: ApiConfig {
                nvd: NvdConfig {
                    base_url: "https://services.nvd.nist.gov/rest/json".to_string(),
                    api_key: None,
                    timeout_seconds: 30,
                    rate_limit_per_30s: 5, // Without API key
                },
                ghsa: GhsaConfig {
                    graphql_url: "https://api.github.com/graphql".to_string(),
                    token: None,
                    timeout_seconds: 30,
                },
                github: GitHubConfig {
                    base_url: "https://api.github.com".to_string(),
                    token: None,
                    reuse_ghsa_token: true,
                    timeout_seconds: 30,
                    max_concurrent_file_fetches: 8,
                    max_files_scanned: 200,
                    max_total_bytes: 2_000_000,
                    max_single_file_bytes: 1_000_000,
                    backoff_initial_ms: 500,
                    backoff_max_retries: 3,
                    backoff_jitter: true,
                },
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            recommendations: RecommendationsConfig {
                max_version_queries_per_request: 50,
            },
            popular_packages: None,
        }
    }
}

impl Config {
    /// Load configuration from files and environment variables
    pub fn load() -> Result<Self, config::ConfigError> {
        let mut builder = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false));

        // Add environment-specific config if ENV is set
        if let Ok(env) = std::env::var("ENV") {
            builder = builder
                .add_source(config::File::with_name(&format!("config/{}", env)).required(false));
        }

        // Add local config and environment variables last (highest priority)
        builder = builder
            .add_source(config::File::with_name("config/local").required(false))
            .add_source(config::Environment::with_prefix("VULNERA").separator("__"));

        builder.build()?.try_deserialize()
    }
}
