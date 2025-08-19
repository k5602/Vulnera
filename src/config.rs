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
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub directory: PathBuf,
    pub ttl_hours: u64,
    pub redis: Option<RedisConfig>,
    pub strategy: CacheStrategy,
}

/// Redis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub connection_timeout_seconds: u64,
    pub command_timeout_seconds: u64,
    pub retry_attempts: u32,
    pub key_prefix: String,
    pub enable_compression: bool,
    pub max_key_length: usize,
}

/// Cache strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheStrategy {
    FileOnly,
    RedisOnly,
    RedisWithFileFallback,
    Hybrid,
}

/// External API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub osv: OsvConfig,
    pub nvd: NvdConfig,
    pub ghsa: GhsaConfig,
}

/// OSV API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvConfig {
    pub base_url: String,
    pub timeout_seconds: u64,
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

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3000,
                workers: None,
            },
            cache: CacheConfig {
                directory: PathBuf::from(".vulnera_cache"),
                ttl_hours: 24,
                redis: None,
                strategy: CacheStrategy::FileOnly,
            },
            apis: ApiConfig {
                osv: OsvConfig {
                    base_url: "https://api.osv.dev/v1".to_string(),
                    timeout_seconds: 30,
                },
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
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
        }
    }
}

impl Config {
    /// Load configuration from files and environment variables
    pub fn load() -> Result<Self, config::ConfigError> {
        let mut builder = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false))
            .add_source(config::Environment::with_prefix("VULNERA").separator("__"));

        // Override with environment-specific config if ENV is set
        if let Ok(env) = std::env::var("ENV") {
            builder = builder
                .add_source(config::File::with_name(&format!("config/{}", env)).required(false));
        }

        builder.build()?.try_deserialize()
    }
}
