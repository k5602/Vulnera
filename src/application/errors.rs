//! Application layer error types

use crate::domain::DomainError;
use thiserror::Error;

/// Application-level errors
#[derive(Error, Debug)]
pub enum ApplicationError {
    #[error("Domain error: {0}")]
    Domain(#[from] DomainError),

    #[error("Parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Vulnerability lookup error: {0}")]
    Vulnerability(#[from] VulnerabilityError),

    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),

    #[error("Invalid ecosystem: {ecosystem}")]
    InvalidEcosystem { ecosystem: String },

    #[error("File format not supported: {filename}")]
    UnsupportedFormat { filename: String },

    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Resource not found: {resource} with id {id}")]
    NotFound { resource: String, id: String },
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Invalid YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Invalid version format: {version}")]
    Version { version: String },

    #[error("Missing required field: {field}")]
    MissingField { field: String },
}

#[derive(Error, Debug)]
pub enum VulnerabilityError {
    #[error("API error: {0}")]
    Api(#[from] ApiError),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Rate limit exceeded for {api}")]
    RateLimit { api: String },

    #[error("Timeout occurred after {seconds}s")]
    Timeout { seconds: u64 },

    #[error("Domain object creation failed: {message}")]
    DomainCreation { message: String },
}

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP error {status}: {message}")]
    Http { status: u16, message: String },

    #[error("Authentication failed")]
    Authentication,

    #[error("Service unavailable")]
    ServiceUnavailable,
}

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Cache key not found: {key}")]
    KeyNotFound { key: String },

    #[error("Cache entry expired: {key}")]
    Expired { key: String },
}
