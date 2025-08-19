//! Application layer error types

use crate::domain::DomainError;
use thiserror::Error;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

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

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Redis pool error: {0}")]
    RedisPool(#[from] deadpool_redis::PoolError),

    #[error("Cache operation failed: {message}")]
    Operation { message: String },

    #[error("Connection failed: {message}")]
    Connection { message: String },
}

impl IntoResponse for ApplicationError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ApplicationError::Domain(domain_error) => match domain_error {
                DomainError::InvalidInput { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
                DomainError::ValidationFailed { .. } => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
                DomainError::NotFound { .. } => (StatusCode::NOT_FOUND, self.to_string()),
                DomainError::Conflict { .. } => (StatusCode::CONFLICT, self.to_string()),
                DomainError::InvalidVersion { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
                DomainError::InvalidEcosystem { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
                DomainError::InvalidVulnerabilityId { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
                DomainError::VersionComparison { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
            },
            ApplicationError::Parse(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ApplicationError::Vulnerability(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            ApplicationError::Cache(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ApplicationError::InvalidEcosystem { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
            ApplicationError::UnsupportedFormat { .. } => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            ApplicationError::Configuration { .. } => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ApplicationError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
            ApplicationError::Json(_) => (StatusCode::BAD_REQUEST, "Invalid JSON format".to_string()),
            ApplicationError::NotFound { .. } => (StatusCode::NOT_FOUND, self.to_string()),
        };

        let body = Json(json!({
            "error": {
                "message": error_message,
                "type": self.error_type(),
                "status": status.as_u16()
            }
        }));

        (status, body).into_response()
    }
}

impl ApplicationError {
    /// Get the error type as a string for API responses
    pub fn error_type(&self) -> &'static str {
        match self {
            ApplicationError::Domain(_) => "domain_error",
            ApplicationError::Parse(_) => "parse_error",
            ApplicationError::Vulnerability(_) => "vulnerability_error",
            ApplicationError::Cache(_) => "cache_error",
            ApplicationError::InvalidEcosystem { .. } => "invalid_ecosystem",
            ApplicationError::UnsupportedFormat { .. } => "unsupported_format",
            ApplicationError::Configuration { .. } => "configuration_error",
            ApplicationError::Io(_) => "io_error",
            ApplicationError::Json(_) => "json_error",
            ApplicationError::NotFound { .. } => "not_found",
        }
    }
}
