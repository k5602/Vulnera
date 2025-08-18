//! Domain-specific error types

use thiserror::Error;

/// Domain-level errors for vulnerability analysis
#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Invalid version format: {version}")]
    InvalidVersion { version: String },

    #[error("Invalid ecosystem: {ecosystem}")]
    InvalidEcosystem { ecosystem: String },

    #[error("Invalid vulnerability ID: {id}")]
    InvalidVulnerabilityId { id: String },

    #[error("Version comparison failed: {reason}")]
    VersionComparison { reason: String },

    #[error("Invalid input for field {field}: {message}")]
    InvalidInput { field: String, message: String },
}
