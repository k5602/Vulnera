//! Application Layer - Use cases and application services
//!
//! This module orchestrates the business logic and coordinates between
//! the domain and infrastructure layers.

pub mod errors;
pub mod services;
pub mod use_cases;

#[cfg(test)]
mod tests;

pub use errors::*;
pub use services::*;
pub use services::{RepositoryAnalysisInput, RepositoryAnalysisService};
pub use use_cases::*;

use async_trait::async_trait;

/// Version upgrade recommendations for a package.
/// - nearest_safe_above_current: minimal safe version >= current (if current known)
/// - most_up_to_date_safe: newest safe version available (may equal nearest)
#[derive(Debug, Clone)]
pub struct VersionRecommendation {
    pub nearest_safe_above_current: Option<crate::domain::Version>,
    pub most_up_to_date_safe: Option<crate::domain::Version>,
    pub notes: Vec<String>,
}

/// Service API to compute safe version recommendations using OSV + GHSA data
/// and available versions from registries (provided by infrastructure).
#[async_trait]
pub trait VersionResolutionService: Send + Sync {
    async fn recommend(
        &self,
        ecosystem: crate::domain::Ecosystem,
        name: &str,
        current: Option<crate::domain::Version>,
        vulnerabilities: &[crate::domain::Vulnerability],
    ) -> Result<VersionRecommendation, crate::application::errors::ApplicationError>;
}
