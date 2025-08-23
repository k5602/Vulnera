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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeImpact {
    Major,
    Minor,
    Patch,
    Unknown,
}

/// Compute semantic upgrade impact between current and target versions.
/// Returns Major/Minor/Patch when target is higher than current on that axis, Unknown otherwise.
pub fn compute_upgrade_impact(
    current: &crate::domain::Version,
    target: &crate::domain::Version,
) -> UpgradeImpact {
    let c = &current.0;
    let t = &target.0;
    if t.major > c.major {
        UpgradeImpact::Major
    } else if t.major == c.major && t.minor > c.minor {
        UpgradeImpact::Minor
    } else if t.major == c.major && t.minor == c.minor && t.patch > c.patch {
        UpgradeImpact::Patch
    } else {
        UpgradeImpact::Unknown
    }
}

/// Options to control version resolution behavior. The implementation may
/// read defaults from environment variables for convenience.
///
/// Supported env override:
/// - VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=true|false (default: false)
#[derive(Debug, Clone)]
pub struct VersionResolutionOptions {
    pub exclude_prereleases: bool,
}

impl Default for VersionResolutionOptions {
    fn default() -> Self {
        let exclude = std::env::var("VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false);
        Self {
            exclude_prereleases: exclude,
        }
    }
}

/// Version upgrade recommendations for a package.
/// - nearest_safe_above_current: minimal safe version >= current (if current known)
/// - most_up_to_date_safe: newest safe version available (may equal nearest)
#[derive(Debug, Clone)]
pub struct VersionRecommendation {
    /// Minimal safe version >= current (if current known)
    pub nearest_safe_above_current: Option<crate::domain::Version>,
    /// Newest safe version available (may equal nearest)
    pub most_up_to_date_safe: Option<crate::domain::Version>,
    /// Next safe version within the current major (minor bump or patch), if available
    pub next_safe_minor_within_current_major: Option<crate::domain::Version>,
    /// Classification of the nearest upgrade impact (major/minor/patch/unknown)
    pub nearest_impact: Option<UpgradeImpact>,
    /// Classification of the most up-to-date upgrade impact (major/minor/patch/unknown)
    pub most_up_to_date_impact: Option<UpgradeImpact>,
    /// Whether prerelease versions were excluded due to configuration
    pub prerelease_exclusion_applied: bool,
    /// Additional notes about the recommendation process
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
