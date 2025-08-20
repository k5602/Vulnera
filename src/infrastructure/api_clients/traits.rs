//! Traits for vulnerability API clients

use crate::application::errors::VulnerabilityError;
use crate::domain::Package;
use async_trait::async_trait;

/// Raw vulnerability data from external APIs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RawVulnerability {
    pub id: String,
    pub summary: String,
    pub description: String,
    pub severity: Option<String>,
    pub references: Vec<String>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
    pub affected: Vec<AffectedPackageData>,
}

/// Raw affected package data from external APIs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AffectedPackageData {
    pub package: PackageInfo,
    pub ranges: Option<Vec<VersionRangeData>>,
    pub versions: Option<Vec<String>>,
}

/// Package information from external APIs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub ecosystem: String,
    pub purl: Option<String>,
}

/// Version range data from external APIs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionRangeData {
    #[serde(rename = "type")]
    pub range_type: String,
    pub repo: Option<String>,
    pub events: Vec<VersionEventData>,
}

/// Version event data from external APIs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionEventData {
    #[serde(rename = "type")]
    pub event_type: String,
    pub value: String,
}

/// Trait for vulnerability API clients
#[async_trait]
pub trait VulnerabilityApiClient: Send + Sync {
    async fn query_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError>;

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError>;
}
