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
