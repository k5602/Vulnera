//! API request and response models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Request model for dependency analysis
#[derive(Deserialize, ToSchema)]
pub struct AnalysisRequest {
    /// The dependency file content to analyze for vulnerabilities
    #[schema(
        example = r#"{"dependencies": {"express": "4.17.1", "lodash": "4.17.21", "axios": "0.21.0"}}"#
    )]
    pub file_content: String,

    /// The package ecosystem type
    #[schema(example = "npm")]
    pub ecosystem: String,

    /// Optional filename for automatic ecosystem detection
    #[schema(example = "package.json")]
    pub filename: Option<String>,
}

/// Response model for analysis results
#[derive(Serialize, ToSchema)]
pub struct AnalysisResponse {
    /// Unique analysis ID for tracking and retrieval
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,

    /// List of vulnerabilities found in the analyzed dependencies
    pub vulnerabilities: Vec<VulnerabilityDto>,

    /// Comprehensive analysis metadata and statistics
    pub metadata: AnalysisMetadataDto,

    /// Pagination information for large result sets
    pub pagination: PaginationDto,
}

/// DTO for vulnerability information
#[derive(Serialize, ToSchema)]
pub struct VulnerabilityDto {
    /// Unique vulnerability identifier (CVE, GHSA, etc.)
    #[schema(example = "CVE-2021-23337")]
    pub id: String,

    /// Brief vulnerability summary
    #[schema(example = "Prototype Pollution in lodash")]
    pub summary: String,

    /// Detailed vulnerability description
    #[schema(
        example = "lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution via the zipObjectDeep function."
    )]
    pub description: String,

    /// Severity level of the vulnerability
    #[schema(example = "High")]
    pub severity: String,

    /// List of packages affected by this vulnerability
    pub affected_packages: Vec<AffectedPackageDto>,

    /// Reference URLs for more information
    #[schema(
        example = r#"["https://nvd.nist.gov/vuln/detail/CVE-2021-23337", "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"]"#
    )]
    pub references: Vec<String>,

    /// Vulnerability publication date
    #[schema(example = "2021-02-15T10:30:00Z")]
    pub published_at: DateTime<Utc>,

    /// Data sources that provided this vulnerability information
    #[schema(example = r#"["OSV", "NVD", "GHSA"]"#)]
    pub sources: Vec<String>,
}

/// DTO for affected package information
#[derive(Serialize, ToSchema)]
pub struct AffectedPackageDto {
    /// Package name in the ecosystem
    #[schema(example = "lodash")]
    pub name: String,

    /// Current package version found in dependencies
    #[schema(example = "4.17.20")]
    pub version: String,

    /// Package ecosystem
    #[schema(example = "npm")]
    pub ecosystem: String,

    /// Version ranges affected by the vulnerability
    #[schema(example = r#"["< 4.17.21", ">= 4.0.0"]"#)]
    pub vulnerable_ranges: Vec<String>,

    /// Versions that fix the vulnerability
    #[schema(example = r#"["4.17.21", "5.0.0"]"#)]
    pub fixed_versions: Vec<String>,
}

/// DTO for analysis metadata
#[derive(Serialize, ToSchema)]
pub struct AnalysisMetadataDto {
    /// Total number of packages analyzed from the dependency file
    #[schema(example = 25)]
    pub total_packages: usize,

    /// Number of packages with known vulnerabilities
    #[schema(example = 3)]
    pub vulnerable_packages: usize,

    /// Total number of unique vulnerabilities discovered
    #[schema(example = 5)]
    pub total_vulnerabilities: usize,

    /// Vulnerability count breakdown by severity level
    pub severity_breakdown: SeverityBreakdownDto,

    /// Time taken to complete the analysis in milliseconds
    #[schema(example = 1250)]
    pub analysis_duration_ms: u64,

    /// List of vulnerability databases that were consulted
    #[schema(example = r#"["OSV", "NVD", "GHSA"]"#)]
    pub sources_queried: Vec<String>,
}

/// DTO for severity breakdown
#[derive(Serialize, ToSchema)]
pub struct SeverityBreakdownDto {
    /// Number of critical severity vulnerabilities
    #[schema(example = 1)]
    pub critical: usize,

    /// Number of high severity vulnerabilities
    #[schema(example = 2)]
    pub high: usize,

    /// Number of medium severity vulnerabilities
    #[schema(example = 1)]
    pub medium: usize,

    /// Number of low severity vulnerabilities
    #[schema(example = 1)]
    pub low: usize,
}

/// DTO for pagination information
#[derive(Serialize, ToSchema)]
pub struct PaginationDto {
    /// Current page number (1-based indexing)
    #[schema(example = 1, minimum = 1)]
    pub page: u32,

    /// Number of items per page
    #[schema(example = 50, minimum = 1, maximum = 500)]
    pub per_page: u32,

    /// Total number of items across all pages
    #[schema(example = 150)]
    pub total: u64,

    /// Total number of pages available
    #[schema(example = 3)]
    pub total_pages: u32,

    /// Whether there are additional pages after the current one
    #[schema(example = true)]
    pub has_next: bool,

    /// Whether there are pages before the current one
    #[schema(example = false)]
    pub has_prev: bool,
}

/// Error response model
#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Machine-readable error code
    #[schema(example = "PARSE_ERROR")]
    pub code: String,

    /// Human-readable error message
    #[schema(example = "Failed to parse dependency file: Invalid JSON format")]
    pub message: String,

    /// Additional error context and debugging information
    #[schema(example = r#"{"field": "file_content", "line": 5, "column": 12}"#)]
    pub details: Option<serde_json::Value>,

    /// Unique request identifier for tracking and support
    #[schema(example = "req_550e8400-e29b-41d4-a716-446655440000")]
    pub request_id: Uuid,

    /// Error occurrence timestamp
    #[schema(example = "2024-01-15T10:30:00Z")]
    pub timestamp: DateTime<Utc>,
}

/// Health check response
#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// Overall service health status
    #[schema(example = "healthy")]
    pub status: String,

    /// Current service version
    #[schema(example = "1.0.0")]
    pub version: String,

    /// Health check timestamp
    #[schema(example = "2024-01-15T10:30:00Z")]
    pub timestamp: DateTime<Utc>,

    /// Detailed health information and dependency status
    #[schema(
        example = r#"{"dependencies": {"cache": {"status": "healthy"}, "external_apis": {"osv": "healthy", "nvd": "healthy"}}}"#
    )]
    pub details: Option<serde_json::Value>,
}

/// Response for vulnerability listing
#[derive(Serialize, ToSchema)]
pub struct VulnerabilityListResponse {
    /// Array of vulnerability details matching the query criteria
    pub vulnerabilities: Vec<VulnerabilityDto>,

    /// Pagination metadata for navigating through results
    pub pagination: PaginationDto,
}
