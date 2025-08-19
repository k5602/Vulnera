//! Analysis controller for vulnerability analysis endpoints

use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::application::{CacheService, errors::ApplicationError};
use crate::domain::{Ecosystem, VulnerabilityId};
use crate::presentation::models::{
    AffectedPackageDto, AnalysisMetadataDto, AnalysisRequest, AnalysisResponse, ErrorResponse,
    PaginationDto, SeverityBreakdownDto, VulnerabilityDto, VulnerabilityListResponse,
};

/// Query parameters for pagination
#[derive(Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// Query parameters for vulnerability listing with filters
#[derive(Deserialize)]
pub struct VulnerabilityListQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub severity: Option<String>,
    pub ecosystem: Option<String>,
}

impl PaginationQuery {
    /// Validate and normalize pagination parameters
    pub fn validate(&self) -> Result<(u32, u32), ApplicationError> {
        let page = self.page.unwrap_or(1);
        let per_page = self.per_page.unwrap_or(50);

        // Validate page number
        if page < 1 {
            return Err(ApplicationError::Domain(
                crate::domain::DomainError::InvalidInput {
                    field: "page".to_string(),
                    message: "Page number must be greater than 0".to_string(),
                },
            ));
        }

        // Validate per_page limits
        if per_page < 1 {
            return Err(ApplicationError::Domain(
                crate::domain::DomainError::InvalidInput {
                    field: "per_page".to_string(),
                    message: "Items per page must be greater than 0".to_string(),
                },
            ));
        }

        if per_page > 500 {
            return Err(ApplicationError::Domain(
                crate::domain::DomainError::InvalidInput {
                    field: "per_page".to_string(),
                    message: "Items per page cannot exceed 500".to_string(),
                },
            ));
        }

        Ok((page, per_page))
    }
}

impl VulnerabilityListQuery {
    /// Validate and normalize pagination parameters
    pub fn validate(&self) -> Result<(u32, u32), ApplicationError> {
        let page = self.page.unwrap_or(1);
        let per_page = self.per_page.unwrap_or(50);

        // Validate page number
        if page < 1 {
            return Err(ApplicationError::Domain(
                crate::domain::DomainError::InvalidInput {
                    field: "page".to_string(),
                    message: "Page number must be greater than 0".to_string(),
                },
            ));
        }

        // Validate per_page limits
        if per_page < 1 {
            return Err(ApplicationError::Domain(
                crate::domain::DomainError::InvalidInput {
                    field: "per_page".to_string(),
                    message: "Items per page must be greater than 0".to_string(),
                },
            ));
        }

        if per_page > 500 {
            return Err(ApplicationError::Domain(
                crate::domain::DomainError::InvalidInput {
                    field: "per_page".to_string(),
                    message: "Items per page cannot exceed 500".to_string(),
                },
            ));
        }

        Ok((page, per_page))
    }
}

/// Application state containing services
#[derive(Clone)]
pub struct AppState {
    pub analysis_service: Arc<dyn crate::application::AnalysisService>,
    pub cache_service: Arc<crate::infrastructure::cache::cache_service_wrapper::CacheServiceWrapper>,
    pub report_service: Arc<crate::application::ReportServiceImpl>,
}

/// Analyze dependencies endpoint
#[utoipa::path(
    post,
    path = "/api/v1/analyze",
    tag = "analysis",
    request_body = AnalysisRequest,
    responses(
        (status = 200, description = "Analysis completed successfully", body = AnalysisResponse),
        (status = 400, description = "Invalid request format", body = ErrorResponse),
        (status = 422, description = "Unsupported file format", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn analyze_dependencies(
    State(app_state): State<AppState>,
    Json(request): Json<AnalysisRequest>,
) -> Result<Json<AnalysisResponse>, ApplicationError> {
    tracing::info!(
        "Starting dependency analysis for ecosystem: {}",
        request.ecosystem
    );

    // Parse ecosystem from string
    let ecosystem = match request.ecosystem.to_lowercase().as_str() {
        "npm" => Ecosystem::Npm,
        "pypi" | "pip" | "python" => Ecosystem::PyPI,
        "maven" => Ecosystem::Maven,
        "cargo" | "rust" => Ecosystem::Cargo,
        "go" => Ecosystem::Go,
        "packagist" | "composer" | "php" => Ecosystem::Packagist,
        _ => {
            return Err(ApplicationError::InvalidEcosystem {
                ecosystem: request.ecosystem,
            });
        }
    };

    // Perform analysis
    let analysis_report = app_state
        .analysis_service
        .analyze_dependencies(&request.file_content, ecosystem)
        .await?;

    // Convert domain model to DTO
    let vulnerabilities: Vec<VulnerabilityDto> = analysis_report
        .vulnerabilities
        .iter()
        .map(|v| VulnerabilityDto {
            id: v.id.as_str().to_string(),
            summary: v.summary.clone(),
            description: v.description.clone(),
            severity: format!("{:?}", v.severity),
            affected_packages: v
                .affected_packages
                .iter()
                .map(|p| AffectedPackageDto {
                    name: p.package.name.clone(),
                    version: p.package.version.to_string(),
                    ecosystem: format!("{:?}", p.package.ecosystem),
                    vulnerable_ranges: p
                        .vulnerable_ranges
                        .iter()
                        .map(|r| format!("{:?}", r))
                        .collect(),
                    fixed_versions: p.fixed_versions.iter().map(|v| v.to_string()).collect(),
                })
                .collect(),
            references: v.references.clone(),
            published_at: v.published_at,
            sources: v.sources.iter().map(|s| format!("{:?}", s)).collect(),
        })
        .collect();

    let metadata = AnalysisMetadataDto {
        total_packages: analysis_report.metadata.total_packages,
        vulnerable_packages: analysis_report.metadata.vulnerable_packages,
        total_vulnerabilities: analysis_report.metadata.total_vulnerabilities,
        severity_breakdown: SeverityBreakdownDto {
            critical: analysis_report.metadata.severity_breakdown.critical,
            high: analysis_report.metadata.severity_breakdown.high,
            medium: analysis_report.metadata.severity_breakdown.medium,
            low: analysis_report.metadata.severity_breakdown.low,
        },
        analysis_duration_ms: analysis_report.metadata.analysis_duration.as_millis() as u64,
        sources_queried: analysis_report.metadata.sources_queried,
    };

    let pagination = PaginationDto {
        page: 1,
        per_page: vulnerabilities.len() as u32,
        total: vulnerabilities.len() as u64,
        total_pages: 1,
        has_next: false,
        has_prev: false,
    };

    let response = AnalysisResponse {
        id: analysis_report.id,
        vulnerabilities,
        metadata,
        pagination,
    };

    tracing::info!(
        "Analysis completed: {} vulnerabilities found",
        response.vulnerabilities.len()
    );

    Ok(Json(response))
}

/// Get vulnerability details endpoint
#[utoipa::path(
    get,
    path = "/api/v1/vulnerabilities/{id}",
    tag = "vulnerabilities",
    params(
        ("id" = String, Path, description = "Vulnerability ID")
    ),
    responses(
        (status = 200, description = "Vulnerability details", body = VulnerabilityDto),
        (status = 404, description = "Vulnerability not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_vulnerability(
    State(app_state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<VulnerabilityDto>, ApplicationError> {
    tracing::info!("Fetching vulnerability details for ID: {}", id);

    let vulnerability_id = VulnerabilityId::new(id).map_err(|e| {
        ApplicationError::Domain(crate::domain::DomainError::InvalidVulnerabilityId { id: e })
    })?;
    let vulnerability = app_state
        .analysis_service
        .get_vulnerability_details(&vulnerability_id)
        .await?;

    let vulnerability_dto = VulnerabilityDto {
        id: vulnerability.id.as_str().to_string(),
        summary: vulnerability.summary,
        description: vulnerability.description,
        severity: format!("{:?}", vulnerability.severity),
        affected_packages: vulnerability
            .affected_packages
            .iter()
            .map(|p| AffectedPackageDto {
                name: p.package.name.clone(),
                version: p.package.version.to_string(),
                ecosystem: format!("{:?}", p.package.ecosystem),
                vulnerable_ranges: p
                    .vulnerable_ranges
                    .iter()
                    .map(|r| format!("{:?}", r))
                    .collect(),
                fixed_versions: p.fixed_versions.iter().map(|v| v.to_string()).collect(),
            })
            .collect(),
        references: vulnerability.references,
        published_at: vulnerability.published_at,
        sources: vulnerability
            .sources
            .iter()
            .map(|s| format!("{:?}", s))
            .collect(),
    };

    tracing::info!(
        "Successfully retrieved vulnerability: {}",
        vulnerability_id.as_str()
    );
    Ok(Json(vulnerability_dto))
}

/// List vulnerabilities with pagination
#[utoipa::path(
    get,
    path = "/api/v1/vulnerabilities",
    tag = "vulnerabilities",
    params(
        ("page" = Option<u32>, Query, description = "Page number (1-based)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 500)"),
        ("severity" = Option<String>, Query, description = "Filter by severity (critical, high, medium, low)"),
        ("ecosystem" = Option<String>, Query, description = "Filter by ecosystem")
    ),
    responses(
        (status = 200, description = "List of vulnerabilities", body = VulnerabilityListResponse),
        (status = 400, description = "Invalid pagination parameters", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn list_vulnerabilities(
    State(_app_state): State<AppState>,
    Query(pagination): Query<VulnerabilityListQuery>,
) -> Result<Json<VulnerabilityListResponse>, ApplicationError> {
    tracing::info!("Listing vulnerabilities with pagination");

    // Validate pagination parameters
    let (page, per_page) = pagination.validate()?;

    // For now, return an empty list since we don't have a vulnerability database yet
    // In a real implementation, this would query the vulnerability repository
    let vulnerabilities = Vec::new();
    let total_count = 0u64;
    let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as u32;

    let pagination_dto = PaginationDto {
        page,
        per_page,
        total: total_count,
        total_pages,
        has_next: page < total_pages,
        has_prev: page > 1,
    };

    let response = VulnerabilityListResponse {
        vulnerabilities,
        pagination: pagination_dto,
    };

    tracing::info!(
        "Retrieved {} vulnerabilities (page {} of {})",
        response.vulnerabilities.len(),
        page,
        total_pages
    );

    Ok(Json(response))
}

/// Get analysis report endpoint
#[utoipa::path(
    get,
    path = "/api/v1/reports/{id}",
    tag = "analysis",
    params(
        ("id" = Uuid, Path, description = "Analysis report ID"),
        ("page" = Option<u32>, Query, description = "Page number (1-based)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 500)")
    ),
    responses(
        (status = 200, description = "Analysis report", body = AnalysisResponse),
        (status = 404, description = "Report not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_analysis_report(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<AnalysisResponse>, ApplicationError> {
    tracing::info!("Fetching analysis report for ID: {}", id);

    // Validate pagination parameters
    let (page, per_page) = pagination.validate()?;

    // For now, we'll return a placeholder response since we don't have persistent storage yet
    // In a real implementation, this would fetch from a database or cache
    let cache_key = format!("analysis_report:{}", id);

    // Try to get cached analysis report
    if let Some(cached_report) = app_state
        .cache_service
        .get::<crate::domain::AnalysisReport>(&cache_key)
        .await?
    {
        tracing::info!("Found cached analysis report: {}", id);

        // Apply pagination to vulnerabilities
        let total_vulnerabilities = cached_report.vulnerabilities.len() as u64;
        let start_index = ((page - 1) * per_page) as usize;
        let end_index = (start_index + per_page as usize).min(cached_report.vulnerabilities.len());

        let paginated_vulnerabilities = if start_index < cached_report.vulnerabilities.len() {
            &cached_report.vulnerabilities[start_index..end_index]
        } else {
            &[]
        };

        let vulnerabilities: Vec<VulnerabilityDto> = paginated_vulnerabilities
            .iter()
            .map(|v| VulnerabilityDto {
                id: v.id.as_str().to_string(),
                summary: v.summary.clone(),
                description: v.description.clone(),
                severity: format!("{:?}", v.severity),
                affected_packages: v
                    .affected_packages
                    .iter()
                    .map(|p| AffectedPackageDto {
                        name: p.package.name.clone(),
                        version: p.package.version.to_string(),
                        ecosystem: format!("{:?}", p.package.ecosystem),
                        vulnerable_ranges: p
                            .vulnerable_ranges
                            .iter()
                            .map(|r| r.to_string())
                            .collect(),
                        fixed_versions: p.fixed_versions.iter().map(|v| v.to_string()).collect(),
                    })
                    .collect(),
                references: v.references.clone(),
                published_at: v.published_at,
                sources: v.sources.iter().map(|s| format!("{:?}", s)).collect(),
            })
            .collect();

        let total_pages = ((total_vulnerabilities as f64) / (per_page as f64)).ceil() as u32;

        let metadata = AnalysisMetadataDto {
            total_packages: cached_report.metadata.total_packages,
            vulnerable_packages: cached_report.metadata.vulnerable_packages,
            total_vulnerabilities: cached_report.metadata.total_vulnerabilities,
            severity_breakdown: SeverityBreakdownDto {
                critical: cached_report.metadata.severity_breakdown.critical,
                high: cached_report.metadata.severity_breakdown.high,
                medium: cached_report.metadata.severity_breakdown.medium,
                low: cached_report.metadata.severity_breakdown.low,
            },
            analysis_duration_ms: cached_report.metadata.analysis_duration.as_millis() as u64,
            sources_queried: cached_report.metadata.sources_queried,
        };

        let pagination_dto = PaginationDto {
            page,
            per_page,
            total: total_vulnerabilities,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        };

        let response = AnalysisResponse {
            id: cached_report.id,
            vulnerabilities,
            metadata,
            pagination: pagination_dto,
        };

        tracing::info!(
            "Retrieved analysis report: {} vulnerabilities (page {} of {})",
            response.vulnerabilities.len(),
            page,
            total_pages
        );

        Ok(Json(response))
    } else {
        tracing::warn!("Analysis report not found: {}", id);
        Err(ApplicationError::NotFound {
            resource: "analysis report".to_string(),
            id: id.to_string(),
        })
    }
}
