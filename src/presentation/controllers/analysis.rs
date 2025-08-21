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
    PaginationDto, RepositoryAnalysisMetadataDto, RepositoryAnalysisRequest,
    RepositoryAnalysisResponse, RepositoryConfigCapsDto, RepositoryDescriptorDto,
    RepositoryFileResultDto, RepositoryPackageDto, SeverityBreakdownDto, VulnerabilityDto,
    VulnerabilityListResponse,
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
    pub cache_service: Arc<crate::application::CacheServiceImpl>,
    pub report_service: Arc<crate::application::ReportServiceImpl>,
    pub vulnerability_repository: Arc<dyn crate::infrastructure::VulnerabilityRepository>,
    pub popular_package_service: Arc<dyn crate::application::PopularPackageService>,
    pub repository_analysis_service: Option<Arc<dyn crate::application::RepositoryAnalysisService>>, // optional until fully wired
}

/// Analyze an entire repository (stub implementation)
#[utoipa::path(
    post,
    path = "/api/v1/analyze/repository",
    tag = "repository",
    request_body = RepositoryAnalysisRequest,
    responses(
        (status = 200, description = "Repository analysis completed", body = RepositoryAnalysisResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn analyze_repository(
    State(app_state): State<AppState>,
    Json(request): Json<RepositoryAnalysisRequest>,
) -> Result<Json<RepositoryAnalysisResponse>, ApplicationError> {
    let service = match &app_state.repository_analysis_service {
        Some(s) => s.clone(),
        None => {
            return Err(ApplicationError::Configuration {
                message: "Repository analysis not enabled".into(),
            });
        }
    };
    // Derive owner/repo
    let (owner, repo, derived_ref) = if let Some(url) = &request.repository_url {
        if let Some(parsed) = crate::infrastructure::repository_source::parse_github_repo_url(url) {
            (parsed.owner, parsed.repo, parsed.r#ref)
        } else {
            return Err(ApplicationError::Domain(
                crate::domain::DomainError::InvalidInput {
                    field: "repository_url".into(),
                    message: "Invalid GitHub repository URL".into(),
                },
            ));
        }
    } else {
        let owner = request.owner.clone().ok_or_else(|| {
            ApplicationError::Domain(crate::domain::DomainError::InvalidInput {
                field: "owner".into(),
                message: "owner is required".into(),
            })
        })?;
        let repo = request.repo.clone().ok_or_else(|| {
            ApplicationError::Domain(crate::domain::DomainError::InvalidInput {
                field: "repo".into(),
                message: "repo is required".into(),
            })
        })?;
        (owner, repo, None)
    };

    let effective_ref = request.r#ref.clone().or(derived_ref);

    let input = crate::application::RepositoryAnalysisInput {
        owner: owner.clone(),
        repo: repo.clone(),
        requested_ref: effective_ref.clone(),
        include_paths: request.include_paths.clone(),
        exclude_paths: request.exclude_paths.clone(),
        max_files: request.max_files.unwrap_or(100),
        include_lockfiles: request.include_lockfiles.unwrap_or(true),
        return_packages: request.return_packages.unwrap_or(false),
    };

    let result = match service.analyze_repository(input).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                error = %e,
                owner = request.owner.as_deref().unwrap_or(""),
                repo = request.repo.as_deref().unwrap_or(""),
                repo_url = request.repository_url.as_deref().unwrap_or(""),
                r#ref = request.r#ref.as_deref().unwrap_or(""),
                "Repository analysis failed"
            );
            return Err(e);
        }
    };

    let files: Vec<RepositoryFileResultDto> = result
        .files
        .iter()
        .map(|f| RepositoryFileResultDto {
            path: f.path.clone(),
            ecosystem: f
                .ecosystem
                .as_ref()
                .map(|e| format!("{:?}", e).to_lowercase()),
            packages_count: f.packages.len() as u32,
            packages: if request.return_packages.unwrap_or(false) {
                Some(
                    f.packages
                        .iter()
                        .map(|p| RepositoryPackageDto {
                            name: p.name.clone(),
                            version: p.version.to_string(),
                            ecosystem: format!("{:?}", p.ecosystem).to_lowercase(),
                        })
                        .collect(),
                )
            } else {
                None
            },
            error: f.error.clone(),
        })
        .collect();

    let vulnerabilities: Vec<VulnerabilityDto> = result
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
                .map(|ap| AffectedPackageDto {
                    name: ap.package.name.clone(),
                    version: ap.package.version.to_string(),
                    ecosystem: format!("{:?}", ap.package.ecosystem).to_lowercase(),
                    vulnerable_ranges: ap
                        .vulnerable_ranges
                        .iter()
                        .map(|r| format!("{:?}", r))
                        .collect(),
                    fixed_versions: ap.fixed_versions.iter().map(|fx| fx.to_string()).collect(),
                })
                .collect(),
            references: v.references.clone(),
            published_at: v.published_at,
            sources: v.sources.iter().map(|s| format!("{:?}", s)).collect(),
        })
        .collect();

    let metadata = RepositoryAnalysisMetadataDto {
        total_files_scanned: result.total_files_scanned,
        analyzed_files: result.analyzed_files,
        skipped_files: result.skipped_files,
        unique_packages: result.unique_packages,
        total_vulnerabilities: result.vulnerabilities.len() as u32,
        severity_breakdown: SeverityBreakdownDto {
            critical: result.severity_breakdown.critical,
            high: result.severity_breakdown.high,
            medium: result.severity_breakdown.medium,
            low: result.severity_breakdown.low,
        },
        duration_ms: result.duration.as_millis() as u64,
        file_errors: result.file_errors,
        rate_limit_remaining: result.rate_limit_remaining,
        truncated: result.truncated,
        config_caps: RepositoryConfigCapsDto {
            max_files_scanned: result.total_files_scanned.max(result.analyzed_files),
            max_total_bytes: 2_000_000,
        },
    };

    let response = RepositoryAnalysisResponse {
        id: result.id,
        repository: RepositoryDescriptorDto {
            owner,
            repo,
            requested_ref: effective_ref,
            commit_sha: result.commit_sha,
            source_url: request.repository_url.clone(),
        },
        files,
        vulnerabilities,
        metadata,
    };

    Ok(Json(response))
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
    State(app_state): State<AppState>,
    Query(pagination): Query<VulnerabilityListQuery>,
) -> Result<Json<VulnerabilityListResponse>, ApplicationError> {
    tracing::info!("Listing vulnerabilities with pagination and filters");

    // Validate pagination parameters
    let (page, per_page) = pagination.validate()?;

    // Validate severity filter if provided
    if let Some(ref severity_filter) = pagination.severity {
        match severity_filter.to_lowercase().as_str() {
            "critical" | "high" | "medium" | "low" => {}
            _ => {
                return Err(ApplicationError::Domain(
                    crate::domain::DomainError::InvalidInput {
                        field: "severity".to_string(),
                        message:
                            "Invalid severity filter. Must be one of: critical, high, medium, low"
                                .to_string(),
                    },
                ));
            }
        }
    }

    // Use the popular package service to get vulnerabilities efficiently
    let result = app_state
        .popular_package_service
        .list_vulnerabilities(
            page,
            per_page,
            pagination.ecosystem.as_deref(),
            pagination.severity.as_deref(),
        )
        .await?;

    // Convert to DTOs
    let vulnerabilities: Vec<VulnerabilityDto> = result
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
                    vulnerable_ranges: p.vulnerable_ranges.iter().map(|r| r.to_string()).collect(),
                    fixed_versions: p.fixed_versions.iter().map(|v| v.to_string()).collect(),
                })
                .collect(),
            references: v.references.clone(),
            published_at: v.published_at,
            sources: v.sources.iter().map(|s| format!("{:?}", s)).collect(),
        })
        .collect();

    let total_pages = if result.total_count == 0 {
        1
    } else {
        ((result.total_count as f64) / (per_page as f64)).ceil() as u32
    };

    let pagination_dto = PaginationDto {
        page,
        per_page,
        total: result.total_count,
        total_pages,
        has_next: page < total_pages,
        has_prev: page > 1,
    };

    let response = VulnerabilityListResponse {
        vulnerabilities,
        pagination: pagination_dto,
    };

    tracing::info!(
        "Retrieved {} vulnerabilities (page {} of {}, total: {}, cache: {})",
        response.vulnerabilities.len(),
        page,
        total_pages,
        result.total_count,
        result.cache_status
    );

    Ok(Json(response))
}

/// Refresh popular packages vulnerability cache
#[utoipa::path(
    post,
    path = "/api/v1/vulnerabilities/refresh-cache",
    tag = "vulnerabilities",
    responses(
        (status = 200, description = "Cache refreshed successfully"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn refresh_vulnerability_cache(
    State(app_state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApplicationError> {
    tracing::info!("Refreshing popular packages vulnerability cache");

    app_state.popular_package_service.refresh_cache().await?;

    let response = serde_json::json!({
        "message": "Popular packages vulnerability cache refreshed successfully",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    tracing::info!("Cache refresh completed successfully");
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

    // Retrieve analysis report from the file cache system
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
