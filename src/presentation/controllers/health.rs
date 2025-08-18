//! Health check controller

use axum::{extract::State, http::StatusCode, response::Json};
use chrono::Utc;
use serde_json::json;
use std::time::Instant;

use crate::presentation::controllers::AppState;
use crate::presentation::models::HealthResponse;

/// Basic health check endpoint for liveness probe
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    )
)]
pub async fn health_check(State(_app_state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now(),
        details: None,
    })
}

/// Detailed health check endpoint for readiness probe
#[utoipa::path(
    get,
    path = "/health/detailed",
    tag = "health",
    responses(
        (status = 200, description = "Detailed health information", body = HealthResponse),
        (status = 503, description = "Service is unhealthy", body = HealthResponse)
    )
)]
pub async fn detailed_health_check(
    State(app_state): State<AppState>,
) -> Result<Json<HealthResponse>, (StatusCode, Json<HealthResponse>)> {
    let start_time = Instant::now();
    let mut overall_status = "healthy";
    let mut dependency_statuses = serde_json::Map::new();

    // Check cache service health
    let cache_status = check_cache_health(&app_state).await;
    dependency_statuses.insert("cache".to_string(), json!(cache_status));
    if cache_status.status != "healthy" {
        overall_status = "degraded";
    }

    // Check external API connectivity (placeholder for now)
    let api_statuses = check_external_apis().await;
    dependency_statuses.insert("external_apis".to_string(), json!(api_statuses));

    // Get cache statistics
    if let Ok(cache_stats) = app_state.cache_service.get_cache_statistics().await {
        dependency_statuses.insert(
            "cache_statistics".to_string(),
            json!({
                "hit_rate": cache_stats.hit_rate,
                "total_entries": cache_stats.total_entries,
                "total_size_bytes": cache_stats.total_size_bytes
            }),
        );
    }

    let check_duration = start_time.elapsed();
    let response = HealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now(),
        details: Some(json!({
            "dependencies": dependency_statuses,
            "check_duration_ms": check_duration.as_millis(),
            "uptime": "N/A", // Would be calculated from service start time
            "build_info": {
                "version": env!("CARGO_PKG_VERSION"),
                "build_date": option_env!("VERGEN_BUILD_DATE").unwrap_or("unknown"),
                "git_sha": option_env!("VERGEN_GIT_SHA").unwrap_or("unknown")
            }
        })),
    };

    if overall_status == "healthy" {
        Ok(Json(response))
    } else {
        Err((StatusCode::SERVICE_UNAVAILABLE, Json(response)))
    }
}

/// Check cache service health
async fn check_cache_health(app_state: &AppState) -> HealthCheckResult {
    match app_state.cache_service.get_cache_statistics().await {
        Ok(_) => HealthCheckResult {
            status: "healthy".to_string(),
            message: "Cache service is operational".to_string(),
            last_check: Utc::now(),
        },
        Err(e) => HealthCheckResult {
            status: "unhealthy".to_string(),
            message: format!("Cache service error: {}", e),
            last_check: Utc::now(),
        },
    }
}

/// Check external API connectivity
async fn check_external_apis() -> serde_json::Map<String, serde_json::Value> {
    let mut api_statuses = serde_json::Map::new();

    // OSV API check (placeholder)
    api_statuses.insert(
        "osv_api".to_string(),
        json!({
            "status": "healthy",
            "message": "API connectivity not implemented yet",
            "last_check": Utc::now()
        }),
    );

    // NVD API check (placeholder)
    api_statuses.insert(
        "nvd_api".to_string(),
        json!({
            "status": "healthy",
            "message": "API connectivity not implemented yet",
            "last_check": Utc::now()
        }),
    );

    // GHSA API check (placeholder)
    api_statuses.insert(
        "ghsa_api".to_string(),
        json!({
            "status": "healthy",
            "message": "API connectivity not implemented yet",
            "last_check": Utc::now()
        }),
    );

    api_statuses
}

/// Health check result structure
#[derive(serde::Serialize)]
struct HealthCheckResult {
    status: String,
    message: String,
    last_check: chrono::DateTime<Utc>,
}

/// Prometheus-style metrics endpoint
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "health",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain")
    )
)]
pub async fn metrics(State(app_state): State<AppState>) -> Result<String, StatusCode> {
    let mut metrics = String::new();

    // Add basic service metrics
    metrics.push_str(&format!(
        "# HELP vulnera_info Information about the Vulnera service\n"
    ));
    metrics.push_str(&format!("# TYPE vulnera_info gauge\n"));
    metrics.push_str(&format!(
        "vulnera_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    // Add cache metrics if available
    if let Ok(cache_stats) = app_state.cache_service.get_cache_statistics().await {
        metrics.push_str(&format!(
            "# HELP vulnera_cache_hits_total Total number of cache hits\n"
        ));
        metrics.push_str(&format!("# TYPE vulnera_cache_hits_total counter\n"));
        metrics.push_str(&format!("vulnera_cache_hits_total {}\n", cache_stats.hits));

        metrics.push_str(&format!(
            "# HELP vulnera_cache_misses_total Total number of cache misses\n"
        ));
        metrics.push_str(&format!("# TYPE vulnera_cache_misses_total counter\n"));
        metrics.push_str(&format!(
            "vulnera_cache_misses_total {}\n",
            cache_stats.misses
        ));

        metrics.push_str(&format!(
            "# HELP vulnera_cache_hit_rate Cache hit rate (0.0 to 1.0)\n"
        ));
        metrics.push_str(&format!("# TYPE vulnera_cache_hit_rate gauge\n"));
        metrics.push_str(&format!(
            "vulnera_cache_hit_rate {}\n",
            cache_stats.hit_rate
        ));

        metrics.push_str(&format!(
            "# HELP vulnera_cache_entries_total Total number of cache entries\n"
        ));
        metrics.push_str(&format!("# TYPE vulnera_cache_entries_total gauge\n"));
        metrics.push_str(&format!(
            "vulnera_cache_entries_total {}\n",
            cache_stats.total_entries
        ));

        metrics.push_str(&format!(
            "# HELP vulnera_cache_size_bytes Total cache size in bytes\n"
        ));
        metrics.push_str(&format!("# TYPE vulnera_cache_size_bytes gauge\n"));
        metrics.push_str(&format!(
            "vulnera_cache_size_bytes {}\n",
            cache_stats.total_size_bytes
        ));
    }

    // Add uptime metric (placeholder)
    metrics.push_str(&format!(
        "# HELP vulnera_uptime_seconds Service uptime in seconds\n"
    ));
    metrics.push_str(&format!("# TYPE vulnera_uptime_seconds counter\n"));
    metrics.push_str(&format!("vulnera_uptime_seconds 0\n")); // Placeholder

    Ok(metrics)
}

/// Kubernetes liveness probe endpoint
#[utoipa::path(
    get,
    path = "/health/live",
    tag = "health",
    responses(
        (status = 200, description = "Service is alive")
    )
)]
pub async fn liveness_probe() -> StatusCode {
    // Simple liveness check - if we can respond, we're alive
    StatusCode::OK
}

/// Kubernetes readiness probe endpoint
#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "health",
    responses(
        (status = 200, description = "Service is ready to accept traffic"),
        (status = 503, description = "Service is not ready")
    )
)]
pub async fn readiness_probe(State(app_state): State<AppState>) -> StatusCode {
    // Check if critical dependencies are available
    match app_state.cache_service.get_cache_statistics().await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
