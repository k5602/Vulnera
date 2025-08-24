//! Health check controller

use axum::{extract::State, http::StatusCode, response::Json};
use chrono::Utc;

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
    metrics.push_str("# HELP vulnera_info Information about the Vulnera service\n");
    metrics.push_str("# TYPE vulnera_info gauge\n");
    metrics.push_str(&format!(
        "vulnera_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    // Add cache metrics if available
    if let Ok(cache_stats) = app_state.cache_service.get_cache_statistics().await {
        metrics.push_str("# HELP vulnera_cache_hits_total Total number of cache hits\n");
        metrics.push_str("# TYPE vulnera_cache_hits_total counter\n");
        metrics.push_str(&format!("vulnera_cache_hits_total {}\n", cache_stats.hits));

        metrics.push_str("# HELP vulnera_cache_misses_total Total number of cache misses\n");
        metrics.push_str("# TYPE vulnera_cache_misses_total counter\n");
        metrics.push_str(&format!(
            "vulnera_cache_misses_total {}\n",
            cache_stats.misses
        ));

        metrics.push_str("# HELP vulnera_cache_hit_rate Cache hit rate (0.0 to 1.0)\n");
        metrics.push_str("# TYPE vulnera_cache_hit_rate gauge\n");
        metrics.push_str(&format!(
            "vulnera_cache_hit_rate {}\n",
            cache_stats.hit_rate
        ));

        metrics.push_str("# HELP vulnera_cache_entries_total Total number of cache entries\n");
        metrics.push_str("# TYPE vulnera_cache_entries_total gauge\n");
        metrics.push_str(&format!(
            "vulnera_cache_entries_total {}\n",
            cache_stats.total_entries
        ));

        metrics.push_str("# HELP vulnera_cache_size_bytes Total cache size in bytes\n");
        metrics.push_str("# TYPE vulnera_cache_size_bytes gauge\n");
        metrics.push_str(&format!(
            "vulnera_cache_size_bytes {}\n",
            cache_stats.total_size_bytes
        ));
    }

    // Add uptime metric (placeholder)
    metrics.push_str("# HELP vulnera_uptime_seconds Service uptime in seconds\n");
    metrics.push_str("# TYPE vulnera_uptime_seconds counter\n");
    metrics.push_str("vulnera_uptime_seconds 0\n"); // Placeholder

    Ok(metrics)
}
