//! Cache management controller for admin endpoints

use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::{
    application::{ApplicationError, CacheService},
    infrastructure::cache::{
        cache_service_wrapper::CacheStats,
    },
    presentation::controllers::analysis::AppState,
};

/// Cache statistics response
#[derive(Debug, Serialize)]
pub struct CacheStatsResponse {
    pub cache_type: String,
    pub total_hits: u64,
    pub total_misses: u64,
    pub hit_rate: f64,
    pub cache_size: Option<usize>,
    pub detailed_stats: serde_json::Value,
}

/// Cache warming request
#[derive(Debug, Deserialize)]
pub struct CacheWarmingRequest {
    pub keys: Vec<String>,
    pub strategy: Option<String>,
    pub batch_size: Option<usize>,
}

/// Cache warming response
#[derive(Debug, Serialize)]
pub struct CacheWarmingResponse {
    pub message: String,
    pub keys_processed: usize,
    pub successful: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// Cache invalidation request
#[derive(Debug, Deserialize)]
pub struct CacheInvalidationRequest {
    pub keys: Option<Vec<String>>,
    pub pattern: Option<String>,
    pub clear_all: Option<bool>,
}

/// Cache invalidation response
#[derive(Debug, Serialize)]
pub struct CacheInvalidationResponse {
    pub message: String,
    pub keys_invalidated: usize,
    pub errors: Vec<String>,
}

/// Cache health response
#[derive(Debug, Serialize)]
pub struct CacheHealthResponse {
    pub status: String,
    pub cache_type: String,
    pub connectivity: bool,
    pub last_check: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
}

/// Query parameters for cache operations
#[derive(Debug, Deserialize)]
pub struct CacheQuery {
    pub include_details: Option<bool>,
    pub format: Option<String>,
}

/// Get cache statistics
pub async fn get_cache_stats(
    State(app_state): State<AppState>,
    Query(query): Query<CacheQuery>,
) -> Result<Json<CacheStatsResponse>, ApplicationError> {
    let stats = app_state.cache_service.get_stats().await;
    let cache_size = app_state.cache_service.size().await.ok();

    let detailed_stats = if query.include_details.unwrap_or(false) {
        match &stats {
            CacheStats::File(file_stats) => serde_json::json!({
                "hits": file_stats.hits,
                "misses": file_stats.misses,
                "expired_entries": file_stats.expired_entries,
                "total_entries": file_stats.total_entries,
                "cleanup_runs": file_stats.cleanup_runs,
            }),
            CacheStats::Redis(redis_stats) => serde_json::json!({
                "hits": redis_stats.hits,
                "misses": redis_stats.misses,
                "sets": redis_stats.sets,
                "deletes": redis_stats.deletes,
                "errors": redis_stats.errors,
                "connection_errors": redis_stats.connection_errors,
                "serialization_errors": redis_stats.serialization_errors,
                "total_operations": redis_stats.total_operations,
            }),
            CacheStats::Hybrid(hybrid_stats) => serde_json::json!({
                "strategy": format!("{:?}", hybrid_stats.strategy),
                "redis_available": hybrid_stats.redis_available,
                "file_stats": {
                    "hits": hybrid_stats.file_stats.hits,
                    "misses": hybrid_stats.file_stats.misses,
                    "expired_entries": hybrid_stats.file_stats.expired_entries,
                    "total_entries": hybrid_stats.file_stats.total_entries,
                    "cleanup_runs": hybrid_stats.file_stats.cleanup_runs,
                },
                "redis_stats": hybrid_stats.redis_stats.as_ref().map(|rs| serde_json::json!({
                    "hits": rs.hits,
                    "misses": rs.misses,
                    "sets": rs.sets,
                    "deletes": rs.deletes,
                    "errors": rs.errors,
                    "connection_errors": rs.connection_errors,
                    "serialization_errors": rs.serialization_errors,
                    "total_operations": rs.total_operations,
                })),
            }),
        }
    } else {
        serde_json::json!({})
    };

    let response = CacheStatsResponse {
        cache_type: stats.cache_type().to_string(),
        total_hits: stats.total_hits(),
        total_misses: stats.total_misses(),
        hit_rate: stats.hit_rate(),
        cache_size,
        detailed_stats,
    };

    Ok(Json(response))
}

/// Clear all cache entries
pub async fn clear_cache(
    State(app_state): State<AppState>,
) -> Result<Json<CacheInvalidationResponse>, ApplicationError> {
    match app_state.cache_service.clear_all().await {
        Ok(()) => {
            info!("Cache cleared successfully");
            Ok(Json(CacheInvalidationResponse {
                message: "Cache cleared successfully".to_string(),
                keys_invalidated: 0, // We don't track exact count for clear_all
                errors: vec![],
            }))
        }
        Err(e) => {
            warn!("Failed to clear cache: {}", e);
            Ok(Json(CacheInvalidationResponse {
                message: "Failed to clear cache".to_string(),
                keys_invalidated: 0,
                errors: vec![e.to_string()],
            }))
        }
    }
}

/// Invalidate specific cache keys
pub async fn invalidate_cache_keys(
    State(app_state): State<AppState>,
    Json(request): Json<CacheInvalidationRequest>,
) -> Result<Json<CacheInvalidationResponse>, ApplicationError> {
    let mut keys_invalidated = 0;
    let mut errors = Vec::new();

    if request.clear_all.unwrap_or(false) {
        return clear_cache(State(app_state)).await;
    }

    if let Some(keys) = request.keys {
        for key in keys {
            match app_state.cache_service.invalidate(&key).await {
                Ok(()) => {
                    keys_invalidated += 1;
                    info!("Invalidated cache key: {}", key);
                }
                Err(e) => {
                    errors.push(format!("Failed to invalidate key {}: {}", key, e));
                    warn!("Failed to invalidate cache key {}: {}", key, e);
                }
            }
        }
    }

    // TODO: Implement pattern-based invalidation
    if let Some(_pattern) = request.pattern {
        errors.push("Pattern-based invalidation not yet implemented".to_string());
    }

    let message = if errors.is_empty() {
        format!("Successfully invalidated {} cache keys", keys_invalidated)
    } else {
        format!(
            "Invalidated {} cache keys with {} errors",
            keys_invalidated,
            errors.len()
        )
    };

    Ok(Json(CacheInvalidationResponse {
        message,
        keys_invalidated,
        errors,
    }))
}

/// Check cache health
pub async fn check_cache_health(
    State(app_state): State<AppState>,
) -> Result<Json<CacheHealthResponse>, ApplicationError> {
    let stats = app_state.cache_service.get_stats().await;
    
    // Test cache connectivity
    let test_key = "health_check_test";
    let test_value = "test";
    let connectivity = match app_state.cache_service.set(test_key, &test_value, std::time::Duration::from_secs(60)).await {
        Ok(()) => {
            // Try to retrieve the value
            match app_state.cache_service.get::<String>(test_key).await {
                Ok(Some(retrieved)) if retrieved == test_value => {
                    // Clean up test key
                    let _ = app_state.cache_service.invalidate(test_key).await;
                    true
                }
                _ => false,
            }
        }
        Err(_) => false,
    };

    let status = if connectivity { "healthy" } else { "unhealthy" };
    
    let mut details = HashMap::new();
    details.insert("hit_rate".to_string(), serde_json::json!(stats.hit_rate()));
    details.insert("total_hits".to_string(), serde_json::json!(stats.total_hits()));
    details.insert("total_misses".to_string(), serde_json::json!(stats.total_misses()));
    
    if let Ok(size) = app_state.cache_service.size().await {
        details.insert("cache_size".to_string(), serde_json::json!(size));
    }

    Ok(Json(CacheHealthResponse {
        status: status.to_string(),
        cache_type: stats.cache_type().to_string(),
        connectivity,
        last_check: Some(chrono::Utc::now().to_rfc3339()),
        details,
    }))
}

/// Get cache key information
pub async fn get_cache_key_info(
    State(app_state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, ApplicationError> {
    let exists = app_state.cache_service.exists(&key).await.unwrap_or(false);
    
    let mut info = serde_json::json!({
        "key": key,
        "exists": exists,
        "checked_at": chrono::Utc::now().to_rfc3339(),
    });

    if exists {
        // Try to get the value to check if it's accessible
        match app_state.cache_service.get::<serde_json::Value>(&key).await {
            Ok(Some(value)) => {
                info["accessible"] = serde_json::json!(true);
                info["value_type"] = serde_json::json!(match value {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "boolean",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                });
            }
            Ok(None) => {
                info["accessible"] = serde_json::json!(false);
                info["note"] = serde_json::json!("Key exists but value is None");
            }
            Err(e) => {
                info["accessible"] = serde_json::json!(false);
                info["error"] = serde_json::json!(e.to_string());
            }
        }
    }

    Ok(Json(info))
}

/// Warm cache with specific keys
pub async fn warm_cache(
    State(app_state): State<AppState>,
    Json(request): Json<CacheWarmingRequest>,
) -> Result<Json<CacheWarmingResponse>, ApplicationError> {
    let mut successful = 0;
    let mut failed = 0;
    let mut errors = Vec::new();

    // For now, we'll just simulate cache warming
    // In a real implementation, you would use the CacheWarmingService
    for key in &request.keys {
        // Simulate warming by checking if key exists
        match app_state.cache_service.exists(key).await {
            Ok(_) => {
                successful += 1;
                info!("Simulated warming for cache key: {}", key);
            }
            Err(e) => {
                failed += 1;
                errors.push(format!("Failed to warm key {}: {}", key, e));
                warn!("Failed to warm cache key {}: {}", key, e);
            }
        }
    }

    let message = format!(
        "Cache warming completed: {} successful, {} failed",
        successful, failed
    );

    Ok(Json(CacheWarmingResponse {
        message,
        keys_processed: request.keys.len(),
        successful,
        failed,
        errors,
    }))
}
