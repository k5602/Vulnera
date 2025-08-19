//! Cache factory for creating appropriate cache implementations

use std::{sync::Arc, time::Duration};
use tracing::{error, info, warn};

use crate::{
    application::{ApplicationError, CacheService, CacheError},
    config::{CacheConfig, CacheStrategy},
    infrastructure::cache::{
        file_cache::FileCacheRepository,
        redis_cache::RedisCacheRepository,
        hybrid_cache::HybridCacheRepository,
        cache_service_wrapper::CacheServiceWrapper,
    },
};

/// Cache factory for creating cache services based on configuration
pub struct CacheFactory;

impl CacheFactory {
    /// Create a cache service based on the configuration
    pub async fn create_cache_service(
        config: &CacheConfig,
    ) -> Result<CacheServiceWrapper, ApplicationError> {
        let default_ttl = Duration::from_secs(config.ttl_hours * 3600);

        match &config.strategy {
            CacheStrategy::FileOnly => {
                info!("Creating file-only cache service");
                let file_cache = Arc::new(FileCacheRepository::new(
                    config.directory.clone(),
                    default_ttl,
                ));
                Ok(CacheServiceWrapper::file(file_cache))
            }
            CacheStrategy::RedisOnly => {
                info!("Creating Redis-only cache service");
                let redis_config = config.redis.as_ref().ok_or_else(|| {
                    ApplicationError::Cache(CacheError::Operation {
                        message: "Redis configuration required for RedisOnly strategy".to_string()
                    })
                })?;

                let redis_cache = Arc::new(
                    RedisCacheRepository::new(redis_config, default_ttl).await?
                );
                Ok(CacheServiceWrapper::redis(redis_cache))
            }
            CacheStrategy::RedisWithFileFallback => {
                info!("Creating Redis cache with file fallback");
                let file_cache = Arc::new(FileCacheRepository::new(
                    config.directory.clone(),
                    default_ttl,
                ));

                let redis_cache = if let Some(redis_config) = &config.redis {
                    match RedisCacheRepository::new(redis_config, default_ttl).await {
                        Ok(cache) => Some(Arc::new(cache)),
                        Err(e) => {
                            warn!("Failed to create Redis cache, using file cache only: {}", e);
                            None
                        }
                    }
                } else {
                    warn!("No Redis configuration provided, using file cache only");
                    None
                };

                let hybrid_cache = Arc::new(HybridCacheRepository::new(
                    redis_cache,
                    file_cache,
                    config.strategy.clone(),
                ));
                Ok(CacheServiceWrapper::hybrid(hybrid_cache))
            }
            CacheStrategy::Hybrid => {
                info!("Creating hybrid cache service (Redis + File)");
                let file_cache = Arc::new(FileCacheRepository::new(
                    config.directory.clone(),
                    default_ttl,
                ));

                let redis_cache = if let Some(redis_config) = &config.redis {
                    match RedisCacheRepository::new(redis_config, default_ttl).await {
                        Ok(cache) => Some(Arc::new(cache)),
                        Err(e) => {
                            error!("Failed to create Redis cache for hybrid strategy: {}", e);
                            return Err(e);
                        }
                    }
                } else {
                    return Err(ApplicationError::Cache(CacheError::Operation {
                        message: "Redis configuration required for Hybrid strategy".to_string()
                    }));
                };

                let hybrid_cache = Arc::new(HybridCacheRepository::new(
                    redis_cache,
                    file_cache,
                    config.strategy.clone(),
                ));
                Ok(CacheServiceWrapper::hybrid(hybrid_cache))
            }
        }
    }

    /// Create a cache service with automatic fallback strategy
    pub async fn create_with_fallback(
        config: &CacheConfig,
    ) -> CacheServiceWrapper {
        match Self::create_cache_service(config).await {
            Ok(cache) => cache,
            Err(e) => {
                error!("Failed to create configured cache service: {}", e);
                warn!("Falling back to file-only cache");
                
                let default_ttl = Duration::from_secs(config.ttl_hours * 3600);
                let file_cache = Arc::new(FileCacheRepository::new(
                    config.directory.clone(),
                    default_ttl,
                ));
                CacheServiceWrapper::file(file_cache)
            }
        }
    }

    /// Test cache connectivity
    pub async fn test_cache_connectivity(
        cache: &CacheServiceWrapper,
    ) -> Result<(), ApplicationError> {
        let test_key = "connectivity_test";
        let test_value = "test_value";
        let test_ttl = Duration::from_secs(60);

        // Test set operation
        cache.set(test_key, &test_value, test_ttl).await?;

        // Test get operation
        let retrieved: Option<String> = cache.get(test_key).await?;
        if retrieved.as_deref() != Some(test_value) {
            return Err(ApplicationError::Cache(CacheError::Operation {
                message: "Cache connectivity test failed: value mismatch".to_string()
            }));
        }

        // Test invalidate operation
        cache.invalidate(test_key).await?;

        // Verify invalidation
        let after_invalidate: Option<String> = cache.get(test_key).await?;
        if after_invalidate.is_some() {
            return Err(ApplicationError::Cache(CacheError::Operation {
                message: "Cache connectivity test failed: invalidation failed".to_string()
            }));
        }

        info!("Cache connectivity test passed");
        Ok(())
    }

    /// Create cache service for testing with in-memory fallback
    #[cfg(test)]
    pub fn create_test_cache() -> CacheServiceWrapper {
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_cache = Arc::new(FileCacheRepository::new(
            temp_dir.path().to_path_buf(),
            Duration::from_secs(3600),
        ));
        
        // Keep temp_dir alive by leaking it (acceptable for tests)
        std::mem::forget(temp_dir);

        CacheServiceWrapper::file(file_cache)
    }
}

/// Cache health information
#[derive(Debug, Clone)]
pub struct CacheHealth {
    pub strategy: CacheStrategy,
    pub redis_available: bool,
    pub file_cache_available: bool,
    pub last_connectivity_check: Option<std::time::SystemTime>,
    pub connectivity_status: ConnectivityStatus,
}

/// Cache connectivity status
#[derive(Debug, Clone)]
pub enum ConnectivityStatus {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

impl CacheHealth {
    /// Create a new cache health instance
    pub fn new(strategy: CacheStrategy) -> Self {
        Self {
            strategy,
            redis_available: false,
            file_cache_available: true, // File cache is always available
            last_connectivity_check: None,
            connectivity_status: ConnectivityStatus::Healthy,
        }
    }

    /// Update health status based on cache test results
    pub fn update_status(&mut self, test_result: Result<(), ApplicationError>) {
        self.last_connectivity_check = Some(std::time::SystemTime::now());
        
        match test_result {
            Ok(()) => {
                self.connectivity_status = ConnectivityStatus::Healthy;
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("Redis") {
                    self.redis_available = false;
                    match self.strategy {
                        CacheStrategy::RedisOnly => {
                            self.connectivity_status = ConnectivityStatus::Unhealthy(error_msg);
                        }
                        CacheStrategy::RedisWithFileFallback | CacheStrategy::Hybrid => {
                            self.connectivity_status = ConnectivityStatus::Degraded(error_msg);
                        }
                        CacheStrategy::FileOnly => {
                            // Redis error doesn't affect file-only strategy
                        }
                    }
                } else {
                    self.connectivity_status = ConnectivityStatus::Unhealthy(error_msg);
                }
            }
        }
    }

    /// Check if cache is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self.connectivity_status, ConnectivityStatus::Healthy)
    }

    /// Check if cache is degraded but functional
    pub fn is_degraded(&self) -> bool {
        matches!(self.connectivity_status, ConnectivityStatus::Degraded(_))
    }

    /// Get health status as string
    pub fn status_string(&self) -> String {
        match &self.connectivity_status {
            ConnectivityStatus::Healthy => "Healthy".to_string(),
            ConnectivityStatus::Degraded(msg) => format!("Degraded: {}", msg),
            ConnectivityStatus::Unhealthy(msg) => format!("Unhealthy: {}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_only_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = CacheConfig {
            directory: temp_dir.path().to_path_buf(),
            ttl_hours: 1,
            redis: None,
            strategy: CacheStrategy::FileOnly,
        };

        let cache = CacheFactory::create_cache_service(&config).await.unwrap();
        assert!(CacheFactory::test_cache_connectivity(&cache).await.is_ok());
    }

    #[tokio::test]
    async fn test_cache_health() {
        let mut health = CacheHealth::new(CacheStrategy::FileOnly);
        assert!(health.is_healthy());

        health.update_status(Err(ApplicationError::Cache(CacheError::Operation {
            message: "Test error".to_string()
        })));
        assert!(!health.is_healthy());
        assert!(health.status_string().contains("Unhealthy"));
    }
}
