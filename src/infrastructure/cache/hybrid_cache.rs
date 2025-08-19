//! Hybrid cache implementation that combines Redis and file caching

use std::{sync::Arc, time::Duration};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, warn};

use crate::{
    application::{ApplicationError, CacheService, CacheError},
    config::CacheStrategy,
    infrastructure::cache::{
        file_cache::FileCacheRepository,
        redis_cache::RedisCacheRepository,
    },
};

/// Hybrid cache repository that combines Redis and file caching
pub struct HybridCacheRepository {
    redis_cache: Option<Arc<RedisCacheRepository>>,
    file_cache: Arc<FileCacheRepository>,
    strategy: CacheStrategy,
}

impl HybridCacheRepository {
    /// Create a new hybrid cache repository
    pub fn new(
        redis_cache: Option<Arc<RedisCacheRepository>>,
        file_cache: Arc<FileCacheRepository>,
        strategy: CacheStrategy,
    ) -> Self {
        Self {
            redis_cache,
            file_cache,
            strategy,
        }
    }

    /// Check if Redis is available
    fn has_redis(&self) -> bool {
        self.redis_cache.is_some()
    }

    /// Get from Redis first, then file cache as fallback
    async fn get_with_fallback<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: for<'de> Deserialize<'de> + Serialize + Send + Sync,
    {
        // Try Redis first if available
        if let Some(redis) = &self.redis_cache {
            match redis.get(key).await {
                Ok(Some(value)) => {
                    debug!("Cache hit from Redis for key: {}", key);
                    return Ok(Some(value));
                }
                Ok(None) => {
                    debug!("Cache miss from Redis for key: {}", key);
                }
                Err(e) => {
                    warn!("Redis cache error, falling back to file cache: {}", e);
                }
            }
        }

        // Fallback to file cache
        match self.file_cache.get(key).await {
            Ok(Some(value)) => {
                debug!("Cache hit from file cache for key: {}", key);
                
                // If we have Redis and got a hit from file cache, populate Redis
                if let Some(redis) = &self.redis_cache {
                    let default_ttl = Duration::from_secs(3600); // 1 hour default
                    if let Err(e) = redis.set(key, &value, default_ttl).await {
                        warn!("Failed to populate Redis cache from file cache: {}", e);
                    } else {
                        debug!("Populated Redis cache from file cache for key: {}", key);
                    }
                }
                
                Ok(Some(value))
            }
            Ok(None) => {
                debug!("Cache miss from file cache for key: {}", key);
                Ok(None)
            }
            Err(e) => {
                error!("File cache error: {}", e);
                Err(e)
            }
        }
    }

    /// Set to both Redis and file cache
    async fn set_to_both<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: Serialize + Send + Sync,
    {
        let mut redis_result = Ok(());

        // Set to Redis if available
        if let Some(redis) = &self.redis_cache {
            redis_result = redis.set(key, value, ttl).await;
            if let Err(ref e) = redis_result {
                warn!("Failed to set Redis cache for key {}: {}", key, e);
            }
        }

        // Set to file cache
        let file_result = self.file_cache.set(key, value, ttl).await;
        if let Err(ref e) = file_result {
            error!("Failed to set file cache for key {}: {}", key, e);
        }

        // Return error only if both failed
        match (redis_result, file_result) {
            (Err(redis_err), Err(file_err)) => {
                error!("Both Redis and file cache failed for key {}: Redis: {}, File: {}", 
                       key, redis_err, file_err);
                Err(file_err) // Return file cache error as primary
            }
            (Err(_), Ok(())) => {
                debug!("Redis failed but file cache succeeded for key: {}", key);
                Ok(())
            }
            (Ok(()), Err(_)) => {
                debug!("File cache failed but Redis succeeded for key: {}", key);
                Ok(())
            }
            (Ok(()), Ok(())) => {
                debug!("Successfully set cache in both Redis and file for key: {}", key);
                Ok(())
            }
        }
    }

    /// Invalidate from both Redis and file cache
    async fn invalidate_both(&self, key: &str) -> Result<(), ApplicationError> {
        let mut redis_result = Ok(());

        // Invalidate from Redis if available
        if let Some(redis) = &self.redis_cache {
            redis_result = redis.invalidate(key).await;
            if let Err(ref e) = redis_result {
                warn!("Failed to invalidate Redis cache for key {}: {}", key, e);
            }
        }

        // Invalidate from file cache
        let file_result = self.file_cache.invalidate(key).await;
        if let Err(ref e) = file_result {
            warn!("Failed to invalidate file cache for key {}: {}", key, e);
        }

        // Return success if at least one succeeded
        match (redis_result, file_result) {
            (Err(redis_err), Err(file_err)) => {
                error!("Both Redis and file cache invalidation failed for key {}: Redis: {}, File: {}", 
                       key, redis_err, file_err);
                Err(file_err) // Return file cache error as primary
            }
            _ => {
                debug!("Successfully invalidated cache for key: {}", key);
                Ok(())
            }
        }
    }

    /// Get cache statistics from both caches
    pub async fn get_combined_stats(&self) -> HybridCacheStats {
        let file_stats = self.file_cache.get_stats().await;
        
        let redis_stats = if let Some(redis) = &self.redis_cache {
            Some(redis.get_stats().await)
        } else {
            None
        };

        HybridCacheStats {
            file_stats,
            redis_stats,
            strategy: self.strategy.clone(),
            redis_available: self.has_redis(),
        }
    }

    /// Clear all caches
    pub async fn clear_all(&self) -> Result<(), ApplicationError> {
        let mut errors = Vec::new();

        // Clear Redis if available
        if let Some(redis) = &self.redis_cache {
            if let Err(e) = redis.clear_all().await {
                errors.push(format!("Redis clear failed: {}", e));
            }
        }

        // Clear file cache
        if let Err(e) = self.file_cache.clear_all().await {
            errors.push(format!("File cache clear failed: {}", e));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ApplicationError::Cache(CacheError::Operation {
                message: format!("Cache clear errors: {}", errors.join(", "))
            }))
        }
    }
}

/// Combined cache statistics
#[derive(Debug, Clone)]
pub struct HybridCacheStats {
    pub file_stats: crate::infrastructure::cache::file_cache::CacheStats,
    pub redis_stats: Option<crate::infrastructure::cache::redis_cache::RedisCacheStats>,
    pub strategy: CacheStrategy,
    pub redis_available: bool,
}

#[async_trait]
impl CacheService for HybridCacheRepository {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: for<'de> Deserialize<'de> + Serialize + Send + Sync,
    {
        match self.strategy {
            CacheStrategy::FileOnly => self.file_cache.get(key).await,
            CacheStrategy::RedisOnly => {
                if let Some(redis) = &self.redis_cache {
                    redis.get(key).await
                } else {
                    Err(ApplicationError::Cache(CacheError::Operation {
                        message: "Redis cache not available but RedisOnly strategy selected".to_string()
                    }))
                }
            }
            CacheStrategy::RedisWithFileFallback | CacheStrategy::Hybrid => {
                self.get_with_fallback(key).await
            }
        }
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: Serialize + Send + Sync,
    {
        match self.strategy {
            CacheStrategy::FileOnly => self.file_cache.set(key, value, ttl).await,
            CacheStrategy::RedisOnly => {
                if let Some(redis) = &self.redis_cache {
                    redis.set(key, value, ttl).await
                } else {
                    Err(ApplicationError::Cache(CacheError::Operation {
                        message: "Redis cache not available but RedisOnly strategy selected".to_string()
                    }))
                }
            }
            CacheStrategy::RedisWithFileFallback => {
                if let Some(redis) = &self.redis_cache {
                    match redis.set(key, value, ttl).await {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            warn!("Redis set failed, falling back to file cache: {}", e);
                            self.file_cache.set(key, value, ttl).await
                        }
                    }
                } else {
                    self.file_cache.set(key, value, ttl).await
                }
            }
            CacheStrategy::Hybrid => self.set_to_both(key, value, ttl).await,
        }
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        match self.strategy {
            CacheStrategy::FileOnly => self.file_cache.invalidate(key).await,
            CacheStrategy::RedisOnly => {
                if let Some(redis) = &self.redis_cache {
                    redis.invalidate(key).await
                } else {
                    Err(ApplicationError::Cache(CacheError::Operation {
                        message: "Redis cache not available but RedisOnly strategy selected".to_string()
                    }))
                }
            }
            CacheStrategy::RedisWithFileFallback => {
                if let Some(redis) = &self.redis_cache {
                    match redis.invalidate(key).await {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            warn!("Redis invalidate failed, falling back to file cache: {}", e);
                            self.file_cache.invalidate(key).await
                        }
                    }
                } else {
                    self.file_cache.invalidate(key).await
                }
            }
            CacheStrategy::Hybrid => self.invalidate_both(key).await,
        }
    }
}
