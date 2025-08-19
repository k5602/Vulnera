//! Cache service wrapper to handle different cache implementations

use std::{sync::Arc, time::Duration};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    application::{ApplicationError, CacheService},
    infrastructure::cache::{
        file_cache::FileCacheRepository,
        redis_cache::RedisCacheRepository,
        hybrid_cache::HybridCacheRepository,
    },
};

/// Wrapper enum for different cache service implementations
pub enum CacheServiceWrapper {
    File(Arc<FileCacheRepository>),
    Redis(Arc<RedisCacheRepository>),
    Hybrid(Arc<HybridCacheRepository>),
}

impl CacheServiceWrapper {
    /// Create a file cache wrapper
    pub fn file(cache: Arc<FileCacheRepository>) -> Self {
        Self::File(cache)
    }

    /// Create a Redis cache wrapper
    pub fn redis(cache: Arc<RedisCacheRepository>) -> Self {
        Self::Redis(cache)
    }

    /// Create a hybrid cache wrapper
    pub fn hybrid(cache: Arc<HybridCacheRepository>) -> Self {
        Self::Hybrid(cache)
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        match self {
            Self::File(cache) => CacheStats::File(cache.get_stats().await),
            Self::Redis(cache) => CacheStats::Redis(cache.get_stats().await),
            Self::Hybrid(cache) => CacheStats::Hybrid(cache.get_combined_stats().await),
        }
    }

    /// Get cache statistics (alias for compatibility)
    pub async fn get_cache_statistics(&self) -> Result<CacheStats, ApplicationError> {
        Ok(self.get_stats().await)
    }

    /// Clear all cache entries
    pub async fn clear_all(&self) -> Result<(), ApplicationError> {
        match self {
            Self::File(cache) => cache.clear_all().await,
            Self::Redis(cache) => cache.clear_all().await,
            Self::Hybrid(cache) => cache.clear_all().await,
        }
    }

    /// Check if a key exists
    pub async fn exists(&self, key: &str) -> Result<bool, ApplicationError> {
        match self {
            Self::File(cache) => cache.exists(key).await,
            Self::Redis(cache) => cache.exists(key).await,
            Self::Hybrid(_) => {
                // For hybrid, we'll use the get method to check existence
                let result: Option<serde_json::Value> = self.get(key).await?;
                Ok(result.is_some())
            }
        }
    }

    /// Get cache size
    pub async fn size(&self) -> Result<usize, ApplicationError> {
        match self {
            Self::File(cache) => cache.size().await,
            Self::Redis(cache) => cache.size().await,
            Self::Hybrid(_) => {
                // For hybrid, we can't easily get the combined size
                // Return 0 as a placeholder
                Ok(0)
            }
        }
    }
}

#[async_trait]
impl CacheService for CacheServiceWrapper {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: for<'de> Deserialize<'de> + Serialize + Send + Sync,
    {
        match self {
            Self::File(cache) => cache.get(key).await,
            Self::Redis(cache) => cache.get(key).await,
            Self::Hybrid(cache) => cache.get(key).await,
        }
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: Serialize + Send + Sync,
    {
        match self {
            Self::File(cache) => cache.set(key, value, ttl).await,
            Self::Redis(cache) => cache.set(key, value, ttl).await,
            Self::Hybrid(cache) => cache.set(key, value, ttl).await,
        }
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        match self {
            Self::File(cache) => cache.invalidate(key).await,
            Self::Redis(cache) => cache.invalidate(key).await,
            Self::Hybrid(cache) => cache.invalidate(key).await,
        }
    }
}

/// Combined cache statistics
#[derive(Debug, Clone)]
pub enum CacheStats {
    File(crate::infrastructure::cache::file_cache::CacheStats),
    Redis(crate::infrastructure::cache::redis_cache::RedisCacheStats),
    Hybrid(crate::infrastructure::cache::hybrid_cache::HybridCacheStats),
}

impl CacheStats {
    /// Get total hits across all cache types
    pub fn total_hits(&self) -> u64 {
        match self {
            Self::File(stats) => stats.hits,
            Self::Redis(stats) => stats.hits,
            Self::Hybrid(stats) => {
                let mut total = stats.file_stats.hits;
                if let Some(redis_stats) = &stats.redis_stats {
                    total += redis_stats.hits;
                }
                total
            }
        }
    }

    /// Get total misses across all cache types
    pub fn total_misses(&self) -> u64 {
        match self {
            Self::File(stats) => stats.misses,
            Self::Redis(stats) => stats.misses,
            Self::Hybrid(stats) => {
                let mut total = stats.file_stats.misses;
                if let Some(redis_stats) = &stats.redis_stats {
                    total += redis_stats.misses;
                }
                total
            }
        }
    }

    /// Get cache hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let hits = self.total_hits();
        let misses = self.total_misses();
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }

    /// Get cache type as string
    pub fn cache_type(&self) -> &'static str {
        match self {
            Self::File(_) => "File",
            Self::Redis(_) => "Redis",
            Self::Hybrid(_) => "Hybrid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cache_wrapper_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_cache = Arc::new(FileCacheRepository::new(
            temp_dir.path().to_path_buf(),
            Duration::from_secs(3600),
        ));
        
        let wrapper = CacheServiceWrapper::file(file_cache);
        
        // Test basic operations
        let key = "test_key";
        let value = "test_value";
        let ttl = Duration::from_secs(60);
        
        wrapper.set(key, &value, ttl).await.unwrap();
        let retrieved: Option<String> = wrapper.get(key).await.unwrap();
        assert_eq!(retrieved.as_deref(), Some(value));
        
        wrapper.invalidate(key).await.unwrap();
        let after_invalidate: Option<String> = wrapper.get(key).await.unwrap();
        assert!(after_invalidate.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let file_stats = crate::infrastructure::cache::file_cache::CacheStats {
            hits: 10,
            misses: 5,
            expired_entries: 2,
            total_entries: 8,
            cleanup_runs: 1,
        };
        
        let stats = CacheStats::File(file_stats);
        assert_eq!(stats.total_hits(), 10);
        assert_eq!(stats.total_misses(), 5);
        assert_eq!(stats.hit_rate(), 66.66666666666667);
        assert_eq!(stats.cache_type(), "File");
    }
}
