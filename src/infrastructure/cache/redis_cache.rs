//! Redis-based cache implementation with connection pooling and advanced features

use std::{sync::Arc, time::Duration};
use async_trait::async_trait;
use deadpool_redis::{Config as RedisConfig, Pool, Runtime};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::{
    application::{ApplicationError, CacheService, CacheError},
    config::RedisConfig as AppRedisConfig,
};

/// Redis cache entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisCacheEntry<T> {
    pub data: T,
    pub created_at: u64,
    pub expires_at: u64,
    pub access_count: u64,
    pub version: u32,
}

/// Cache statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct RedisCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub sets: u64,
    pub deletes: u64,
    pub errors: u64,
    pub connection_errors: u64,
    pub serialization_errors: u64,
    pub total_operations: u64,
}

/// Redis cache repository with connection pooling and advanced features
pub struct RedisCacheRepository {
    pool: Pool,
    key_prefix: String,
    enable_compression: bool,
    max_key_length: usize,
    stats: Arc<Mutex<RedisCacheStats>>,
    default_ttl: Duration,
}

impl RedisCacheRepository {
    /// Create a new Redis cache repository
    pub async fn new(config: &AppRedisConfig, default_ttl: Duration) -> Result<Self, ApplicationError> {
        let redis_config = RedisConfig::from_url(&config.url);
        
        let pool = redis_config
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| {
                error!("Failed to create Redis connection pool: {}", e);
                ApplicationError::Cache(CacheError::Connection {
                    message: format!("Redis pool creation failed: {}", e)
                })
            })?;

        // Test the connection
        let mut conn = pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::Connection {
                message: format!("Redis connection failed: {}", e)
            })
        })?;

        // Ping Redis to ensure connectivity
        let _: String = redis::cmd("PING").query_async(&mut conn).await.map_err(|e| {
            error!("Redis ping failed: {}", e);
            ApplicationError::Cache(CacheError::Redis(e))
        })?;

        info!("Redis cache repository initialized successfully");

        Ok(Self {
            pool,
            key_prefix: config.key_prefix.clone(),
            enable_compression: config.enable_compression,
            max_key_length: config.max_key_length,
            stats: Arc::new(Mutex::new(RedisCacheStats::default())),
            default_ttl,
        })
    }

    /// Generate a prefixed cache key
    fn cache_key(&self, key: &str) -> Result<String, ApplicationError> {
        let full_key = format!("{}{}", self.key_prefix, key);
        
        if full_key.len() > self.max_key_length {
            return Err(ApplicationError::Cache(CacheError::Operation {
                message: format!(
                    "Cache key too long: {} > {}",
                    full_key.len(),
                    self.max_key_length
                )
            }));
        }

        Ok(full_key)
    }

    /// Get current timestamp in seconds
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Check if cache entry is expired
    fn is_entry_expired<T>(entry: &RedisCacheEntry<T>) -> bool {
        Self::current_timestamp() > entry.expires_at
    }

    /// Serialize data with optional compression
    fn serialize_data<T>(&self, data: &T) -> Result<Vec<u8>, ApplicationError>
    where
        T: Serialize,
    {
        let json_data = serde_json::to_vec(data).map_err(|e| {
            error!("Failed to serialize data: {}", e);
            ApplicationError::Json(e)
        })?;

        if self.enable_compression {
            // TODO: Add compression support (e.g., using flate2)
            Ok(json_data)
        } else {
            Ok(json_data)
        }
    }

    /// Deserialize data with optional decompression
    fn deserialize_data<T>(&self, data: &[u8]) -> Result<T, ApplicationError>
    where
        T: for<'de> Deserialize<'de>,
    {
        if self.enable_compression {
            // TODO: Add decompression support
            serde_json::from_slice(data).map_err(|e| {
                error!("Failed to deserialize data: {}", e);
                ApplicationError::Json(e)
            })
        } else {
            serde_json::from_slice(data).map_err(|e| {
                error!("Failed to deserialize data: {}", e);
                ApplicationError::Json(e)
            })
        }
    }

    /// Update cache statistics
    async fn update_stats<F>(&self, update_fn: F)
    where
        F: FnOnce(&mut RedisCacheStats),
    {
        let mut stats = self.stats.lock().await;
        update_fn(&mut stats);
        stats.total_operations += 1;
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> RedisCacheStats {
        self.stats.lock().await.clone()
    }

    /// Clear all cache statistics
    pub async fn clear_stats(&self) {
        let mut stats = self.stats.lock().await;
        *stats = RedisCacheStats::default();
    }

    /// Check if a key exists in the cache
    pub async fn exists(&self, key: &str) -> Result<bool, ApplicationError> {
        let cache_key = self.cache_key(key)?;
        
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::RedisPool(e))
        })?;

        let exists: bool = conn.exists(&cache_key).await.map_err(|e| {
            error!("Redis EXISTS command failed: {}", e);
            ApplicationError::Cache(CacheError::Redis(e))
        })?;

        Ok(exists)
    }

    /// Get cache size (number of keys with our prefix)
    pub async fn size(&self) -> Result<usize, ApplicationError> {
        let pattern = format!("{}*", self.key_prefix);
        
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::Connection {
                message: format!("Redis connection failed: {}", e)
            })
        })?;

        let keys: Vec<String> = conn.keys(&pattern).await.map_err(|e| {
            error!("Redis KEYS command failed: {}", e);
            ApplicationError::Cache(CacheError::Redis(e))
        })?;

        Ok(keys.len())
    }

    /// Clear all cache entries with our prefix
    pub async fn clear_all(&self) -> Result<(), ApplicationError> {
        let pattern = format!("{}*", self.key_prefix);
        
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::Connection {
                message: format!("Redis connection failed: {}", e)
            })
        })?;

        let keys: Vec<String> = conn.keys(&pattern).await.map_err(|e| {
            error!("Redis KEYS command failed: {}", e);
            ApplicationError::Cache(CacheError::Redis(e))
        })?;

        if !keys.is_empty() {
            let _: () = conn.del(&keys).await.map_err(|e| {
                error!("Redis DEL command failed: {}", e);
                ApplicationError::Cache(CacheError::Redis(e))
            })?;
            
            info!("Cleared {} cache entries", keys.len());
        }

        Ok(())
    }

    /// Set cache entry with TTL
    pub async fn set_with_ttl<T>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> Result<(), ApplicationError>
    where
        T: Serialize + Send + Sync,
    {
        let cache_key = self.cache_key(key)?;
        let now = Self::current_timestamp();
        let expires_at = now + ttl.as_secs();

        let entry = RedisCacheEntry {
            data: value,
            created_at: now,
            expires_at,
            access_count: 0,
            version: 1,
        };

        let serialized_data = self.serialize_data(&entry)?;

        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::Connection {
                message: format!("Redis connection failed: {}", e)
            })
        })?;

        let _: () = conn
            .set_ex(&cache_key, serialized_data, ttl.as_secs())
            .await
            .map_err(|e| {
                error!("Redis SET command failed: {}", e);
                ApplicationError::Cache(CacheError::Redis(e))
            })?;

        self.update_stats(|stats| {
            stats.connection_errors += 1;
            stats.sets += 1;
        }).await;
        debug!("Cached entry with key: {}", cache_key);

        Ok(())
    }

    /// Get cache entry and update access count
    pub async fn get_with_stats<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: for<'de> Deserialize<'de> + Serialize + Send + Sync,
    {
        let cache_key = self.cache_key(key)?;

        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::Connection {
                message: format!("Redis connection failed: {}", e)
            })
        })?;

        let data: Option<Vec<u8>> = conn.get(&cache_key).await.map_err(|e| {
            error!("Redis GET command failed: {}", e);
            ApplicationError::Cache(CacheError::Redis(e))
        })?;

        match data {
            Some(bytes) => {
                let entry: RedisCacheEntry<T> = self.deserialize_data(&bytes)?;

                if Self::is_entry_expired(&entry) {
                    // Remove expired entry
                    let _: () = conn.del(&cache_key).await.map_err(|e| {
                        warn!("Failed to delete expired cache entry: {}", e);
                        ApplicationError::Cache(CacheError::Redis(e))
                    })?;

                    debug!("Cache entry expired and removed: {}", cache_key);
                    Ok(None)
                } else {
                    // Update access count (fire and forget)
                    let updated_entry = RedisCacheEntry {
                        data: entry.data,
                        created_at: entry.created_at,
                        expires_at: entry.expires_at,
                        access_count: entry.access_count + 1,
                        version: entry.version,
                    };

                    if let Ok(updated_data) = self.serialize_data(&updated_entry) {
                        let ttl_remaining = entry.expires_at.saturating_sub(Self::current_timestamp());
                        if ttl_remaining > 0 {
                            let _: Result<(), _> = conn.set_ex(&cache_key, updated_data, ttl_remaining).await;
                        }
                    }

                    debug!("Cache hit for key: {}", cache_key);
                    Ok(Some(updated_entry.data))
                }
            }
            None => {
                debug!("Cache miss for key: {}", cache_key);
                Ok(None)
            }
        }
    }

    /// Delete cache entry
    pub async fn delete(&self, key: &str) -> Result<bool, ApplicationError> {
        let cache_key = self.cache_key(key)?;

        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::Connection {
                message: format!("Redis connection failed: {}", e)
            })
        })?;

        let deleted: u32 = conn.del(&cache_key).await.map_err(|e| {
            error!("Redis DEL command failed: {}", e);
            ApplicationError::Cache(CacheError::Redis(e))
        })?;

        let was_deleted = deleted > 0;
        if was_deleted {
            self.update_stats(|stats| stats.deletes += 1).await;
            debug!("Deleted cache entry: {}", cache_key);
        }

        Ok(was_deleted)
    }

    /// Get multiple cache entries at once
    pub async fn get_multiple<T>(&self, keys: &[&str]) -> Result<Vec<(String, Option<T>)>, ApplicationError>
    where
        T: for<'de> Deserialize<'de> + Send,
    {
        if keys.is_empty() {
            return Ok(vec![]);
        }

        let cache_keys: Result<Vec<String>, ApplicationError> = keys
            .iter()
            .map(|key| self.cache_key(key))
            .collect();
        let cache_keys = cache_keys?;

        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::Connection {
                message: format!("Redis connection failed: {}", e)
            })
        })?;

        let data: Vec<Option<Vec<u8>>> = conn.get(&cache_keys).await.map_err(|e| {
            error!("Redis MGET command failed: {}", e);
            ApplicationError::Cache(CacheError::Redis(e))
        })?;

        let mut results = Vec::with_capacity(keys.len());

        for (i, (original_key, data_opt)) in keys.iter().zip(data.iter()).enumerate() {
            match data_opt {
                Some(bytes) => {
                    match self.deserialize_data::<RedisCacheEntry<T>>(bytes) {
                        Ok(entry) => {
                            if Self::is_entry_expired(&entry) {
                                // Remove expired entry (fire and forget)
                                let _: Result<(), _> = conn.del(&cache_keys[i]).await;
                                self.update_stats(|stats| stats.misses += 1).await;
                                results.push((original_key.to_string(), None));
                            } else {
                                self.update_stats(|stats| stats.hits += 1).await;
                                results.push((original_key.to_string(), Some(entry.data)));
                            }
                        }
                        Err(_) => {
                            self.update_stats(|stats| stats.serialization_errors += 1).await;
                            results.push((original_key.to_string(), None));
                        }
                    }
                }
                None => {
                    self.update_stats(|stats| stats.misses += 1).await;
                    results.push((original_key.to_string(), None));
                }
            }
        }

        Ok(results)
    }

    /// Set multiple cache entries at once
    pub async fn set_multiple<T>(
        &self,
        entries: &[(&str, &T, Duration)],
    ) -> Result<(), ApplicationError>
    where
        T: Serialize + Send + Sync,
    {
        if entries.is_empty() {
            return Ok(());
        }

        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get Redis connection: {}", e);
            ApplicationError::Cache(CacheError::Connection {
                message: format!("Redis connection failed: {}", e)
            })
        })?;

        let now = Self::current_timestamp();

        for (key, value, ttl) in entries {
            let cache_key = self.cache_key(key)?;
            let expires_at = now + ttl.as_secs();

            let entry = RedisCacheEntry {
                data: *value,
                created_at: now,
                expires_at,
                access_count: 0,
                version: 1,
            };

            let serialized_data = self.serialize_data(&entry)?;

            let _: () = conn
                .set_ex(&cache_key, serialized_data, ttl.as_secs())
                .await
                .map_err(|e| {
                    error!("Redis SET command failed: {}", e);
                    ApplicationError::Cache(CacheError::Redis(e))
                })?;

            self.update_stats(|stats| stats.sets += 1).await;
        }

        debug!("Set {} cache entries", entries.len());
        Ok(())
    }

    /// Get the default TTL for this cache
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Set a value with the default TTL
    pub async fn set_with_default_ttl<T>(&self, key: &str, value: &T) -> Result<(), ApplicationError>
    where
        T: Serialize + Send + Sync,
    {
        self.set_with_ttl(key, value, self.default_ttl).await
    }
}

#[async_trait]
impl CacheService for RedisCacheRepository {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: for<'de> Deserialize<'de> + Serialize + Send + Sync,
    {
        self.get_with_stats(key).await
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: Serialize + Send + Sync,
    {
        self.set_with_ttl(key, value, ttl).await
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        self.delete(key).await?;
        Ok(())
    }
}
