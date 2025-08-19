//! Cache strategies and warming implementations

use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::{
    application::{ApplicationError, CacheService},
    infrastructure::cache::cache_service_wrapper::CacheServiceWrapper,
};

/// Cache warming strategy
#[derive(Debug, Clone)]
pub enum WarmingStrategy {
    /// Warm cache on startup
    Startup,
    /// Warm cache periodically
    Periodic { interval_seconds: u64 },
    /// Warm cache on demand
    OnDemand,
    /// Warm cache based on access patterns
    Predictive,
}

/// Cache invalidation pattern
#[derive(Debug, Clone)]
pub enum InvalidationPattern {
    /// Time-based expiration
    TimeToLive { ttl: Duration },
    /// Invalidate by key pattern
    KeyPattern { pattern: String },
    /// Invalidate by tags
    TagBased { tags: Vec<String> },
    /// Manual invalidation
    Manual,
    /// Write-through invalidation
    WriteThrough,
}

/// Cache warming configuration
#[derive(Debug, Clone)]
pub struct CacheWarmingConfig {
    pub strategy: WarmingStrategy,
    pub batch_size: usize,
    pub concurrent_requests: usize,
    pub retry_attempts: u32,
    pub retry_delay: Duration,
    pub enabled: bool,
}

impl Default for CacheWarmingConfig {
    fn default() -> Self {
        Self {
            strategy: WarmingStrategy::OnDemand,
            batch_size: 100,
            concurrent_requests: 10,
            retry_attempts: 3,
            retry_delay: Duration::from_secs(1),
            enabled: true,
        }
    }
}

/// Cache warming service
pub struct CacheWarmingService {
    cache: Arc<CacheServiceWrapper>,
    config: CacheWarmingConfig,
    warming_data: Arc<tokio::sync::RwLock<HashMap<String, WarmingEntry>>>,
}

#[derive(Debug, Clone)]
struct WarmingEntry {
    key: String,
    priority: u32,
    last_accessed: std::time::SystemTime,
    access_count: u64,
}

impl CacheWarmingService {
    /// Create a new cache warming service
    pub fn new(cache: Arc<CacheServiceWrapper>, config: CacheWarmingConfig) -> Self {
        Self {
            cache,
            config,
            warming_data: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Start cache warming based on strategy
    pub async fn start_warming(&self) -> Result<(), ApplicationError> {
        if !self.config.enabled {
            info!("Cache warming is disabled");
            return Ok(());
        }

        match &self.config.strategy {
            WarmingStrategy::Startup => {
                info!("Starting cache warming on startup");
                self.warm_startup_data().await?;
            }
            WarmingStrategy::Periodic { interval_seconds } => {
                info!("Starting periodic cache warming with interval: {}s", interval_seconds);
                self.start_periodic_warming(*interval_seconds).await;
            }
            WarmingStrategy::OnDemand => {
                info!("Cache warming set to on-demand mode");
            }
            WarmingStrategy::Predictive => {
                info!("Starting predictive cache warming");
                self.start_predictive_warming().await;
            }
        }

        Ok(())
    }

    /// Warm cache with startup data
    async fn warm_startup_data(&self) -> Result<(), ApplicationError> {
        // Common cache keys that should be warmed on startup
        let startup_keys = vec![
            "vulnerability_sources",
            "ecosystem_metadata",
            "common_packages",
        ];

        for key in startup_keys {
            if let Err(e) = self.warm_key(key).await {
                warn!("Failed to warm startup key {}: {}", key, e);
            }
        }

        info!("Startup cache warming completed");
        Ok(())
    }

    /// Start periodic cache warming
    async fn start_periodic_warming(&self, interval_seconds: u64) {
        let cache = self.cache.clone();
        let warming_data = self.warming_data.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_seconds));
            
            loop {
                interval.tick().await;
                
                debug!("Running periodic cache warming");
                
                let warming_entries = {
                    let data = warming_data.read().await;
                    data.values().cloned().collect::<Vec<_>>()
                };

                // Sort by priority and access patterns
                let mut sorted_entries = warming_entries;
                sorted_entries.sort_by(|a, b| {
                    b.priority.cmp(&a.priority)
                        .then_with(|| b.access_count.cmp(&a.access_count))
                });

                // Warm top entries
                let batch_size = config.batch_size.min(sorted_entries.len());
                for entry in sorted_entries.iter().take(batch_size) {
                    if let Err(e) = Self::warm_key_static(&cache, &entry.key).await {
                        warn!("Failed to warm key {}: {}", entry.key, e);
                    }
                }
                
                debug!("Periodic cache warming completed for {} keys", batch_size);
            }
        });
    }

    /// Start predictive cache warming
    async fn start_predictive_warming(&self) {
        let cache = self.cache.clone();
        let warming_data = self.warming_data.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // 5 minutes
            
            loop {
                interval.tick().await;
                
                debug!("Running predictive cache warming");
                
                // Analyze access patterns and predict what to warm
                let predictions = Self::predict_cache_needs(&warming_data).await;
                
                for key in predictions {
                    if let Err(e) = Self::warm_key_static(&cache, &key).await {
                        warn!("Failed to predictively warm key {}: {}", key, e);
                    }
                }
            }
        });
    }

    /// Predict cache needs based on access patterns
    async fn predict_cache_needs(
        warming_data: &Arc<tokio::sync::RwLock<HashMap<String, WarmingEntry>>>,
    ) -> Vec<String> {
        let data = warming_data.read().await;
        let now = std::time::SystemTime::now();
        
        data.values()
            .filter(|entry| {
                // Predict based on access frequency and recency
                let time_since_access = now.duration_since(entry.last_accessed)
                    .unwrap_or_default()
                    .as_secs();
                
                entry.access_count > 5 && time_since_access < 3600 // Accessed > 5 times in last hour
            })
            .map(|entry| entry.key.clone())
            .collect()
    }

    /// Warm a specific cache key
    async fn warm_key(&self, key: &str) -> Result<(), ApplicationError> {
        Self::warm_key_static(&self.cache, key).await
    }

    /// Static method to warm a cache key
    async fn warm_key_static(
        cache: &Arc<CacheServiceWrapper>,
        key: &str,
    ) -> Result<(), ApplicationError> {
        // Check if key already exists in cache
        if cache.exists(key).await.unwrap_or(false) {
            debug!("Cache key {} already exists, skipping warming", key);
            return Ok(());
        }

        // This is where you would implement the logic to fetch and cache the data
        // For now, we'll just log that we would warm the key
        debug!("Would warm cache key: {}", key);
        
        // In a real implementation, you would:
        // 1. Determine the data source for this key
        // 2. Fetch the data from the source
        // 3. Store it in the cache with appropriate TTL
        
        Ok(())
    }

    /// Record cache access for predictive warming
    pub async fn record_access(&self, key: &str) {
        let mut data = self.warming_data.write().await;
        let entry = data.entry(key.to_string()).or_insert_with(|| WarmingEntry {
            key: key.to_string(),
            priority: 1,
            last_accessed: std::time::SystemTime::now(),
            access_count: 0,
        });

        entry.last_accessed = std::time::SystemTime::now();
        entry.access_count += 1;
        
        // Increase priority based on access frequency
        if entry.access_count % 10 == 0 {
            entry.priority = (entry.priority + 1).min(10);
        }
    }

    /// Get warming statistics
    pub async fn get_warming_stats(&self) -> WarmingStats {
        let data = self.warming_data.read().await;
        
        WarmingStats {
            total_entries: data.len(),
            high_priority_entries: data.values().filter(|e| e.priority >= 5).count(),
            total_accesses: data.values().map(|e| e.access_count).sum(),
            strategy: self.config.strategy.clone(),
            enabled: self.config.enabled,
        }
    }

    /// Clear warming data
    pub async fn clear_warming_data(&self) {
        let mut data = self.warming_data.write().await;
        data.clear();
        info!("Cache warming data cleared");
    }
}

/// Cache warming statistics
#[derive(Debug, Clone)]
pub struct WarmingStats {
    pub total_entries: usize,
    pub high_priority_entries: usize,
    pub total_accesses: u64,
    pub strategy: WarmingStrategy,
    pub enabled: bool,
}

/// Cache invalidation service
pub struct CacheInvalidationService {
    cache: Arc<CacheServiceWrapper>,
    patterns: Arc<tokio::sync::RwLock<Vec<InvalidationPattern>>>,
}

impl CacheInvalidationService {
    /// Create a new cache invalidation service
    pub fn new(cache: Arc<CacheServiceWrapper>) -> Self {
        Self {
            cache,
            patterns: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// Add invalidation pattern
    pub async fn add_pattern(&self, pattern: InvalidationPattern) {
        let mut patterns = self.patterns.write().await;
        patterns.push(pattern);
    }

    /// Invalidate cache based on patterns
    pub async fn invalidate_by_pattern(&self, key: &str) -> Result<(), ApplicationError> {
        let patterns = self.patterns.read().await;
        
        for pattern in patterns.iter() {
            match pattern {
                InvalidationPattern::KeyPattern { pattern: p } => {
                    if key.contains(p) {
                        self.cache.invalidate(key).await?;
                        debug!("Invalidated key {} matching pattern {}", key, p);
                    }
                }
                InvalidationPattern::Manual => {
                    // Manual invalidation is handled separately
                }
                _ => {
                    // Other patterns would be implemented here
                }
            }
        }
        
        Ok(())
    }

    /// Invalidate all cache entries
    pub async fn invalidate_all(&self) -> Result<(), ApplicationError> {
        self.cache.clear_all().await?;
        info!("All cache entries invalidated");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::infrastructure::cache::{
        file_cache::FileCacheRepository,
        cache_service_wrapper::CacheServiceWrapper,
    };

    #[tokio::test]
    async fn test_cache_warming_service() {
        let temp_dir = TempDir::new().unwrap();
        let file_cache = Arc::new(FileCacheRepository::new(
            temp_dir.path().to_path_buf(),
            Duration::from_secs(3600),
        ));
        let cache = Arc::new(CacheServiceWrapper::file(file_cache));
        
        let config = CacheWarmingConfig::default();
        let warming_service = CacheWarmingService::new(cache, config);
        
        // Test recording access
        warming_service.record_access("test_key").await;
        
        let stats = warming_service.get_warming_stats().await;
        assert_eq!(stats.total_entries, 1);
        assert!(stats.enabled);
    }

    #[tokio::test]
    async fn test_cache_invalidation_service() {
        let temp_dir = TempDir::new().unwrap();
        let file_cache = Arc::new(FileCacheRepository::new(
            temp_dir.path().to_path_buf(),
            Duration::from_secs(3600),
        ));
        let cache = Arc::new(CacheServiceWrapper::file(file_cache));
        
        let invalidation_service = CacheInvalidationService::new(cache);
        
        // Add a pattern
        invalidation_service.add_pattern(InvalidationPattern::KeyPattern {
            pattern: "test_".to_string(),
        }).await;
        
        // Test invalidation (would work if cache had the key)
        let result = invalidation_service.invalidate_by_pattern("test_key").await;
        assert!(result.is_ok());
    }
}
