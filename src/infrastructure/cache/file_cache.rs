//! File-based cache implementation

use crate::application::{ApplicationError, CacheService};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

/// Cache entry metadata for TTL and statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry<T> {
    data: T,
    created_at: u64,
    expires_at: u64,
    access_count: u64,
}

/// Cache statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub expired_entries: u64,
    pub total_entries: u64,
    pub cleanup_runs: u64,
}

/// File-based cache repository with TTL support and concurrent access safety
pub struct FileCacheRepository {
    cache_dir: PathBuf,
    #[allow(dead_code)]
    default_ttl: Duration, // Future: configurable TTL support
    /// Mutex for file operations to prevent concurrent write conflicts
    file_locks: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>>,
    stats: Arc<Mutex<CacheStats>>,
    /// Background cleanup task handle
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl FileCacheRepository {
    /// Create a new file-based cache repository
    pub fn new(cache_dir: PathBuf, default_ttl: Duration) -> Self {
        Self {
            cache_dir,
            default_ttl,
            file_locks: Arc::new(Mutex::new(std::collections::HashMap::new())),
            stats: Arc::new(Mutex::new(CacheStats::default())),
            cleanup_handle: None,
        }
    }

    /// Create a new file-based cache repository with background cleanup
    pub fn new_with_cleanup(
        cache_dir: PathBuf,
        default_ttl: Duration,
        cleanup_interval: Duration,
    ) -> Self {
        let mut cache = Self::new(cache_dir.clone(), default_ttl);

        // Start background cleanup task
        let cache_dir_clone = cache_dir.clone();
        let stats_clone = cache.stats.clone();

        let handle = tokio::spawn(async move {
            Self::background_cleanup_task(cache_dir_clone, stats_clone, cleanup_interval).await;
        });

        cache.cleanup_handle = Some(handle);
        cache
    }

    /// Generate a SHA256-based cache key to ensure uniqueness and avoid filesystem issues
    fn cache_key(&self, key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Get the file path for a cache key
    fn cache_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", self.cache_key(key)))
    }

    /// Get the temporary file path for atomic writes
    fn temp_cache_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.tmp", self.cache_key(key)))
    }

    /// Get current timestamp in seconds since UNIX epoch
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Check if a cache entry is expired based on its metadata
    fn is_entry_expired(entry: &CacheEntry<serde_json::Value>) -> bool {
        let now = Self::current_timestamp();
        now > entry.expires_at
    }

    /// Get or create a file lock for the given cache key
    async fn get_file_lock(&self, cache_key: &str) -> Arc<Mutex<()>> {
        let mut locks = self.file_locks.lock().await;
        locks
            .entry(cache_key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Ensure cache directory exists with proper permissions
    async fn ensure_cache_dir(&self) -> Result<(), ApplicationError> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir).await.map_err(|e| {
                error!("Failed to create cache directory: {}", e);
                ApplicationError::Io(e)
            })?;
            debug!("Created cache directory: {:?}", self.cache_dir);
        }
        Ok(())
    }

    /// Perform atomic write operation using temporary file and rename
    async fn atomic_write<T>(
        &self,
        key: &str,
        entry: &CacheEntry<T>,
    ) -> Result<(), ApplicationError>
    where
        T: Serialize,
    {
        let cache_key = self.cache_key(key);
        let temp_path = self.temp_cache_path(key);
        let final_path = self.cache_path(key);

        // Serialize the entry
        let content = serde_json::to_string_pretty(entry).map_err(|e| {
            error!("Failed to serialize cache entry: {}", e);
            ApplicationError::Json(e)
        })?;

        // Write to temporary file first
        fs::write(&temp_path, content).await.map_err(|e| {
            error!("Failed to write temporary cache file: {}", e);
            ApplicationError::Io(e)
        })?;

        // Atomically rename temporary file to final location
        fs::rename(&temp_path, &final_path).await.map_err(|e| {
            error!("Failed to rename cache file: {}", e);
            ApplicationError::Io(e)
        })?;

        debug!("Successfully cached entry for key: {}", cache_key);
        Ok(())
    }

    /// Clean up expired entries during get operations
    async fn cleanup_expired_entry(&self, path: &PathBuf) -> Result<(), ApplicationError> {
        if let Err(e) = fs::remove_file(path).await {
            warn!("Failed to remove expired cache file {:?}: {}", path, e);
        } else {
            debug!("Cleaned up expired cache file: {:?}", path);
            let mut stats = self.stats.lock().await;
            stats.expired_entries += 1;
        }
        Ok(())
    }

    /// Get cache statistics for monitoring
    pub async fn get_stats(&self) -> CacheStats {
        self.stats.lock().await.clone()
    }

    /// Reset cache statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.lock().await;
        *stats = CacheStats::default();
    }

    /// Start background task for periodic cache cleanup
    /// This task runs every hour and removes expired entries
    pub fn start_background_cleanup(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(3600)); // 1 hour

            loop {
                cleanup_interval.tick().await;

                if let Err(e) = self.cleanup_expired_entries().await {
                    error!("Background cache cleanup failed: {}", e);
                } else {
                    let mut stats = self.stats.lock().await;
                    stats.cleanup_runs += 1;
                    info!(
                        "Background cache cleanup completed. Total cleanup runs: {}",
                        stats.cleanup_runs
                    );
                }
            }
        })
    }

    /// Manually trigger cleanup of all expired entries
    pub async fn cleanup_expired_entries(&self) -> Result<u64, ApplicationError> {
        let mut cleaned_count = 0u64;

        // Read all files in cache directory
        let mut entries = fs::read_dir(&self.cache_dir).await.map_err(|e| {
            error!("Failed to read cache directory: {}", e);
            ApplicationError::Io(e)
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            error!("Failed to read directory entry: {}", e);
            ApplicationError::Io(e)
        })? {
            let path = entry.path();

            // Skip non-JSON files and temporary files
            if !path.extension().is_some_and(|ext| ext == "json") {
                continue;
            }

            // Try to read and parse the cache entry
            match self.check_and_cleanup_entry(&path).await {
                Ok(true) => cleaned_count += 1,
                Ok(false) => {} // Entry is still valid
                Err(e) => {
                    warn!("Failed to check cache entry {:?}: {}", path, e);
                    // Try to remove corrupted files
                    if let Err(remove_err) = fs::remove_file(&path).await {
                        warn!(
                            "Failed to remove corrupted cache file {:?}: {}",
                            path, remove_err
                        );
                    } else {
                        cleaned_count += 1;
                    }
                }
            }
        }

        if cleaned_count > 0 {
            info!("Cleaned up {} expired cache entries", cleaned_count);
            let mut stats = self.stats.lock().await;
            stats.expired_entries += cleaned_count;
            if stats.total_entries >= cleaned_count {
                stats.total_entries -= cleaned_count;
            } else {
                stats.total_entries = 0;
            }
        }

        Ok(cleaned_count)
    }

    /// Check if a cache entry file is expired and clean it up if necessary
    /// Returns Ok(true) if the entry was cleaned up, Ok(false) if it's still valid
    async fn check_and_cleanup_entry(&self, path: &PathBuf) -> Result<bool, ApplicationError> {
        let content = fs::read_to_string(path)
            .await
            .map_err(ApplicationError::Io)?;

        let entry: CacheEntry<serde_json::Value> =
            serde_json::from_str(&content).map_err(ApplicationError::Json)?;

        if Self::is_entry_expired(&entry) {
            fs::remove_file(path).await.map_err(ApplicationError::Io)?;
            debug!("Cleaned up expired cache file: {:?}", path);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get cache directory size and entry count for monitoring
    pub async fn get_cache_info(&self) -> Result<(u64, u64), ApplicationError> {
        let mut total_size = 0u64;
        let mut entry_count = 0u64;

        let mut entries = fs::read_dir(&self.cache_dir)
            .await
            .map_err(ApplicationError::Io)?;

        while let Some(entry) = entries.next_entry().await.map_err(ApplicationError::Io)? {
            let path = entry.path();

            // Only count JSON cache files
            if path.extension().is_some_and(|ext| ext == "json") {
                if let Ok(metadata) = fs::metadata(&path).await {
                    total_size += metadata.len();
                    entry_count += 1;
                }
            }
        }

        Ok((total_size, entry_count))
    }

    /// Background task for periodic cache cleanup
    async fn background_cleanup_task(
        cache_dir: PathBuf,
        stats: Arc<Mutex<CacheStats>>,
        cleanup_interval: Duration,
    ) {
        let mut interval = interval(cleanup_interval);

        loop {
            interval.tick().await;

            if let Err(e) = Self::background_cleanup_expired_entries(&cache_dir, &stats).await {
                error!("Background cleanup failed: {}", e);
            }
        }
    }

    /// Clean up all expired entries in the cache directory (background task version)
    async fn background_cleanup_expired_entries(
        cache_dir: &PathBuf,
        stats: &Arc<Mutex<CacheStats>>,
    ) -> Result<(), ApplicationError> {
        if !cache_dir.exists() {
            return Ok(());
        }

        let mut entries = fs::read_dir(cache_dir)
            .await
            .map_err(ApplicationError::Io)?;
        let mut cleaned_count = 0u64;
        let mut total_checked = 0u64;

        while let Some(entry) = entries.next_entry().await.map_err(ApplicationError::Io)? {
            let path = entry.path();

            // Skip temporary files and non-JSON files
            if let Some(extension) = path.extension() {
                if extension != "json" {
                    continue;
                }
            } else {
                continue;
            }

            total_checked += 1;

            // Read and check if entry is expired
            match fs::read_to_string(&path).await {
                Ok(content) => {
                    match serde_json::from_str::<CacheEntry<serde_json::Value>>(&content) {
                        Ok(entry) => {
                            if Self::is_entry_expired(&entry) {
                                if let Err(e) = fs::remove_file(&path).await {
                                    warn!("Failed to remove expired cache file {:?}: {}", path, e);
                                } else {
                                    cleaned_count += 1;
                                    debug!("Cleaned up expired cache file: {:?}", path);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse cache entry {:?}: {}", path, e);
                            // Remove corrupted cache files
                            if let Err(e) = fs::remove_file(&path).await {
                                warn!("Failed to remove corrupted cache file {:?}: {}", path, e);
                            } else {
                                cleaned_count += 1;
                                debug!("Cleaned up corrupted cache file: {:?}", path);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read cache file {:?}: {}", path, e);
                }
            }
        }

        // Update statistics
        {
            let mut stats_guard = stats.lock().await;
            stats_guard.expired_entries += cleaned_count;
            stats_guard.cleanup_runs += 1;
            if stats_guard.total_entries >= cleaned_count {
                stats_guard.total_entries -= cleaned_count;
            } else {
                stats_guard.total_entries = 0;
            }
        }

        if cleaned_count > 0 {
            info!(
                "Background cleanup completed: {} expired entries removed out of {} checked",
                cleaned_count, total_checked
            );
        } else {
            debug!(
                "Background cleanup completed: no expired entries found out of {} checked",
                total_checked
            );
        }

        Ok(())
    }

    /// Manually trigger cache cleanup
    pub async fn cleanup_expired(&self) -> Result<u64, ApplicationError> {
        let mut cleaned_count = 0u64;

        if !self.cache_dir.exists() {
            return Ok(0);
        }

        let mut entries = fs::read_dir(&self.cache_dir)
            .await
            .map_err(ApplicationError::Io)?;

        while let Some(entry) = entries.next_entry().await.map_err(ApplicationError::Io)? {
            let path = entry.path();

            // Skip temporary files and non-JSON files
            if let Some(extension) = path.extension() {
                if extension != "json" {
                    continue;
                }
            } else {
                continue;
            }

            // Read and check if entry is expired
            match fs::read_to_string(&path).await {
                Ok(content) => {
                    match serde_json::from_str::<CacheEntry<serde_json::Value>>(&content) {
                        Ok(entry) => {
                            if Self::is_entry_expired(&entry) {
                                if let Err(e) = fs::remove_file(&path).await {
                                    warn!("Failed to remove expired cache file {:?}: {}", path, e);
                                } else {
                                    cleaned_count += 1;
                                    debug!("Manually cleaned up expired cache file: {:?}", path);
                                }
                            }
                        }
                        Err(_) => {
                            // Remove corrupted cache files
                            if fs::remove_file(&path).await.is_ok() {
                                cleaned_count += 1;
                                debug!("Manually cleaned up corrupted cache file: {:?}", path);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Skip files we can't read
                    continue;
                }
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.lock().await;
            stats.expired_entries += cleaned_count;
            if stats.total_entries >= cleaned_count {
                stats.total_entries -= cleaned_count;
            } else {
                stats.total_entries = 0;
            }
        }

        info!(
            "Manual cleanup completed: {} expired entries removed",
            cleaned_count
        );
        Ok(cleaned_count)
    }

    /// Get the total number of cache entries (including expired ones)
    pub async fn get_total_entries(&self) -> Result<u64, ApplicationError> {
        if !self.cache_dir.exists() {
            return Ok(0);
        }

        let mut entries = fs::read_dir(&self.cache_dir)
            .await
            .map_err(ApplicationError::Io)?;
        let mut count = 0u64;

        while let Some(entry) = entries.next_entry().await.map_err(ApplicationError::Io)? {
            let path = entry.path();

            // Count only JSON files (skip temporary files)
            if let Some(extension) = path.extension() {
                if extension == "json" {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Check if a specific cache entry exists and is not expired
    pub async fn exists(&self, key: &str) -> Result<bool, ApplicationError> {
        let cache_key = self.cache_key(key);
        let path = self.cache_path(key);

        // Get file lock to prevent concurrent access
        let file_lock = self.get_file_lock(&cache_key).await;
        let _lock = file_lock.lock().await;

        if !path.exists() {
            return Ok(false);
        }

        // Read and parse the cache entry
        let content = fs::read_to_string(&path)
            .await
            .map_err(ApplicationError::Io)?;
        let entry: CacheEntry<serde_json::Value> =
            serde_json::from_str(&content).map_err(ApplicationError::Json)?;

        // Check if entry is expired
        if Self::is_entry_expired(&entry) {
            self.cleanup_expired_entry(&path).await?;
            return Ok(false);
        }

        Ok(true)
    }
}

impl Drop for FileCacheRepository {
    fn drop(&mut self) {
        // Cancel the background cleanup task if it exists
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
            debug!("Background cleanup task cancelled");
        }
    }
}

#[async_trait]
impl CacheService for FileCacheRepository {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        let cache_key = self.cache_key(key);
        let path = self.cache_path(key);

        // Get file lock to prevent concurrent access
        let file_lock = self.get_file_lock(&cache_key).await;
        let _lock = file_lock.lock().await;

        if !path.exists() {
            let mut stats = self.stats.lock().await;
            stats.misses += 1;
            return Ok(None);
        }

        // Read and parse the cache entry
        let content = fs::read_to_string(&path).await.map_err(|e| {
            error!("Failed to read cache file {:?}: {}", path, e);
            ApplicationError::Io(e)
        })?;

        let entry: CacheEntry<serde_json::Value> = serde_json::from_str(&content).map_err(|e| {
            error!("Failed to parse cache entry: {}", e);
            ApplicationError::Json(e)
        })?;

        // Check if entry is expired
        if Self::is_entry_expired(&entry) {
            self.cleanup_expired_entry(&path).await?;
            let mut stats = self.stats.lock().await;
            stats.misses += 1;
            return Ok(None);
        }

        // Deserialize the actual data
        let value: T = serde_json::from_value(entry.data).map_err(|e| {
            error!("Failed to deserialize cached data: {}", e);
            ApplicationError::Json(e)
        })?;

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.hits += 1;

        debug!("Cache hit for key: {}", cache_key);
        Ok(Some(value))
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: serde::Serialize + Send + Sync,
    {
        let cache_key = self.cache_key(key);

        // Ensure cache directory exists
        self.ensure_cache_dir().await?;

        // Get file lock to prevent concurrent writes
        let file_lock = self.get_file_lock(&cache_key).await;
        let _lock = file_lock.lock().await;

        let now = Self::current_timestamp();
        let expires_at = now + ttl.as_secs();

        // Serialize value to JSON for storage
        let json_value = serde_json::to_value(value).map_err(|e| {
            error!("Failed to serialize value for caching: {}", e);
            ApplicationError::Json(e)
        })?;

        let entry = CacheEntry {
            data: json_value,
            created_at: now,
            expires_at,
            access_count: 0,
        };

        // Perform atomic write
        self.atomic_write(key, &entry).await?;

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.total_entries += 1;

        debug!(
            "Cached entry for key: {} (expires in {}s)",
            cache_key,
            ttl.as_secs()
        );
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        let cache_key = self.cache_key(key);
        let path = self.cache_path(key);

        // Get file lock to prevent concurrent access
        let file_lock = self.get_file_lock(&cache_key).await;
        let _lock = file_lock.lock().await;

        if path.exists() {
            fs::remove_file(&path).await.map_err(|e| {
                error!("Failed to invalidate cache entry {:?}: {}", path, e);
                ApplicationError::Io(e)
            })?;

            // Update statistics
            let mut stats = self.stats.lock().await;
            if stats.total_entries > 0 {
                stats.total_entries -= 1;
            }

            debug!("Invalidated cache entry for key: {}", cache_key);
        }

        Ok(())
    }
}
