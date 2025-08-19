//! Redis-based session management and rate limiting

use std::{collections::HashMap, sync::Arc, time::Duration};
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    application::{ApplicationError, CacheService},
    infrastructure::cache::cache_service_wrapper::CacheServiceWrapper,
};

/// Session data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub session_id: String,
    pub user_id: Option<String>,
    pub created_at: u64,
    pub last_accessed: u64,
    pub expires_at: u64,
    pub data: HashMap<String, serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_timeout: Duration,
    pub cleanup_interval: Duration,
    pub max_sessions_per_user: usize,
    pub secure_cookies: bool,
    pub session_key_prefix: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(3600), // 1 hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            max_sessions_per_user: 5,
            secure_cookies: true,
            session_key_prefix: "session:".to_string(),
        }
    }
}

/// Session manager for Redis-based session storage
pub struct SessionManager {
    cache: Arc<CacheServiceWrapper>,
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(cache: Arc<CacheServiceWrapper>, config: SessionConfig) -> Self {
        Self { cache, config }
    }

    /// Create a new session
    pub async fn create_session(
        &self,
        user_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SessionData, ApplicationError> {
        let session_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();
        let expires_at = now + self.config.session_timeout.as_secs();

        let session = SessionData {
            session_id: session_id.clone(),
            user_id: user_id.clone(),
            created_at: now,
            last_accessed: now,
            expires_at,
            data: HashMap::new(),
            ip_address,
            user_agent,
        };

        // Store session in cache
        let cache_key = format!("{}{}", self.config.session_key_prefix, session_id);
        self.cache
            .set(&cache_key, &session, self.config.session_timeout)
            .await?;

        // If user_id is provided, track user sessions
        if let Some(ref uid) = user_id {
            self.track_user_session(uid, &session_id).await?;
        }

        info!("Created session {} for user {:?}", session_id, user_id);
        Ok(session)
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>, ApplicationError> {
        let cache_key = format!("{}{}", self.config.session_key_prefix, session_id);
        
        match self.cache.get::<SessionData>(&cache_key).await? {
            Some(mut session) => {
                // Check if session is expired
                if Self::current_timestamp() > session.expires_at {
                    self.delete_session(session_id).await?;
                    return Ok(None);
                }

                // Update last accessed time
                session.last_accessed = Self::current_timestamp();
                session.expires_at = Self::current_timestamp() + self.config.session_timeout.as_secs();
                
                // Update session in cache
                self.cache
                    .set(&cache_key, &session, self.config.session_timeout)
                    .await?;

                debug!("Retrieved and updated session {}", session_id);
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Update session data
    pub async fn update_session(
        &self,
        session_id: &str,
        data: HashMap<String, serde_json::Value>,
    ) -> Result<(), ApplicationError> {
        let cache_key = format!("{}{}", self.config.session_key_prefix, session_id);
        
        if let Some(mut session) = self.cache.get::<SessionData>(&cache_key).await? {
            session.data = data;
            session.last_accessed = Self::current_timestamp();
            session.expires_at = Self::current_timestamp() + self.config.session_timeout.as_secs();
            
            self.cache
                .set(&cache_key, &session, self.config.session_timeout)
                .await?;

            debug!("Updated session {}", session_id);
            Ok(())
        } else {
            Err(ApplicationError::NotFound {
                resource: "session".to_string(),
                id: session_id.to_string(),
            })
        }
    }

    /// Delete session
    pub async fn delete_session(&self, session_id: &str) -> Result<(), ApplicationError> {
        let cache_key = format!("{}{}", self.config.session_key_prefix, session_id);
        
        // Get session to find user_id for cleanup
        if let Ok(Some(session)) = self.cache.get::<SessionData>(&cache_key).await {
            if let Some(user_id) = &session.user_id {
                self.untrack_user_session(user_id, session_id).await?;
            }
        }

        self.cache.invalidate(&cache_key).await?;
        info!("Deleted session {}", session_id);
        Ok(())
    }

    /// Track user session for multi-session management
    async fn track_user_session(&self, user_id: &str, session_id: &str) -> Result<(), ApplicationError> {
        let user_sessions_key = format!("user_sessions:{}", user_id);
        
        let mut sessions: Vec<String> = self.cache
            .get(&user_sessions_key)
            .await?
            .unwrap_or_default();

        sessions.push(session_id.to_string());

        // Enforce max sessions per user
        if sessions.len() > self.config.max_sessions_per_user {
            let excess = sessions.len() - self.config.max_sessions_per_user;
            for old_session in sessions.drain(0..excess) {
                self.delete_session(&old_session).await?;
            }
        }

        self.cache
            .set(&user_sessions_key, &sessions, self.config.session_timeout)
            .await?;

        Ok(())
    }

    /// Untrack user session
    async fn untrack_user_session(&self, user_id: &str, session_id: &str) -> Result<(), ApplicationError> {
        let user_sessions_key = format!("user_sessions:{}", user_id);
        
        if let Ok(Some(mut sessions)) = self.cache.get::<Vec<String>>(&user_sessions_key).await {
            sessions.retain(|s| s != session_id);
            
            if sessions.is_empty() {
                self.cache.invalidate(&user_sessions_key).await?;
            } else {
                self.cache
                    .set(&user_sessions_key, &sessions, self.config.session_timeout)
                    .await?;
            }
        }

        Ok(())
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Start session cleanup task
    pub fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let _cache = self.cache.clone();
        let cleanup_interval = self.config.cleanup_interval;
        let _session_prefix = self.config.session_key_prefix.clone();

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                debug!("Running session cleanup");
                
                // In a real implementation, you would scan for expired sessions
                // For now, we'll just log that cleanup is running
                // This would require implementing a scan operation in the cache service
                
                debug!("Session cleanup completed");
            }
        })
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub window_size: Duration,
    pub max_requests: u32,
    pub key_prefix: String,
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_size: Duration::from_secs(60), // 1 minute window
            max_requests: 100,
            key_prefix: "rate_limit:".to_string(),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Rate limiter using sliding window algorithm
pub struct RateLimiter {
    cache: Arc<CacheServiceWrapper>,
    config: RateLimitConfig,
}

/// Rate limit entry for sliding window
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimitEntry {
    requests: Vec<u64>, // Timestamps of requests
    window_start: u64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(cache: Arc<CacheServiceWrapper>, config: RateLimitConfig) -> Self {
        Self { cache, config }
    }

    /// Check if request is allowed and update counter
    pub async fn is_allowed(&self, key: &str) -> Result<bool, ApplicationError> {
        let cache_key = format!("{}{}", self.config.key_prefix, key);
        let now = Self::current_timestamp();
        let window_start = now - self.config.window_size.as_secs();

        let mut entry: RateLimitEntry = self.cache
            .get(&cache_key)
            .await?
            .unwrap_or_else(|| RateLimitEntry {
                requests: Vec::new(),
                window_start: now,
            });

        // Remove requests outside the current window
        entry.requests.retain(|&timestamp| timestamp > window_start);
        entry.window_start = window_start;

        // Check if we're within the limit
        if entry.requests.len() >= self.config.max_requests as usize {
            debug!("Rate limit exceeded for key: {}", key);
            return Ok(false);
        }

        // Add current request
        entry.requests.push(now);

        // Store updated entry
        self.cache
            .set(&cache_key, &entry, self.config.window_size)
            .await?;

        debug!("Rate limit check passed for key: {} ({}/{})", 
               key, entry.requests.len(), self.config.max_requests);
        Ok(true)
    }

    /// Get current request count for a key
    pub async fn get_current_count(&self, key: &str) -> Result<u32, ApplicationError> {
        let cache_key = format!("{}{}", self.config.key_prefix, key);
        let now = Self::current_timestamp();
        let window_start = now - self.config.window_size.as_secs();

        if let Some(mut entry) = self.cache.get::<RateLimitEntry>(&cache_key).await? {
            entry.requests.retain(|&timestamp| timestamp > window_start);
            Ok(entry.requests.len() as u32)
        } else {
            Ok(0)
        }
    }

    /// Reset rate limit for a key
    pub async fn reset(&self, key: &str) -> Result<(), ApplicationError> {
        let cache_key = format!("{}{}", self.config.key_prefix, key);
        self.cache.invalidate(&cache_key).await?;
        info!("Reset rate limit for key: {}", key);
        Ok(())
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
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
    async fn test_session_management() {
        let temp_dir = TempDir::new().unwrap();
        let file_cache = Arc::new(FileCacheRepository::new(
            temp_dir.path().to_path_buf(),
            Duration::from_secs(3600),
        ));
        let cache = Arc::new(CacheServiceWrapper::file(file_cache));
        
        let config = SessionConfig::default();
        let session_manager = SessionManager::new(cache, config);
        
        // Create session
        let session = session_manager
            .create_session(Some("user123".to_string()), None, None)
            .await
            .unwrap();
        
        assert!(!session.session_id.is_empty());
        assert_eq!(session.user_id, Some("user123".to_string()));
        
        // Get session
        let retrieved = session_manager
            .get_session(&session.session_id)
            .await
            .unwrap();
        
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, Some("user123".to_string()));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let temp_dir = TempDir::new().unwrap();
        let file_cache = Arc::new(FileCacheRepository::new(
            temp_dir.path().to_path_buf(),
            Duration::from_secs(3600),
        ));
        let cache = Arc::new(CacheServiceWrapper::file(file_cache));
        
        let config = RateLimitConfig {
            max_requests: 2,
            ..Default::default()
        };
        let rate_limiter = RateLimiter::new(cache, config);
        
        let key = "test_key";
        
        // First two requests should be allowed
        assert!(rate_limiter.is_allowed(key).await.unwrap());
        assert!(rate_limiter.is_allowed(key).await.unwrap());
        
        // Third request should be denied
        assert!(!rate_limiter.is_allowed(key).await.unwrap());
        
        // Check current count
        let count = rate_limiter.get_current_count(key).await.unwrap();
        assert_eq!(count, 2);
    }
}
