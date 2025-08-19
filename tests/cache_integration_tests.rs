//! Integration tests for Redis cache functionality

use std::{sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::time::sleep;

use vulnera_rust::{
    application::CacheService,
    config::{CacheConfig, CacheStrategy},
    infrastructure::cache::{
        cache_factory::CacheFactory,
        cache_service_wrapper::CacheServiceWrapper,
        file_cache::FileCacheRepository,
        session_management::{SessionManager, SessionConfig, RateLimiter, RateLimitConfig},
        metrics::{CacheMonitor, AlertConfig},
    },
};

/// Test basic cache operations with file cache
#[tokio::test]
async fn test_file_cache_operations() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache = CacheServiceWrapper::file(file_cache);

    // Test set and get
    let key = "test_key";
    let value = "test_value";
    let ttl = Duration::from_secs(60);

    cache.set(key, &value, ttl).await.unwrap();
    let retrieved: Option<String> = cache.get(key).await.unwrap();
    assert_eq!(retrieved.as_deref(), Some(value));

    // Test invalidation
    cache.invalidate(key).await.unwrap();
    let after_invalidate: Option<String> = cache.get(key).await.unwrap();
    assert!(after_invalidate.is_none());
}

/// Test cache factory with different strategies
#[tokio::test]
async fn test_cache_factory_file_only() {
    let temp_dir = TempDir::new().unwrap();
    let config = CacheConfig {
        directory: temp_dir.path().to_path_buf(),
        ttl_hours: 1,
        redis: None,
        strategy: CacheStrategy::FileOnly,
    };

    let cache = CacheFactory::create_cache_service(&config).await.unwrap();
    
    // Test connectivity
    assert!(CacheFactory::test_cache_connectivity(&cache).await.is_ok());
    
    // Test basic operations
    let key = "factory_test";
    let value = 42i32;
    let ttl = Duration::from_secs(60);

    cache.set(key, &value, ttl).await.unwrap();
    let retrieved: Option<i32> = cache.get(key).await.unwrap();
    assert_eq!(retrieved, Some(value));
}

/// Test cache with TTL expiration
#[tokio::test]
async fn test_cache_ttl_expiration() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache = CacheServiceWrapper::file(file_cache);

    let key = "expiring_key";
    let value = "expiring_value";
    let short_ttl = Duration::from_millis(100);

    // Set with short TTL
    cache.set(key, &value, short_ttl).await.unwrap();
    
    // Should be available immediately
    let retrieved: Option<String> = cache.get(key).await.unwrap();
    assert_eq!(retrieved.as_deref(), Some(value));

    // Wait for expiration
    sleep(Duration::from_millis(150)).await;

    // Should be expired now
    let after_expiry: Option<String> = cache.get(key).await.unwrap();
    assert!(after_expiry.is_none());
}

/// Test session management
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
        .create_session(
            Some("user123".to_string()),
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string()),
        )
        .await
        .unwrap();

    assert!(!session.session_id.is_empty());
    assert_eq!(session.user_id, Some("user123".to_string()));
    assert_eq!(session.ip_address, Some("192.168.1.1".to_string()));

    // Retrieve session
    let retrieved = session_manager
        .get_session(&session.session_id)
        .await
        .unwrap();

    assert!(retrieved.is_some());
    let retrieved_session = retrieved.unwrap();
    assert_eq!(retrieved_session.user_id, Some("user123".to_string()));
    assert!(retrieved_session.last_accessed >= session.last_accessed);

    // Update session data
    let mut session_data = std::collections::HashMap::new();
    session_data.insert("key1".to_string(), serde_json::json!("value1"));
    session_data.insert("key2".to_string(), serde_json::json!(42));

    session_manager
        .update_session(&session.session_id, session_data.clone())
        .await
        .unwrap();

    // Verify updated data
    let updated_session = session_manager
        .get_session(&session.session_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated_session.data.get("key1"), Some(&serde_json::json!("value1")));
    assert_eq!(updated_session.data.get("key2"), Some(&serde_json::json!(42)));

    // Delete session
    session_manager.delete_session(&session.session_id).await.unwrap();

    let deleted_session = session_manager
        .get_session(&session.session_id)
        .await
        .unwrap();

    assert!(deleted_session.is_none());
}

/// Test rate limiting
#[tokio::test]
async fn test_rate_limiting() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache = Arc::new(CacheServiceWrapper::file(file_cache));
    
    let config = RateLimitConfig {
        window_size: Duration::from_secs(60),
        max_requests: 3,
        key_prefix: "test_rate_limit:".to_string(),
        cleanup_interval: Duration::from_secs(300),
    };
    let rate_limiter = RateLimiter::new(cache, config);

    let key = "test_client";

    // First 3 requests should be allowed
    assert!(rate_limiter.is_allowed(key).await.unwrap());
    assert!(rate_limiter.is_allowed(key).await.unwrap());
    assert!(rate_limiter.is_allowed(key).await.unwrap());

    // 4th request should be denied
    assert!(!rate_limiter.is_allowed(key).await.unwrap());

    // Check current count
    let count = rate_limiter.get_current_count(key).await.unwrap();
    assert_eq!(count, 3);

    // Reset and try again
    rate_limiter.reset(key).await.unwrap();
    let count_after_reset = rate_limiter.get_current_count(key).await.unwrap();
    assert_eq!(count_after_reset, 0);

    // Should be allowed again after reset
    assert!(rate_limiter.is_allowed(key).await.unwrap());
}

/// Test cache monitoring and metrics
#[tokio::test]
async fn test_cache_monitoring() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache = Arc::new(CacheServiceWrapper::file(file_cache));
    
    let alert_config = AlertConfig::default();
    let monitor = CacheMonitor::new(cache.clone(), alert_config);

    // Perform some cache operations to generate metrics
    cache.set("key1", &"value1", Duration::from_secs(60)).await.unwrap();
    cache.set("key2", &"value2", Duration::from_secs(60)).await.unwrap();
    
    let _: Option<String> = cache.get("key1").await.unwrap(); // Hit
    let _: Option<String> = cache.get("key3").await.unwrap(); // Miss

    // Record some response times
    monitor.record_response_time(25.0).await;
    monitor.record_response_time(30.0).await;
    monitor.record_response_time(35.0).await;

    // Collect metrics
    let metrics = monitor.collect_metrics().await.unwrap();
    
    assert!(metrics.total_requests > 0);
    assert!(metrics.hit_rate > 0.0);
    assert!(metrics.average_response_time_ms > 0.0);

    // Test metrics history
    let history = monitor.get_metrics_history(Some(10)).await;
    assert!(history.is_empty()); // No history yet since we didn't start monitoring

    // Test alerts
    let alerts = monitor.get_active_alerts().await;
    // Should be empty for this simple test
    assert!(alerts.is_empty());
}

/// Test cache statistics
#[tokio::test]
async fn test_cache_statistics() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache = CacheServiceWrapper::file(file_cache);

    // Perform operations to generate stats
    cache.set("key1", &"value1", Duration::from_secs(60)).await.unwrap();
    cache.set("key2", &"value2", Duration::from_secs(60)).await.unwrap();
    
    let _: Option<String> = cache.get("key1").await.unwrap(); // Hit
    let _: Option<String> = cache.get("key1").await.unwrap(); // Hit
    let _: Option<String> = cache.get("key3").await.unwrap(); // Miss

    let stats = cache.get_stats().await;
    
    assert_eq!(stats.total_hits(), 2);
    assert_eq!(stats.total_misses(), 1);
    assert_eq!(stats.hit_rate(), 66.66666666666667); // 2/3 * 100
    assert_eq!(stats.cache_type(), "File");
}

/// Test concurrent cache operations
#[tokio::test]
async fn test_concurrent_cache_operations() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache = Arc::new(CacheServiceWrapper::file(file_cache));

    let mut handles = Vec::new();

    // Spawn multiple tasks performing cache operations
    for i in 0..10 {
        let cache_clone = cache.clone();
        let handle = tokio::spawn(async move {
            let key = format!("concurrent_key_{}", i);
            let value = format!("concurrent_value_{}", i);
            
            // Set value
            cache_clone.set(&key, &value, Duration::from_secs(60)).await.unwrap();
            
            // Get value
            let retrieved: Option<String> = cache_clone.get(&key).await.unwrap();
            assert_eq!(retrieved.as_deref(), Some(value.as_str()));
            
            // Invalidate
            cache_clone.invalidate(&key).await.unwrap();
            
            // Verify invalidation
            let after_invalidate: Option<String> = cache_clone.get(&key).await.unwrap();
            assert!(after_invalidate.is_none());
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }
}

/// Test error handling
#[tokio::test]
async fn test_error_handling() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache = CacheServiceWrapper::file(file_cache);

    // Test getting non-existent key
    let result: Option<String> = cache.get("non_existent_key").await.unwrap();
    assert!(result.is_none());

    // Test invalidating non-existent key (should not error)
    let result = cache.invalidate("non_existent_key").await;
    assert!(result.is_ok());
}

/// Test cache with different data types
#[tokio::test]
async fn test_cache_different_data_types() {
    let temp_dir = TempDir::new().unwrap();
    let file_cache = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));
    let cache = CacheServiceWrapper::file(file_cache);

    let ttl = Duration::from_secs(60);

    // Test string
    cache.set("string_key", &"string_value", ttl).await.unwrap();
    let string_val: Option<String> = cache.get("string_key").await.unwrap();
    assert_eq!(string_val.as_deref(), Some("string_value"));

    // Test integer
    cache.set("int_key", &42i32, ttl).await.unwrap();
    let int_val: Option<i32> = cache.get("int_key").await.unwrap();
    assert_eq!(int_val, Some(42));

    // Test boolean
    cache.set("bool_key", &true, ttl).await.unwrap();
    let bool_val: Option<bool> = cache.get("bool_key").await.unwrap();
    assert_eq!(bool_val, Some(true));

    // Test JSON object
    let json_obj = serde_json::json!({
        "name": "test",
        "value": 123,
        "active": true
    });
    cache.set("json_key", &json_obj, ttl).await.unwrap();
    let retrieved_json: Option<serde_json::Value> = cache.get("json_key").await.unwrap();
    assert_eq!(retrieved_json, Some(json_obj));

    // Test vector
    let vec_data = vec![1, 2, 3, 4, 5];
    cache.set("vec_key", &vec_data, ttl).await.unwrap();
    let retrieved_vec: Option<Vec<i32>> = cache.get("vec_key").await.unwrap();
    assert_eq!(retrieved_vec, Some(vec_data));
}
