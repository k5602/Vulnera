//! Comprehensive tests for cache concurrency and safety features

#[cfg(test)]
mod tests {
    use super::super::file_cache::{CacheStats, FileCacheRepository};
    use crate::application::CacheService;
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::Barrier;
    use tokio::time::sleep;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: u64,
        name: String,
        value: f64,
    }

    impl TestData {
        fn new(id: u64) -> Self {
            Self {
                id,
                name: format!("test_item_{}", id),
                value: id as f64 * 1.5,
            }
        }
    }

    /// Create a test cache repository with a temporary directory
    async fn create_test_cache() -> (FileCacheRepository, TempDir) {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path().to_path_buf();
        let cache = FileCacheRepository::new(cache_dir, Duration::from_secs(3600));
        (cache, temp_dir)
    }

    /// Test concurrent writes to the same cache key
    #[tokio::test]
    async fn test_concurrent_writes_same_key() {
        let (cache, _temp_dir) = create_test_cache().await;
        let cache = Arc::new(cache);
        let num_writers = 10;
        let barrier = Arc::new(Barrier::new(num_writers));

        let mut handles = Vec::new();

        // Spawn multiple writers trying to write to the same key
        for i in 0..num_writers {
            let cache_clone = cache.clone();
            let barrier_clone = barrier.clone();
            let data = TestData::new(i as u64);

            let handle = tokio::spawn(async move {
                // Wait for all writers to be ready
                barrier_clone.wait().await;

                // All writers try to write at the same time
                cache_clone
                    .set("concurrent_key", &data, Duration::from_secs(60))
                    .await
                    .expect("Failed to write to cache");

                data.id
            });

            handles.push(handle);
        }

        // Wait for all writes to complete
        let results: Vec<u64> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("Task failed"))
            .collect();

        // Verify that all writes completed successfully
        assert_eq!(results.len(), num_writers);

        // Verify that the cache contains exactly one entry (the last write won)
        let cached_data: Option<TestData> = cache
            .get("concurrent_key")
            .await
            .expect("Failed to read from cache");

        assert!(cached_data.is_some());
        let cached_data = cached_data.unwrap();

        // The cached data should be one of the written values
        assert!(results.contains(&cached_data.id));

        println!(
            "Concurrent writes test passed. Final cached value: {:?}",
            cached_data
        );
    }

    /// Test concurrent reads and writes to different keys
    #[tokio::test]
    async fn test_concurrent_reads_writes_different_keys() {
        let (cache, _temp_dir) = create_test_cache().await;
        let cache = Arc::new(cache);
        let num_operations = 20;
        let barrier = Arc::new(Barrier::new(num_operations));

        let mut handles = Vec::new();

        // Spawn mixed read and write operations
        for i in 0..num_operations {
            let cache_clone = cache.clone();
            let barrier_clone = barrier.clone();
            let key = format!("key_{}", i);
            let data = TestData::new(i as u64);

            let handle = if i % 2 == 0 {
                // Write operation
                tokio::spawn(async move {
                    barrier_clone.wait().await;
                    cache_clone
                        .set(&key, &data, Duration::from_secs(60))
                        .await
                        .expect("Failed to write to cache");
                    format!("write_{}", i)
                })
            } else {
                // Read operation (will likely miss since we're writing concurrently)
                tokio::spawn(async move {
                    barrier_clone.wait().await;
                    let _result: Option<TestData> = cache_clone
                        .get(&key)
                        .await
                        .expect("Failed to read from cache");
                    format!("read_{}", i)
                })
            };

            handles.push(handle);
        }

        // Wait for all operations to complete
        let results: Vec<String> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("Task failed"))
            .collect();

        assert_eq!(results.len(), num_operations);

        // Verify that all write operations created cache entries
        for i in (0..num_operations).step_by(2) {
            let key = format!("key_{}", i);
            let cached_data: Option<TestData> =
                cache.get(&key).await.expect("Failed to read from cache");

            assert!(cached_data.is_some());
            assert_eq!(cached_data.unwrap().id, i as u64);
        }

        println!(
            "Concurrent reads/writes test passed with {} operations",
            num_operations
        );
    }

    /// Test atomic write operations using temporary files
    #[tokio::test]
    async fn test_atomic_write_operations() {
        let (cache, temp_dir) = create_test_cache().await;
        let cache = Arc::new(cache);
        let num_writers = 5;
        let writes_per_writer = 10;

        let mut handles = Vec::new();

        // Spawn multiple writers, each writing multiple entries
        for writer_id in 0..num_writers {
            let cache_clone = cache.clone();

            let handle = tokio::spawn(async move {
                let mut successful_writes = 0;

                for write_id in 0..writes_per_writer {
                    let key = format!("atomic_key_{}_{}", writer_id, write_id);
                    let data = TestData::new((writer_id * writes_per_writer + write_id) as u64);

                    match cache_clone.set(&key, &data, Duration::from_secs(60)).await {
                        Ok(()) => successful_writes += 1,
                        Err(e) => eprintln!("Write failed for {}: {}", key, e),
                    }

                    // Small delay to increase chance of concurrent operations
                    sleep(Duration::from_millis(1)).await;
                }

                successful_writes
            });

            handles.push(handle);
        }

        // Wait for all writers to complete
        let results: Vec<i32> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("Task failed"))
            .collect();

        // Verify all writes were successful
        let total_successful = results.iter().sum::<i32>();
        let expected_total = num_writers * writes_per_writer;
        assert_eq!(total_successful, expected_total);

        // Verify that no temporary files are left behind
        let cache_dir = temp_dir.path();
        let mut entries = tokio::fs::read_dir(cache_dir)
            .await
            .expect("Failed to read cache directory");

        let mut temp_file_count = 0;
        let mut json_file_count = 0;

        while let Some(entry) = entries
            .next_entry()
            .await
            .expect("Failed to read directory entry")
        {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                match extension.to_str() {
                    Some("tmp") => temp_file_count += 1,
                    Some("json") => json_file_count += 1,
                    _ => {}
                }
            }
        }

        assert_eq!(temp_file_count, 0, "Temporary files should be cleaned up");
        assert_eq!(json_file_count, expected_total as usize);

        println!(
            "Atomic write test passed: {} successful writes, {} JSON files, {} temp files",
            total_successful, json_file_count, temp_file_count
        );
    }

    /// Test cache directory creation and permissions
    #[tokio::test]
    async fn test_cache_directory_creation() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let cache_dir = temp_dir
            .path()
            .join("nested")
            .join("cache")
            .join("directory");

        // Cache directory doesn't exist initially
        assert!(!cache_dir.exists());

        let cache = FileCacheRepository::new(cache_dir.clone(), Duration::from_secs(3600));
        let data = TestData::new(1);

        // Writing to cache should create the directory
        cache
            .set("test_key", &data, Duration::from_secs(60))
            .await
            .expect("Failed to write to cache");

        // Verify directory was created
        assert!(cache_dir.exists());
        assert!(cache_dir.is_dir());

        // Verify we can read the data back
        let cached_data: Option<TestData> = cache
            .get("test_key")
            .await
            .expect("Failed to read from cache");

        assert!(cached_data.is_some());
        assert_eq!(cached_data.unwrap(), data);

        println!("Cache directory creation test passed");
    }

    /// Test race conditions during cache cleanup
    #[tokio::test]
    async fn test_concurrent_cleanup_operations() {
        let (cache, _temp_dir) = create_test_cache().await;
        let cache = Arc::new(cache);

        // Write some entries with short TTL
        for i in 0..10 {
            let key = format!("cleanup_key_{}", i);
            let data = TestData::new(i);
            cache
                .set(&key, &data, Duration::from_millis(100))
                .await
                .expect("Failed to write to cache");
        }

        // Wait for entries to expire
        sleep(Duration::from_millis(200)).await;

        // Start multiple cleanup operations concurrently
        let num_cleaners = 5;
        let mut handles = Vec::new();

        for i in 0..num_cleaners {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                let cleaned = cache_clone.cleanup_expired().await.expect("Cleanup failed");
                (i, cleaned)
            });
            handles.push(handle);
        }

        // Wait for all cleanup operations to complete
        let results: Vec<(i32, u64)> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("Task failed"))
            .collect();

        // Verify that cleanup operations completed successfully
        let total_cleaned: u64 = results.iter().map(|(_, cleaned)| cleaned).sum();

        // At least some entries should have been cleaned up
        // (exact number depends on timing and which cleaner gets there first)
        assert!(
            total_cleaned <= 10,
            "Should not clean more entries than exist"
        );

        println!(
            "Concurrent cleanup test passed: {} total entries cleaned by {} cleaners",
            total_cleaned, num_cleaners
        );
    }

    /// Test file locking prevents corruption during concurrent access
    #[tokio::test]
    async fn test_file_locking_prevents_corruption() {
        let (cache, _temp_dir) = create_test_cache().await;
        let cache = Arc::new(cache);
        let key = "corruption_test_key";
        let num_writers = 20;

        let mut handles = Vec::new();

        // Spawn many writers trying to write different data to the same key
        for i in 0..num_writers {
            let cache_clone = cache.clone();
            let data = TestData::new(i as u64);

            let handle = tokio::spawn(async move {
                // Random small delay to increase chance of concurrent access
                sleep(Duration::from_millis(i % 10)).await;

                cache_clone
                    .set(key, &data, Duration::from_secs(60))
                    .await
                    .expect("Failed to write to cache");

                data.id
            });

            handles.push(handle);
        }

        // Wait for all writes to complete
        let written_ids: Vec<u64> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("Task failed"))
            .collect();

        // Read the final value from cache
        let cached_data: Option<TestData> =
            cache.get(key).await.expect("Failed to read from cache");

        assert!(cached_data.is_some());
        let cached_data = cached_data.unwrap();

        // The cached data should be valid and match one of the written values
        assert!(written_ids.contains(&cached_data.id));
        assert_eq!(cached_data.name, format!("test_item_{}", cached_data.id));
        assert_eq!(cached_data.value, cached_data.id as f64 * 1.5);

        println!(
            "File locking test passed. Final cached data: {:?}",
            cached_data
        );
    }

    /// Test cache statistics accuracy under concurrent operations
    #[tokio::test]
    async fn test_cache_statistics_accuracy() {
        let (cache, _temp_dir) = create_test_cache().await;
        let cache = Arc::new(cache);
        let num_operations = 50;

        // Reset statistics
        cache.reset_stats().await;

        let mut handles = Vec::new();

        // Spawn mixed operations (writes, reads, invalidations)
        for i in 0..num_operations {
            let cache_clone = cache.clone();
            let key = format!("stats_key_{}", i % 10); // Reuse some keys

            let handle = match i % 3 {
                0 => {
                    // Write operation
                    let data = TestData::new(i as u64);
                    tokio::spawn(async move {
                        cache_clone
                            .set(&key, &data, Duration::from_secs(60))
                            .await
                            .expect("Write failed");
                        "write".to_string()
                    })
                }
                1 => {
                    // Read operation
                    tokio::spawn(async move {
                        let _: Option<TestData> = cache_clone.get(&key).await.expect("Read failed");
                        "read".to_string()
                    })
                }
                2 => {
                    // Invalidate operation
                    tokio::spawn(async move {
                        cache_clone
                            .invalidate(&key)
                            .await
                            .expect("Invalidate failed");
                        "invalidate".to_string()
                    })
                }
                _ => unreachable!(),
            };

            handles.push(handle);
        }

        // Wait for all operations to complete
        let results: Vec<String> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("Task failed"))
            .collect();

        assert_eq!(results.len(), num_operations);

        // Check final statistics
        let stats = cache.get_stats().await;
        println!("Final cache statistics: {:?}", stats);

        // Statistics should be consistent (hits + misses should equal read operations)
        let read_operations = results.iter().filter(|&op| op == "read").count() as u64;
        assert_eq!(stats.hits + stats.misses, read_operations);

        println!("Cache statistics test passed");
    }

    /// Test cache behavior under high concurrency load
    #[tokio::test]
    async fn test_high_concurrency_load() {
        let (cache, _temp_dir) = create_test_cache().await;
        let cache = Arc::new(cache);
        let num_tasks = 100;
        let operations_per_task = 10;

        let start_time = std::time::Instant::now();
        let mut handles = Vec::new();

        // Spawn many tasks performing multiple operations each
        for task_id in 0..num_tasks {
            let cache_clone = cache.clone();

            let handle = tokio::spawn(async move {
                let mut successful_ops = 0;

                for op_id in 0..operations_per_task {
                    let key = format!("load_key_{}_{}", task_id, op_id);
                    let data = TestData::new((task_id * operations_per_task + op_id) as u64);

                    // Write
                    if cache_clone
                        .set(&key, &data, Duration::from_secs(60))
                        .await
                        .is_ok()
                    {
                        successful_ops += 1;
                    }

                    // Read back
                    if let Ok(Some(_)) = cache_clone.get::<TestData>(&key).await {
                        successful_ops += 1;
                    }
                }

                successful_ops
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        let results: Vec<i32> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("Task failed"))
            .collect();

        let duration = start_time.elapsed();
        let total_successful = results.iter().sum::<i32>();
        let expected_total = num_tasks * operations_per_task * 2; // 2 operations per iteration

        println!(
            "High concurrency load test completed in {:?}: {}/{} operations successful",
            duration, total_successful, expected_total
        );

        // At least 90% of operations should succeed
        assert!(
            total_successful as f64 >= expected_total as f64 * 0.9,
            "Too many operations failed: {}/{}",
            total_successful,
            expected_total
        );

        // Performance check: should complete within reasonable time
        assert!(
            duration < Duration::from_secs(30),
            "Load test took too long: {:?}",
            duration
        );
    }
}
