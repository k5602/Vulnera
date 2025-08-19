# Redis Cache System Guide

This guide provides comprehensive documentation for the Redis caching system implemented in Vulnera.

## Overview

The Vulnera Redis cache system provides a flexible, high-performance caching solution with support for:

- **Multiple Cache Strategies**: File-only, Redis-only, Redis with file fallback, and hybrid caching
- **Session Management**: Redis-based session storage with automatic cleanup
- **Rate Limiting**: Sliding window rate limiting with distributed counters
- **Monitoring & Metrics**: Comprehensive performance monitoring and alerting
- **Cache Warming**: Intelligent cache pre-loading strategies
- **HTTP Middleware**: Response caching and request deduplication

## Configuration

### Basic Configuration

Add Redis configuration to your `config/default.toml`:

```toml
[cache]
directory = ".vulnera_cache"
ttl_hours = 24
strategy = "RedisWithFileFallback"

[cache.redis]
url = "redis://localhost:6379"
pool_size = 10
connection_timeout_seconds = 5
command_timeout_seconds = 3
retry_attempts = 3
key_prefix = "vulnera:"
enable_compression = true
max_key_length = 250
```

### Environment Variables

You can also configure Redis using environment variables:

```bash
# Redis connection
VULNERA__CACHE__REDIS__URL=redis://localhost:6379
VULNERA__CACHE__REDIS__POOL_SIZE=10

# Cache strategy
VULNERA__CACHE__STRATEGY=RedisWithFileFallback

# Connection settings
VULNERA__CACHE__REDIS__CONNECTION_TIMEOUT_SECONDS=5
VULNERA__CACHE__REDIS__COMMAND_TIMEOUT_SECONDS=3
VULNERA__CACHE__REDIS__RETRY_ATTEMPTS=3
```

### Cache Strategies

#### 1. FileOnly
Uses only file-based caching. No Redis required.

```toml
[cache]
strategy = "FileOnly"
```

#### 2. RedisOnly
Uses only Redis for caching. Requires Redis to be available.

```toml
[cache]
strategy = "RedisOnly"
[cache.redis]
url = "redis://localhost:6379"
```

#### 3. RedisWithFileFallback
Prefers Redis but falls back to file cache if Redis is unavailable.

```toml
[cache]
strategy = "RedisWithFileFallback"
[cache.redis]
url = "redis://localhost:6379"
```

#### 4. Hybrid
Uses both Redis and file cache simultaneously for maximum reliability.

```toml
[cache]
strategy = "Hybrid"
[cache.redis]
url = "redis://localhost:6379"
```

## Usage Examples

### Basic Cache Operations

```rust
use vulnera_rust::infrastructure::cache::cache_factory::CacheFactory;
use std::time::Duration;

// Create cache service
let cache = CacheFactory::create_with_fallback(&config.cache).await;

// Set a value
cache.set("my_key", &"my_value", Duration::from_secs(3600)).await?;

// Get a value
let value: Option<String> = cache.get("my_key").await?;

// Invalidate a key
cache.invalidate("my_key").await?;

// Clear all cache
cache.clear_all().await?;
```

### Session Management

```rust
use vulnera_rust::infrastructure::cache::session_management::{
    SessionManager, SessionConfig
};

let session_manager = SessionManager::new(cache, SessionConfig::default());

// Create a session
let session = session_manager.create_session(
    Some("user123".to_string()),
    Some("192.168.1.1".to_string()),
    Some("Mozilla/5.0".to_string()),
).await?;

// Get session
let retrieved_session = session_manager
    .get_session(&session.session_id)
    .await?;

// Update session data
let mut data = std::collections::HashMap::new();
data.insert("key".to_string(), serde_json::json!("value"));
session_manager.update_session(&session.session_id, data).await?;

// Delete session
session_manager.delete_session(&session.session_id).await?;
```

### Rate Limiting

```rust
use vulnera_rust::infrastructure::cache::session_management::{
    RateLimiter, RateLimitConfig
};

let config = RateLimitConfig {
    window_size: Duration::from_secs(60),
    max_requests: 100,
    ..Default::default()
};
let rate_limiter = RateLimiter::new(cache, config);

// Check if request is allowed
if rate_limiter.is_allowed("client_ip").await? {
    // Process request
} else {
    // Rate limit exceeded
}

// Get current count
let count = rate_limiter.get_current_count("client_ip").await?;

// Reset rate limit
rate_limiter.reset("client_ip").await?;
```

### Cache Monitoring

```rust
use vulnera_rust::infrastructure::cache::metrics::{
    CacheMonitor, AlertConfig
};

let monitor = CacheMonitor::new(cache, AlertConfig::default());

// Start monitoring (collects metrics every 5 minutes)
let _handle = monitor.start_monitoring(Duration::from_secs(300));

// Collect current metrics
let metrics = monitor.collect_metrics().await?;

// Get metrics history
let history = monitor.get_metrics_history(Some(100)).await;

// Get active alerts
let alerts = monitor.get_active_alerts().await;

// Generate performance report
let report = monitor.generate_performance_report(24).await?; // Last 24 hours
```

## API Endpoints

The cache system provides admin endpoints for management:

### Cache Statistics
```
GET /admin/cache/stats?include_details=true
```

Response:
```json
{
  "cache_type": "Hybrid",
  "total_hits": 1250,
  "total_misses": 150,
  "hit_rate": 89.3,
  "cache_size": 5000,
  "detailed_stats": {
    "strategy": "Hybrid",
    "redis_available": true,
    "file_stats": { ... },
    "redis_stats": { ... }
  }
}
```

### Cache Health Check
```
GET /admin/cache/health
```

### Clear Cache
```
POST /admin/cache/clear
```

### Invalidate Specific Keys
```
POST /admin/cache/invalidate
Content-Type: application/json

{
  "keys": ["key1", "key2"],
  "pattern": "user:*",
  "clear_all": false
}
```

### Cache Warming
```
POST /admin/cache/warm
Content-Type: application/json

{
  "keys": ["important_key1", "important_key2"],
  "strategy": "startup",
  "batch_size": 100
}
```

### Key Information
```
GET /admin/cache/keys/{key}
```

## Performance Tuning

### Redis Configuration

For optimal performance, configure Redis with:

```redis
# Memory management
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence (adjust based on needs)
save 900 1
save 300 10
save 60 10000

# Network
tcp-keepalive 300
timeout 0

# Performance
tcp-nodelay yes
```

### Connection Pool Settings

Adjust pool size based on your application's concurrency:

```toml
[cache.redis]
pool_size = 20  # For high-concurrency applications
connection_timeout_seconds = 10
command_timeout_seconds = 5
```

### Cache Key Design

Use hierarchical key naming for better organization:

```
vulnera:user:123:profile
vulnera:vulnerability:CVE-2023-1234
vulnera:analysis:npm:package-name:1.0.0
```

## Monitoring and Alerting

### Key Metrics

The system tracks:

- **Hit Rate**: Percentage of cache hits vs total requests
- **Response Time**: Average cache operation latency
- **Error Rate**: Percentage of failed operations
- **Memory Usage**: Cache memory consumption
- **Connection Health**: Redis connection status

### Alert Thresholds

Default alert thresholds:

- Hit rate below 80%
- Response time above 100ms
- Error rate above 5%
- Memory usage above 90%
- More than 5 consecutive connection failures

### Custom Alerts

Configure custom alert thresholds:

```rust
let alert_config = AlertConfig {
    hit_rate_threshold: 85.0,
    response_time_threshold_ms: 50.0,
    error_rate_threshold: 2.0,
    memory_usage_threshold_percent: 80.0,
    connection_failure_threshold: 3,
};
```

## Troubleshooting

### Common Issues

#### Redis Connection Failures
- Check Redis server status: `redis-cli ping`
- Verify connection URL and credentials
- Check network connectivity and firewall rules
- Monitor Redis logs for errors

#### High Memory Usage
- Review cache TTL settings
- Implement cache eviction policies
- Monitor key patterns for memory leaks
- Consider data compression

#### Poor Hit Rates
- Analyze cache key patterns
- Review TTL settings
- Implement cache warming strategies
- Check for cache invalidation issues

### Debug Mode

Enable debug logging for detailed cache operations:

```toml
[logging]
level = "debug"
```

### Health Checks

Use the health check endpoint to monitor cache status:

```bash
curl http://localhost:3000/admin/cache/health
```

## Best Practices

1. **Key Naming**: Use consistent, hierarchical key naming conventions
2. **TTL Management**: Set appropriate TTL values based on data volatility
3. **Error Handling**: Always handle cache failures gracefully
4. **Monitoring**: Implement comprehensive monitoring and alerting
5. **Testing**: Test cache behavior under various failure scenarios
6. **Security**: Use Redis AUTH and network security measures
7. **Backup**: Implement cache warming strategies for critical data

## Migration Guide

### From File-Only to Redis

1. Update configuration to use `RedisWithFileFallback`
2. Deploy Redis infrastructure
3. Test cache operations
4. Monitor performance metrics
5. Gradually migrate to `RedisOnly` if desired

### Scaling Considerations

For high-scale deployments:

- Use Redis Cluster for horizontal scaling
- Implement cache sharding strategies
- Consider read replicas for read-heavy workloads
- Monitor and tune connection pool sizes
- Implement circuit breakers for resilience

## Security

### Redis Security

- Enable Redis AUTH: `requirepass your-strong-password`
- Use TLS encryption: `tls-port 6380`
- Restrict network access with firewalls
- Disable dangerous commands: `rename-command FLUSHALL ""`

### Application Security

- Validate cache keys to prevent injection
- Implement proper access controls
- Use secure session management
- Monitor for suspicious cache patterns
