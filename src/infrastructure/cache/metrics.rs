//! Cache metrics and monitoring

use std::{
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, time::interval};
use tracing::{debug, error, info, warn};

use crate::{
    application::ApplicationError,
    infrastructure::cache::{
        cache_service_wrapper::{CacheServiceWrapper, CacheStats},
    },
};

/// Cache performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    pub timestamp: u64,
    pub hit_rate: f64,
    pub miss_rate: f64,
    pub total_requests: u64,
    pub total_hits: u64,
    pub total_misses: u64,
    pub average_response_time_ms: f64,
    pub cache_size: Option<usize>,
    pub memory_usage_bytes: Option<u64>,
    pub connection_errors: u64,
    pub serialization_errors: u64,
    pub evictions: u64,
    pub expired_entries: u64,
}

/// Cache alert configuration
#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub hit_rate_threshold: f64,
    pub response_time_threshold_ms: f64,
    pub error_rate_threshold: f64,
    pub memory_usage_threshold_percent: f64,
    pub connection_failure_threshold: u32,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            hit_rate_threshold: 80.0, // Alert if hit rate drops below 80%
            response_time_threshold_ms: 100.0, // Alert if response time exceeds 100ms
            error_rate_threshold: 5.0, // Alert if error rate exceeds 5%
            memory_usage_threshold_percent: 90.0, // Alert if memory usage exceeds 90%
            connection_failure_threshold: 5, // Alert after 5 consecutive connection failures
        }
    }
}

/// Cache alert types
#[derive(Debug, Clone, Serialize)]
pub enum AlertType {
    LowHitRate { current: f64, threshold: f64 },
    HighResponseTime { current: f64, threshold: f64 },
    HighErrorRate { current: f64, threshold: f64 },
    HighMemoryUsage { current: f64, threshold: f64 },
    ConnectionFailures { count: u32, threshold: u32 },
    CacheUnavailable,
}

/// Cache alert
#[derive(Debug, Clone, Serialize)]
pub struct CacheAlert {
    pub alert_type: AlertType,
    pub timestamp: u64,
    pub severity: AlertSeverity,
    pub message: String,
    pub resolved: bool,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Cache monitoring service
pub struct CacheMonitor {
    cache: Arc<CacheServiceWrapper>,
    metrics_history: Arc<RwLock<Vec<CacheMetrics>>>,
    alerts: Arc<RwLock<Vec<CacheAlert>>>,
    alert_config: AlertConfig,
    response_times: Arc<RwLock<Vec<f64>>>,
    connection_failures: Arc<AtomicU64>,
}

impl CacheMonitor {
    /// Create a new cache monitor
    pub fn new(cache: Arc<CacheServiceWrapper>, alert_config: AlertConfig) -> Self {
        Self {
            cache,
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            alert_config,
            response_times: Arc::new(RwLock::new(Vec::new())),
            connection_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start monitoring with periodic collection
    pub fn start_monitoring(&self, collection_interval: Duration) -> tokio::task::JoinHandle<()> {
        let cache = self.cache.clone();
        let metrics_history = self.metrics_history.clone();
        let alerts = self.alerts.clone();
        let alert_config = self.alert_config.clone();
        let response_times = self.response_times.clone();
        let connection_failures = self.connection_failures.clone();

        tokio::spawn(async move {
            let mut interval = interval(collection_interval);
            
            loop {
                interval.tick().await;
                
                debug!("Collecting cache metrics");
                
                match Self::collect_metrics_static(
                    &cache,
                    &response_times,
                    connection_failures.load(Ordering::Relaxed),
                ).await {
                    Ok(metrics) => {
                        // Store metrics
                        {
                            let mut history = metrics_history.write().await;
                            history.push(metrics.clone());
                            
                            // Keep only last 1000 metrics (configurable)
                            if history.len() > 1000 {
                                history.remove(0);
                            }
                        }
                        
                        // Check for alerts
                        if let Some(alert) = Self::check_alerts(&metrics, &alert_config) {
                            let mut alerts_guard = alerts.write().await;
                            alerts_guard.push(alert.clone());
                            
                            // Keep only last 100 alerts
                            if alerts_guard.len() > 100 {
                                alerts_guard.remove(0);
                            }
                            
                            match alert.severity {
                                AlertSeverity::Critical => error!("Cache alert: {}", alert.message),
                                AlertSeverity::Warning => warn!("Cache alert: {}", alert.message),
                                AlertSeverity::Info => info!("Cache alert: {}", alert.message),
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to collect cache metrics: {}", e);
                        connection_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    }

    /// Collect current cache metrics
    pub async fn collect_metrics(&self) -> Result<CacheMetrics, ApplicationError> {
        Self::collect_metrics_static(
            &self.cache,
            &self.response_times,
            self.connection_failures.load(Ordering::Relaxed),
        ).await
    }

    /// Static method to collect metrics
    async fn collect_metrics_static(
        cache: &Arc<CacheServiceWrapper>,
        response_times: &Arc<RwLock<Vec<f64>>>,
        connection_failures: u64,
    ) -> Result<CacheMetrics, ApplicationError> {
        let stats = cache.get_stats().await;
        let cache_size = cache.size().await.ok();
        
        let total_requests = stats.total_hits() + stats.total_misses();
        let hit_rate = if total_requests > 0 {
            (stats.total_hits() as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };
        let miss_rate = 100.0 - hit_rate;

        // Calculate average response time
        let avg_response_time = {
            let times = response_times.read().await;
            if times.is_empty() {
                0.0
            } else {
                times.iter().sum::<f64>() / times.len() as f64
            }
        };

        // Get additional metrics based on cache type
        let (memory_usage, serialization_errors, evictions, expired_entries) = match &stats {
            CacheStats::File(file_stats) => (
                None,
                0,
                0,
                file_stats.expired_entries,
            ),
            CacheStats::Redis(redis_stats) => (
                None, // Would need Redis INFO command to get memory usage
                redis_stats.serialization_errors,
                0, // Would need Redis INFO command to get evictions
                0,
            ),
            CacheStats::Hybrid(hybrid_stats) => {
                let redis_serialization_errors = hybrid_stats.redis_stats
                    .as_ref()
                    .map(|rs| rs.serialization_errors)
                    .unwrap_or(0);
                (
                    None,
                    redis_serialization_errors,
                    0,
                    hybrid_stats.file_stats.expired_entries,
                )
            }
        };

        Ok(CacheMetrics {
            timestamp: Self::current_timestamp(),
            hit_rate,
            miss_rate,
            total_requests,
            total_hits: stats.total_hits(),
            total_misses: stats.total_misses(),
            average_response_time_ms: avg_response_time,
            cache_size,
            memory_usage_bytes: memory_usage,
            connection_errors: connection_failures,
            serialization_errors,
            evictions,
            expired_entries,
        })
    }

    /// Check for alert conditions
    fn check_alerts(metrics: &CacheMetrics, config: &AlertConfig) -> Option<CacheAlert> {
        let timestamp = Self::current_timestamp();

        // Check hit rate
        if metrics.hit_rate < config.hit_rate_threshold {
            return Some(CacheAlert {
                alert_type: AlertType::LowHitRate {
                    current: metrics.hit_rate,
                    threshold: config.hit_rate_threshold,
                },
                timestamp,
                severity: AlertSeverity::Warning,
                message: format!(
                    "Cache hit rate ({:.1}%) is below threshold ({:.1}%)",
                    metrics.hit_rate, config.hit_rate_threshold
                ),
                resolved: false,
            });
        }

        // Check response time
        if metrics.average_response_time_ms > config.response_time_threshold_ms {
            return Some(CacheAlert {
                alert_type: AlertType::HighResponseTime {
                    current: metrics.average_response_time_ms,
                    threshold: config.response_time_threshold_ms,
                },
                timestamp,
                severity: AlertSeverity::Warning,
                message: format!(
                    "Cache response time ({:.1}ms) exceeds threshold ({:.1}ms)",
                    metrics.average_response_time_ms, config.response_time_threshold_ms
                ),
                resolved: false,
            });
        }

        // Check error rate
        let error_rate = if metrics.total_requests > 0 {
            ((metrics.connection_errors + metrics.serialization_errors) as f64 / metrics.total_requests as f64) * 100.0
        } else {
            0.0
        };

        if error_rate > config.error_rate_threshold {
            return Some(CacheAlert {
                alert_type: AlertType::HighErrorRate {
                    current: error_rate,
                    threshold: config.error_rate_threshold,
                },
                timestamp,
                severity: AlertSeverity::Critical,
                message: format!(
                    "Cache error rate ({:.1}%) exceeds threshold ({:.1}%)",
                    error_rate, config.error_rate_threshold
                ),
                resolved: false,
            });
        }

        // Check connection failures
        if metrics.connection_errors > config.connection_failure_threshold as u64 {
            return Some(CacheAlert {
                alert_type: AlertType::ConnectionFailures {
                    count: metrics.connection_errors as u32,
                    threshold: config.connection_failure_threshold,
                },
                timestamp,
                severity: AlertSeverity::Critical,
                message: format!(
                    "Cache connection failures ({}) exceed threshold ({})",
                    metrics.connection_errors, config.connection_failure_threshold
                ),
                resolved: false,
            });
        }

        None
    }

    /// Record response time
    pub async fn record_response_time(&self, duration_ms: f64) {
        let mut times = self.response_times.write().await;
        times.push(duration_ms);
        
        // Keep only last 1000 response times
        if times.len() > 1000 {
            times.remove(0);
        }
    }

    /// Get metrics history
    pub async fn get_metrics_history(&self, limit: Option<usize>) -> Vec<CacheMetrics> {
        let history = self.metrics_history.read().await;
        let limit = limit.unwrap_or(history.len());
        
        if limit >= history.len() {
            history.clone()
        } else {
            history[history.len() - limit..].to_vec()
        }
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<CacheAlert> {
        let alerts = self.alerts.read().await;
        alerts.iter().filter(|alert| !alert.resolved).cloned().collect()
    }

    /// Get all alerts
    pub async fn get_all_alerts(&self, limit: Option<usize>) -> Vec<CacheAlert> {
        let alerts = self.alerts.read().await;
        let limit = limit.unwrap_or(alerts.len());
        
        if limit >= alerts.len() {
            alerts.clone()
        } else {
            alerts[alerts.len() - limit..].to_vec()
        }
    }

    /// Clear resolved alerts
    pub async fn clear_resolved_alerts(&self) {
        let mut alerts = self.alerts.write().await;
        alerts.retain(|alert| !alert.resolved);
        info!("Cleared resolved alerts");
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Cache performance report
#[derive(Debug, Serialize)]
pub struct CachePerformanceReport {
    pub period_start: u64,
    pub period_end: u64,
    pub total_requests: u64,
    pub average_hit_rate: f64,
    pub average_response_time_ms: f64,
    pub peak_response_time_ms: f64,
    pub total_errors: u64,
    pub error_rate: f64,
    pub uptime_percentage: f64,
    pub cache_efficiency_score: f64,
}

impl CacheMonitor {
    /// Generate performance report
    pub async fn generate_performance_report(
        &self,
        period_hours: u32,
    ) -> Result<CachePerformanceReport, ApplicationError> {
        let history = self.metrics_history.read().await;
        let now = Self::current_timestamp();
        let period_start = now - (period_hours as u64 * 3600);

        let relevant_metrics: Vec<&CacheMetrics> = history
            .iter()
            .filter(|m| m.timestamp >= period_start)
            .collect();

        if relevant_metrics.is_empty() {
            return Err(ApplicationError::NotFound {
                resource: "metrics".to_string(),
                id: format!("period_{}h", period_hours),
            });
        }

        let total_requests: u64 = relevant_metrics.iter().map(|m| m.total_requests).sum();
        let average_hit_rate = relevant_metrics.iter().map(|m| m.hit_rate).sum::<f64>() / relevant_metrics.len() as f64;
        let average_response_time = relevant_metrics.iter().map(|m| m.average_response_time_ms).sum::<f64>() / relevant_metrics.len() as f64;
        let peak_response_time = relevant_metrics.iter().map(|m| m.average_response_time_ms).fold(0.0, f64::max);
        let total_errors: u64 = relevant_metrics.iter().map(|m| m.connection_errors + m.serialization_errors).sum();
        let error_rate = if total_requests > 0 {
            (total_errors as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        // Calculate uptime (simplified - based on successful metric collections)
        let expected_collections = period_hours as usize * 12; // Assuming 5-minute intervals
        let actual_collections = relevant_metrics.len();
        let uptime_percentage = if expected_collections > 0 {
            (actual_collections as f64 / expected_collections as f64) * 100.0
        } else {
            100.0
        };

        // Calculate cache efficiency score (weighted combination of metrics)
        let cache_efficiency_score = (average_hit_rate * 0.4) + 
                                   ((100.0 - error_rate) * 0.3) + 
                                   (uptime_percentage * 0.3);

        Ok(CachePerformanceReport {
            period_start,
            period_end: now,
            total_requests,
            average_hit_rate,
            average_response_time_ms: average_response_time,
            peak_response_time_ms: peak_response_time,
            total_errors,
            error_rate,
            uptime_percentage,
            cache_efficiency_score,
        })
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
    async fn test_cache_monitor() {
        let temp_dir = TempDir::new().unwrap();
        let file_cache = Arc::new(FileCacheRepository::new(
            temp_dir.path().to_path_buf(),
            Duration::from_secs(3600),
        ));
        let cache = Arc::new(CacheServiceWrapper::file(file_cache));
        
        let alert_config = AlertConfig::default();
        let monitor = CacheMonitor::new(cache, alert_config);
        
        // Collect metrics
        let metrics = monitor.collect_metrics().await.unwrap();
        assert_eq!(metrics.total_hits, 0);
        assert_eq!(metrics.total_misses, 0);
        
        // Record response time
        monitor.record_response_time(50.0).await;
        
        let response_times = monitor.response_times.read().await;
        assert_eq!(response_times.len(), 1);
        assert_eq!(response_times[0], 50.0);
    }

    #[test]
    fn test_alert_creation() {
        let metrics = CacheMetrics {
            timestamp: 1234567890,
            hit_rate: 70.0, // Below default threshold of 80%
            miss_rate: 30.0,
            total_requests: 100,
            total_hits: 70,
            total_misses: 30,
            average_response_time_ms: 50.0,
            cache_size: Some(1000),
            memory_usage_bytes: None,
            connection_errors: 0,
            serialization_errors: 0,
            evictions: 0,
            expired_entries: 0,
        };
        
        let config = AlertConfig::default();
        let alert = CacheMonitor::check_alerts(&metrics, &config);
        
        assert!(alert.is_some());
        let alert = alert.unwrap();
        
        match alert.alert_type {
            AlertType::LowHitRate { current, threshold } => {
                assert_eq!(current, 70.0);
                assert_eq!(threshold, 80.0);
            }
            _ => panic!("Expected LowHitRate alert"),
        }
    }
}
