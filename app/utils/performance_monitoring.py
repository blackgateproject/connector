"""
Advanced Performance Monitoring and Alerting System

This module provides comprehensive performance monitoring, alerting, and analytics
for the Blackgate SMT proof system. It tracks detailed metrics across all operations
and provides real-time insights for optimization and troubleshooting.

Features:
- Real-time performance tracking with sub-millisecond precision
- Advanced statistical analysis (percentiles, moving averages, anomaly detection)
- Multi-dimensional metrics collection (latency, throughput, error rates)
- Automatic alerting for performance degradation
- Historical trend analysis and reporting
- Resource utilization monitoring
- Custom metric aggregation and export
"""

import asyncio
import json
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

import psutil


@dataclass
class PerformanceAlert:
    """Structure for performance alerts and notifications."""

    alert_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    metric_name: str
    current_value: float
    threshold_value: float
    timestamp: float = field(default_factory=time.time)
    resolved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "metric_name": self.metric_name,
            "current_value": self.current_value,
            "threshold_value": self.threshold_value,
            "timestamp": self.timestamp,
            "resolved": self.resolved,
            "formatted_time": datetime.fromtimestamp(self.timestamp).isoformat(),
        }


@dataclass
class MetricSnapshot:
    """Snapshot of a specific metric at a point in time."""

    name: str
    value: float
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)

    def age_seconds(self) -> float:
        return time.time() - self.timestamp


class AdvancedMetricsCollector:
    """
    Enterprise-grade metrics collection with statistical analysis and alerting.

    This collector provides:
    - High-resolution timing metrics
    - Statistical aggregation (mean, median, percentiles)
    - Anomaly detection using moving averages
    - Automatic alerting based on thresholds
    - Historical data retention with configurable windows
    - Export capabilities for external monitoring systems
    """

    def __init__(
        self, max_history_size: int = 10000, alert_cooldown_seconds: float = 300
    ):
        self.max_history_size = max_history_size
        self.alert_cooldown_seconds = alert_cooldown_seconds

        # Multi-dimensional metrics storage
        self.metrics_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=max_history_size)
        )
        self.aggregated_metrics: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.alerts_history: List[PerformanceAlert] = []

        # Alert configuration and state
        self.alert_thresholds: Dict[str, Dict[str, float]] = {
            "smt_proof_generation_ms": {"warning": 15.0, "critical": 25.0},
            "verification_duration_ms": {"warning": 8.0, "critical": 15.0},
            "cache_hit_ratio": {
                "warning": 0.8,  # Below 80%
                "critical": 0.6,  # Below 60%
            },
            "error_rate": {"warning": 0.05, "critical": 0.1},  # Above 5%  # Above 10%
            "memory_usage_mb": {"warning": 500.0, "critical": 800.0},
            "cpu_usage_percent": {"warning": 80.0, "critical": 95.0},
        }

        self.last_alert_times: Dict[str, float] = {}
        self.metric_lock = threading.RLock()

        # Statistical analysis configuration
        self.moving_average_window = 100
        self.anomaly_detection_threshold = 2.0  # Standard deviations

        # Alert callbacks for external notification systems
        self.alert_callbacks: List[Callable[[PerformanceAlert], None]] = []

        print("[AdvancedMetricsCollector] Performance monitoring system initialized")

    def record_metric(
        self, name: str, value: float, tags: Optional[Dict[str, str]] = None
    ):
        """Record a metric value with comprehensive statistical tracking."""
        with self.metric_lock:
            snapshot = MetricSnapshot(
                name=name, value=value, timestamp=time.time(), tags=tags or {}
            )

            # Store in history
            self.metrics_history[name].append(snapshot)

            # Update aggregated statistics
            self._update_aggregated_metrics(name)

            # Check for alerts
            self._check_metric_alerts(name, value)

            # Anomaly detection
            self._detect_anomalies(name, value)

    def _update_aggregated_metrics(self, metric_name: str):
        """Update aggregated statistics for a metric."""
        history = self.metrics_history[metric_name]
        if not history:
            return

        values = [snapshot.value for snapshot in history]
        recent_values = (
            values[-self.moving_average_window :]
            if len(values) > self.moving_average_window
            else values
        )

        # Calculate comprehensive statistics
        self.aggregated_metrics[metric_name] = {
            "count": len(values),
            "latest": values[-1],
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "min": min(values),
            "max": max(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "moving_average": statistics.mean(recent_values),
            "p50": statistics.median(values),
            "p90": self._percentile(values, 0.9),
            "p95": self._percentile(values, 0.95),
            "p99": self._percentile(values, 0.99),
            "recent_trend": (
                self._calculate_trend(recent_values[-10:])
                if len(recent_values) >= 10
                else 0.0
            ),
            "last_updated": time.time(),
        }

    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile value from a list of values."""
        if not values:
            return 0.0

        sorted_values = sorted(values)
        index = int(percentile * len(sorted_values))
        index = min(index, len(sorted_values) - 1)
        return sorted_values[index]

    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend direction (-1 to 1) for recent values."""
        if len(values) < 2:
            return 0.0

        # Simple linear regression slope calculation
        n = len(values)
        x_sum = sum(range(n))
        y_sum = sum(values)
        xy_sum = sum(i * values[i] for i in range(n))
        x_squared_sum = sum(i * i for i in range(n))

        denominator = n * x_squared_sum - x_sum * x_sum
        if denominator == 0:
            return 0.0

        slope = (n * xy_sum - x_sum * y_sum) / denominator
        return max(-1.0, min(1.0, slope))  # Normalize to [-1, 1]

    def _check_metric_alerts(self, metric_name: str, value: float):
        """Check if metric value triggers any alerts."""
        if metric_name not in self.alert_thresholds:
            return

        thresholds = self.alert_thresholds[metric_name]
        current_time = time.time()

        # Check cooldown period
        last_alert_time = self.last_alert_times.get(metric_name, 0)
        if current_time - last_alert_time < self.alert_cooldown_seconds:
            return

        # Check thresholds
        alert = None
        if "critical" in thresholds:
            if (
                (
                    metric_name
                    in ["error_rate", "memory_usage_mb", "cpu_usage_percent"]
                    and value > thresholds["critical"]
                )
                or (metric_name == "cache_hit_ratio" and value < thresholds["critical"])
                or (
                    metric_name
                    in ["smt_proof_generation_ms", "verification_duration_ms"]
                    and value > thresholds["critical"]
                )
            ):
                alert = PerformanceAlert(
                    alert_type="THRESHOLD_EXCEEDED",
                    severity="CRITICAL",
                    message=f"CRITICAL: {metric_name} = {value:.2f} exceeds critical threshold {thresholds['critical']:.2f}",
                    metric_name=metric_name,
                    current_value=value,
                    threshold_value=thresholds["critical"],
                )

        if not alert and "warning" in thresholds:
            if (
                (
                    metric_name
                    in ["error_rate", "memory_usage_mb", "cpu_usage_percent"]
                    and value > thresholds["warning"]
                )
                or (metric_name == "cache_hit_ratio" and value < thresholds["warning"])
                or (
                    metric_name
                    in ["smt_proof_generation_ms", "verification_duration_ms"]
                    and value > thresholds["warning"]
                )
            ):
                alert = PerformanceAlert(
                    alert_type="THRESHOLD_EXCEEDED",
                    severity="WARNING",
                    message=f"WARNING: {metric_name} = {value:.2f} exceeds warning threshold {thresholds['warning']:.2f}",
                    metric_name=metric_name,
                    current_value=value,
                    threshold_value=thresholds["warning"],
                )

        if alert:
            self._trigger_alert(alert)
            self.last_alert_times[metric_name] = current_time

    def _detect_anomalies(self, metric_name: str, value: float):
        """Detect anomalies using statistical analysis."""
        history = self.metrics_history[metric_name]
        if len(history) < 20:  # Need sufficient history
            return

        recent_values = [s.value for s in list(history)[-self.moving_average_window :]]
        if len(recent_values) < 10:
            return

        mean_value = statistics.mean(recent_values[:-1])  # Exclude current value
        std_dev = statistics.stdev(recent_values[:-1]) if len(recent_values) > 2 else 0

        if std_dev == 0:
            return

        z_score = abs(value - mean_value) / std_dev

        if z_score > self.anomaly_detection_threshold:
            anomaly_alert = PerformanceAlert(
                alert_type="ANOMALY_DETECTED",
                severity="MEDIUM",
                message=f"ANOMALY: {metric_name} = {value:.2f} deviates {z_score:.2f} standard deviations from mean {mean_value:.2f}",
                metric_name=metric_name,
                current_value=value,
                threshold_value=mean_value
                + (self.anomaly_detection_threshold * std_dev),
            )
            self._trigger_alert(anomaly_alert)

    def _trigger_alert(self, alert: PerformanceAlert):
        """Trigger an alert and notify all registered callbacks."""
        self.alerts_history.append(alert)

        # Keep alert history manageable
        if len(self.alerts_history) > 1000:
            self.alerts_history = self.alerts_history[-800:]  # Keep most recent 800

        print(f"[ALERT] {alert.severity}: {alert.message}")

        # Notify all registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"[AdvancedMetricsCollector] Alert callback error: {e}")

    def add_alert_callback(self, callback: Callable[[PerformanceAlert], None]):
        """Register a callback function for alert notifications."""
        self.alert_callbacks.append(callback)

    def get_metric_summary(self, metric_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive summary for a specific metric."""
        with self.metric_lock:
            if metric_name not in self.aggregated_metrics:
                return None

            return {
                "name": metric_name,
                "statistics": self.aggregated_metrics[metric_name].copy(),
                "recent_alerts": [
                    alert.to_dict()
                    for alert in self.alerts_history[-10:]
                    if alert.metric_name == metric_name and not alert.resolved
                ],
                "sample_count": len(self.metrics_history[metric_name]),
                "alert_thresholds": self.alert_thresholds.get(metric_name, {}),
            }

    def get_all_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of all tracked metrics."""
        with self.metric_lock:
            return {
                "metrics": {
                    name: self.get_metric_summary(name)
                    for name in self.aggregated_metrics.keys()
                },
                "system_overview": {
                    "total_metrics": len(self.aggregated_metrics),
                    "total_measurements": sum(
                        len(history) for history in self.metrics_history.values()
                    ),
                    "active_alerts": len(
                        [a for a in self.alerts_history if not a.resolved]
                    ),
                    "monitoring_uptime_hours": (
                        (time.time() - self._start_time) / 3600
                        if hasattr(self, "_start_time")
                        else 0
                    ),
                    "last_updated": time.time(),
                },
                "recent_alerts": [
                    alert.to_dict()
                    for alert in self.alerts_history[-20:]
                    if not alert.resolved
                ],
            }

    def export_metrics_for_external_system(
        self, format_type: str = "prometheus"
    ) -> str:
        """Export metrics in format suitable for external monitoring systems."""
        if format_type == "prometheus":
            return self._export_prometheus_format()
        elif format_type == "json":
            return json.dumps(self.get_all_metrics_summary(), default=str, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def _export_prometheus_format(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        current_time = int(time.time() * 1000)

        with self.metric_lock:
            for metric_name, stats in self.aggregated_metrics.items():
                safe_name = metric_name.replace(".", "_").replace("-", "_")

                # Export key statistics
                lines.append(
                    f"blackgate_{safe_name}_mean {stats['mean']:.6f} {current_time}"
                )
                lines.append(
                    f"blackgate_{safe_name}_p95 {stats['p95']:.6f} {current_time}"
                )
                lines.append(
                    f"blackgate_{safe_name}_count {stats['count']} {current_time}"
                )
                lines.append(
                    f"blackgate_{safe_name}_latest {stats['latest']:.6f} {current_time}"
                )

        return "\n".join(lines)

    def cleanup_old_data(self, max_age_hours: float = 24):
        """Clean up old metric data to manage memory usage."""
        cutoff_time = time.time() - (max_age_hours * 3600)

        with self.metric_lock:
            # Clean metric history
            for metric_name, history in self.metrics_history.items():
                # Convert deque to list, filter, convert back
                filtered_snapshots = [s for s in history if s.timestamp > cutoff_time]
                history.clear()
                history.extend(filtered_snapshots)

            # Clean alert history
            self.alerts_history = [
                alert for alert in self.alerts_history if alert.timestamp > cutoff_time
            ]

        print(
            f"[AdvancedMetricsCollector] Cleaned data older than {max_age_hours} hours"
        )


# Global metrics collector instance
_metrics_collector = None
_collector_lock = threading.Lock()


def get_metrics_collector() -> AdvancedMetricsCollector:
    """Get singleton instance of the advanced metrics collector."""
    global _metrics_collector

    if _metrics_collector is None:
        with _collector_lock:
            if _metrics_collector is None:
                _metrics_collector = AdvancedMetricsCollector()
                _metrics_collector._start_time = time.time()
                print("[get_metrics_collector] Advanced metrics collector initialized")

    return _metrics_collector


def log_verification_metrics(metrics_data: Dict[str, Any]):
    """
    Log verification metrics to the advanced collector.

    This function provides a simple interface for logging metrics from
    various parts of the application.
    """
    collector = get_metrics_collector()

    # Extract and log individual metrics
    if "duration_ms" in metrics_data:
        collector.record_metric(
            f"{metrics_data.get('operation', 'unknown')}_duration_ms",
            metrics_data["duration_ms"],
            tags={"operation": metrics_data.get("operation", "unknown")},
        )

    if "success" in metrics_data:
        success_value = 1.0 if metrics_data["success"] else 0.0
        collector.record_metric(
            f"{metrics_data.get('operation', 'unknown')}_success_rate",
            success_value,
            tags={"operation": metrics_data.get("operation", "unknown")},
        )

    if "cache_hit" in metrics_data:
        cache_hit_value = 1.0 if metrics_data["cache_hit"] else 0.0
        collector.record_metric(
            "cache_hit_ratio",
            cache_hit_value,
            tags={"operation": metrics_data.get("operation", "unknown")},
        )


def log_performance_metric(
    name: str, value: float, tags: Optional[Dict[str, str]] = None
):
    """Simple interface for logging a single performance metric."""
    collector = get_metrics_collector()
    collector.record_metric(name, value, tags)


# Decorator for automatic performance monitoring
def monitor_performance_advanced(metric_name: str, include_success_rate: bool = True):
    """
    Advanced decorator for automatic performance monitoring with detailed metrics.

    This decorator automatically tracks:
    - Operation duration
    - Success/failure rates
    - Exception types and frequencies
    - Resource utilization during operation
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024

            try:
                result = func(*args, **kwargs)

                # Success metrics
                duration_ms = (time.time() - start_time) * 1000
                end_memory = psutil.Process().memory_info().rss / 1024 / 1024
                memory_delta = end_memory - start_memory

                collector.record_metric(f"{metric_name}_duration_ms", duration_ms)
                collector.record_metric(f"{metric_name}_memory_delta_mb", memory_delta)

                if include_success_rate:
                    collector.record_metric(f"{metric_name}_success_rate", 1.0)

                return result

            except Exception as e:
                # Failure metrics
                duration_ms = (time.time() - start_time) * 1000
                collector.record_metric(f"{metric_name}_duration_ms", duration_ms)

                if include_success_rate:
                    collector.record_metric(f"{metric_name}_success_rate", 0.0)

                # Log exception type
                exception_type = type(e).__name__
                collector.record_metric(
                    f"{metric_name}_error_rate",
                    1.0,
                    tags={"exception_type": exception_type},
                )

                raise

        # Handle async functions
        if asyncio.iscoroutinefunction(func):

            async def async_wrapper(*args, **kwargs):
                collector = get_metrics_collector()
                start_time = time.time()
                start_memory = psutil.Process().memory_info().rss / 1024 / 1024

                try:
                    result = await func(*args, **kwargs)

                    # Success metrics
                    duration_ms = (time.time() - start_time) * 1000
                    end_memory = psutil.Process().memory_info().rss / 1024 / 1024
                    memory_delta = end_memory - start_memory

                    collector.record_metric(f"{metric_name}_duration_ms", duration_ms)
                    collector.record_metric(
                        f"{metric_name}_memory_delta_mb", memory_delta
                    )

                    if include_success_rate:
                        collector.record_metric(f"{metric_name}_success_rate", 1.0)

                    return result

                except Exception as e:
                    # Failure metrics
                    duration_ms = (time.time() - start_time) * 1000
                    collector.record_metric(f"{metric_name}_duration_ms", duration_ms)

                    if include_success_rate:
                        collector.record_metric(f"{metric_name}_success_rate", 0.0)

                    # Log exception type
                    exception_type = type(e).__name__
                    collector.record_metric(
                        f"{metric_name}_error_rate",
                        1.0,
                        tags={"exception_type": exception_type},
                    )

                    raise

            return async_wrapper
        else:
            return wrapper

    return decorator
