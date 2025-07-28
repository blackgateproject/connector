"""
Performance Testing Configuration and Utilities

This module provides configuration management and utility functions
for the performance testing framework.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class PerformanceTestConfig:
    """Configuration for performance tests."""

    # Connection settings
    base_url: str = "http://localhost:8000"
    timeout: float = 60.0

    # Database settings
    db_url: Optional[str] = None

    # Load test settings
    default_load_levels: list = None
    max_concurrent_requests: int = 50
    poll_interval: float = 2.0
    max_poll_attempts: int = 30

    # Simulation settings
    simulate_wallet_generation_delay: float = 0.01
    simulate_wallet_encryption_delay: float = 0.005
    simulate_network_info_delay: float = 0.002
    simulate_vp_generation_delay: float = 0.01

    # Output settings
    output_directory: str = "performance_reports"
    generate_json_output: bool = True
    generate_markdown_reports: bool = True

    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0

    def __post_init__(self):
        if self.default_load_levels is None:
            self.default_load_levels = [100, 200, 400, 800, 1000]

    @classmethod
    def from_env(cls) -> "PerformanceTestConfig":
        """Create configuration from environment variables."""
        return cls(
            base_url=os.getenv("PERF_TEST_BASE_URL", "http://localhost:8000"),
            timeout=float(os.getenv("PERF_TEST_TIMEOUT", "60.0")),
            db_url=os.getenv("PERF_TEST_DB_URL"),
            max_concurrent_requests=int(os.getenv("PERF_TEST_MAX_CONCURRENT", "50")),
            poll_interval=float(os.getenv("PERF_TEST_POLL_INTERVAL", "2.0")),
            max_poll_attempts=int(os.getenv("PERF_TEST_MAX_POLL_ATTEMPTS", "30")),
            output_directory=os.getenv("PERF_TEST_OUTPUT_DIR", "performance_reports"),
            generate_json_output=os.getenv("PERF_TEST_GENERATE_JSON", "true").lower()
            == "true",
            generate_markdown_reports=os.getenv("PERF_TEST_GENERATE_MD", "true").lower()
            == "true",
            max_retries=int(os.getenv("PERF_TEST_MAX_RETRIES", "3")),
            retry_delay=float(os.getenv("PERF_TEST_RETRY_DELAY", "1.0")),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "base_url": self.base_url,
            "timeout": self.timeout,
            "db_url": self.db_url,
            "default_load_levels": self.default_load_levels,
            "max_concurrent_requests": self.max_concurrent_requests,
            "poll_interval": self.poll_interval,
            "max_poll_attempts": self.max_poll_attempts,
            "simulate_wallet_generation_delay": self.simulate_wallet_generation_delay,
            "simulate_wallet_encryption_delay": self.simulate_wallet_encryption_delay,
            "simulate_network_info_delay": self.simulate_network_info_delay,
            "simulate_vp_generation_delay": self.simulate_vp_generation_delay,
            "output_directory": self.output_directory,
            "generate_json_output": self.generate_json_output,
            "generate_markdown_reports": self.generate_markdown_reports,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
        }


def create_output_directory(config: PerformanceTestConfig) -> Path:
    """Create and return the output directory path."""
    output_path = Path(config.output_directory)
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def validate_database_connection(db_url: str) -> bool:
    """Validate database connection."""
    if not db_url:
        return False

    try:
        import psycopg

        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                return True
    except Exception:
        return False


def check_server_health(base_url: str, timeout: float = 10.0) -> bool:
    """Check if the server is running and healthy."""
    try:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            response = client.get(f"{base_url.rstrip('/')}/")
            return response.status_code == 200
    except Exception:
        return False


def estimate_test_duration(
    num_users: int, max_concurrent: int, avg_time_per_user: float = 30.0
) -> float:
    """Estimate total test duration based on parameters."""
    # Calculate number of batches
    num_batches = (num_users + max_concurrent - 1) // max_concurrent

    # Estimate duration (assuming some overlap between batches)
    estimated_duration = (
        num_batches * avg_time_per_user
    ) * 0.8  # 20% overlap assumption

    return estimated_duration


def format_duration(seconds: float) -> str:
    """Format duration in a human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def calculate_memory_usage_estimate(num_users: int) -> str:
    """Estimate memory usage for the test."""
    # Rough estimate: ~1KB per user for metrics storage
    memory_kb = num_users * 1

    if memory_kb < 1024:
        return f"{memory_kb}KB"
    elif memory_kb < 1024 * 1024:
        return f"{memory_kb / 1024:.1f}MB"
    else:
        return f"{memory_kb / (1024 * 1024):.1f}GB"


def get_recommended_concurrency(num_users: int) -> int:
    """Get recommended concurrency level based on number of users."""
    if num_users <= 50:
        return min(10, num_users)
    elif num_users <= 100:
        return 20
    elif num_users <= 200:
        return 30
    elif num_users <= 500:
        return 40
    else:
        return 50


class PerformanceTestValidator:
    """Validator for performance test configurations and prerequisites."""

    def __init__(self, config: PerformanceTestConfig):
        self.config = config
        self.validation_errors = []
        self.validation_warnings = []

    def validate_all(self) -> bool:
        """Run all validations and return True if all pass."""
        self.validation_errors.clear()
        self.validation_warnings.clear()

        # Validate server connection
        if not check_server_health(self.config.base_url, self.config.timeout):
            self.validation_errors.append(
                f"Cannot connect to server at {self.config.base_url}"
            )

        # Validate database connection (if provided)
        if self.config.db_url and not validate_database_connection(self.config.db_url):
            self.validation_warnings.append(
                "Database connection failed - metrics will not be stored"
            )

        # Validate output directory
        try:
            create_output_directory(self.config)
        except Exception as e:
            self.validation_errors.append(f"Cannot create output directory: {str(e)}")

        # Validate configuration values
        if self.config.timeout <= 0:
            self.validation_errors.append("Timeout must be positive")

        if self.config.max_concurrent_requests <= 0:
            self.validation_errors.append("Max concurrent requests must be positive")

        if not self.config.default_load_levels:
            self.validation_errors.append("Default load levels cannot be empty")

        if any(level <= 0 for level in self.config.default_load_levels):
            self.validation_errors.append("All load levels must be positive")

        # Performance warnings
        max_load = (
            max(self.config.default_load_levels)
            if self.config.default_load_levels
            else 0
        )
        if max_load > 1000:
            self.validation_warnings.append(
                f"Load level {max_load} is quite high - ensure server can handle it"
            )

        if self.config.max_concurrent_requests > 100:
            self.validation_warnings.append("High concurrency may overwhelm the server")

        return len(self.validation_errors) == 0

    def get_validation_report(self) -> str:
        """Get a formatted validation report."""
        report = "Performance Test Validation Report\n"
        report += "=" * 40 + "\n\n"

        if not self.validation_errors and not self.validation_warnings:
            report += "✅ All validations passed!\n"
        else:
            if self.validation_errors:
                report += "❌ Errors:\n"
                for error in self.validation_errors:
                    report += f"  - {error}\n"
                report += "\n"

            if self.validation_warnings:
                report += "⚠️ Warnings:\n"
                for warning in self.validation_warnings:
                    report += f"  - {warning}\n"
                report += "\n"

        # Add configuration summary
        report += "Configuration Summary:\n"
        report += f"  - Base URL: {self.config.base_url}\n"
        report += f"  - Load Levels: {self.config.default_load_levels}\n"
        report += f"  - Max Concurrent: {self.config.max_concurrent_requests}\n"
        report += f"  - Timeout: {self.config.timeout}s\n"
        report += f"  - Output Directory: {self.config.output_directory}\n"

        return report
