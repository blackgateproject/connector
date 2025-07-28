"""
PyTest Configuration for Performance Tests

This module provides pytest fixtures and configuration for performance testing.
"""

import asyncio
import os
import shutil
import tempfile
from typing import AsyncGenerator, Generator

import pytest

from performance_testing.config import PerformanceTestConfig
from performance_testing.load_test_framework import LoadTestRunner


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def perf_test_config() -> PerformanceTestConfig:
    """Provide performance test configuration."""
    config = PerformanceTestConfig.from_env()

    # Override for testing
    config.base_url = os.getenv("TEST_BASE_URL", "http://localhost:8000")
    config.default_load_levels = [5, 10]  # Smaller loads for testing
    config.max_concurrent_requests = 5
    config.timeout = 30.0

    return config


@pytest.fixture(scope="session")
async def load_test_runner(
    perf_test_config: PerformanceTestConfig,
) -> AsyncGenerator[LoadTestRunner, None]:
    """Provide a configured load test runner."""
    runner = LoadTestRunner(
        base_url=perf_test_config.base_url, db_url=perf_test_config.db_url
    )
    yield runner


@pytest.fixture(scope="function")
def temp_output_dir() -> Generator[str, None, None]:
    """Provide a temporary output directory for test reports."""
    temp_dir = tempfile.mkdtemp(prefix="perf_test_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def server_health_check(perf_test_config: PerformanceTestConfig) -> bool:
    """Check if the test server is running before running tests."""
    from performance_testing.config import check_server_health

    is_healthy = check_server_health(perf_test_config.base_url)
    if not is_healthy:
        pytest.skip(f"Server at {perf_test_config.base_url} is not responding")

    return is_healthy


# Markers for different types of performance tests
pytestmark = [pytest.mark.asyncio, pytest.mark.performance]


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "performance: mark test as a performance test")
    config.addinivalue_line("markers", "load_test: mark test as a load test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "integration: mark test as integration test")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add appropriate markers."""
    for item in items:
        # Add performance marker to all tests in performance_testing directory
        if "performance_testing" in str(item.fspath):
            item.add_marker(pytest.mark.performance)

        # Add slow marker to load tests
        if "load_test" in item.name:
            item.add_marker(pytest.mark.slow)


@pytest.fixture(autouse=True)
def performance_test_setup(request):
    """Automatic setup for performance tests."""
    # Skip performance tests if explicitly disabled
    if request.config.getoption("--skip-performance", default=False):
        pytest.skip("Performance tests disabled via --skip-performance")


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--skip-performance",
        action="store_true",
        default=False,
        help="Skip performance tests",
    )
    parser.addoption(
        "--performance-only",
        action="store_true",
        default=False,
        help="Run only performance tests",
    )
    parser.addoption(
        "--load-level", type=int, help="Run load tests with specific user count"
    )


def pytest_runtest_setup(item):
    """Setup for individual test runs."""
    if item.config.getoption("--performance-only"):
        if "performance" not in [marker.name for marker in item.iter_markers()]:
            pytest.skip("Non-performance test skipped due to --performance-only")


class PerformanceTestResults:
    """Container for collecting performance test results."""

    def __init__(self):
        self.results = []
        self.summary = {}

    def add_result(self, test_name: str, result: dict):
        """Add a test result."""
        self.results.append(
            {
                "test_name": test_name,
                "timestamp": asyncio.get_event_loop().time(),
                **result,
            }
        )

    def generate_summary(self) -> dict:
        """Generate summary of all test results."""
        if not self.results:
            return {"total_tests": 0}

        total_tests = len(self.results)
        successful_tests = len([r for r in self.results if r.get("success", False)])

        self.summary = {
            "total_tests": total_tests,
            "successful_tests": successful_tests,
            "failed_tests": total_tests - successful_tests,
            "success_rate": (
                (successful_tests / total_tests) * 100 if total_tests > 0 else 0
            ),
            "results": self.results,
        }

        return self.summary


@pytest.fixture(scope="session")
def performance_results() -> PerformanceTestResults:
    """Provide a container for collecting performance test results."""
    return PerformanceTestResults()
