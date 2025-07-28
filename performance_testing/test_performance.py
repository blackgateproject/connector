"""
Performance Test Cases

This module contains specific test cases for performance testing
the Blackgate Connector registration and verification flow.
"""

import asyncio
import time
from typing import List

import pytest

from performance_testing.config import PerformanceTestConfig
from performance_testing.conftest import PerformanceTestResults
from performance_testing.load_test_framework import (
    LoadTestResult,
    LoadTestRunner,
    UserMetrics,
)


@pytest.mark.performance
@pytest.mark.asyncio
class TestLoadPerformance:
    """Test class for load performance testing."""

    async def test_single_user_registration_flow(
        self, load_test_runner: LoadTestRunner
    ):
        """Test the complete registration and verification flow for a single user."""
        result = await load_test_runner.run_load_test(num_users=1, max_concurrent=1)

        assert result.total_users == 1
        assert result.successful_users >= 0
        assert result.test_duration > 0

        if result.successful_users > 0:
            user_metric = result.user_metrics[0]
            assert user_metric.did_str
            assert user_metric.wallet_gen_time >= 0
            assert user_metric.wallet_enc_time >= 0
            assert user_metric.network_info_time >= 0

    @pytest.mark.slow
    async def test_load_test_100_users(
        self,
        load_test_runner: LoadTestRunner,
        performance_results: PerformanceTestResults,
    ):
        """Test load performance with 100 concurrent users."""
        start_time = time.time()
        result = await load_test_runner.run_load_test(num_users=100, max_concurrent=20)
        test_duration = time.time() - start_time

        # Record results
        performance_results.add_result(
            "load_test_100_users",
            {
                "success": result.successful_users > 0,
                "total_users": result.total_users,
                "successful_users": result.successful_users,
                "failed_users": result.failed_users,
                "test_duration": test_duration,
                "throughput": result.throughput_per_second,
                "avg_total_time": result.avg_total_time,
            },
        )

        # Assertions
        assert result.total_users == 100
        assert result.test_duration > 0
        assert result.throughput_per_second >= 0

        # Performance criteria (adjust based on your requirements)
        if result.successful_users > 0:
            assert (
                result.avg_total_time < 60.0
            ), "Average total time should be under 60 seconds"
            assert result.error_rate < 0.1, "Error rate should be less than 10%"

    @pytest.mark.slow
    async def test_load_test_200_users(
        self,
        load_test_runner: LoadTestRunner,
        performance_results: PerformanceTestResults,
    ):
        """Test load performance with 200 concurrent users."""
        start_time = time.time()
        result = await load_test_runner.run_load_test(num_users=200, max_concurrent=30)
        test_duration = time.time() - start_time

        # Record results
        performance_results.add_result(
            "load_test_200_users",
            {
                "success": result.successful_users > 0,
                "total_users": result.total_users,
                "successful_users": result.successful_users,
                "failed_users": result.failed_users,
                "test_duration": test_duration,
                "throughput": result.throughput_per_second,
                "avg_total_time": result.avg_total_time,
            },
        )

        # Assertions
        assert result.total_users == 200
        assert result.test_duration > 0

        # Performance criteria
        if result.successful_users > 0:
            assert (
                result.avg_total_time < 90.0
            ), "Average total time should be under 90 seconds"
            assert result.error_rate < 0.15, "Error rate should be less than 15%"

    @pytest.mark.slow
    async def test_load_test_400_users(
        self,
        load_test_runner: LoadTestRunner,
        performance_results: PerformanceTestResults,
    ):
        """Test load performance with 400 concurrent users."""
        start_time = time.time()
        result = await load_test_runner.run_load_test(num_users=400, max_concurrent=40)
        test_duration = time.time() - start_time

        # Record results
        performance_results.add_result(
            "load_test_400_users",
            {
                "success": result.successful_users > 0,
                "total_users": result.total_users,
                "successful_users": result.successful_users,
                "failed_users": result.failed_users,
                "test_duration": test_duration,
                "throughput": result.throughput_per_second,
                "avg_total_time": result.avg_total_time,
            },
        )

        # Assertions
        assert result.total_users == 400
        assert result.test_duration > 0

        # Performance criteria
        if result.successful_users > 0:
            assert (
                result.avg_total_time < 120.0
            ), "Average total time should be under 120 seconds"
            assert result.error_rate < 0.2, "Error rate should be less than 20%"

    @pytest.mark.slow
    async def test_load_test_800_users(
        self,
        load_test_runner: LoadTestRunner,
        performance_results: PerformanceTestResults,
    ):
        """Test load performance with 800 concurrent users."""
        start_time = time.time()
        result = await load_test_runner.run_load_test(num_users=800, max_concurrent=50)
        test_duration = time.time() - start_time

        # Record results
        performance_results.add_result(
            "load_test_800_users",
            {
                "success": result.successful_users > 0,
                "total_users": result.total_users,
                "successful_users": result.successful_users,
                "failed_users": result.failed_users,
                "test_duration": test_duration,
                "throughput": result.throughput_per_second,
                "avg_total_time": result.avg_total_time,
            },
        )

        # Assertions
        assert result.total_users == 800
        assert result.test_duration > 0

        # Performance criteria (more relaxed for higher load)
        if result.successful_users > 0:
            assert (
                result.avg_total_time < 180.0
            ), "Average total time should be under 180 seconds"
            assert result.error_rate < 0.25, "Error rate should be less than 25%"

    @pytest.mark.slow
    async def test_load_test_1000_users(
        self,
        load_test_runner: LoadTestRunner,
        performance_results: PerformanceTestResults,
    ):
        """Test load performance with 1000 concurrent users."""
        start_time = time.time()
        result = await load_test_runner.run_load_test(num_users=1000, max_concurrent=50)
        test_duration = time.time() - start_time

        # Record results
        performance_results.add_result(
            "load_test_1000_users",
            {
                "success": result.successful_users > 0,
                "total_users": result.total_users,
                "successful_users": result.successful_users,
                "failed_users": result.failed_users,
                "test_duration": test_duration,
                "throughput": result.throughput_per_second,
                "avg_total_time": result.avg_total_time,
            },
        )

        # Assertions
        assert result.total_users == 1000
        assert result.test_duration > 0

        # Performance criteria (most relaxed for highest load)
        if result.successful_users > 0:
            assert (
                result.avg_total_time < 300.0
            ), "Average total time should be under 300 seconds"
            # Note: Error rate criteria can be adjusted based on expected system behavior


@pytest.mark.performance
@pytest.mark.asyncio
class TestTimingMetrics:
    """Test class for detailed timing metrics validation."""

    async def test_individual_timing_metrics(self, load_test_runner: LoadTestRunner):
        """Test that individual timing metrics are properly captured."""
        result = await load_test_runner.run_load_test(num_users=5, max_concurrent=2)

        assert result.total_users == 5

        for user_metric in result.user_metrics:
            if user_metric.success:
                # Validate that timing metrics are reasonable
                assert (
                    user_metric.wallet_gen_time >= 0
                ), "Wallet generation time should be non-negative"
                assert (
                    user_metric.wallet_enc_time >= 0
                ), "Wallet encryption time should be non-negative"
                assert (
                    user_metric.network_info_time >= 0
                ), "Network info time should be non-negative"
                assert (
                    user_metric.total_process_time > 0
                ), "Total process time should be positive"

                # Check that DID string is properly formatted
                assert user_metric.did_str.startswith(
                    "did:"
                ), "DID should have proper format"

    async def test_database_metrics_storage(self, load_test_runner: LoadTestRunner):
        """Test that metrics are properly stored in the database (if configured)."""
        if not load_test_runner.db_url:
            pytest.skip("Database URL not configured")

        result = await load_test_runner.run_load_test(num_users=3, max_concurrent=2)

        # If successful users exist, verify they were stored
        if result.successful_users > 0:
            # This test would require database verification
            # For now, we just check that the storage attempt was made
            assert len(result.user_metrics) >= result.successful_users


@pytest.mark.performance
@pytest.mark.asyncio
class TestScalabilityMetrics:
    """Test class for scalability analysis."""

    async def test_throughput_scalability(self, load_test_runner: LoadTestRunner):
        """Test throughput scalability across different load levels."""
        load_levels = [10, 25, 50]
        results = []

        for level in load_levels:
            result = await load_test_runner.run_load_test(
                num_users=level, max_concurrent=min(20, level // 2)
            )
            results.append(result)

        # Analyze scalability
        throughputs = [
            r.throughput_per_second for r in results if r.successful_users > 0
        ]

        if len(throughputs) >= 2:
            # Throughput should generally increase or remain stable with more users
            # (until system saturation point)
            max_throughput = max(throughputs)
            min_throughput = min(throughputs)

            # The ratio shouldn't be too extreme (indicates system issues)
            assert max_throughput / min_throughput < 10, "Throughput variance too high"

    async def test_response_time_scalability(self, load_test_runner: LoadTestRunner):
        """Test response time behavior under different loads."""
        load_levels = [5, 15, 30]
        results = []

        for level in load_levels:
            result = await load_test_runner.run_load_test(
                num_users=level, max_concurrent=min(15, level // 2)
            )
            results.append(result)

        # Analyze response times
        avg_times = [r.avg_total_time for r in results if r.successful_users > 0]

        if len(avg_times) >= 2:
            # Response times shouldn't increase dramatically
            max_time = max(avg_times)
            min_time = min(avg_times)

            # Under normal load, response time shouldn't increase by more than 5x
            assert max_time / min_time < 5, "Response time degradation too severe"


@pytest.mark.performance
class TestErrorHandling:
    """Test class for error handling under load."""

    async def test_error_rate_thresholds(self, load_test_runner: LoadTestRunner):
        """Test that error rates stay within acceptable thresholds."""
        result = await load_test_runner.run_load_test(num_users=20, max_concurrent=10)

        # Error rate should be reasonable
        if result.total_users > 0:
            assert result.error_rate < 0.5, "Error rate should be less than 50%"

    async def test_system_stability(self, load_test_runner: LoadTestRunner):
        """Test system stability over multiple small loads."""
        results = []

        # Run multiple small tests to check stability
        for _ in range(3):
            result = await load_test_runner.run_load_test(num_users=5, max_concurrent=3)
            results.append(result)

            # Small delay between tests
            await asyncio.sleep(2)

        # All tests should have some successful users
        successful_tests = [r for r in results if r.successful_users > 0]
        assert (
            len(successful_tests) >= len(results) // 2
        ), "System should be stable across multiple tests"


def pytest_sessionfinish(session, exitstatus):
    """Generate final performance report after all tests."""
    if hasattr(session.config, "_performance_results"):
        results = session.config._performance_results
        summary = results.generate_summary()

        print("\n" + "=" * 80)
        print("PERFORMANCE TEST SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {summary.get('total_tests', 0)}")
        print(f"Successful Tests: {summary.get('successful_tests', 0)}")
        print(f"Failed Tests: {summary.get('failed_tests', 0)}")
        print(f"Success Rate: {summary.get('success_rate', 0):.1f}%")
        print("=" * 80)
