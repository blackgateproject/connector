"""
Individual Load Test Scripts for Specific User Counts

This module provides standalone scripts for running specific load levels,
useful for targeted testing or integration with CI/CD pipelines.
"""

import asyncio
import os
import sys
from typing import Optional

# Add the parent directory to the path to import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from performance_testing.load_test_framework import (
    LoadTestRunner,
    generate_load_test_report,
)


async def run_load_test_100_users(
    base_url: str = "http://localhost:8000", db_url: Optional[str] = None
):
    """Run load test for 100 users."""
    print("🚀 Starting load test for 100 users...")
    runner = LoadTestRunner(base_url, db_url)
    result = await runner.run_load_test(num_users=100, max_concurrent=20)

    # Generate report
    report_file = f"performance_reports/load_test_100_users_{int(asyncio.get_event_loop().time())}.md"
    os.makedirs("performance_reports", exist_ok=True)
    generate_load_test_report(result, report_file)

    print(f"✅ Test completed! Report saved to: {report_file}")
    return result


async def run_load_test_200_users(
    base_url: str = "http://localhost:8000", db_url: Optional[str] = None
):
    """Run load test for 200 users."""
    print("🚀 Starting load test for 200 users...")
    runner = LoadTestRunner(base_url, db_url)
    result = await runner.run_load_test(num_users=200, max_concurrent=30)

    # Generate report
    report_file = f"performance_reports/load_test_200_users_{int(asyncio.get_event_loop().time())}.md"
    os.makedirs("performance_reports", exist_ok=True)
    generate_load_test_report(result, report_file)

    print(f"✅ Test completed! Report saved to: {report_file}")
    return result


async def run_load_test_400_users(
    base_url: str = "http://localhost:8000", db_url: Optional[str] = None
):
    """Run load test for 400 users."""
    print("🚀 Starting load test for 400 users...")
    runner = LoadTestRunner(base_url, db_url)
    result = await runner.run_load_test(num_users=400, max_concurrent=40)

    # Generate report
    report_file = f"performance_reports/load_test_400_users_{int(asyncio.get_event_loop().time())}.md"
    os.makedirs("performance_reports", exist_ok=True)
    generate_load_test_report(result, report_file)

    print(f"✅ Test completed! Report saved to: {report_file}")
    return result


async def run_load_test_800_users(
    base_url: str = "http://localhost:8000", db_url: Optional[str] = None
):
    """Run load test for 800 users."""
    print("🚀 Starting load test for 800 users...")
    runner = LoadTestRunner(base_url, db_url)
    result = await runner.run_load_test(num_users=800, max_concurrent=50)

    # Generate report
    report_file = f"performance_reports/load_test_800_users_{int(asyncio.get_event_loop().time())}.md"
    os.makedirs("performance_reports", exist_ok=True)
    generate_load_test_report(result, report_file)

    print(f"✅ Test completed! Report saved to: {report_file}")
    return result


async def run_load_test_1000_users(
    base_url: str = "http://localhost:8000", db_url: Optional[str] = None
):
    """Run load test for 1000 users."""
    print("🚀 Starting load test for 1000 users...")
    runner = LoadTestRunner(base_url, db_url)
    result = await runner.run_load_test(num_users=1000, max_concurrent=50)

    # Generate report
    report_file = f"performance_reports/load_test_1000_users_{int(asyncio.get_event_loop().time())}.md"
    os.makedirs("performance_reports", exist_ok=True)
    generate_load_test_report(result, report_file)

    print(f"✅ Test completed! Report saved to: {report_file}")
    return result


# Convenience functions for running specific tests
def run_100_users_test():
    """Convenience function to run 100 users test."""
    return asyncio.run(run_load_test_100_users())


def run_200_users_test():
    """Convenience function to run 200 users test."""
    return asyncio.run(run_load_test_200_users())


def run_400_users_test():
    """Convenience function to run 400 users test."""
    return asyncio.run(run_load_test_400_users())


def run_800_users_test():
    """Convenience function to run 800 users test."""
    return asyncio.run(run_load_test_800_users())


def run_1000_users_test():
    """Convenience function to run 1000 users test."""
    return asyncio.run(run_load_test_1000_users())


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run individual load tests")
    parser.add_argument(
        "users",
        type=int,
        choices=[100, 200, 400, 800, 1000],
        help="Number of users to test",
    )
    parser.add_argument(
        "--url", default="http://localhost:8000", help="Base URL for the connector API"
    )
    parser.add_argument("--db-url", help="PostgreSQL database URL for storing metrics")

    args = parser.parse_args()

    # Map user counts to functions
    test_functions = {
        100: run_load_test_100_users,
        200: run_load_test_200_users,
        400: run_load_test_400_users,
        800: run_load_test_800_users,
        1000: run_load_test_1000_users,
    }

    # Run the selected test
    test_func = test_functions[args.users]
    asyncio.run(test_func(args.url, args.db_url))
