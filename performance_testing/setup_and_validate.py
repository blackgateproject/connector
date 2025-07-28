"""
Quick Setup and Validation Script for Performance Testing Framework

This script helps set up and validate the performance testing environment.
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from performance_testing.config import PerformanceTestConfig, PerformanceTestValidator
from performance_testing.load_test_framework import LoadTestRunner


async def check_server_connection(base_url: str) -> bool:
    """Check if the Blackgate Connector server is running."""
    print(f"🔍 Checking server connection to {base_url}...")

    try:
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{base_url.rstrip('/')}/")
            if response.status_code == 200:
                print("✅ Server is running and accessible")
                return True
            else:
                print(f"❌ Server responded with status {response.status_code}")
                return False
    except Exception as e:
        print(f"❌ Cannot connect to server: {str(e)}")
        return False


async def run_smoke_test(base_url: str) -> bool:
    """Run a quick smoke test with 1 user."""
    print("🧪 Running smoke test with 1 user...")

    try:
        runner = LoadTestRunner(base_url)
        result = await runner.run_load_test(num_users=1, max_concurrent=1)

        if result.successful_users > 0:
            print("✅ Smoke test passed - 1 user completed successfully")
            print(f"   Total time: {result.avg_total_time:.2f}s")
            return True
        else:
            print("❌ Smoke test failed - no users completed successfully")
            if result.errors:
                print(f"   Errors: {result.errors[:3]}")  # Show first 3 errors
            return False
    except Exception as e:
        print(f"❌ Smoke test exception: {str(e)}")
        return False


def install_dependencies() -> bool:
    """Install required dependencies."""
    print("📦 Installing performance testing dependencies...")

    try:
        requirements_file = Path(__file__).parent / "requirements-perf.txt"
        if requirements_file.exists():
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)],
                check=True,
                capture_output=True,
            )
            print("✅ Dependencies installed successfully")
            return True
        else:
            print("❌ Requirements file not found")
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False
    except Exception as e:
        print(f"❌ Exception during installation: {str(e)}")
        return False


def create_output_directory() -> bool:
    """Create the output directory for reports."""
    print("📁 Creating output directory...")

    try:
        output_dir = Path("performance_reports")
        output_dir.mkdir(exist_ok=True)
        print(f"✅ Output directory created: {output_dir.absolute()}")
        return True
    except Exception as e:
        print(f"❌ Failed to create output directory: {str(e)}")
        return False


def validate_configuration(config: PerformanceTestConfig) -> bool:
    """Validate the performance test configuration."""
    print("⚙️ Validating configuration...")

    validator = PerformanceTestValidator(config)
    is_valid = validator.validate_all()

    print(validator.get_validation_report())

    if is_valid:
        print("✅ Configuration validation passed")
    else:
        print("❌ Configuration validation failed")

    return is_valid


async def run_mini_load_test(base_url: str) -> bool:
    """Run a mini load test with 5 users."""
    print("🚀 Running mini load test with 5 users...")

    try:
        runner = LoadTestRunner(base_url)
        result = await runner.run_load_test(num_users=5, max_concurrent=3)

        success_rate = (result.successful_users / result.total_users) * 100
        print(f"📊 Mini load test results:")
        print(f"   Success rate: {success_rate:.1f}%")
        print(f"   Throughput: {result.throughput_per_second:.2f} users/sec")
        print(f"   Average time: {result.avg_total_time:.2f}s")

        if result.successful_users >= 3:  # At least 60% success rate
            print("✅ Mini load test passed")
            return True
        else:
            print("⚠️ Mini load test had low success rate")
            return False
    except Exception as e:
        print(f"❌ Mini load test exception: {str(e)}")
        return False


async def main():
    """Main validation and setup routine."""
    print("🛠️ Blackgate Connector - Performance Testing Setup & Validation")
    print("=" * 80)

    # Get configuration
    config = PerformanceTestConfig.from_env()
    print(f"🎯 Target URL: {config.base_url}")

    # Track validation steps
    steps_passed = 0
    total_steps = 6

    # Step 1: Install dependencies
    if install_dependencies():
        steps_passed += 1

    # Step 2: Create output directory
    if create_output_directory():
        steps_passed += 1

    # Step 3: Validate configuration
    if validate_configuration(config):
        steps_passed += 1

    # Step 4: Check server connection
    if await check_server_connection(config.base_url):
        steps_passed += 1

    # Step 5: Run smoke test
    if await run_smoke_test(config.base_url):
        steps_passed += 1

    # Step 6: Run mini load test
    if await run_mini_load_test(config.base_url):
        steps_passed += 1

    # Summary
    print("\n" + "=" * 80)
    print("📋 VALIDATION SUMMARY")
    print("=" * 80)
    print(f"Steps passed: {steps_passed}/{total_steps}")

    if steps_passed == total_steps:
        print("🎉 All validation steps passed! Ready for load testing.")
        print("\n🚀 To run load tests:")
        print("   python performance_testing/run_load_tests.py")
        print("   python performance_testing/individual_tests.py 100")
        print("   pytest performance_testing/ -m performance")
    elif steps_passed >= 4:
        print("⚠️ Most validation steps passed. Some issues detected.")
        print("   You can proceed with caution or fix the issues first.")
    else:
        print("❌ Many validation steps failed. Please fix issues before proceeding.")

    print("=" * 80)

    return steps_passed == total_steps


if __name__ == "__main__":
    # Allow custom base URL via command line
    import argparse

    parser = argparse.ArgumentParser(
        description="Setup and validate performance testing"
    )
    parser.add_argument(
        "--url", default="http://localhost:8000", help="Base URL for API"
    )
    parser.add_argument(
        "--skip-deps", action="store_true", help="Skip dependency installation"
    )
    args = parser.parse_args()

    # Override config if URL provided
    if args.url != "http://localhost:8000":
        os.environ["PERF_TEST_BASE_URL"] = args.url

    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏹️ Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Validation failed with exception: {str(e)}")
        sys.exit(1)
