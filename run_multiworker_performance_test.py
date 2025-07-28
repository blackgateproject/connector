#!/usr/bin/env python3
"""
Multi-worker FastAPI startup script for performance testing.

This script starts FastAPI with multiple workers for improved throughput
and runs the comprehensive performance tests.
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil


def check_redis():
    """Check if Redis is available for multi-worker support."""
    try:
        import redis

        client = redis.Redis(host="localhost", port=6379, decode_responses=True)
        client.ping()
        print("✅ Redis is available for multi-worker support")
        return True
    except:
        print("⚠️  Redis not available - will use single worker mode")
        return False


def start_fastapi_multiworker(workers=4):
    """Start FastAPI with multiple workers."""
    print(f"🚀 Starting FastAPI with {workers} workers...")

    # Set environment variables for multi-worker support
    env = os.environ.copy()
    env["MULTI_WORKER_MODE"] = "true"
    env["BLOCKCHAIN_WORKERS"] = "3"
    env["BLOCKCHAIN_BATCH_SIZE"] = "5"

    if check_redis():
        env["REDIS_URL"] = "redis://localhost:6379"

    # Start FastAPI with workers
    cmd = [
        sys.executable,
        "-m",
        "fastapi",
        "run",
        "--workers",
        str(workers),
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        "app.main:app",
    ]

    print(f"Command: {' '.join(cmd)}")
    process = subprocess.Popen(cmd, env=env)

    # Wait for startup
    print("⏳ Waiting for FastAPI to start...")
    time.sleep(10)

    return process


def run_performance_test():
    """Run the comprehensive performance test."""
    print("🧪 Running comprehensive performance test...")

    cmd = [sys.executable, "-m", "performance_testing.comprehensive_google_sheet_test"]

    result = subprocess.run(cmd)
    return result.returncode == 0


def main():
    """Main function to orchestrate multi-worker testing."""
    print("=" * 80)
    print("MULTI-WORKER FASTAPI PERFORMANCE TESTING")
    print("=" * 80)

    # Check if we're in the right directory
    if not Path("app/main.py").exists():
        print("❌ Please run this script from the connector root directory")
        sys.exit(1)

    fastapi_process = None

    try:
        # Start FastAPI with multiple workers
        workers = int(os.getenv("FASTAPI_WORKERS", "4"))
        fastapi_process = start_fastapi_multiworker(workers)

        if fastapi_process.poll() is not None:
            print("❌ Failed to start FastAPI")
            sys.exit(1)

        print("✅ FastAPI started successfully")

        # Run performance test
        success = run_performance_test()

        if success:
            print("✅ Performance test completed successfully")
        else:
            print("❌ Performance test failed")

    except KeyboardInterrupt:
        print("\\n🛑 Interrupted by user")

    finally:
        # Cleanup
        if fastapi_process:
            print("🧹 Shutting down FastAPI...")
            fastapi_process.terminate()

            # Wait for graceful shutdown
            try:
                fastapi_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("⚠️  Force killing FastAPI process...")
                fastapi_process.kill()
                fastapi_process.wait()

            print("✅ FastAPI shutdown complete")


if __name__ == "__main__":
    main()
