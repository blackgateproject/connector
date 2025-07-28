#!/usr/bin/env python3
"""
Redis Configuration Verification Script

This script verifies that Redis is properly configured and accessible
for the multi-worker FastAPI system.
"""

import asyncio
import os
import sys

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def verify_environment_variables():
    """Verify all required Redis and multi-worker environment variables are set."""
    print("🔍 Checking environment variables...")

    required_vars = {
        "REDIS_URL": os.getenv("REDIS_URL"),
        "MULTI_WORKER_MODE": os.getenv("MULTI_WORKER_MODE"),
        "WORKER_COUNT": os.getenv("WORKER_COUNT"),
        "BLOCKCHAIN_WORKERS": os.getenv("BLOCKCHAIN_WORKERS"),
        "BLOCKCHAIN_BATCH_SIZE": os.getenv("BLOCKCHAIN_BATCH_SIZE"),
    }

    optional_vars = {
        "WORKER_ID": os.getenv("WORKER_ID", "auto-generated"),
    }

    print("\n📋 Required Environment Variables:")
    all_set = True
    for var, value in required_vars.items():
        status = "✅" if value else "❌"
        print(f"  {status} {var}: {value}")
        if not value:
            all_set = False

    print("\n📋 Optional Environment Variables:")
    for var, value in optional_vars.items():
        print(f"  ℹ️  {var}: {value}")

    return all_set


def test_redis_connection():
    """Test Redis connection using the configured URL."""
    print("\n🔌 Testing Redis connection...")

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    print(f"  Redis URL: {redis_url}")

    try:
        import redis

        print("  ✅ Redis Python library available")

        # Test connection
        client = redis.from_url(redis_url, decode_responses=True)
        client.ping()
        print("  ✅ Redis server connection successful")

        # Test basic operations
        test_key = "blackgate:test:connection"
        client.set(test_key, "test_value", ex=10)  # Expires in 10 seconds
        value = client.get(test_key)

        if value == "test_value":
            print("  ✅ Redis read/write operations working")
            client.delete(test_key)
            print("  ✅ Redis cleanup successful")
            return True
        else:
            print("  ❌ Redis read/write test failed")
            return False

    except ImportError:
        print("  ❌ Redis Python library not installed")
        print("     Run: pip install redis")
        return False
    except Exception as e:
        print(f"  ❌ Redis connection failed: {e}")
        print("     Make sure Redis server is running")
        print("     For Docker: docker run -d -p 6379:6379 redis:latest")
        return False


async def test_shared_state_manager():
    """Test the SharedStateManager functionality."""
    print("\n🔄 Testing SharedStateManager...")

    try:
        # Import the SharedStateManager
        sys.path.append(os.path.join(os.path.dirname(__file__), "app"))
        from app.utils.shared_state import SharedStateManager

        # Initialize and test
        manager = SharedStateManager()
        await manager.initialize()
        print("  ✅ SharedStateManager initialized successfully")

        # Test basic operations
        test_data = {"test": "data", "timestamp": "2024-01-01"}
        await manager.save_state("test_key", test_data)
        print("  ✅ State save operation successful")

        retrieved_data = await manager.load_state("test_key")
        if retrieved_data == test_data:
            print("  ✅ State load operation successful")

            # Cleanup
            await manager.delete_state("test_key")
            print("  ✅ State cleanup successful")
            return True
        else:
            print("  ❌ State data mismatch")
            return False

    except Exception as e:
        print(f"  ❌ SharedStateManager test failed: {e}")
        return False


def verify_multi_worker_setup():
    """Verify multi-worker configuration is correct."""
    print("\n👥 Verifying multi-worker configuration...")

    multi_worker_mode = os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"
    worker_count = int(os.getenv("WORKER_COUNT", "1"))
    blockchain_workers = int(os.getenv("BLOCKCHAIN_WORKERS", "3"))
    batch_size = int(os.getenv("BLOCKCHAIN_BATCH_SIZE", "5"))

    print(
        f"  Multi-worker mode: {'✅ Enabled' if multi_worker_mode else 'ℹ️  Disabled'}"
    )
    print(f"  Worker count: {worker_count}")
    print(f"  Blockchain workers per FastAPI worker: {blockchain_workers}")
    print(f"  Blockchain batch size: {batch_size}")

    if multi_worker_mode and worker_count == 1:
        print("  ⚠️  Multi-worker mode enabled but worker count is 1")
        print("     Consider setting WORKER_COUNT > 1 or disable multi-worker mode")

    if not multi_worker_mode and worker_count > 1:
        print("  ⚠️  Worker count > 1 but multi-worker mode disabled")
        print("     Enable MULTI_WORKER_MODE=true for multiple workers")

    return True


async def main():
    """Main verification function."""
    print("🚀 Blackgate Redis Configuration Verification")
    print("=" * 50)

    # Step 1: Environment variables
    env_ok = verify_environment_variables()

    # Step 2: Redis connection
    redis_ok = test_redis_connection()

    # Step 3: SharedStateManager
    shared_state_ok = await test_shared_state_manager() if redis_ok else False

    # Step 4: Multi-worker setup
    multi_worker_ok = verify_multi_worker_setup()

    # Summary
    print("\n" + "=" * 50)
    print("📊 Verification Summary:")
    print(f"  Environment Variables: {'✅' if env_ok else '❌'}")
    print(f"  Redis Connection: {'✅' if redis_ok else '❌'}")
    print(f"  SharedStateManager: {'✅' if shared_state_ok else '❌'}")
    print(f"  Multi-worker Config: {'✅' if multi_worker_ok else '❌'}")

    if all([env_ok, redis_ok, shared_state_ok, multi_worker_ok]):
        print("\n🎉 All verifications passed! Redis is properly configured.")
        print("\n📖 Next steps:")
        print("  1. To run with multiple workers:")
        print("     uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 5")
        print("  2. Set MULTI_WORKER_MODE=true in .env for production")
        return 0
    else:
        print("\n❌ Some verifications failed. Please fix the issues above.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
