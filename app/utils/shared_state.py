"""
Shared state manager for multi-worker FastAPI deployment.

This module handles synchronization of SMT trees, Merkle trees, and other shared state
across multiple FastAPI worker processes using Redis as the shared storage backend.
"""

import asyncio
import json
import logging
import os
import pickle
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Redis support
try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None


class SharedStateManager:
    """
    Manages shared state across multiple FastAPI workers.

    Uses Redis as the backend for sharing SMT trees, Merkle trees, and other state
    that needs to be synchronized across worker processes.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis_client = None
        self.worker_id = os.getenv("WORKER_ID", str(os.getpid()))

        # State keys
        self.smt_tree_key = "shared_smt_tree"
        self.merkle_tree_key = "shared_merkle_tree"
        self.accumulator_key = "shared_accumulator"
        self.smt_lock_key = "smt_operation_lock"
        self.merkle_lock_key = "merkle_operation_lock"
        self.accumulator_lock_key = "accumulator_operation_lock"

        # Local cache
        self._local_smt_cache = None
        self._local_merkle_cache = None
        self._local_accumulator_cache = None
        self._cache_timestamp = 0
        self.cache_ttl = 5.0  # Cache for 5 seconds

    async def initialize(self):
        """Initialize the shared state manager."""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available - shared state disabled")
            return False

        try:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=False)
            await asyncio.get_event_loop().run_in_executor(None, self.redis_client.ping)
            logger.info(
                f"SharedStateManager initialized with Redis (Worker: {self.worker_id})"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            return False

    async def close(self):
        """Close Redis connection."""
        if self.redis_client:
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.close
                )
            except:
                pass

    async def acquire_lock(self, lock_key: str, timeout: float = 10.0) -> bool:
        """Acquire a distributed lock."""
        if not self.redis_client:
            return True  # No locking if Redis unavailable

        try:
            # Try to acquire lock with expiration
            acquired = await asyncio.get_event_loop().run_in_executor(
                None,
                self.redis_client.set,
                lock_key,
                self.worker_id,
                nx=True,  # Only set if key doesn't exist
                ex=int(timeout),  # Expire after timeout seconds
            )
            return bool(acquired)
        except Exception as e:
            logger.error(f"Error acquiring lock {lock_key}: {e}")
            return False

    async def release_lock(self, lock_key: str):
        """Release a distributed lock."""
        if not self.redis_client:
            return

        try:
            # Only release if we own the lock
            lua_script = """
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
            """
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.eval, lua_script, 1, lock_key, self.worker_id
            )
        except Exception as e:
            logger.error(f"Error releasing lock {lock_key}: {e}")

    async def save_smt_tree(self, smt_tree_data: Any):
        """Save SMT tree to shared storage."""
        if not self.redis_client:
            logger.warning("Cannot save SMT tree - Redis unavailable")
            return False

        try:
            # Acquire lock before saving
            if await self.acquire_lock(self.smt_lock_key, timeout=30.0):
                try:
                    # Serialize the SMT tree
                    serialized_data = pickle.dumps(smt_tree_data)

                    # Save to Redis with timestamp
                    data_with_metadata = {
                        "data": serialized_data,
                        "timestamp": time.time(),
                        "worker_id": self.worker_id,
                    }

                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        self.redis_client.hset,
                        self.smt_tree_key,
                        mapping={
                            "data": serialized_data,
                            "timestamp": str(time.time()),
                            "worker_id": self.worker_id,
                        },
                    )

                    # Update local cache
                    self._local_smt_cache = smt_tree_data
                    self._cache_timestamp = time.time()

                    logger.info(
                        f"SMT tree saved to shared storage by worker {self.worker_id}"
                    )
                    return True

                finally:
                    await self.release_lock(self.smt_lock_key)
            else:
                logger.warning("Could not acquire SMT lock for saving")
                return False

        except Exception as e:
            logger.error(f"Error saving SMT tree: {e}")
            return False

    async def load_smt_tree(self) -> Optional[Any]:
        """Load SMT tree from shared storage."""
        if not self.redis_client:
            return None

        # Check local cache first
        if (
            self._local_smt_cache is not None
            and time.time() - self._cache_timestamp < self.cache_ttl
        ):
            return self._local_smt_cache

        try:
            # Load from Redis
            tree_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hgetall, self.smt_tree_key
            )

            if tree_data and b"data" in tree_data:
                # Deserialize the SMT tree
                smt_tree = pickle.loads(tree_data[b"data"])

                # Update local cache
                self._local_smt_cache = smt_tree
                self._cache_timestamp = time.time()

                logger.debug(
                    f"SMT tree loaded from shared storage by worker {self.worker_id}"
                )
                return smt_tree
            else:
                logger.debug("No SMT tree found in shared storage")
                return None

        except Exception as e:
            logger.error(f"Error loading SMT tree: {e}")
            return None

    async def save_merkle_tree(self, merkle_tree_data: Any):
        """Save Merkle tree to shared storage."""
        if not self.redis_client:
            logger.warning("Cannot save Merkle tree - Redis unavailable")
            return False

        try:
            # Acquire lock before saving
            if await self.acquire_lock(self.merkle_lock_key, timeout=30.0):
                try:
                    # Serialize the Merkle tree
                    serialized_data = pickle.dumps(merkle_tree_data)

                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        self.redis_client.hset,
                        self.merkle_tree_key,
                        mapping={
                            "data": serialized_data,
                            "timestamp": str(time.time()),
                            "worker_id": self.worker_id,
                        },
                    )

                    # Update local cache
                    self._local_merkle_cache = merkle_tree_data

                    logger.info(
                        f"Merkle tree saved to shared storage by worker {self.worker_id}"
                    )
                    return True

                finally:
                    await self.release_lock(self.merkle_lock_key)
            else:
                logger.warning("Could not acquire Merkle lock for saving")
                return False

        except Exception as e:
            logger.error(f"Error saving Merkle tree: {e}")
            return False

    async def load_merkle_tree(self) -> Optional[Any]:
        """Load Merkle tree from shared storage."""
        if not self.redis_client:
            return None

        # Check local cache first
        if (
            self._local_merkle_cache is not None
            and time.time() - self._cache_timestamp < self.cache_ttl
        ):
            return self._local_merkle_cache

        try:
            # Load from Redis
            tree_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hgetall, self.merkle_tree_key
            )

            if tree_data and b"data" in tree_data:
                # Deserialize the Merkle tree
                merkle_tree = pickle.loads(tree_data[b"data"])

                # Update local cache
                self._local_merkle_cache = merkle_tree

                logger.debug(
                    f"Merkle tree loaded from shared storage by worker {self.worker_id}"
                )
                return merkle_tree
            else:
                logger.debug("No Merkle tree found in shared storage")
                return None

        except Exception as e:
            logger.error(f"Error loading Merkle tree: {e}")
            return None

    async def save_accumulator(self, accumulator_data: Any):
        """Save Accumulator to shared storage."""
        if not self.redis_client:
            logger.warning("Cannot save Accumulator - Redis unavailable")
            return False

        try:
            # Acquire lock before saving
            if await self.acquire_lock(self.accumulator_lock_key, timeout=30.0):
                try:
                    # Serialize the Accumulator
                    serialized_data = pickle.dumps(accumulator_data)

                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        self.redis_client.hset,
                        self.accumulator_key,
                        mapping={
                            "data": serialized_data,
                            "timestamp": str(time.time()),
                            "worker_id": self.worker_id,
                        },
                    )

                    # Update local cache
                    self._local_accumulator_cache = accumulator_data

                    logger.info(
                        f"Accumulator saved to shared storage by worker {self.worker_id}"
                    )
                    return True

                finally:
                    await self.release_lock(self.accumulator_lock_key)
            else:
                logger.warning("Could not acquire Accumulator lock for saving")
                return False

        except Exception as e:
            logger.error(f"Error saving Accumulator: {e}")
            return False

    async def load_accumulator(self) -> Optional[Any]:
        """Load Accumulator from shared storage."""
        if not self.redis_client:
            return None

        # Check local cache first
        if (
            self._local_accumulator_cache is not None
            and time.time() - self._cache_timestamp < self.cache_ttl
        ):
            return self._local_accumulator_cache

        try:
            # Load from Redis
            acc_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hgetall, self.accumulator_key
            )

            if acc_data and b"data" in acc_data:
                # Deserialize the Accumulator
                accumulator = pickle.loads(acc_data[b"data"])

                # Update local cache
                self._local_accumulator_cache = accumulator

                logger.debug(
                    f"Accumulator loaded from shared storage by worker {self.worker_id}"
                )
                return accumulator
            else:
                logger.debug("No Accumulator found in shared storage")
                return None

        except Exception as e:
            logger.error(f"Error loading Accumulator: {e}")
            return None

    async def invalidate_cache(self):
        """Invalidate local cache to force reload from Redis."""
        self._local_smt_cache = None
        self._local_merkle_cache = None
        self._local_accumulator_cache = None
        self._cache_timestamp = 0


# Global instance
_shared_state_manager: Optional[SharedStateManager] = None


def get_shared_state_manager() -> SharedStateManager:
    """Get or create the global shared state manager."""
    global _shared_state_manager
    if _shared_state_manager is None:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        _shared_state_manager = SharedStateManager(redis_url)
    return _shared_state_manager


async def initialize_shared_state():
    """Initialize the shared state manager."""
    manager = get_shared_state_manager()
    return await manager.initialize()


async def shutdown_shared_state():
    """Shutdown the shared state manager."""
    global _shared_state_manager
    if _shared_state_manager:
        await _shared_state_manager.close()
        _shared_state_manager = None
