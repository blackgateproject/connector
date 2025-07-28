"""
Multi-worker Merkle Tree wrapper that synchronizes state across FastAPI workers.

This wrapper ensures that Merkle Tree operations are consistent across multiple workers
by using Redis as a shared state backend.
"""

import asyncio
import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional

from ..core.merkle import abdMerkleClass
from ..utils.shared_state import get_shared_state_manager

logger = logging.getLogger(__name__)


class MultiWorkerMerkleCore:
    """
    Multi-worker aware Merkle core that synchronizes state across FastAPI workers.
    """

    def __init__(self):
        self.worker_id = os.getenv("WORKER_ID", str(os.getpid()))
        self.multi_worker_mode = (
            os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"
        )

        # Local Merkle Tree instance
        self._local_merkle = abdMerkleClass()
        self._lock = Lock()
        self._last_sync_time = 0
        self.sync_interval = 5.0  # Sync every 5 seconds

        # Shared state manager
        self._shared_state = get_shared_state_manager()
        self._initialized = False

    async def initialize(self):
        """Initialize the multi-worker Merkle Tree."""
        if self._initialized:
            return

        if self.multi_worker_mode:
            # Initialize shared state manager
            await self._shared_state.initialize()

            # Try to load existing Merkle Tree from shared storage
            shared_merkle = await self._shared_state.load_merkle_tree()
            if shared_merkle:
                self._local_merkle = shared_merkle
                logger.info(
                    f"Loaded Merkle Tree from shared storage (Worker: {self.worker_id})"
                )
            else:
                # Save current Merkle Tree to shared storage
                await self._shared_state.save_merkle_tree(self._local_merkle)
                logger.info(
                    f"Initialized Merkle Tree in shared storage (Worker: {self.worker_id})"
                )

        self._initialized = True

    async def _sync_if_needed(self):
        """Sync with shared storage if needed."""
        if not self.multi_worker_mode or not self._initialized:
            return

        import time

        current_time = time.time()

        # Check if we need to sync
        if current_time - self._last_sync_time > self.sync_interval:
            shared_merkle = await self._shared_state.load_merkle_tree()
            if shared_merkle and shared_merkle != self._local_merkle:
                with self._lock:
                    self._local_merkle = shared_merkle
                logger.debug(
                    f"Synced Merkle Tree from shared storage (Worker: {self.worker_id})"
                )

            self._last_sync_time = current_time

    async def _save_to_shared_storage(self):
        """Save current Merkle Tree to shared storage."""
        if self.multi_worker_mode and self._initialized:
            await self._shared_state.save_merkle_tree(self._local_merkle)

    def add_data(self, data: str) -> Dict[str, Any]:
        """Add data to Merkle Tree with multi-worker synchronization."""
        with self._lock:
            # Sync before operation
            if self.multi_worker_mode:
                import asyncio

                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._sync_if_needed())
                except RuntimeError:
                    pass  # No event loop running

            # Perform local operation
            result = self._local_merkle.add_data(data)

            # Save to shared storage
            if self.multi_worker_mode:
                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._save_to_shared_storage())
                except RuntimeError:
                    pass

            return result

    def generate_proof(self, index: int) -> Optional[List[str]]:
        """Generate proof for data at index with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            return self._local_merkle.generate_proof(index)

    def verify_proof(self, data: str, proof: List[str], root: str) -> bool:
        """Verify proof with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            return self._local_merkle.verify_proof(data, proof, root)

    def get_root(self) -> str:
        """Get Merkle Tree root with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            return self._local_merkle.get_root()

    def get_leaves(self) -> List[str]:
        """Get all leaves with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            return (
                self._local_merkle.leaves.copy()
                if hasattr(self._local_merkle, "leaves")
                else []
            )

    def save_tree_to_file(self, filename: str):
        """Save tree to file (only from main worker to avoid conflicts)."""
        # Only save from main worker in multi-worker mode
        if self.multi_worker_mode:
            if self.worker_id != "main" and not self.worker_id.endswith("-0"):
                logger.debug(f"Skipping file save from worker {self.worker_id}")
                return

        with self._lock:
            if hasattr(self._local_merkle, "save_tree_to_file"):
                self._local_merkle.save_tree_to_file(filename)

    def load_tree_from_file(self, filename: str):
        """Load tree from file and sync to shared storage."""
        with self._lock:
            if hasattr(self._local_merkle, "load_tree_from_file"):
                self._local_merkle.load_tree_from_file(filename)

            # Save to shared storage after loading
            if self.multi_worker_mode:
                import asyncio

                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._save_to_shared_storage())
                except RuntimeError:
                    pass

    async def shutdown(self):
        """Shutdown the multi-worker Merkle Tree."""
        if self.multi_worker_mode and self._initialized:
            # Final save to shared storage
            await self._save_to_shared_storage()

        # Close shared state manager
        await self._shared_state.close()


# Global instance
merkleCore = MultiWorkerMerkleCore()
