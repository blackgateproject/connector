"""
Multi-worker SMT wrapper that synchronizes SMT state across FastAPI workers.

This wrapper ensures that SMT operations are consistent across multiple workers
by using Redis as a shared state backend.
"""

import asyncio
import logging
import os
from threading import Lock
from typing import Any, Dict, Optional

from ..core.sparseMerkleTree import sparseMerkleTree
from ..utils.shared_state import get_shared_state_manager

logger = logging.getLogger(__name__)


class MultiWorkerSMTCore:
    """
    Multi-worker aware SMT core that synchronizes state across FastAPI workers.
    """

    def __init__(self, depth: int = 16):
        self.depth = depth
        self.worker_id = os.getenv("WORKER_ID", str(os.getpid()))
        self.multi_worker_mode = (
            os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"
        )

        # Local SMT instance
        self._local_smt = sparseMerkleTree(depth=depth)
        self._lock = Lock()
        self._last_sync_time = 0
        self.sync_interval = 5.0  # Sync every 5 seconds

        # Shared state manager
        self._shared_state = get_shared_state_manager()
        self._initialized = False

    async def initialize(self):
        """Initialize the multi-worker SMT."""
        if self._initialized:
            return

        if self.multi_worker_mode:
            # Initialize shared state manager
            await self._shared_state.initialize()

            # Try to load existing SMT from shared storage
            shared_smt = await self._shared_state.load_smt_tree()
            if shared_smt:
                self._local_smt = shared_smt
                logger.info(
                    f"Loaded SMT from shared storage (Worker: {self.worker_id})"
                )
            else:
                # Save current SMT to shared storage
                await self._shared_state.save_smt_tree(self._local_smt)
                logger.info(
                    f"Initialized SMT in shared storage (Worker: {self.worker_id})"
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
            shared_smt = await self._shared_state.load_smt_tree()
            if shared_smt and shared_smt != self._local_smt:
                with self._lock:
                    self._local_smt = shared_smt
                logger.debug(
                    f"Synced SMT from shared storage (Worker: {self.worker_id})"
                )

            self._last_sync_time = current_time

    async def _save_to_shared_storage(self):
        """Save current SMT to shared storage."""
        if self.multi_worker_mode and self._initialized:
            await self._shared_state.save_smt_tree(self._local_smt)

    def add_user(self, user_id: str, credentials: str = None) -> Dict[str, Any]:
        """Add user to SMT with multi-worker synchronization."""
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
            result = self._local_smt.add_user(user_id, credentials)

            # Save to shared storage
            if self.multi_worker_mode:
                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._save_to_shared_storage())
                except RuntimeError:
                    pass

            return result

    def get_proof(self, user_id: str) -> Optional[Any]:
        """Get proof for user with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            return self._local_smt.get_proof(user_id)

    def verify_proof(self, user_id: str, proof: Any) -> bool:
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
            return self._local_smt.verify_proof(user_id, proof)

    def get_root(self) -> str:
        """Get SMT root with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            return self._local_smt.get_root()

    def save_tree_to_file(self, filename: str):
        """Save tree to file (only from main worker to avoid conflicts)."""
        # Only save from main worker in multi-worker mode
        if self.multi_worker_mode:
            if self.worker_id != "main" and not self.worker_id.endswith("-0"):
                logger.debug(f"Skipping file save from worker {self.worker_id}")
                return

        with self._lock:
            self._local_smt.save_tree_to_file(filename)

    def load_tree_from_file(self, filename: str):
        """Load tree from file and sync to shared storage."""
        with self._lock:
            self._local_smt.load_tree_from_file(filename)

            # Save to shared storage after loading
            if self.multi_worker_mode:
                import asyncio

                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._save_to_shared_storage())
                except RuntimeError:
                    pass

    async def shutdown(self):
        """Shutdown the multi-worker SMT."""
        if self.multi_worker_mode and self._initialized:
            # Final save to shared storage
            await self._save_to_shared_storage()

        # Close shared state manager
        await self._shared_state.close()


# Global instance
smtCore = MultiWorkerSMTCore(depth=16)
