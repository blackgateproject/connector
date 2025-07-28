"""
Multi-worker Accumulator wrapper that synchronizes state across FastAPI workers.

This wrapper ensures that Accumulator operations are consistent across multiple workers
by using Redis as a shared state backend.
"""

import asyncio
import logging
import os
from threading import Lock
from typing import Any, Dict, Optional, Union

from ..core.accumulator import AccumulatorClass
from ..utils.shared_state import get_shared_state_manager

logger = logging.getLogger(__name__)


class MultiWorkerAccumulatorCore:
    """
    Multi-worker aware Accumulator core that synchronizes state across FastAPI workers.
    """

    def __init__(self):
        self.worker_id = os.getenv("WORKER_ID", str(os.getpid()))
        self.multi_worker_mode = (
            os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"
        )

        # Local Accumulator instance
        self._local_accumulator = AccumulatorClass()
        self._lock = Lock()
        self._last_sync_time = 0
        self.sync_interval = 5.0  # Sync every 5 seconds

        # Shared state manager
        self._shared_state = get_shared_state_manager()
        self._initialized = False

    async def initialize(self):
        """Initialize the multi-worker Accumulator."""
        if self._initialized:
            return

        if self.multi_worker_mode:
            # Initialize shared state manager
            await self._shared_state.initialize()

            # Try to load existing Accumulator from shared storage
            shared_accumulator = await self._shared_state.load_accumulator()
            if shared_accumulator:
                self._local_accumulator = shared_accumulator
                logger.info(
                    f"Loaded Accumulator from shared storage (Worker: {self.worker_id})"
                )
            else:
                # Save current Accumulator to shared storage
                await self._shared_state.save_accumulator(self._local_accumulator)
                logger.info(
                    f"Initialized Accumulator in shared storage (Worker: {self.worker_id})"
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
            shared_accumulator = await self._shared_state.load_accumulator()
            if shared_accumulator:
                # Compare current accumulator values to see if sync is needed
                if (
                    shared_accumulator.currentAccumulator
                    != self._local_accumulator.currentAccumulator
                    or shared_accumulator.prevAccumulator
                    != self._local_accumulator.prevAccumulator
                ):
                    with self._lock:
                        self._local_accumulator = shared_accumulator
                    logger.debug(
                        f"Synced Accumulator from shared storage (Worker: {self.worker_id})"
                    )

            self._last_sync_time = current_time

    async def _save_to_shared_storage(self):
        """Save current Accumulator to shared storage."""
        if self.multi_worker_mode and self._initialized:
            await self._shared_state.save_accumulator(self._local_accumulator)

    def add(self, element: Union[int, str]) -> Dict[str, Any]:
        """Add element to accumulator with multi-worker synchronization."""
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
            result = self._local_accumulator.add(element)

            # Save to shared storage
            if self.multi_worker_mode:
                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._save_to_shared_storage())
                except RuntimeError:
                    pass

            return result

    def remove(self, element: Union[int, str]) -> Dict[str, Any]:
        """Remove element from accumulator with multi-worker synchronization."""
        with self._lock:
            # Sync before operation
            if self.multi_worker_mode:
                import asyncio

                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._sync_if_needed())
                except RuntimeError:
                    pass

            # Perform local operation
            result = self._local_accumulator.remove(element)

            # Save to shared storage
            if self.multi_worker_mode:
                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._save_to_shared_storage())
                except RuntimeError:
                    pass

            return result

    def generate_membership_proof(self, element: Union[int, str]) -> Optional[Any]:
        """Generate membership proof with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            if hasattr(self._local_accumulator, "generate_membership_proof"):
                return self._local_accumulator.generate_membership_proof(element)
            elif hasattr(self._local_accumulator, "prove_membership"):
                return self._local_accumulator.prove_membership(element)
            return None

    def verify_membership(self, element: Union[int, str], proof: Any) -> bool:
        """Verify membership proof with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            if hasattr(self._local_accumulator, "verify_membership"):
                return self._local_accumulator.verify_membership(element, proof)
            return False

    def get_current_accumulator(self) -> int:
        """Get current accumulator value with multi-worker synchronization."""
        # Sync before operation
        if self.multi_worker_mode:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._sync_if_needed())
            except RuntimeError:
                pass

        with self._lock:
            return self._local_accumulator.currentAccumulator

    def get_modulus(self) -> int:
        """Get modulus value."""
        with self._lock:
            return self._local_accumulator.MODULUS

    def get_generator(self) -> int:
        """Get generator value."""
        with self._lock:
            return self._local_accumulator.GENERATOR

    def save_state_to_file(self, filename: str):
        """Save accumulator state to file (only from main worker to avoid conflicts)."""
        # Only save from main worker in multi-worker mode
        if self.multi_worker_mode:
            if self.worker_id != "main" and not self.worker_id.endswith("-0"):
                logger.debug(f"Skipping file save from worker {self.worker_id}")
                return

        with self._lock:
            if hasattr(self._local_accumulator, "save_state"):
                self._local_accumulator.save_state(filename)

    def load_state_from_file(self, filename: str):
        """Load accumulator state from file and sync to shared storage."""
        with self._lock:
            if hasattr(self._local_accumulator, "load_state"):
                self._local_accumulator.load_state(filename)

            # Save to shared storage after loading
            if self.multi_worker_mode:
                import asyncio

                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._save_to_shared_storage())
                except RuntimeError:
                    pass

    async def shutdown(self):
        """Shutdown the multi-worker Accumulator."""
        if self.multi_worker_mode and self._initialized:
            # Final save to shared storage
            await self._save_to_shared_storage()

        # Close shared state manager
        await self._shared_state.close()


# Global instance
accumulatorCore = MultiWorkerAccumulatorCore()
