"""
Async blockchain operations for improved performance during load testing.

This module provides async blockchain operations and background task processing
to prevent blockchain network calls from blocking the registration process.
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from .web3_utils import addUserToSMTOnChain

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class BlockchainTask:
    """Represents a blockchain operation to be processed."""

    task_id: str
    task_type: str  # 'smt_add', 'merkle_add', 'accumulator_add'
    merkle_root: str
    vc_hash: str
    device_id: str
    fog_node_pubkey: str
    timestamp: float
    status: str = "pending"  # pending, processing, completed, failed
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None


class AsyncBlockchainProcessor:
    """
    Async blockchain processor that handles blockchain operations in the background.

    This prevents blockchain network calls from blocking the registration API response,
    significantly improving throughput during load testing.
    """

    def __init__(self, max_workers: int = 5, batch_size: int = 10):
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.completed_tasks: Dict[str, BlockchainTask] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.is_running = False
        self.processor_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the background blockchain processor."""
        if not self.is_running:
            self.is_running = True
            self.processor_task = asyncio.create_task(self._process_tasks())
            logger.info(
                f"Started async blockchain processor with {self.max_workers} workers"
            )

    async def stop(self):
        """Stop the background blockchain processor."""
        self.is_running = False
        if self.processor_task:
            await self.processor_task
        self.executor.shutdown(wait=True)
        logger.info("Stopped async blockchain processor")

    async def submit_smt_add_task(
        self,
        task_id: str,
        merkle_root: str,
        vc_hash: str,
        device_id: str,
        fog_node_pubkey: str,
    ) -> str:
        """
        Submit an SMT add task to the background processor.
        Returns immediately with a task ID for status checking.
        """
        task = BlockchainTask(
            task_id=task_id,
            task_type="smt_add",
            merkle_root=merkle_root,
            vc_hash=vc_hash,
            device_id=device_id,
            fog_node_pubkey=fog_node_pubkey,
            timestamp=time.time(),
        )

        await self.task_queue.put(task)
        logger.info(f"Queued SMT add task {task_id}")
        return task_id

    async def get_task_status(self, task_id: str) -> Optional[BlockchainTask]:
        """Get the status of a submitted task."""
        return self.completed_tasks.get(task_id)

    async def wait_for_task(
        self, task_id: str, timeout: float = 30.0
    ) -> BlockchainTask:
        """
        Wait for a task to complete with timeout.
        Useful for testing or when you need to ensure completion.
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            task = await self.get_task_status(task_id)
            if task and task.status in ["completed", "failed"]:
                return task
            await asyncio.sleep(0.1)

        raise TimeoutError(f"Task {task_id} did not complete within {timeout} seconds")

    async def _process_tasks(self):
        """Background task processor that handles blockchain operations."""
        logger.info("Started blockchain task processor")

        while self.is_running:
            try:
                # Get tasks from queue with timeout
                tasks_to_process = []

                # Collect batch of tasks
                try:
                    # Get first task (blocking)
                    task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                    tasks_to_process.append(task)

                    # Get additional tasks (non-blocking) up to batch size
                    for _ in range(self.batch_size - 1):
                        try:
                            task = self.task_queue.get_nowait()
                            tasks_to_process.append(task)
                        except asyncio.QueueEmpty:
                            break

                except asyncio.TimeoutError:
                    # No tasks available, continue loop
                    continue

                # Process batch of tasks
                if tasks_to_process:
                    await self._process_task_batch(tasks_to_process)

            except Exception as e:
                logger.error(f"Error in blockchain task processor: {e}")
                await asyncio.sleep(1.0)

    async def _process_task_batch(self, tasks: list[BlockchainTask]):
        """Process a batch of blockchain tasks."""
        logger.info(f"Processing batch of {len(tasks)} blockchain tasks")

        # Process tasks concurrently
        futures = []
        for task in tasks:
            task.status = "processing"
            future = asyncio.get_event_loop().run_in_executor(
                self.executor, self._execute_blockchain_task, task
            )
            futures.append(future)

        # Wait for all tasks to complete
        results = await asyncio.gather(*futures, return_exceptions=True)

        # Update task statuses and store results
        for task, result in zip(tasks, results):
            if isinstance(result, Exception):
                task.status = "failed"
                task.error = str(result)
                logger.error(f"Task {task.task_id} failed: {result}")
            else:
                task.status = "completed"
                task.result = result
                logger.info(f"Task {task.task_id} completed successfully")

            # Store completed task
            self.completed_tasks[task.task_id] = task

            # Clean up old completed tasks (keep last 1000)
            if len(self.completed_tasks) > 1000:
                oldest_tasks = sorted(
                    self.completed_tasks.keys(),
                    key=lambda x: self.completed_tasks[x].timestamp,
                )[:100]
                for old_task_id in oldest_tasks:
                    del self.completed_tasks[old_task_id]

    def _execute_blockchain_task(self, task: BlockchainTask) -> Dict[str, Any]:
        """
        Execute a single blockchain task synchronously.
        This runs in a thread pool to avoid blocking the async event loop.
        """
        start_time = time.time()

        try:
            if task.task_type == "smt_add":
                result = addUserToSMTOnChain(
                    merkleRoot=task.merkle_root,
                    vc_hash=task.vc_hash,
                    device_id=task.device_id,
                    fog_node_pubkey=task.fog_node_pubkey,
                )

                processing_time = time.time() - start_time
                task.processing_time = processing_time

                return {
                    "success": True,
                    "result": result,
                    "processing_time": processing_time,
                }
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")

        except Exception as e:
            processing_time = time.time() - start_time
            task.processing_time = processing_time
            logger.error(f"Blockchain task execution failed: {e}")
            raise


# Global instance
_blockchain_processor: Optional[AsyncBlockchainProcessor] = None


def get_blockchain_processor() -> AsyncBlockchainProcessor:
    """Get or create the global blockchain processor instance."""
    global _blockchain_processor
    if _blockchain_processor is None:
        _blockchain_processor = AsyncBlockchainProcessor(max_workers=5, batch_size=10)
    return _blockchain_processor


async def initialize_blockchain_processor():
    """Initialize and start the global blockchain processor."""
    processor = get_blockchain_processor()
    await processor.start()
    return processor


async def shutdown_blockchain_processor():
    """Shutdown the global blockchain processor."""
    global _blockchain_processor
    if _blockchain_processor:
        await _blockchain_processor.stop()
        _blockchain_processor = None
