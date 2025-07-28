"""
Async blockchain operations with multi-worker support for improved performance.

This module provides async blockchain operations and background task processing
to prevent blockchain network calls from blocking the registration process.

Multi-worker support: Uses Redis as a shared task queue when multiple FastAPI workers are used.
"""

import asyncio
import json
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from .web3_utils import addUserToSMTOnChain

# Configure logging
logger = logging.getLogger(__name__)

# Multi-worker support
WORKER_ID = os.getenv("WORKER_ID", str(uuid.uuid4())[:8])
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Redis support for multi-worker setup
try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None


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
    worker_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Redis storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BlockchainTask":
        """Create from dictionary for Redis retrieval."""
        return cls(**data)


class MultiWorkerAsyncBlockchainProcessor:
    """
    Multi-worker async blockchain processor using Redis as shared queue.

    This allows multiple FastAPI workers to share blockchain processing load,
    significantly improving throughput and reliability.
    """

    def __init__(self, max_workers: int = 3, batch_size: int = 5):
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.worker_id = WORKER_ID
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.is_running = False
        self.processor_tasks: List[asyncio.Task] = []

        # Redis setup
        self.redis_client = None
        self.task_queue_key = "blockchain_tasks"
        self.completed_tasks_key = "blockchain_completed"

        # Fallback to in-memory for single worker
        self.local_queue: asyncio.Queue = asyncio.Queue()
        self.local_completed: Dict[str, BlockchainTask] = {}

    async def start(self):
        """Start the background blockchain processor."""
        if self.is_running:
            return

        self.is_running = True

        # Try to connect to Redis for multi-worker support
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.from_url(REDIS_URL, decode_responses=True)
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.ping
                )
                logger.info(
                    f"Connected to Redis for multi-worker blockchain processing (Worker: {self.worker_id})"
                )
            except Exception as e:
                logger.warning(
                    f"Redis not available, falling back to local processing: {e}"
                )
                self.redis_client = None

        # Start processor tasks
        for i in range(self.max_workers):
            task = asyncio.create_task(self._process_tasks(worker_index=i))
            self.processor_tasks.append(task)

        logger.info(
            f"Started blockchain processor with {self.max_workers} workers (Worker ID: {self.worker_id})"
        )

    async def stop(self):
        """Stop the background blockchain processor."""
        self.is_running = False

        # Wait for all processor tasks to complete
        if self.processor_tasks:
            await asyncio.gather(*self.processor_tasks, return_exceptions=True)
            self.processor_tasks.clear()

        # Shutdown executor
        self.executor.shutdown(wait=True)

        # Close Redis connection
        if self.redis_client:
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.close
                )
            except:
                pass

        logger.info(f"Stopped blockchain processor (Worker ID: {self.worker_id})")

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
            worker_id=self.worker_id,
        )

        if self.redis_client:
            # Submit to Redis queue for multi-worker processing
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.redis_client.lpush,
                    self.task_queue_key,
                    json.dumps(task.to_dict()),
                )
                logger.info(
                    f"Queued SMT add task {task_id} to Redis (Worker: {self.worker_id})"
                )
            except Exception as e:
                logger.error(
                    f"Failed to queue task to Redis: {e}, falling back to local queue"
                )
                await self.local_queue.put(task)
        else:
            # Fallback to local queue
            await self.local_queue.put(task)
            logger.info(
                f"Queued SMT add task {task_id} locally (Worker: {self.worker_id})"
            )

        return task_id

    async def get_task_status(self, task_id: str) -> Optional[BlockchainTask]:
        """Get the status of a submitted task."""
        if self.redis_client:
            try:
                # Check Redis for completed task
                task_data = await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.hget, self.completed_tasks_key, task_id
                )
                if task_data:
                    return BlockchainTask.from_dict(json.loads(task_data))
            except Exception as e:
                logger.error(f"Error getting task status from Redis: {e}")

        # Fallback to local storage
        return self.local_completed.get(task_id)

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
            await asyncio.sleep(0.2)  # Check every 200ms

        raise TimeoutError(f"Task {task_id} did not complete within {timeout} seconds")

    async def _process_tasks(self, worker_index: int):
        """Background task processor that handles blockchain operations."""
        logger.info(
            f"Started blockchain task processor {worker_index} (Worker: {self.worker_id})"
        )

        while self.is_running:
            try:
                # Get tasks from queue
                tasks_to_process = []

                if self.redis_client:
                    # Get tasks from Redis
                    try:
                        for _ in range(self.batch_size):
                            task_data = await asyncio.get_event_loop().run_in_executor(
                                None,
                                self.redis_client.brpop,
                                self.task_queue_key,
                                1,  # 1 second timeout
                            )
                            if task_data:
                                _, task_json = task_data
                                task_dict = json.loads(task_json)
                                task = BlockchainTask.from_dict(task_dict)
                                tasks_to_process.append(task)
                            else:
                                break
                    except Exception as e:
                        logger.error(f"Error getting tasks from Redis: {e}")
                        await asyncio.sleep(1.0)
                        continue
                else:
                    # Get tasks from local queue
                    try:
                        # Get first task (blocking)
                        task = await asyncio.wait_for(
                            self.local_queue.get(), timeout=1.0
                        )
                        tasks_to_process.append(task)

                        # Get additional tasks (non-blocking) up to batch size
                        for _ in range(self.batch_size - 1):
                            try:
                                task = self.local_queue.get_nowait()
                                tasks_to_process.append(task)
                            except asyncio.QueueEmpty:
                                break

                    except asyncio.TimeoutError:
                        # No tasks available, continue loop
                        continue

                # Process batch of tasks
                if tasks_to_process:
                    await self._process_task_batch(tasks_to_process, worker_index)

            except Exception as e:
                logger.error(f"Error in blockchain task processor {worker_index}: {e}")
                await asyncio.sleep(1.0)

    async def _process_task_batch(self, tasks: List[BlockchainTask], worker_index: int):
        """Process a batch of blockchain tasks."""
        logger.info(
            f"Worker {worker_index} processing batch of {len(tasks)} blockchain tasks"
        )

        # Process tasks concurrently
        futures = []
        for task in tasks:
            task.status = "processing"
            task.worker_id = f"{self.worker_id}-{worker_index}"
            future = asyncio.get_event_loop().run_in_executor(
                self.executor, self._execute_blockchain_task, task
            )
            futures.append((task, future))

        # Wait for all tasks to complete
        for task, future in futures:
            try:
                result = await future
                task.status = "completed"
                task.result = result
            except Exception as e:
                task.status = "failed"
                task.error = str(e)
                logger.error(f"Task {task.task_id} failed: {e}")

            # Store completed task
            await self._store_completed_task(task)

    async def _store_completed_task(self, task: BlockchainTask):
        """Store completed task in Redis or local storage."""
        if self.redis_client:
            try:
                # Store in Redis with expiration
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.redis_client.hset,
                    self.completed_tasks_key,
                    task.task_id,
                    json.dumps(task.to_dict()),
                )
                # Set expiration on the hash key (24 hours)
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.expire, self.completed_tasks_key, 86400
                )
                logger.info(f"Task {task.task_id} completed and stored in Redis")
            except Exception as e:
                logger.error(f"Error storing completed task in Redis: {e}")
                # Fallback to local storage
                self.local_completed[task.task_id] = task
        else:
            # Store locally
            self.local_completed[task.task_id] = task

            # Clean up old completed tasks (keep last 100)
            if len(self.local_completed) > 100:
                oldest_tasks = sorted(
                    self.local_completed.keys(),
                    key=lambda x: self.local_completed[x].timestamp,
                )[:20]
                for old_task_id in oldest_tasks:
                    del self.local_completed[old_task_id]

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
                    "worker_id": task.worker_id,
                }
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")

        except Exception as e:
            processing_time = time.time() - start_time
            task.processing_time = processing_time
            logger.error(f"Blockchain task execution failed: {e}")
            raise


# Global instance
_blockchain_processor: Optional[MultiWorkerAsyncBlockchainProcessor] = None


def get_blockchain_processor() -> MultiWorkerAsyncBlockchainProcessor:
    """Get or create the global blockchain processor instance."""
    global _blockchain_processor
    if _blockchain_processor is None:
        # Configure workers based on environment
        max_workers = int(os.getenv("BLOCKCHAIN_WORKERS", "3"))
        batch_size = int(os.getenv("BLOCKCHAIN_BATCH_SIZE", "5"))
        _blockchain_processor = MultiWorkerAsyncBlockchainProcessor(
            max_workers=max_workers, batch_size=batch_size
        )
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
