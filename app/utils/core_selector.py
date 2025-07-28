"""
Core selector utilities for multi-worker support.

This module provides utilities to select the appropriate core instances
(original vs multi-worker) based on the deployment mode.
"""

import os
from typing import Any


def get_smt_core():
    """Get the appropriate SMT core based on deployment mode."""
    multi_worker_mode = os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"

    if multi_worker_mode:
        from ..core.multiworker_smt import smtCore

        return smtCore
    else:
        from ..core.sparseMerkleTree import smtCore

        return smtCore


def get_merkle_core():
    """Get the appropriate Merkle core based on deployment mode."""
    multi_worker_mode = os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"

    if multi_worker_mode:
        from ..core.multiworker_merkle import merkleCore

        return merkleCore
    else:
        from ..core.merkle import merkleCore

        return merkleCore


def get_accumulator_core():
    """Get the appropriate Accumulator core based on deployment mode."""
    multi_worker_mode = os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"

    if multi_worker_mode:
        from ..core.multiworker_accumulator import accumulatorCore

        return accumulatorCore
    else:
        from ..core.accumulator import AccumulatorClass

        # Return a singleton instance for compatibility
        if not hasattr(get_accumulator_core, "_instance"):
            get_accumulator_core._instance = AccumulatorClass()
        return get_accumulator_core._instance


# Pre-initialize cores for performance (avoid repeated imports)
_smt_core = None
_merkle_core = None
_accumulator_core = None


def get_cached_smt_core():
    """Get cached SMT core instance."""
    global _smt_core
    if _smt_core is None:
        _smt_core = get_smt_core()
    return _smt_core


def get_cached_merkle_core():
    """Get cached Merkle core instance."""
    global _merkle_core
    if _merkle_core is None:
        _merkle_core = get_merkle_core()
    return _merkle_core


def get_cached_accumulator_core():
    """Get cached Accumulator core instance."""
    global _accumulator_core
    if _accumulator_core is None:
        _accumulator_core = get_accumulator_core()
    return _accumulator_core


def is_multi_worker_mode() -> bool:
    """Check if running in multi-worker mode."""
    return os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"
