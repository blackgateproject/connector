"""
API v1 endpoints - configurable between original and refactored versions.
"""

# For backward compatibility, also export individual modules
from . import accumulator, admin, auth, blockchain, merkle, setup, sparse_merkle, user
from .config import (
    accumulator_router,
    admin_router,
    auth_router,
    blockchain_router,
    merkle_router,
    setup_router,
    sparse_merkle_router,
    user_router,
)
