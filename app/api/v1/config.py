"""
Configuration for API routing - choose between original and refactored endpoints.
"""

# Set to True to use refactored endpoints, False for original
USE_REFACTORED_ENDPOINTS = True

# Import mappings
if USE_REFACTORED_ENDPOINTS:
    from . import accumulator_refactored as accumulator
    from . import admin_refactored as admin
    from . import auth_refactored as auth
    from . import blockchain_refactored as blockchain
    from . import merkle_refactored as merkle
    from . import setup_refactored as setup
    from . import sparse_merkle_refactored as sparse_merkle
    from . import user_refactored as user
else:
    from . import (
        accumulator,
        admin,
        auth,
        blockchain,
        merkle,
        setup,
        sparse_merkle,
        user,
    )

# Export routers
auth_router = auth.router
admin_router = admin.router
user_router = user.router
blockchain_router = blockchain.router
merkle_router = merkle.router
sparse_merkle_router = sparse_merkle.router
accumulator_router = accumulator.router
setup_router = setup.router
