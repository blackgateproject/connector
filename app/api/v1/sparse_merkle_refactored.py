"""
Refactored Sparse Merkle Tree API endpoints using service layer.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...core.sparseMerkleTree import smtCore
from ...models.requests import MerkleInput
from ...services.blockchain_service import BlockchainService
from ...utils.core_utils import settings_dependency

router = APIRouter()


@router.get("/")
async def health_check():
    """Health check endpoint."""
    return "Reached SMT Endpoint, Router SMT is Active"


@router.get("/root")
async def get_smt_root():
    """Get the SMT root offchain."""
    try:
        # Get the SMT root from memory
        memory_root = smtCore.get_root()

        # TODO: Implement blockchain SMT root retrieval
        chain_root = "chain_root"  # Placeholder

        return JSONResponse(
            content={"memory_root": memory_root, "chain_root": chain_root}
        )
    except Exception as e:
        print(f"[get_smt_root()] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error getting SMT root", "error": str(e)},
        )


@router.post("/addUser")
async def add_user(data: MerkleInput, settings: settings_dependency):
    """Add user to the SMT tree."""
    blockchain_service = BlockchainService(settings)
    return blockchain_service.add_user_to_smt(data.user_id, data.credentials)


@router.post("/verifyUser")
async def verify_user(request: Request, settings: settings_dependency):
    """Verify user on the SMT tree."""
    body = await request.json()
    smt_hash = body["user_id"]
    smt_key = body["key"]
    smt_proof = body["credentials"]

    blockchain_service = BlockchainService(settings)
    return blockchain_service.verify_user_on_smt(smt_hash, smt_key, smt_proof)
