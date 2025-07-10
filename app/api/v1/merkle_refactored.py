"""
Refactored Merkle tree API endpoints using service layer.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ...core.merkle import merkleCore
from ...models.requests import HashProof, MerkleInput
from ...services.blockchain_service import BlockchainService
from ...utils.core_utils import settings_dependency
from ...utils.web3_utils import getZKSyncMerkleRoot

router = APIRouter()


@router.get("/")
async def health_check():
    """Health check endpoint."""
    return "Reached Merkle Endpoint, Router merkle is Active"


@router.get("/root")
async def get_merkle_root():
    """Get the merkle root both offchain and onchain."""
    try:
        # Get the merkle root from memory
        memory_root = merkleCore.get_root()

        # Get the merkle root from the blockchain
        chain_root = await getZKSyncMerkleRoot()

        return JSONResponse(
            content={"memory_root": memory_root, "chain_root": chain_root}
        )
    except Exception as e:
        print(f"[get_merkle_root()] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error getting merkle root", "error": str(e)},
        )


@router.post("/addUser")
async def add_user(data: MerkleInput, settings: settings_dependency):
    """Add user to the merkle tree."""
    blockchain_service = BlockchainService(settings)
    return blockchain_service.add_user_to_merkle(data.user_id, data.credentials)


@router.post("/verifyUser")
async def verify_user(zkp: HashProof, settings: settings_dependency):
    """Verify user on the merkle tree."""
    blockchain_service = BlockchainService(settings)
    return blockchain_service.verify_user_on_merkle(zkp.merkleHash)
