from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from supabase import Client, create_client

from ...core.merkle import merkleCore
from ...models.requests import HashProof, MerkleInput
from ...utils.core_utils import log_user_action, settings_dependency  # , verify_jwt
from ...utils.web3_utils import addUserToMerkle, getZKSyncMerkleRoot, verifyUserOnMerkle

# from ...utils.pki_utils import generate_private_key, generate_public_key

# Initialize the API router
router = APIRouter()


# Split this into core/models.py when there are more models


# Health check endpoint
@router.get("/")
# async def health_check(_: dict = Depends(verify_jwt)):
async def health_check():
    return "Reached Merkle Endpoint, Router merkle is Active"


# Get the merkle root
@router.get("/root")
async def get_merkle_root(
    # request: Request,
    # settings: dict = Depends(settings_dependency),
    # _: dict = Depends(verify_jwt),
):
    """
    Get the merkle root of the merkle tree offchain + onchain.
    """
    try:
        # Get the merkle root
        memory_root = merkleCore.get_root()

        # Get the merkle root from the blockchain
        chain_root = await getZKSyncMerkleRoot()
    except Exception as e:
        print(f"[get_merkle_root()] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error getting merkle root", "error": str(e)},
        )
    # Return the merkle root
    return JSONResponse(content={"memory_root": memory_root, "chain_root": chain_root})


# Add user to merkle tree
@router.post("/addUser")
async def add_user(
    # request: Request,
    data: MerkleInput,
    # settings: dict = Depends(settings_dependency),
    # _: dict = Depends(verify_jwt),
):
    """
    Add user to the merkle tree.
    """
    try:
        # Get the request body
        # body = await request.json()
        # user_id = body["user_id"]
        # credentials = body["credentials"]
        user_id = data.user_id
        credentials = data.credentials

        # Add user to the merkle tree
        data = addUserToMerkle(user_id, credentials)

        # log_user_action(
        #     settings["supabase_client"],
        #     user_id,
        #     "addUser",
        #     "Added user to merkle tree",
        #     datetime.now(timezone.utc),
        # )
    except Exception as e:
        print(f"[/addUser] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error adding user to merkle tree", "error": str(e)},
        )
    return JSONResponse(content={"message": "User added to merkle tree", "data": data})


# Verify user on merkle tree
@router.post("/verifyUser")
async def verify_user(
    # request: Request,
    zkp: HashProof,
    # settings: dict = Depends(settings_dependency),
    # _: dict = Depends(verify_jwt),
):
    """
    Verify user on the merkle tree.
    """
    merkleHash = zkp.merkleHash
    # merkleProof = zkp.merkleProof
    print(f"[verify_user()] merkleHash: {merkleHash}")
    # print(f"[verify_user()] merkleProof: {merkleProof}")

    # Verify user on the merkle tree
    result = verifyUserOnMerkle(
        merkleHash,
        # merkleProof,
    )

    print(f"[verify_user()] results: {result}")

    return JSONResponse(
        content={"message": "User verified on merkle tree", "results": result}
    )
