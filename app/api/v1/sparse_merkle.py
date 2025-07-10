from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from supabase import Client, create_client

from ...core.sparseMerkleTree import smtCore
from ...models.requests import HashProof, MerkleInput
from ...utils.core_utils import log_user_action, settings_dependency  # , verify_jwt
from ...utils.web3_utils import addUserToSMT, getZKSyncMerkleRoot, verifyUserOnSMT

# from ...utils.pki_utils import generate_private_key, generate_public_key

# Initialize the API router
router = APIRouter()


# Split this into core/models.py when there are more models


# Health check endpoint
@router.get("/")
# async def health_check(_: dict = Depends(verify_jwt)):
async def health_check():
    return "Reached SMT Endpoint, Router SMT is Active"


# Get the SMT root
@router.get("/root")
async def get_SMT_root(
    # request: Request,
    # settings: dict = Depends(settings_dependency),
    # _: dict = Depends(verify_jwt),
):
    """
    Get the SMT root of the SMT tree offchain + onchain.
    """
    try:
        # Get the SMT root
        memory_root = smtCore.get_root()

        # Get the SMT root from the blockchain
        # chain_root = await getZKSyncSMTRoot()
    except Exception as e:
        print(f"[get_SMT_root()] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error getting SMT root", "error": str(e)},
        )
    # Return the SMT root
    # return JSONResponse(content={"memory_root": memory_root, "chain_root": chain_root})
    return JSONResponse(
        content={"memory_root": memory_root, "chain_root": "chain_root"}
    )


# Add user to SMT tree
@router.post("/addUser")
async def add_user(
    # request: Request,
    data: MerkleInput,
    # settings: dict = Depends(settings_dependency),
    # _: dict = Depends(verify_jwt),
):
    """
    Add user to the SMT tree.
    """
    try:
        # Get the request body
        # body = await request.json()
        # user_id = body["user_id"]
        # credentials = body["credentials"]
        user_id = data.user_id
        credentials = data.credentials

        # Add user to the SMT tree
        print(f"[/addUser] user_id: {user_id}, credentials: {credentials}")
        data = addUserToSMT(user_id, credentials)

        # log_user_action(
        #     settings["supabase_client"],
        #     user_id,
        #     "addUser",
        #     "Added user to SMT tree",
        #     datetime.now(timezone.utc),
        # )
    except Exception as e:
        print(f"[/addUser] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error adding user to SMT tree", "error": str(e)},
        )
    return JSONResponse(content={"message": "User added to SMT tree", "data": data})


# Verify user on SMT tree
@router.post("/verifyUser")
async def verify_user(
    request: Request,
    # zkp: MerkleInput,
    # settings: dict = Depends(settings_dependency),
    # _: dict = Depends(verify_jwt),
):
    """
    Verify user on the SMT tree.
    """
    # SMTHash = zkp.user_id
    # SMTProof = zkp.credentials
    body = await request.json()
    SMTHash = body["user_id"]
    SMTKey = body["key"]
    SMTProof = body["credentials"]
    print(f"[verify_user()] SMTHash: {SMTHash}, SMTProof: {SMTProof}")
    # print(f"[verify_user()] SMTProof: {SMTProof}")
    # Verify user on the SMT tree
    result = verifyUserOnSMT(SMTHash, SMTKey, SMTProof)

    print(f"[verify_user()] results: {result}")

    return JSONResponse(
        content={
            "message": (
                "User verified on SMT tree"
                if result.get("valid_Offchain")
                else "User not verified on SMT tree"
            ),
            "results": result,
        }
    )
