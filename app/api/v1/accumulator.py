import re
from datetime import datetime, timezone
from os import error
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from supabase import Client, create_client

from ...core.accumulator import accumulatorCore
from ...models.requests import HashProof, MerkleInput
from ...utils.core_utils import log_user_action, settings_dependency  # , verify_jwt
from ...utils.web3_utils import (
    addUserToAccumulator,
    getBlockchainModulus,
    verifyUserOnAccumulator,
)

# Initialize the API router
router = APIRouter()


# Health check endpoint
@router.get("/")
# async def health_check(_: dict = Depends(verify_jwt)):
async def health_check():
    return "Reached Accumulator Endpoint, Router Accumulator is Active"


@router.post("/addUser")
async def add_user_to_accumulator(
    request: Request,
):
    """
    Add a user to the accumulator tree.
    """
    errors = True
    try:
        # Get the request body
        body = await request.json()
        # Get the user address from the request body
        did_str = body.get("formData")
        vc = body.get("networkInfo")

        data = addUserToAccumulator(did_str, vc)

        return JSONResponse(
            status_code=200,
            content={
                "message": "User added to Accumulator successfully",
                "data": data,
            },
        )

    except Exception as e:
        errors = False
        print(f"[/addUser] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error adding user to Accumulator", "error": str(e)},
        )


@router.post("/verifyUser")
async def verify_user_on_accumulator(
    request: Request,
):
    """
    Verify a user on the accumulator
    """
    errors = True
    try:
        # Get the request body
        body = await request.json()
        # Get the ZKP values
        accVal = body.get("accVal")
        proof = body.get("proof")
        prime = body.get("prime")
        dataHash = body.get("dataHash")

        # Print the values for debugging
        # print(f"[/verifyUser] dataHash: {dataHash}")
        # print(f"[/verifyUser] accVal: {accVal}")
        # print(f"[/verifyUser] proof: {proof}")
        # print(f"[/verifyUser] prime: {prime}")

        # Verify the user on the accumulator
        restult = verifyUserOnAccumulator(
            dataHash=dataHash,
            accVal=accVal,
            proof=proof,
            prime=prime,
        )

        return JSONResponse(
            status_code=200,
            content={
                "message": (
                    "User verified on Accumulator successfully"
                    if restult
                    else "User not verified on Accumulator"
                ),
                "data": restult,
            },
        )
    except Exception as e:
        errors = False
        print(f"[/verifyUser] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error verifying user on Accumulator", "error": str(e)},
        )


@router.get("/getModulus")
async def get_modulus():
    """
    Get the modulus of the accumulator.
    """
    errors = True
    try:
        # Get the request body
        # body = await request.json()
        # Get the user address from the request body
        # did_str = body.get("formData")
        # vc = body.get("networkInfo")

        data = getBlockchainModulus()

        return JSONResponse(
            status_code=200,
            content={
                "data": data,
            },
        )

    except Exception as e:
        errors = False
        print(f"[/getModulus] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error adding user to Accumulator", "error": str(e)},
        )
