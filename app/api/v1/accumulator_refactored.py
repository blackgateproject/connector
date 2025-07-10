"""
Refactored Accumulator API endpoints using service layer.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...services.blockchain_service import BlockchainService
from ...utils.core_utils import settings_dependency

router = APIRouter()


@router.get("/")
async def health_check():
    """Health check endpoint."""
    return "Reached Accumulator Endpoint, Router Accumulator is Active"


@router.post("/addUser")
async def add_user_to_accumulator(request: Request, settings: settings_dependency):
    """Add a user to the accumulator tree."""
    try:
        body = await request.json()
        did_str = body.get("formData")
        vc = body.get("networkInfo")

        blockchain_service = BlockchainService(settings)
        return blockchain_service.add_user_to_accumulator(did_str, vc)

    except Exception as e:
        print(f"[/addUser] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error adding user to Accumulator", "error": str(e)},
        )


@router.post("/verifyUser")
async def verify_user_on_accumulator(request: Request, settings: settings_dependency):
    """Verify a user on the accumulator."""
    try:
        body = await request.json()
        acc_val = body.get("accVal")
        proof = body.get("proof")
        prime = body.get("prime")
        data_hash = body.get("dataHash")

        blockchain_service = BlockchainService(settings)
        return blockchain_service.verify_user_on_accumulator(
            data_hash, acc_val, proof, prime
        )

    except Exception as e:
        print(f"[/verifyUser] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Error verifying user on Accumulator", "error": str(e)},
        )


@router.get("/getModulus")
async def get_modulus(settings: settings_dependency):
    """Get the modulus of the accumulator."""
    blockchain_service = BlockchainService(settings)
    return blockchain_service.get_accumulator_modulus()
