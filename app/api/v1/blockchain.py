import json
from datetime import datetime, timedelta, timezone, tzinfo

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...utils.core_utils import settings_dependency, verify_jwt
from ...utils.web3_utils import (  # issue_did,; issue_vc,; storeDIDonBlockchain,; storeVCOnBlockchain,
    getContractZKsync,
    w3,
)

# Initialize the API router
router = APIRouter()


@router.get("/")
async def health_check():
    """
    Blockchain Endpoint Health Check
    """
    return "Reached Blockchain Endpoint, Router Blockchain is Active"


@router.get("/contracts-test")
async def contract_test():
    """
    Test if contracts can be fetched from /blockchain
    """
    # Retrieve and concatenate contract information for multiple contracts
    contract = getContractZKsync("Merkle")
    contract += getContractZKsync("RSAAccumulator")
    return {"contract": contract}
