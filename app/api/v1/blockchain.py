from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ...core.config import Settings
from ...utils.web3_utils import getContractDetails, settings_dependency

router = APIRouter()


@router.get("/")
async def health_check():
    """
    Blockchain Endpoint Health Check
    """
    return "Reached Blockchain Endpoint, Router Blockchain is Active"


