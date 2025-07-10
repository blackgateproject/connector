"""
Refactored blockchain API endpoints using service layer.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ...services.blockchain_service import BlockchainService
from ...utils.core_utils import settings_dependency

router = APIRouter()


@router.get("/")
async def health_check():
    """Blockchain Endpoint Health Check."""
    return "Reached Blockchain Endpoint, Router Blockchain is Active"


@router.get("/contracts-test")
async def contract_test(settings: settings_dependency):
    """Test if contracts can be fetched from /blockchain."""
    blockchain_service = BlockchainService(settings)
    return blockchain_service.get_contract_info()
