"""
Refactored authentication API endpoints using service layer.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...models.web3_creds import FormData, NetworkInfo
from ...services.auth_service import AuthService
from ...utils.core_utils import settings_dependency

router = APIRouter()


@router.get("/")
async def health_check():
    """Health check endpoint."""
    return "Reached Auth Endpoint, Router Auth is Active"


@router.post("/register")
async def register(
    form_data: FormData, network_info: NetworkInfo, settings: settings_dependency
) -> JSONResponse:
    """Register a new user."""
    auth_service = AuthService(settings)
    return auth_service.register_user(form_data, network_info)


@router.get("/poll/{did_str}")
async def poll_request_status(
    did_str: str, settings: settings_dependency
) -> JSONResponse:
    """Poll the status of a registration request."""
    auth_service = AuthService(settings)
    return auth_service.poll_request_status(did_str)


# TODO: Add other auth endpoints (verify, logout, verify-vp, update-metrics)
# These would follow the same pattern of delegating to the service layer
