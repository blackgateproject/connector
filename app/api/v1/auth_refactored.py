"""
Refactored authentication API endpoints using service layer.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...models.web3_creds import (
    FormData,
    NetworkInfo,
    VerifiableCredential,
    VerifiablePresentation,
)
from ...services.auth_service import AuthService
from ...utils.core_utils import settings_dependency


def get_auth_service(settings=Depends(settings_dependency)):
    return AuthService(settings)


router = APIRouter()


@router.get("/")
async def health_check():
    """Health check endpoint."""
    return "Reached Auth Endpoint, Router Auth is Active"


@router.post("/register")
async def register(
    form_data: FormData,
    network_info: NetworkInfo,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    """Register a new user."""
    return auth_service.register_user(form_data, network_info)


@router.get("/poll/{did_str}")
async def poll_request_status(
    did_str: str,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    """Poll the status of a registration request."""
    return auth_service.poll_request_status(did_str)


# --- Refactored endpoints ---
from ...models.web3_creds import VerifiableCredential, VerifiablePresentation


@router.post("/verify")
async def verify(
    credential: VerifiableCredential,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    """Verify a verifiable credential."""
    return await auth_service.verify_credential(credential)


@router.post("/verify-vp")
async def verify_vp(
    presentation: VerifiablePresentation,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    """Verify a verifiable presentation."""
    return await auth_service.verify_presentation(presentation)


@router.post("/logout")
async def logout(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    """Logout endpoint (token/session management)."""
    return await auth_service.logout(request)


@router.post("/update-metrics")
async def update_metrics(
    metrics: dict,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    """Update performance/statistics metrics."""
    return await auth_service.update_metrics(metrics)
