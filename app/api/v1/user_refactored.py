"""
Refactored user API endpoints using service layer.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...services.user_service import UserService
from ...utils.core_utils import settings_dependency

router = APIRouter()


@router.get("/")
async def health_check():
    """Health check endpoint."""
    return "Reached User Endpoint, Router User is Active"


@router.post("/requests")
async def create_ticket(request: Request, settings: settings_dependency):
    """Create a new support ticket."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON format"})

    title = data.get("title")
    description = data.get("description")
    user_id = data.get("user_id")

    if not all([title, description, user_id]):
        return JSONResponse(
            status_code=400,
            content={"error": "Missing required fields: title, description, user_id"},
        )

    user_service = UserService(settings)
    return await user_service.create_ticket(title, description, user_id)


@router.get("/profile")
async def get_user_profile(request: Request, settings: settings_dependency):
    """Get user profile."""
    user_service = UserService(settings)
    return await user_service.get_user_profile(request)
