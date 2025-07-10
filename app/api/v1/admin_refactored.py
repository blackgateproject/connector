"""
Refactored admin API endpoints using service layer.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...services.admin_service import AdminService
from ...utils.core_utils import settings_dependency

router = APIRouter()


@router.get("/")
async def health_check():
    """Health check endpoint."""
    return "Reached Admin Endpoint, Router Admin is Active"


@router.get("/user-activity-logs")
async def get_user_activity_logs(settings: settings_dependency):
    """Get all user activity logs."""
    admin_service = AdminService(settings)
    return admin_service.get_user_activity_logs()


@router.post("/log")
async def log_action(request: Request, settings: settings_dependency):
    """Log a user action."""
    data = await request.json()
    user_id = data.get("user_id")
    activity = data.get("activity")
    action_type = data.get("type")

    admin_service = AdminService(settings)
    return admin_service.log_user_action(user_id, activity, action_type)


@router.get("/getUsers")
async def get_users(settings: settings_dependency):
    """Get all users with formatted data."""
    admin_service = AdminService(settings)
    return admin_service.get_users()


@router.get("/getAllUsers")
async def get_all_users(settings: settings_dependency):
    """Get all users with simplified data."""
    admin_service = AdminService(settings)
    return admin_service.get_all_users_simple()


@router.get("/requests")
async def get_requests(settings: settings_dependency):
    """Get all requests."""
    admin_service = AdminService(settings)
    return admin_service.get_requests()


@router.post("/requests/{request_id}/approve")
async def approve_request(request_id: str, settings: settings_dependency):
    """Approve a specific request."""
    admin_service = AdminService(settings)
    return admin_service.approve_request(request_id)


@router.post("/requests/{request_id}/reject")
async def reject_request(request_id: str, settings: settings_dependency):
    """Reject a specific request."""
    admin_service = AdminService(settings)
    return admin_service.reject_request(request_id)


@router.delete("/revoke/{did_str}")
async def revoke_did(did_str: str, settings: settings_dependency):
    """Revoke a DID."""
    admin_service = AdminService(settings)
    return admin_service.revoke_did(did_str)


@router.get("/dashboard")
async def get_dashboard_stats(settings: settings_dependency):
    """Get dashboard statistics."""
    admin_service = AdminService(settings)
    return admin_service.get_dashboard_stats()


# TODO: Add remaining admin endpoints (profile, etc.)
# These would follow the same pattern of delegating to the service layer
