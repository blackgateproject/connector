"""
User service for user profile and ticket management.
"""

from typing import Any, Dict, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

from ..utils.core_utils import log_user_action
from .base_service import BaseService


class UserService(BaseService):
    """Service for user-related operations."""

    async def create_ticket(
        self, title: str, description: str, user_id: str
    ) -> JSONResponse:
        """Create a new support ticket."""
        try:
            supabase = self.get_supabase_client()

            self.log_debug(f"Attempting to submit ticket: {title}")
            self.log_debug(f"User ID (UUID): {user_id}")
            self.log_debug(f"Description: {description}")

            response = (
                supabase.table("requests")
                .insert(
                    {
                        "title": title,
                        "description": description,
                        "user_id": user_id,
                        "status": "pending",
                    }
                )
                .execute()
            )

            self.log_debug(f"Response: {response}")

            # Log the action
            await log_user_action(
                user_id,
                f"Created ticket: {title}",
                self.settings,
                type="Ticket Creation",
            )

            return JSONResponse(content=response.data, status_code=200)

        except Exception as e:
            error_response = self.create_error_response("Error creating ticket", e)
            return JSONResponse(content=error_response, status_code=500)

    async def get_user_profile_from_token(self, access_token: str) -> JSONResponse:
        """Get user profile using access token."""
        try:
            supabase = self.get_supabase_client()

            # Fetch user information using the access token
            user_response = supabase.auth.get_user(access_token)
            user = user_response.user

            # Prepare user data to return
            user_data = {
                "firstName": user.user_metadata.get("firstName", ""),
                "lastName": user.user_metadata.get("lastName", ""),
                "email": user.email,
                "phone": user.user_metadata.get("phoneNumber", "N/A"),
            }

            # Log the action
            await log_user_action(
                user.id, "Viewed profile", self.settings, type="Profile View"
            )

            return JSONResponse(content=user_data, status_code=200)

        except Exception as e:
            error_response = self.create_error_response(
                "Error fetching user profile", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def get_mock_user_profile(self) -> Dict[str, Any]:
        """Return mock user profile for testing."""
        return {
            "user": {
                "id": "mock-user-id",
                "email": "test@example.com",
                "user_metadata": {"name": "Test User"},
            }
        }

    async def get_user_profile(self, request: Request) -> JSONResponse:
        """Get user profile with fallback to mock data."""
        # Check if Authorization header exists
        auth_header = request.headers.get("Authorization")

        if auth_header and " " in auth_header:
            access_token = auth_header.split(" ")[1]
            return await self.get_user_profile_from_token(access_token)
        else:
            # Return mock user profile when no token provided
            mock_profile = self.get_mock_user_profile()
            return JSONResponse(content=mock_profile, status_code=200)
