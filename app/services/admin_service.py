"""
Admin service for user management and administrative operations.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi.responses import JSONResponse
from supabase import ClientOptions

from ..utils.core_utils import json_serialize
from ..utils.pscopg_utils import execute_query, fetch_all, fetch_one
from .base_service import BaseService


class AdminService(BaseService):
    """Service for administrative operations."""

    def get_user_activity_logs(self) -> JSONResponse:
        """Retrieve all user activity logs."""
        try:
            supabase = self.get_supabase_client(use_admin=True)
            response = supabase.table("user_activity_logs").select("*").execute()
            return JSONResponse(content=response.data, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error fetching activity logs", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def log_user_action(
        self, user_id: str, activity: str, action_type: str = None
    ) -> JSONResponse:
        """Log a user action."""
        try:
            supabase = self.get_supabase_client(use_admin=True)
            response = (
                supabase.table("user_activity_logs")
                .insert(
                    {
                        "user_id": user_id,
                        "activity": activity,
                        "type": action_type,
                    }
                )
                .execute()
            )

            success_response = self.create_success_response("Log created successfully")
            return JSONResponse(content=success_response, status_code=200)
        except Exception as e:
            error_response = self.create_error_response("Error creating log", e)
            return JSONResponse(content=error_response, status_code=500)

    def serialize_user_data(self, user) -> Dict[str, Any]:
        """Serialize user data to JSON-friendly format."""
        return {
            "id": user.id,
            "app_metadata": json_serialize(user.app_metadata),
            "user_metadata": json_serialize(user.user_metadata),
            "aud": user.aud,
            "confirmation_sent_at": json_serialize(user.confirmation_sent_at),
            "recovery_sent_at": json_serialize(user.recovery_sent_at),
            "email_change_sent_at": json_serialize(user.email_change_sent_at),
            "new_email": user.new_email,
            "new_phone": user.new_phone,
            "invited_at": json_serialize(user.invited_at),
            "action_link": user.action_link,
            "email": user.email,
            "phone": user.phone,
            "created_at": json_serialize(user.created_at),
            "confirmed_at": json_serialize(user.confirmed_at),
            "email_confirmed_at": json_serialize(user.email_confirmed_at),
            "phone_confirmed_at": json_serialize(user.phone_confirmed_at),
            "last_sign_in_at": json_serialize(user.last_sign_in_at),
            "role": user.role,
            "updated_at": json_serialize(user.updated_at),
            "identities": json_serialize(user.identities),
            "is_anonymous": user.is_anonymous,
            "factors": json_serialize(user.factors),
        }

    def format_user_for_response(
        self, serialized_user: Dict[str, Any], role: str = " "
    ) -> Dict[str, Any]:
        """Format user data for API response."""
        return {
            "id": serialized_user["id"],
            "firstName": serialized_user["user_metadata"].get("firstName", ""),
            "lastName": serialized_user["user_metadata"].get("lastName", ""),
            "email": serialized_user["email"],
            "role": serialized_user["user_metadata"].get("role", role),
            "online": serialized_user["aud"] == "authenticated",
        }

    def get_users(self) -> JSONResponse:
        """Get all users with formatted data."""
        try:
            supabase = self.get_supabase_client(use_admin=True)
            users_response = supabase.auth.admin.list_users(page=1, per_page=100)

            self.log_debug(f"Users Response: {users_response}")

            # Serialize and format users
            return_users = []
            for user in users_response:
                serialized_user = self.serialize_user_data(user)
                formatted_user = self.format_user_for_response(serialized_user)
                return_users.append(formatted_user)

                self.log_debug(f"Return User: {formatted_user}")

            return JSONResponse(content=return_users, status_code=200)

        except Exception as e:
            error_response = self.create_error_response("Error fetching users", e)
            return JSONResponse(content=error_response, status_code=500)

    def get_all_users_simple(self) -> JSONResponse:
        """Get all users with simplified data."""
        try:
            supabase = self.get_supabase_client(use_admin=True)
            users_response = supabase.auth.admin.list_users(page=1, per_page=100)

            # Simple user list without complex formatting
            users_data = []
            for user in users_response:
                users_data.append(
                    {
                        "id": user.id,
                        "email": user.email,
                        "created_at": json_serialize(user.created_at),
                        "last_sign_in_at": json_serialize(user.last_sign_in_at),
                    }
                )

            return JSONResponse(content=users_data, status_code=200)

        except Exception as e:
            error_response = self.create_error_response("Error fetching users", e)
            return JSONResponse(content=error_response, status_code=500)

    def get_requests(self) -> JSONResponse:
        """Get all requests from database."""
        try:
            query = "SELECT * FROM requests ORDER BY created_at DESC"
            requests = fetch_all(query)
            return JSONResponse(content=requests, status_code=200)
        except Exception as e:
            error_response = self.create_error_response("Error fetching requests", e)
            return JSONResponse(content=error_response, status_code=500)

    def approve_request(self, request_id: str) -> JSONResponse:
        """Approve a specific request."""
        try:
            query = "UPDATE requests SET request_status = %s WHERE id = %s"
            execute_query(query, ("approved", request_id))

            success_response = self.create_success_response(
                "Request approved successfully"
            )
            return JSONResponse(content=success_response, status_code=200)
        except Exception as e:
            error_response = self.create_error_response("Error approving request", e)
            return JSONResponse(content=error_response, status_code=500)

    def reject_request(self, request_id: str) -> JSONResponse:
        """Reject a specific request."""
        try:
            query = "UPDATE requests SET request_status = %s WHERE id = %s"
            execute_query(query, ("rejected", request_id))

            success_response = self.create_success_response(
                "Request rejected successfully"
            )
            return JSONResponse(content=success_response, status_code=200)
        except Exception as e:
            error_response = self.create_error_response("Error rejecting request", e)
            return JSONResponse(content=error_response, status_code=500)

    def revoke_did(self, did_str: str) -> JSONResponse:
        """Revoke a DID."""
        try:
            query = 'UPDATE requests SET "isRevoked" = %s WHERE did_str = %s'
            execute_query(query, (True, did_str))

            success_response = self.create_success_response("DID revoked successfully")
            return JSONResponse(content=success_response, status_code=200)
        except Exception as e:
            error_response = self.create_error_response("Error revoking DID", e)
            return JSONResponse(content=error_response, status_code=500)

    def get_dashboard_stats(self) -> JSONResponse:
        """Get dashboard statistics."""
        try:
            # Get various statistics
            total_users_query = "SELECT COUNT(*) as count FROM requests"
            pending_requests_query = "SELECT COUNT(*) as count FROM requests WHERE request_status = 'pending'"
            approved_requests_query = "SELECT COUNT(*) as count FROM requests WHERE request_status = 'approved'"

            total_users = fetch_one(total_users_query)
            pending_requests = fetch_one(pending_requests_query)
            approved_requests = fetch_one(approved_requests_query)

            stats = {
                "total_users": total_users["count"] if total_users else 0,
                "pending_requests": (
                    pending_requests["count"] if pending_requests else 0
                ),
                "approved_requests": (
                    approved_requests["count"] if approved_requests else 0
                ),
            }

            return JSONResponse(content=stats, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error fetching dashboard stats", e
            )
            return JSONResponse(content=error_response, status_code=500)
