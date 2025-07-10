"""
Base service class with common functionality.
"""

from typing import Any, Dict

from supabase import Client, create_client

from ..core.config import Settings
from ..utils.core_utils import settings_dependency


class BaseService:
    """Base service class with common database and utility methods."""

    def __init__(self, settings: Settings = None):
        self.settings = settings or settings_dependency()
        self.debug = self.settings.DEBUG

    def get_supabase_client(self, use_admin: bool = False) -> Client:
        """Get Supabase client instance."""
        key = (
            self.settings.SUPABASE_AUTH_SERV_KEY
            if use_admin
            else self.settings.SUPABASE_AUTH_ANON_KEY
        )
        return create_client(
            supabase_url=self.settings.SUPABASE_URL,
            supabase_key=key,
        )

    def log_debug(self, message: str) -> None:
        """Log debug message if debug mode is enabled."""
        if self.debug >= 0:
            print(message)

    def create_error_response(
        self, message: str, error: Exception = None
    ) -> Dict[str, Any]:
        """Create standardized error response."""
        response = {"authenticated": False, "error": message}
        if self.debug >= 0 and error:
            print(f"[ERROR] {message}: {error}")
        return response

    def create_success_response(
        self, message: str, data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create standardized success response."""
        response = {"authenticated": True, "message": message}
        if data:
            response.update(data)
        return response
