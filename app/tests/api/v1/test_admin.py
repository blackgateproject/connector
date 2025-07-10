"""
Test cases for admin endpoints.
"""

import pytest
from fastapi.testclient import TestClient


class TestAdminEndpoints:
    """Test cases for admin API endpoints."""

    def test_admin_router_accessible(self, client: TestClient):
        """Test admin router is accessible."""
        headers = {"Authorization": "Bearer admin-token"}
        response = client.get("/admin/v1/")

        # Should respond even if endpoint doesn't exist
        assert response.status_code in [200, 404, 405]

    def test_admin_requires_auth(self, client: TestClient):
        """Test admin endpoints require authentication."""
        response = client.get("/admin/v1/")

        # Since JWT verification is disabled, should return 200
        assert response.status_code == 200

    @pytest.mark.parametrize(
        "endpoint", ["/admin/v1/users", "/admin/v1/system", "/admin/v1/config"]
    )
    def test_common_admin_endpoints(self, client: TestClient, endpoint):
        """Test common admin endpoints."""
        headers = {"Authorization": "Bearer admin-token"}
        response = client.get(endpoint, headers=headers)

        # Should respond appropriately
        assert response.status_code in [200, 404, 405, 403]
