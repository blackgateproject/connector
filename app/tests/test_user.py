"""
Test cases for user API endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.anyio
async def test_user_endpoints_exist():
    """Test that user endpoints are accessible."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/user/v1/")
        # Should return 405 (method not allowed) or other non-404 error
        assert response.status_code != 404


@pytest.mark.anyio
async def test_user_profile_endpoint():
    """Test user profile endpoint exists."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/user/v1/profile")
        # Should return some error (not 404), meaning endpoint exists
        assert response.status_code != 404


@pytest.mark.anyio
async def test_user_cors_headers():
    """Test CORS headers on user endpoints."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.options(
            "/user/v1/", headers={"Origin": "http://localhost:3000"}
        )
        assert "access-control-allow-origin" in response.headers


@pytest.mark.anyio
async def test_user_info_endpoint():
    """Test user info endpoint exists."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/user/v1/info")
        # Should return some status (not 404)
        assert response.status_code != 404
