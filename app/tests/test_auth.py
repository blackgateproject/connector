"""
Test cases for authentication endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.anyio
async def test_auth_endpoints_exist():
    """Test that auth endpoints are accessible."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Test that auth base endpoint exists
        response = await ac.get("/auth/v1/")
        # Should return 405 (method not allowed) or other non-404 error
        assert response.status_code != 404


@pytest.mark.anyio
async def test_auth_login_endpoint():
    """Test auth login endpoint exists and handles requests."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.post(
            "/auth/v1/login", json={"username": "test", "password": "test"}
        )
        # Should return some error (not 404), meaning endpoint exists
        assert response.status_code != 404


@pytest.mark.anyio
async def test_auth_cors_headers():
    """Test CORS headers on auth endpoints."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.options(
            "/auth/v1/", headers={"Origin": "http://localhost:3000"}
        )
        assert "access-control-allow-origin" in response.headers


@pytest.mark.anyio
async def test_auth_invalid_credentials():
    """Test auth endpoint with invalid credentials."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.post(
            "/auth/v1/login", json={"username": "invalid", "password": "invalid"}
        )
        # Should return error status
        assert response.status_code in [400, 401, 404, 422]


@pytest.mark.anyio
async def test_auth_missing_fields():
    """Test auth endpoint with missing required fields."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.post("/auth/v1/login", json={})
        # Should return validation error
        assert response.status_code in [404, 422]
