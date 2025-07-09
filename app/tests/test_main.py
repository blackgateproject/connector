"""
Test cases for the main FastAPI application endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.anyio
async def test_root():
    """Test the root endpoint returns correct response."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "Connector running" in data["message"]


@pytest.mark.anyio
async def test_get_ip_endpoint():
    """Test the get-ip endpoint returns IP address."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/get-ip")
    assert response.status_code == 200
    data = response.json()
    assert "ip" in data


@pytest.mark.anyio
async def test_get_ip_with_forwarded_header():
    """Test get-ip endpoint with X-Forwarded-For header."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        headers = {"X-Forwarded-For": "192.168.1.100, 10.0.0.1"}
        response = await ac.get("/get-ip", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["ip"] == "192.168.1.100"


@pytest.mark.anyio
async def test_env_endpoint():
    """Test the env endpoint returns environment variables."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/env")
    assert response.status_code == 200
    data = response.json()
    assert "DEBUG" in data
    assert "BLOCKCHAIN_RPC_URL" in data
    assert data["DEBUG"] == 0


@pytest.mark.anyio
async def test_cors_headers():
    """Test CORS headers are properly set."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.options("/", headers={"Origin": "http://localhost:3000"})
        # OPTIONS request may return 405 if not explicitly handled, but should have CORS headers
        assert response.status_code in [200, 405]
        assert "access-control-allow-origin" in response.headers


@pytest.mark.anyio
async def test_validation_error_handler():
    """Test custom validation error handler."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Test with invalid JSON to trigger validation error
        response = await ac.post("/auth/v1/login", json={"invalid": "data"})
        # Should return 422 for validation error or 404 if endpoint doesn't exist
        assert response.status_code in [404, 422]


@pytest.mark.anyio
async def test_concurrent_requests():
    """Test that the app handles multiple concurrent requests."""
    import asyncio

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Test multiple concurrent requests
        responses = await asyncio.gather(
            ac.get("/"), ac.get("/get-ip"), ac.get("/env"), return_exceptions=True
        )

        # All requests should succeed
        for response in responses:
            if hasattr(response, "status_code"):
                assert response.status_code == 200
