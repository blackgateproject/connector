"""
Test cases for all API endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_admin_endpoints():
    """Test admin endpoints are accessible."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost:8000"
    ) as ac:
        response = await ac.get("/admin/v1/")
        assert response.status_code != 404


async def test_merkle_endpoints():
    """Test merkle endpoints are accessible."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost:8000"
    ) as ac:
        response = await ac.get("/merkle/v1/")
        assert response.status_code != 404


async def test_sparse_merkle_endpoints():
    """Test sparse merkle endpoints are accessible."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost:8000"
    ) as ac:
        response = await ac.get("/sparse_merkle/v1/")
        assert response.status_code != 404


async def test_blockchain_endpoints():
    """Test blockchain endpoints are accessible."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost:8000"
    ) as ac:
        response = await ac.get("/blockchain/v1/")
        assert response.status_code != 404


async def test_setup_endpoints():
    """Test setup endpoints are accessible."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost:8000"
    ) as ac:
        response = await ac.get("/setup/v1/")
        assert response.status_code != 404


async def test_accumulator_endpoints():
    """Test accumulator endpoints are accessible."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost:8000"
    ) as ac:
        response = await ac.get("/accumulator/v1/")
        assert response.status_code != 404


async def test_all_endpoints_cors():
    """Test CORS headers on all API endpoints."""
    endpoints = [
        "/admin/v1/",
        "/merkle/v1/",
        "/sparse_merkle/v1/",
        "/blockchain/v1/",
        "/setup/v1/",
        "/accumulator/v1/",
    ]

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost:8000"
    ) as ac:
        for endpoint in endpoints:
            response = await ac.options(
                endpoint, headers={"Origin": "http://localhost:3000"}
            )
            assert "access-control-allow-origin" in response.headers
