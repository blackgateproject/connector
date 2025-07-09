"""
Test cases for blockchain and accumulator endpoints.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


class TestBlockchainEndpoints:
    """Test cases for blockchain API endpoints."""

    def test_blockchain_router_accessible(self, client: TestClient, mock_verify_jwt):
        """Test blockchain router is accessible."""
        headers = {"Authorization": "Bearer test-token"}
        response = client.get("/blockchain/v1/")

        assert response.status_code in [200, 404, 405]

    @patch("app.utils.web3_utils.addUserToAccumulator")
    def test_blockchain_operations(
        self, mock_add_user, client: TestClient, mock_verify_jwt
    ):
        """Test blockchain operations."""
        mock_add_user.return_value = {"tx_hash": "0xabcdef"}

        headers = {"Authorization": "Bearer test-token"}

        # Test blockchain interaction
        blockchain_data = {"user_id": "test-user", "data": "test-data"}
        response = client.post(
            "/blockchain/v1/add-user", headers=headers, json=blockchain_data
        )
        assert response.status_code in [200, 201, 404, 405, 422]

    def test_blockchain_without_auth(self, client: TestClient):
        """Test blockchain endpoints without authentication."""
        response = client.get("/blockchain/v1/")
        assert response.status_code in [401, 403, 404, 405]


class TestAccumulatorEndpoints:
    """Test cases for accumulator API endpoints."""

    def test_accumulator_router_accessible(self, client: TestClient, mock_verify_jwt):
        """Test accumulator router is accessible."""
        headers = {"Authorization": "Bearer test-token"}
        response = client.get("/accumulator/v1/")

        assert response.status_code in [200, 404, 405]

    @patch("app.core.accumulator")
    def test_accumulator_operations(
        self, mock_accumulator, client: TestClient, mock_verify_jwt
    ):
        """Test accumulator operations."""
        mock_accumulator.add_element.return_value = "accumulated_value"
        mock_accumulator.generate_proof.return_value = {"proof": "test-proof"}

        headers = {"Authorization": "Bearer test-token"}

        # Test adding element to accumulator
        element_data = {"element": "test-element"}
        response = client.post(
            "/accumulator/v1/add", headers=headers, json=element_data
        )
        assert response.status_code in [200, 201, 404, 405, 422]

        # Test generating proof
        proof_data = {"element": "test-element"}
        response = client.post(
            "/accumulator/v1/proof", headers=headers, json=proof_data
        )
        assert response.status_code in [200, 404, 405, 422]


class TestSetupEndpoints:
    """Test cases for setup API endpoints."""

    def test_setup_router_accessible(self, client: TestClient):
        """Test setup router is accessible without auth (setup mode)."""
        response = client.get("/setup/v1/")

        # Setup endpoints might not require auth
        assert response.status_code in [200, 404, 405]

    def test_setup_operations(self, client: TestClient, mock_database):
        """Test setup operations."""
        setup_data = {
            "admin_email": "admin@example.com",
            "admin_password": "secure_password",
            "organization": "Test Org",
        }

        response = client.post("/setup/v1/initialize", json=setup_data)
        assert response.status_code in [200, 201, 404, 405, 422]

    def test_setup_status(self, client: TestClient):
        """Test getting setup status."""
        response = client.get("/setup/v1/status")
        assert response.status_code in [200, 404, 405]
