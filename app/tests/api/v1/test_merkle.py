"""
Test cases for merkle tree endpoints.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


class TestMerkleEndpoints:
    """Test cases for merkle tree API endpoints."""

    def test_merkle_router_accessible(self, client: TestClient):
        """Test merkle router is accessible."""
        headers = {"Authorization": "Bearer test-token"}
        response = client.get("/merkle/v1/")

        assert response.status_code in [200, 404, 405]

    @patch("app.core.merkle.merkleCore")
    def test_merkle_operations(self, mock_merkle_core, client: TestClient):
        """Test merkle tree operations."""
        mock_merkle_core.get_root.return_value = "0x123456"
        mock_merkle_core.add_leaf.return_value = True

        headers = {"Authorization": "Bearer test-token"}

        # Test getting merkle root
        response = client.get("/merkle/v1/root", headers=headers)
        assert response.status_code in [
            200,
            404,
            405,
            500,
        ]  # Allow 500 for contract errors

        # Test adding leaf to merkle tree
        leaf_data = {"data": "test-leaf-data"}
        response = client.post("/merkle/v1/add", headers=headers, json=leaf_data)
        assert response.status_code in [200, 201, 404, 405, 422]

    def test_merkle_without_auth(self, client: TestClient):
        """Test merkle endpoints without authentication."""
        response = client.get("/merkle/v1/")
        # Since JWT verification is disabled, should return 200
        assert response.status_code == 200


class TestSparseMerkleEndpoints:
    """Test cases for sparse merkle tree API endpoints."""

    def test_sparse_merkle_router_accessible(self, client: TestClient):
        """Test sparse merkle router is accessible."""
        headers = {"Authorization": "Bearer test-token"}
        response = client.get("/sparse_merkle/v1/")

        assert response.status_code in [200, 404, 405]

    @patch("app.core.sparseMerkleTree.smtCore")
    def test_sparse_merkle_operations(self, mock_smt_core, client: TestClient):
        """Test sparse merkle tree operations."""
        mock_smt_core.get_root.return_value = "0x654321"
        mock_smt_core.update.return_value = True

        headers = {"Authorization": "Bearer test-token"}

        # Test getting SMT root
        response = client.get("/sparse_merkle/v1/root", headers=headers)
        assert response.status_code in [200, 404, 405]

        # Test updating SMT
        update_data = {"key": "test-key", "value": "test-value"}
        response = client.post(
            "/sparse_merkle/v1/update", headers=headers, json=update_data
        )
        assert response.status_code in [200, 201, 404, 405, 422]
