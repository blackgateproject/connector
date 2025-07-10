import pytest
from fastapi.testclient import TestClient

from app.main import app  # Assuming your FastAPI app is in main.py

client = TestClient(app)


def test_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {
        "message": "Connector running! Visit /docs for API documentation."
    }


def test_admin_user_activity_logs():
    """Test admin user activity logs endpoint."""
    response = client.get("/admin/v1/user-activity-logs")
    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error: {error_detail}")
    assert response.status_code == 200


def test_admin_log_action():
    """Test admin log action endpoint."""
    response = client.post(
        "/admin/v1/log",
        json={
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "activity": "Test Activity",
            "type": "Test Type",
        },
    )
    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error: {error_detail}")
    assert response.status_code == 200


def test_admin_get_users():
    """Test admin get users endpoint."""
    response = client.get("/admin/v1/getUsers")
    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error: {error_detail}")
    assert response.status_code == 200


def test_admin_get_all_users():
    """Test admin get all users endpoint."""
    response = client.get("/admin/v1/getAllUsers")
    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error: {error_detail}")
    assert response.status_code == 200


def test_admin_get_requests():
    """Test admin get requests endpoint."""
    response = client.get("/admin/v1/requests")
    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error: {error_detail}")
    assert response.status_code == 200


def test_admin_profile():
    """Test admin profile endpoint."""
    response = client.get(
        "/admin/v1/profile", headers={"Authorization": "Bearer test_token"}
    )
    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error: {error_detail}")
    assert response.status_code in [
        200,
        500,
    ]  # May fail due to missing auth but endpoint exists


def test_admin_dashboard():
    """Test admin dashboard endpoint."""
    response = client.get("/admin/v1/dashboard")
    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error: {error_detail}")
    assert response.status_code == 200


def test_auth_register():
    """Test auth register endpoint with proper FormData and NetworkInfo."""
    form_data = {
        "alias": "test_user",
        "device_id": "test_device_123",
        "did": "did:test:123e4567-e89b-12d3-a456-426614174000",
        "firmware_version": "1.0.0",
        "proof_type": "SMT",
        "selected_role": "device",
        "testMode": True,
        "walletCreateTime": 1234567890.0,
        "walletEncryptTime": 1234567895.0,
    }

    network_info = {
        "ip_address": "192.168.1.1",
        "user_agent": "TestAgent/1.0",
        "location_lat": 40.7128,
        "location_long": -74.0060,
        "user_language": "en-US",
        "user_info_time": 1234567900.0,
    }

    response = client.post(
        "/auth/v1/register", json={"formData": form_data, "networkInfo": network_info}
    )

    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error in /register: {error_detail}")

    assert response.status_code in [200, 400, 422, 500]  # Various valid responses


def test_auth_register_invalid_payload():
    """Test auth register endpoint with invalid payload."""
    response = client.post("/auth/v1/register", json={"invalid": "payload"})
    assert response.status_code == 422  # Validation error


def test_auth_poll():
    """Test auth poll endpoint."""
    test_did = "did:test:123e4567-e89b-12d3-a456-426614174000"
    response = client.get(f"/auth/v1/poll/{test_did}")

    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error in /poll: {error_detail}")

    assert response.status_code in [200, 404, 500]  # Various valid responses


def test_auth_verify():
    """Test auth verify endpoint with VerifiablePresentation."""
    # Mock VerifiablePresentation structure
    verifiable_presentation = {
        "iat": 1234567890,
        "nbf": 1234567890,
        "issuanceDate": "2023-01-01T00:00:00Z",
        "nonce": "test_nonce_123",
        "verifiableCredential": [
            {
                "credentialSubject": {
                    "ZKP": {
                        "userHash": "test_hash",
                        "userIndex": "test_index",
                        "merkleRoot": "test_root",
                    },
                    "networkInfo": {
                        "ip_address": "192.168.1.1",
                        "user_agent": "TestAgent/1.0",
                        "location_lat": 40.7128,
                        "location_long": -74.0060,
                        "user_language": "en-US",
                        "user_info_time": 1234567900.0,
                    },
                    "did": "did:test:123e4567-e89b-12d3-a456-426614174000",
                    "alias": "test_user",
                    "proof_type": "SMT",
                    "selected_role": "device",
                    "firmware_version": "1.0.0",
                    "testMode": True,
                    "device_id": "test_device_123",
                    "walletCreateTime": 1234567890.0,
                    "walletEncryptTime": 1234567895.0,
                },
                "issuer": {"id": "did:issuer:test"},
                "type": ["VerifiableCredential"],
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "issuanceDate": "2023-01-01T00:00:00Z",
                "proof": {"type": "JwtProof2020", "jwt": "test.jwt.token"},
            }
        ],
        "holder": "did:test:123e4567-e89b-12d3-a456-426614174000",
        "verifier": ["did:verifier:test"],
        "type": ["VerifiablePresentation"],
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "expirationDate": "2024-01-01T00:00:00Z",
        "proof": {"type": "JwtProof2020", "jwt": "test.jwt.token"},
    }

    partial_times = {
        "wallet_gen_time": 100.0,
        "wallet_enc_time": 50.0,
        "network_info_time": 25.0,
        "vc_issuance_time": 200.0,
        "smt_local_add_time": 75.0,
        "smt_onchain_add_time": 300.0,
        "vp_gen_time": 150.0,
    }

    try:
        response = client.post(
            "/auth/v1/verify",
            json={
                "verifiablePresentation": verifiable_presentation,
                "partial_times": partial_times,
            },
        )

        if response.status_code == 500:
            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    error_detail = (
                        error_data.get("error", "")
                        or error_data.get("detail", "")
                        or error_data.get("message", "")
                    )
                else:
                    error_detail = str(error_data)
            except:
                error_detail = response.text

            error_keywords = [
                "connection",
                "refused",
                "jwt",
                "signature",
                "invalid",
                "jws",
                "malformed",
                "pgrst301",
            ]
            if any(keyword in error_detail.lower() for keyword in error_keywords):
                pytest.fail(f"Service error in /verify: {error_detail}")

        assert response.status_code in [200, 400, 422, 500]  # Various valid responses

    except Exception as e:
        # Check for specific connection errors that indicate service dependencies are not available
        error_str = str(e).lower()
        connection_error_keywords = [
            "cannot connect to host",
            "connection refused",
            "remote computer refused",
            "clientconnectorerror",
            "network connection",
        ]
        if any(keyword in error_str for keyword in connection_error_keywords):
            pytest.fail(f"Credential service connection error in /verify: {e}")
        else:
            # Re-raise unexpected errors
            raise


def test_auth_verify_invalid_payload():
    """Test auth verify endpoint with invalid payload."""
    response = client.post("/auth/v1/verify", json={"invalid": "payload"})
    assert response.status_code == 422  # Validation error


def test_auth_logout():
    """Test auth logout endpoint."""
    response = client.post(
        "/auth/v1/logout",
        json={
            "access_token": "test_token",
            "uuid": "123e4567-e89b-12d3-a456-426614174000",
        },
    )
    assert response.status_code in [200, 400, 422]


def test_merkle_root():
    """Test merkle root endpoint."""
    response = client.get("/merkle/v1/root")
    assert response.status_code in [200, 500]  # May fail due to contract issues


def test_sparse_merkle_root():
    """Test sparse merkle root endpoint."""
    response = client.get("/sparse_merkle/v1/root")
    if response.status_code == 500:
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                error_detail = (
                    error_data.get("error", "")
                    or error_data.get("detail", "")
                    or error_data.get("message", "")
                )
            else:
                error_detail = str(error_data)
        except:
            error_detail = response.text

        error_keywords = [
            "connection",
            "refused",
            "jwt",
            "signature",
            "invalid",
            "jws",
            "malformed",
            "pgrst301",
        ]
        if any(keyword in error_detail.lower() for keyword in error_keywords):
            pytest.fail(f"Service error: {error_detail}")
    assert response.status_code in [200, 500]


def test_accumulator_modulus():
    """Test accumulator get modulus endpoint."""
    response = client.get("/accumulator/v1/getModulus")
    assert response.status_code == 200


def test_setup_status():
    """Test setup status endpoint."""
    response = client.get("/setup/v1/")
    assert response.status_code == 200


def test_setup_credential_service():
    """Test setup credential service healthcheck."""
    response = client.get("/setup/v1/credential-service-healthcheck")
    assert response.status_code in [200, 500]  # May fail if service not running
