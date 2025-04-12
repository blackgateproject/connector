import pytest
from app.main import app  # Assuming your FastAPI app is in main.py
from fastapi.testclient import TestClient

client = TestClient(app)


def test_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == "Reached User Endpoint, Router User is Active"


def test_create_ticket():
    response = client.post(
        "/requests",
        json={
            "title": "Test Ticket",
            "description": "This is a test ticket",
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
        },
    )
    assert response.status_code == 200
    assert "id" in response.json()


def test_get_user_profile():
    response = client.get("/profile", headers={"Authorization": "Bearer test_token"})
    assert response.status_code == 200
    assert "email" in response.json()


def test_verify():
    response = client.post(
        "/verify", json={"email": "test@example.com", "password": "testpassword"}
    )
    assert response.status_code == 200
    assert response.json()["authenticated"] == True


def test_logout():
    response = client.post(
        "/logout",
        json={
            "access_token": "test_token",
            "uuid": "123e4567-e89b-12d3-a456-426614174000",
        },
    )
    assert response.status_code == 200
    assert response.json()["message"] == "User logged out"


def test_passwordless_login():
    response = client.post(
        "/passwordless-login",
        json={
            "did": "did:example:123456789abcdefghi",
            "proof": "test_proof",
            "context": "https://www.w3.org/2018/credentials/v1",
            "issuance_date": "2023-10-01T00:00:00Z",
        },
    )
    assert response.status_code == 200
    assert response.json()["authenticated"] == True


def test_get_user_activity_logs():
    response = client.get("/user-activity-logs")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_log_action():
    response = client.post(
        "/log",
        json={
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "activity": "Test Activity",
            "type": "Test Type",
        },
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Log created successfully"


def test_get_users():
    response = client.get("/getUsers")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_add_user():
    response = client.post(
        "/addUser",
        json={
            "firstName": "Test",
            "lastName": "User",
            "email": "testuser@example.com",
            "phoneNumber": "1234567890",
            "password": "testpassword",
            "role": "user",
            "autoConfirm": "true",
        },
    )
    assert response.status_code == 200


def test_get_requests():
    response = client.get("/requests")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_complete_ticket():
    response = client.post("/requests/1/complete")
    assert response.status_code == 200
    assert response.json()["status"] == "completed"


def test_delete_user():
    response = client.delete("/deleteUser/123e4567-e89b-12d3-a456-426614174000")
    assert response.status_code == 200
    assert response.json()["message"] == "User deleted successfully"


def test_edit_user():
    response = client.put(
        "/editUser",
        json={
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "firstName": "Updated",
            "lastName": "User",
            "email": "updateduser@example.com",
            "phone": "0987654321",
            "password": "newpassword",
            "role": "admin",
        },
    )
    assert response.status_code == 200
    assert response.json()["message"] == "ok"


def test_get_admin_profile():
    response = client.get("/profile", headers={"Authorization": "Bearer admin_token"})
    assert response.status_code == 200
    assert "email" in response.json()


def test_get_user():
    response = client.get("/getUser/123e4567-e89b-12d3-a456-426614174000")
    assert response.status_code == 200
    assert "email" in response.json()


def test_get_all_users():
    response = client.get("/getAllUsers")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
