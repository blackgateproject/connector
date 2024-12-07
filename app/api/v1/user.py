from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from supabase import Client, ClientOptions, create_client

from ...utils.utils import log_user_action, settings_dependency
from ...utils.web3_utils import (
    get_did_from_registry,
    verify_identity_with_stateless_blockchain,
    verify_with_rsa_accumulator,
)

router = APIRouter()


@router.get("/")
async def health_check():
    return "Reached User Endpoint, Router User is Active"


@router.post("/tickets")
async def create_ticket(request: Request, settings: settings_dependency):
    data = await request.json()
    title = data.get("title")
    description = data.get("description")
    user_id = data.get("user_id")  # Accept UUID as string

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_ANON_KEY,
    )

    try:
        print(f"Attempting to submit ticket: {title}")
        print(f"User ID (UUID): {user_id}")
        print(f"Description: {description}")

        response = (
            supabase.table("tickets")
            .insert(
                {
                    "title": title,
                    "description": description,
                    "user_id": user_id,  # Use UUID directly
                    "status": "pending",
                    # Let the database handle created_at and updated_at defaults
                }
            )
            .execute()
        )

        print(f"Response: {response}")
        await log_user_action(
            user_id, f"Created ticket: {title}", settings, type="Ticket Creation"
        )
        return JSONResponse(content=response.data, status_code=200)
    except Exception as e:
        print(f"Error creating ticket: {str(e)}")  # Add error logging
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/profile")
async def get_user_profile(request: Request, settings: settings_dependency):
    access_token = request.headers.get("Authorization").split(" ")[1]
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_ANON_KEY,
    )

    try:
        user_response = supabase.auth.get_user(access_token)
        user = user_response.user

        # Fetch the role from the user_roles table
        role_response = (
            supabase.table("user_roles")
            .select("role")
            .eq("user_id", user.id)
            .single()
            .execute()
        )
        role = role_response.data["role"] if role_response.data else "user"

        user_data = {
            "firstName": user.user_metadata.get("firstName", ""),
            "lastName": user.user_metadata.get("lastName", ""),
            "email": user.email,
            "phone": user.user_metadata.get("phoneNumber", "N/A"),
            "role": role,
            "passwordSet": True,
            "twoFactorAuth": False,
        }
        await log_user_action(user.id, "Viewed profile", settings, type="Profile View")
        return JSONResponse(content=user_data, status_code=200)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/verify-identity")
async def verify_identity(request: Request):
    data = await request.json()
    user = data.get("user")
    identity_credential = data.get("identity_credential")
    result = verify_identity_with_stateless_blockchain(user, identity_credential)
    return JSONResponse(content={"result": result}, status_code=200)


@router.post("/verify-rsa")
async def verify_rsa(request: Request):
    data = await request.json()
    base = data.get("base")
    e = data.get("e")
    result = verify_with_rsa_accumulator(base, e)
    return JSONResponse(content={"result": result}, status_code=200)


@router.get("/get-did/{controller}")
async def get_did(controller: str):
    did = get_did_from_registry(controller)
    return JSONResponse(content={"did": did}, status_code=200)
