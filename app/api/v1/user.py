from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from supabase import Client, create_client

from ...utils.core_utils import log_user_action, settings_dependency, verify_jwt

# from ...utils.pki_utils import generate_private_key, generate_public_key

# Initialize the API router
router = APIRouter()


# Health check endpoint
@router.get("/")
async def health_check(_: dict = Depends(verify_jwt)):
    return "Reached User Endpoint, Router User is Active"


# Endpoint to create a new ticket
@router.post("/requests")
async def create_ticket(
    request: Request, settings: settings_dependency, _: dict = Depends(verify_jwt)
):
    data = await request.json()
    title = data.get("title")
    description = data.get("description")
    user_id = data.get("user_id")  # Accept UUID as string

    # Initialize Supabase client
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_AUTH_ANON_KEY,
    )

    try:
        print(f"Attempting to submit ticket: {title}")
        print(f"User ID (UUID): {user_id}")
        print(f"Description: {description}")

        # Insert the ticket into the database
        response = (
            supabase.table("requests")
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
        print(f"[ERR_SUPABASE] Error creating ticket: {str(e)}")  # Add error logging
        return JSONResponse(content={"error": str(e)}, status_code=500)


# Endpoint to get user profile
@router.get("/profile")
async def get_user_profile(
    request: Request, settings: settings_dependency, _: dict = Depends(verify_jwt)
):
    access_token = request.headers.get("Authorization").split(" ")[1]

    # Initialize Supabase client
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_AUTH_ANON_KEY,
    )

    try:
        # Fetch user information using the access token
        user_response = supabase.auth.get_user(access_token)
        user = user_response.user

        # #Fetch the role from the user_roles table
        # role_response = (
        #     supabase.table("user_roles")
        #     .select("role")
        #     .eq("user_id", user.id)
        #     .single()
        #     .execute()
        # )
        # role = role_response.data["role"] if role_response.data else "user"

        # # Fetch the twoFactorAuth value from the user_keys table
        # keys_response = (
        #     supabase.table("user_keys")
        #     .select("two_factor_auth")
        #     .eq("user_id", user.id)
        #     .single()
        #     .execute()
        # )
        # two_factor_auth = (
        #     keys_response.data["two_factor_auth"] if keys_response.data else False
        # )

        # Prepare user data to return
        user_data = {
            "firstName": user.user_metadata.get("firstName", ""),
            "lastName": user.user_metadata.get("lastName", ""),
            "email": user.email,
            "phone": user.user_metadata.get("phoneNumber", "N/A"),
            # "role": role,
            # "passwordSet": True,
            # "twoFactorAuth": two_factor_auth,
        }
        await log_user_action(user.id, "Viewed profile", settings, type="Profile View")
        return JSONResponse(content=user_data, status_code=200)
    except Exception as e:
        print(f"[ERR_SUPABASE] Error fetching user profile: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)
