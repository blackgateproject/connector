import json
import uuid
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from eth_keys import keys
from eth_utils import decode_hex
from fastapi import Depends
from fastapi.responses import JSONResponse
from gotrue import AuthResponse
from gotrue.types import AuthResponse
from supabase import Client, create_async_client, create_client
from supabase.client import AuthApiError
from supabase.lib.client_options import ClientOptions
from typing_extensions import Annotated

from ..core.config import Settings
from ..models.user import User
from .web3_utils import (
    get_did_from_registry,
    verify_identity_with_stateless_blockchain,
    verify_with_rsa_accumulator,
)


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]

# HIGHLY POSSIBLE THAT THE FUNCTION WAS NOT BEING CALLED CORRECTLY
# ERROR COMING FROM THE FACT THAT SUPABASE_KEY IS CALLED NOT SUPABASE_ANON_KEY OR
# SUPABASE_SERV_KEY

# # def supaClient(settings: settings_dependency, useAdmin: bool = False) -> Client:
# async def supaClient(settings: settings_dependency, useAdmin: bool = False):
#     """
#     Create a Supabase Client instance
#     :param settings: Settings
#     :param useAdmin: bool
#     :return: Supabase Client instance
#     """
#     try:
#         if useAdmin:
#             print(
#                 f"[UTILS]: WARNING UseAdmin==True \nCreating Supabase client with anon key"
#             )
#             supabase: Client = await create_async_client(
#                 supabase_url=settings.SUPABASE_URL,
#                 supabase_serv_key=settings.SUPABASE_SERV_KEY,
#             )
#             print(f"[UTILS]: Supabase client created \n{supabase}")
#         else:
#             print(f"[UTILS]: Creating Supabase client with anon key")
#             supabase: Client = await create_async_client(
#                 supabase_url=settings.SUPABASE_URL,
#                 supabase_anon_key=settings.SUPABASE_ANON_KEY,
#             )
#             print(f"[UTILS]: Supabase client created \n{supabase}")
#         if not supabase.auth.session:
#             raise Exception("Session not found")
#         if supabase is None:
#             raise Exception("[ERROR]: Supabase client not created")
#         return supabase
#     except AuthApiError as e:
#         print(f"Error: {e.message}")
#         return {"error": e.message}
#     except Exception as e:
#         if "WinError 10061" in str(e):
#             return JSONResponse(
#                 content={
#                     "authenticated": False,
#                     "error": "Supabase docker image is down/not responding",
#                 },
#                 status_code=500,
#             )


def json_serialize(obj):
    """
    Custom serialization function to handle non-serializable objects like datetime and custom objects.
    :param obj: Any
    :return str

    """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO 8601 string
    elif isinstance(obj, set):
        return list(obj)  # Convert set to list
    elif isinstance(obj, dict):
        # Recursively handle dictionaries
        return {key: json_serialize(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        # Recursively handle lists
        return [json_serialize(item) for item in obj]
    return str(obj)  # Convert other types to string


def extractUserInfo(user: AuthResponse):
    """
    Extract user information from the AuthResponse object
    :param user: AuthResponse
    :return: dict
    """

    user_id = user.user.id
    # login_time = datetime.now(timezone.utc)

    # Extract user information
    user_data = {
        "id": user_id,
        "app_metadata": user.user.app_metadata,
        "user_metadata": user.user.user_metadata,
        "aud": user.user.aud,
        "confirmation_sent_at": user.user.confirmation_sent_at,
        "recovery_sent_at": user.user.recovery_sent_at,
        "email_change_sent_at": user.user.email_change_sent_at,
        "new_email": user.user.new_email,
        "new_phone": user.user.new_phone,
        "invited_at": user.user.invited_at,
        "action_link": user.user.action_link,
        "email": user.user.email,
        "phone": user.user.phone,
        "created_at": user.user.created_at,
        "confirmed_at": user.user.confirmed_at,
        "email_confirmed_at": user.user.email_confirmed_at,
        "phone_confirmed_at": user.user.phone_confirmed_at,
        "last_sign_in_at": user.user.last_sign_in_at,
        "role": user.user.role,
        "updated_at": user.user.updated_at,
        "identities": [
            {
                "id": identity.id,
                "identity_id": identity.identity_id,
                "user_id": identity.user_id,
                "identity_data": identity.identity_data,
                "provider": identity.provider,
                "created_at": identity.created_at,
                "last_sign_in_at": identity.last_sign_in_at,
                "updated_at": identity.updated_at,
            }
            for identity in user.user.identities
        ],
        "is_anonymous": user.user.is_anonymous,
        "factors": user.user.factors,
    }

    return user_data


def extract_user_details_for_passwordless(user: AuthResponse) -> dict:
    """
    Extract user details for passwordless login.
    """
    user_data = extractUserInfo(user)
    return {
        "id": user_data["id"],
        "email": user_data["email"],
        "did": user_data["user_metadata"].get("did", ""),
        "public_key": user_data["user_metadata"].get("public_key", ""),
    }


# Print the user object
def print_user(user: User):
    print(f"User {user.username} ({user.email})")
    # print(f"  ID: {user.id}")
    print(f"  Phone Number: {user.phone}")
    print(f"  Role: {user.role}")
    print(f"  DID: {user.did}")
    print(f"  Is Passwordless: {user.isPWLess}")
    if user.isPWLess:
        print(f"  Public Key: {user.public_key}")
        print(f"  Private Key: {user.private_key}")
        print(f"  Blockchain Address: {user.blockchain_address}")
    print(f"  Is Online: {user.isOnline}")
    print()


async def log_user_action(
    user_id: str, activity: str, settings: settings_dependency, type: str
):
    """
    Log user actions to the user_activity_logs table.
    :param user_id: str
    :param activity: str
    :param settings: Settings
    :param type: str
    """
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_SERV_KEY,
    )

    try:
        response = (
            supabase.table("user_activity_logs")
            .insert(
                {
                    "user_id": user_id,
                    "activity": activity,
                    "type": type,  # Include type in the log
                }
            )
            .execute()
        )
        print(f"Log created: {response}")
    except Exception as e:
        print(f"Error logging action: {str(e)}")


def verify_identity(user, identity_credential):
    return verify_identity_with_stateless_blockchain(user, identity_credential)


def verify_rsa(base, e):
    return verify_with_rsa_accumulator(base, e)


def get_did(controller):
    return get_did_from_registry(controller)
