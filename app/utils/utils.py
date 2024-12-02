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
from supabase import Client, create_client
from supabase.client import AuthApiError
from supabase.lib.client_options import ClientOptions
from typing_extensions import Annotated

from ..models.user import User
from ..core.config import Settings


@lru_cache
def get_settings():
    return Settings()


get_settings_dependency = Annotated[Settings, Depends(get_settings)]


def supaClient(settings: get_settings_dependency, useAdmin: bool = False):
    """
    Create a Supabase Client instance
    :param settings: Settings
    :param useAdmin: bool
    :return: Supabase Client instance
    """
    try:
        if useAdmin:
            supabase: Client = create_client(
                supabase_url=settings.SUPABASE_URL,
                supabase_serv_key=settings.SUPABASE_SERV_KEY,
            )
        else:
            supabase: Client = create_client(
                supabase_url=settings.SUPABASE_URL,
                supabase_anon_key=settings.SUPABASE_ANON_KEY,
            )
    except AuthApiError as e:
        print(f"Error: {e.message}")
        return {"error": e.message}
    except Exception as e:
        if "WinError 10061" in str(e):
            return JSONResponse(
                content={
                    "authenticated": False,
                    "error": "Supabase docker image is down/not responding",
                },
                status_code=500,
            )
    return supabase


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
