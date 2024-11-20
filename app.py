import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from gotrue.errors import AuthApiError
from pydantic import BaseModel, EmailStr
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import FileResponse, PlainTextResponse

from config import settings
from model import Session, User
from supabase import Client, create_client


# CORS Configuration
origins = [
    # "http://localhost:5173",
    # "http://localhost:5174",
    # "http://localhost:8000",
    "*"
]

# List to store logged in users
logged_in_users = []

# Debug flag for print statements
debug = True


# Print Hello message on server startup and Bye on server shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n\n===== Server Up =====\n\n")
    # Load environment variables
    load_dotenv("./.env")

    # Fetch Supabase URL and Key from ENV vars
    try:
        supaURL = settings.SUPABASE_URL
        supaANONKey = settings.SUPABASE_ANON_KEY
        supaSERVKey = settings.SUPABASE_SERV_KEY

        print(
            f"SUPABASE_URL: {supaURL}\nSUPABASE_ANON_KEY: {supaANONKey}\nSUPABASE_SERV_KEY: {supaSERVKey}"
        )
    except KeyError:
        print("ERR: Supabase URL or Key not found in ENV vars")
    yield
    print("\n\n===== Server Shutting down! =====\n\n")


# Main entrypoint
app = FastAPI(lifespan=lifespan)


# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/functions/v1/verifyUser/")
async def verify_user(request: Request):
    body = await request.json()
    email = body.get("email")
    pw = body.get("password")

    # Initialize the Supabase client
    supabase: Client = create_client(
        supabase_url=os.environ.get("SUPABASE_URL"),
        supabase_key=os.environ.get("SUPABASE_ANON_KEY"),
    )

    try:
        # Attempt to sign in with email and password
        user = supabase.auth.sign_in_with_password({"email": email, "password": pw})
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

        # Check if user is already logged in (ensure the check is using UUID comparison)
        if any(UUID(user_data["id"]) == user.id for user in logged_in_users):
            raise Exception("User is already logged in")

        # Convert the user data to Pydantic User model
        user_instance = User(**user_data)

        # Store the user in the logged_in_users list
        logged_in_users.append(user_instance)

        # Print logged-in user information
        if debug:
            print(f"Added user to local store: \n{user_instance}")

        # Return authenticated response
        return JSONResponse(
            content={
                "authenticated": True,
                "role": email.split("@")[1].split(".")[0],
                "uuid": user_id,
            },
            status_code=200,
        )
    except AuthApiError as e:
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=401
        )
    except Exception as e:
        if "WinError 10061" in str(e):
            return JSONResponse(
                content={
                    "authenticated": False,
                    "error": "Supabase docker image is down/not responding",
                },
                status_code=500,
            )
        elif "User is already logged in" in str(
            e
        ):  # Check if the user is already logged in
            return JSONResponse(
                content={
                    "authenticated": True,
                    "role": email.split("@")[1].split(".")[0],
                    "uuid": user_id,
                    "error": "User is already logged in",
                },
                status_code=200,
            )
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


@app.get("/functions/v1/getLoggedUsers/")
async def get_logged_users():
    print("Logged In users")
    # Iterate over the logged_in_users list and print the user information sequentially
    for user in logged_in_users:
        print(f"User: {user}\n")
    # return JSONResponse(content={"logged_in_users": [user.dict() for user in logged_in_users]}, status_code=200)


# Route to signout a user that browser holds the uuid for. NOT COMPLETE YET
@app.post("/functions/v1/signout/")
async def signout_user(request: Request):
    body = await request.json()
    user_id = body.get("user_id")

    global logged_in_users
    logged_in_users = [user for user in logged_in_users if user.id != user_id]

    # Sign out from supabase
    supabase: Client = create_client(
        supabase_url=os.environ.get("SUPABASE_URL"),
        supabase_key=os.environ.get("SUPABASE_ANON_KEY"),
    )
    response = supabase.auth.sign_out(user_id)
    print(response)

    return JSONResponse(content={"signed_out": True}, status_code=200)


# # Signout User
# @app.post("/functions/v1/signout/")
# async def signout_user(request: Request):
#     body = await request.json()
#     user_id = body.get("user_id")

#     global logged_in_users
#     logged_in_users = [user for user in logged_in_users if user["user_id"] != user_id]

#     return JSONResponse(content={"signed_out": True}, status_code=200)
