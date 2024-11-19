import json
import os
import random
import shutil
import string
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

import requests
from bcrypt import checkpw, gensalt, hashpw, kdf
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from gotrue.errors import AuthApiError
from pydantic import BaseModel, EmailStr
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import FileResponse, PlainTextResponse

from config import settings
from supabase import Client, create_client

from model import User, Session

# CSRF Configuration
class CsrfSettings(BaseModel):
    secret_key: str = os.environ.get(
        "SECRET_KEY", "secretkey"
    )  # Replace with a secure secret key
    cookie_same_site: str = "none"


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


# CSRF Util function for get Requests
async def getCSRF(request: Request, csrf_protect: CsrfProtect = Depends()):
    try:
        csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    except CsrfProtectError as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.message})
    return csrf_token, signed_token


# CSRF Util function for POST Requests
async def postCSRF(request: Request, csrf_protect: CsrfProtect = Depends()):
    try:
        csrf_protect.validate_csrf(request)
        return True
    except CsrfProtectError as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.message})


# CORS Configuration
origins = [
    # "http://localhost:5173",
    # "http://localhost:5174",
    # "http://localhost:8000",
    "*"
]


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


# CSRF Middleware
@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.get("/csrftoken/")
async def get_csrf_token(csrf_protect: CsrfProtect = Depends()):
    # response = JSONResponse(status_code=200, content={"csrf_token": "cookie"})
    # csrf_protect.set_csrf_cookie(csrf_protect.generate_csrf_tokens(response))
    csrf_token, _ = csrf_protect.generate_csrf_tokens()
    return {"csrf_token": csrf_token}


# # Ping the frontend on startup (Work in progress)
# @app.on_event("startup")
# def on_startup():
#     ping the frontend to check if it is online


# # Verify User
# @app.post("/functions/v1/verifyUser/")
# # NOTE:: When setting up PKI, move user auth to supabase, handled PKI here
# async def verify_user(
#     requests: Request,
#     # csrf_token: str = Form(...),
#     # csrf_protect: CsrfProtect = Depends(),
# ):
#     # try:
#     #     csrf_protect.validate_csrf(csrf_token)
#     # except CsrfProtectError as e:
#     #     return JSONResponse(status_code=e.status_code, content={"detail": e.message})

#     # Get user and pw from request body
#     body = await requests.json()
#     email = body.get("email")
#     pw = body.get("password")
#     print(
#         f"Email: {email}\nEmail Datatype: {type(email)}\nPassword: {pw}\nPassword Datatype: {type(pw)}"
#     )

#     # Create supabase client
#     supabase: Client = create_client(
#         supabase_url=os.environ.get("SUPABASE_URL"),
#         supabase_key=os.environ.get("SUPABASE_ANON_KEY"),
#     )

#     # Supabase auth sign, try catch block
#     try:
#         user = supabase.auth.sign_in_with_password({"email": email, "password": pw})
#         # Return user
#         print(user)

#         # Return authorized: true and role: admin/user depending on email domain minus the .com
#         return JSONResponse(
#             content={"authenticated": True, "role": email.split("@")[1].split(".")[0]},
#             status_code=200,
#         )
#     except AuthApiError as e:
#         print(f"AuthApiError: {e}")
#         return JSONResponse(
#             content={"authenticated": False, "error": str(e)}, status_code=401
#         )
#     except Exception as e:
#         print(f"ERR: {e}")
#         if "WinError 10061" in str(e):
#             return JSONResponse(
#                 content={"authenticated": False, "error": "Supabase docker image is down/not responding"},
#                 status_code=500,
#             )
#         return JSONResponse(
#             content={"authenticated": False, "error": str(e)}, status_code=500
#         )
# List to store logged in users
logged_in_users = []


# Verify User
@app.post("/functions/v1/verifyUser/")
async def verify_user(
    requests: Request,
):
    body = await requests.json()
    email = body.get("email")
    pw = body.get("password")

    supabase: Client = create_client(
        supabase_url=os.environ.get("SUPABASE_URL"),
        supabase_key=os.environ.get("SUPABASE_ANON_KEY"),
    )

    try:
        user = supabase.auth.sign_in_with_password({"email": email, "password": pw})
        user_id = user.user.id
        login_time = datetime.now(timezone.utc)

        print(user)

        # Store detailed user information
        logged_in_users.append(
            {
                "user_id": user_id,
                "login_time": login_time,
                "email": user.user.email,
                "role": user.user.role,
                "last_sign_in_at": user.user.last_sign_in_at,
                "access_token": user.session.access_token,
                "refresh_token": user.session.refresh_token,
                "expires_at": user.session.expires_at,
            }
        )

        # Print login user
        print(f"Added user to local store: \n{logged_in_users}")

        return JSONResponse(
            content={"authenticated": True, "role": email.split("@")[1].split(".")[0]},
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
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


# Verify User
@app.post("/functions/v1/verifyUser/")
async def verify_user(request: Request):
    body = await request.json()
    email = body.get("email")
    pw = body.get("password")

    supabase: Client = create_client(
        supabase_url=os.environ.get("SUPABASE_URL"),
        supabase_key=os.environ.get("SUPABASE_ANON_KEY"),
    )

    try:
        user = supabase.auth.sign_in_with_password({"email": email, "password": pw})
        user_id = user.user.id
        login_time = datetime.now(timezone.utc)

        # Store detailed user information
        logged_in_users.append(
            {
                "user_id": user_id,
                "login_time": login_time,
                "email": user.user.email,
                "role": user.user.role,
                "last_sign_in_at": user.user.last_sign_in_at,
                "access_token": user.session.access_token,
                "refresh_token": user.session.refresh_token,
                "expires_at": user.session.expires_at,
            }
        )

        # Print login user
        print(user)

        return JSONResponse(
            content={"authenticated": True, "role": email.split("@")[1].split(".")[0]},
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
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


# # Signout User
# @app.post("/functions/v1/signout/")
# async def signout_user(request: Request):
#     body = await request.json()
#     user_id = body.get("user_id")

#     global logged_in_users
#     logged_in_users = [user for user in logged_in_users if user["user_id"] != user_id]

#     return JSONResponse(content={"signed_out": True}, status_code=200)
