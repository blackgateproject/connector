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
from pydantic import BaseModel, EmailStr
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import FileResponse, PlainTextResponse
from supabase import Client, create_client

# Global Variables to hold Supabase URL and Key
supaURL = ""
supaKey = ""


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
    # Fetch Supabase URL and Key from ENV vars
    try:
        load_dotenv("./.env")
        supaURL: str = os.getenv("SUPABASE_URL")
        supaKey: str = os.getenv("SUPABASE_KEY")
        print(f"SUPABASE_URL: {supaURL}\nSUPABASE_KEY: {supaKey}")
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


# Verify User
@app.post("/functions/v1/verifyUser/")
# NOTE:: When setting up PKI, move user auth to supabase, handled PKI here
async def verify_user(
    requests: Request,
    # csrf_token: str = Form(...),
    # csrf_protect: CsrfProtect = Depends(),
):
    # try:
    #     csrf_protect.validate_csrf(csrf_token)
    # except CsrfProtectError as e:
    #     return JSONResponse(status_code=e.status_code, content={"detail": e.message})

    # Get user and pw from request body
    body = await requests.json()
    email = body.get("email")
    pw = body.get("password")
    print(
        f"Email: {email}\nEmail Datatype: {type(email)}\nPassword: {pw}\nPassword Datatype: {type(pw)}"
    )

    # Create a supabase client
    supabase: Client = create_client(
        os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY")
    )

    # Check if the user exists in supabase. NOTE:: APIdocs on supabase are not clear, use the filter function with the modifier passed as a str arg
    print(f"Checking email {email} in supabase")
    data = (
        supabase.table("users")
        .select("*", count="exact")
        .filter("email", "eq", email)
        .execute()
    )
    # Serialize the data to JSON, might not be needed but better safe than sorry
    jsonData = json.dumps(data.data)

    print(f"Data Count: {data.count}")
    print(f"Data: {jsonData}")
    print(f"ID: {data.data[0]['id']}")

    if data.count == 0:
        print("ERR: User/password not found. Empty json body returned from supabase.")
        return JSONResponse(
            status_code=400, content={"Error": "User/password not found"}
        )
    elif data.count > 1:
        print("ERR: Multiple users found with the same email")
        return JSONResponse(
            status_code=400,
            content={"Error": "Multiple users found with the same email"},
        )
    else:
        # Get the pw_hash, role and last_access_at from the data
        pw_hash = data.data[0]["pw_hash"]
        role = data.data[0]["role"]
        last_access = data.data[0]["last_access_at"]

        print(f"pw_hash: {pw_hash}\nrole: {role}\nlast_access: {last_access}")

        # Verify the correct role exists for the user given email i.e email domain should match the stored role. email.split("@")[1] gives the domain, need to get rid of the .com
        if role != email.split("@")[1][:-4]:
            print(
                f"ERR: Role does not match email domain\nEmail Role: {email.split('@')[1][:-4]}\nRole: {role}"
            )
            return JSONResponse(
                status_code=400,
                content={"Error": "Role does not match email domain"},
            )

        # Verify the password
        if checkpw(pw.encode("utf-8"), pw_hash.encode("utf-8")):
            print("Password verified")

            # Update the last access time. NOTE:: Should probably log this on the connector server instead of supabase
            print(
                f"Updating last access time to {datetime.now(timezone.utc).isoformat()}"
            )
            data = (
                supabase.table("users")
                .update({"last_access_at": f"{datetime.now(timezone.utc).isoformat()}"})
                .filter("email", "eq", email)
                .execute()
            )
            print("Last access time updated")

            # Return Valid response
            return JSONResponse(
                status_code=200,
                content={"authenticated": True, "role": role},
            )
        else:
            print("ERR: Incorrect Password")
            return JSONResponse(
                status_code=400, content={"Error": "Incorrect Password"}
            )
