import os
import random
import shutil
import string
import time
from contextlib import asynccontextmanager
from typing import Annotated

import requests
from bcrypt import gensalt, hashpw, checkpw, kdf
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from pydantic import BaseModel, EmailStr
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import FileResponse, PlainTextResponse
from supabase_py import Client, create_client


# CSRF Configuration
class CsrfSettings(BaseModel):
    secret_key: str = os.environ.get(
        "SECRET_KEY", "secretkey"
    )  # Replace with a secure secret key
    cookie_same_site: str = "none"


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


# # CSRF Util function for get Requests
# async def getCSRF(request: Request, csrf_protect: CsrfProtect = Depends()):
#     try:
#         csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
#     except CsrfProtectError as e:
#         return JSONResponse(status_code=e.status_code, content={"detail": e.message})
#     return csrf_token, signed_token

# # CSRF Util function for POST Requests
# async def postCSRF(request: Request, csrf_protect: CsrfProtect = Depends()):
#     try:
#         csrf_protect.validate_csrf(request)
#         return True
#     except CsrfProtectError as e:
#         return JSONResponse(status_code=e.status_code, content={"detail": e.message})

# Route frontend to backend


# Print Hello message on server startup and Bye on server shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n\n===== Server Up =====\n\n")
    yield
    print("\n\n===== Server Shutting down! =====\n\n")


# Main entrypoint
app = FastAPI(lifespan=lifespan)


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
@app.post("/functions/v1/verify_user/")
async def verify_user(
    requests: Request,
    # csrf_token: str = Form(...),
    # csrf_protect: CsrfProtect = Depends(),
):
    # try:
    #     csrf_protect.validate_csrf(csrf_token)
    # except CsrfProtectError as e:
    #     return JSONResponse(status_code=e.status_code, content={"detail": e.message})

    # Get user and pw from request headers
    email = str(requests.headers.get("email"))
    pw = str(requests.headers.get("pw"))
    print(f"Email: {email}\nEmail Datatype: {type(email)}\nPassword: {pw}\nPassword Datatype: {type(pw)}")

    # Create a supabase client
    supaURL = "http://localhost:54321"
    supaKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0"
    supabase: Client = create_client(supaURL, supaKey)

    # Check if the user exists in supabase. NOTE:: APIdocs on supabase are not clear, use the filter function with the modifier passed as a str arg
    print(f"Checking email {email} in supabase")
    data = supabase.table("users").select("*").filter("email", "eq", email).execute()

    # # Check status code in response, if 200 then continue
    if data["status_code"] != 200:
        print(f"Backend Error: Got status code {data['status_code']}")
        return JSONResponse(
            status_code=400,
            content={"Error": f"From Backend: Got status code {data['status_code']}"},
        )
    else:
        # Check if anythign was returned, if not then return invalid user/password
        if len(data["data"]) == 0:
            print("ERR: User/password not found. Empty json body returned from supabase.")
            return JSONResponse(
                status_code=400, content={"Error": "User/password not found"}
            )
        else:
            # Data now has the pw_hash, role and last access time.
            # Verify the pw_hash which was salted
            print(data["data"])
