import pickle

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from .api.v1 import (
    accumulator,
    admin,
    auth,
    blockchain,
    merkle,
    setup,
    sparse_merkle,
    user,
)
from .core.merkle import merkleCore
from .core.sparseMerkleTree import smtCore
from .core.tasks.credserver_keepalive import (
    shutdown_scheduler,
    start_health_check_scheduler,
)
from .utils.core_utils import settings_dependency, setup_state, verify_jwt

app = FastAPI()
debug = settings_dependency().DEBUG
API_VERSION = "v1"

# CORS Middleware
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware to check if setup is completed
# @app.middleware("http")
# async def setup_mode_middleware(request: Request, call_next):
#     try:
#         # If setup is completed, let the request pass through
#         if setup_state["is_setup_completed"] == True:
#             response = await call_next(request)
#         else:
#             # Only let setup requests pass through during setup mode or the docs
#             if (
#                 request.url.path.startswith("/setup/")
#                 and setup_state["is_setup_completed"] == False
#                 or request.url.path.startswith("/docs")
#                 or request.url.path.startswith("/openapi.json")
#             ):
#                 response = await call_next(request)

#             else:
#                 # Redirect the rest to the setup page
#                 response = RedirectResponse(url=f"/setup/{API_VERSION}/")
#     except HTTPException as e:
#         print(f"Error in setup_mode_middleware: {e}")
#         response = {"message": f"Error in setup_mode_middleware: {e}"}

#     return response


# Add startup events
@app.on_event("startup")
async def startup_event():
    print(f"[CORE] Starting up health service check for credserver")
    start_health_check_scheduler()


# Add a shutdown event to dump the merkle tree
@app.on_event("shutdown")
async def shutdown_event():
    print(f"[CORE] Shutting down merkle tree.")
    # Save the merkle tree to a file
    merkleCore.save_tree_to_file("merkle_tree.pkl")
    print(f"[CORE] Shutting down SMT.")
    smtCore.save_tree_to_file("smt.pkl")
    shutdown_scheduler()


# Add a redirect middleware for invalid JWT, this will redirect to the login page at "/"
# @app.middleware("http")
# async def redirect_invalid_jwt(request: Request, call_next):
#     try:
#         # print(f"JWT_MIDDLEWARE: Verifying JWT")
#         if debug >= 6:
#             print(f"JWT_MIDDLEWARE: Request URL: {request.url}")
#         await verify_jwt(request)
#     except HTTPException as e:
#         if e.status_code == 401:
#             print(f"JWT_MIDDLEWARE: Caught a 401. Redirecting to /")
#     return await call_next(request)


# Load routes
app.include_router(auth.router, prefix=f"/auth/{API_VERSION}", tags=["Auth"])
app.include_router(user.router, prefix=f"/user/{API_VERSION}", tags=["User"])
app.include_router(admin.router, prefix=f"/admin/{API_VERSION}", tags=["Admin"])
app.include_router(merkle.router, prefix=f"/merkle/{API_VERSION}", tags=["Merkle"])
app.include_router(
    sparse_merkle.router, prefix=f"/sparse_merkle/{API_VERSION}", tags=["Spare Merkle"]
)
app.include_router(
    blockchain.router, prefix=f"/blockchain/{API_VERSION}", tags=["Blockchain"]
)
app.include_router(setup.router, prefix=f"/setup/{API_VERSION}", tags=["Setup"])
app.include_router(
    accumulator.router, prefix=f"/accumulator/{API_VERSION}", tags=["Accumulator"]
)
# app.include_router(onboarding.router, prefix=f"/onboarding/{API_VERSION}", tags=["Onboarding"])


# root endpoint
@app.get("/")
def root():
    return JSONResponse(
        content={
            "message": "Connector running! Visit /docs for API documentation.",
        }
    )


# return env var
@app.get("/env")
def get_env(settings: settings_dependency):
    return JSONResponse(content=settings.dict())
