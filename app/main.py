import pickle
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import HTTPException, RequestValidationError
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
from .utils.async_blockchain_multiworker import (
    initialize_blockchain_processor,
    shutdown_blockchain_processor,
)
from .utils.core_utils import settings_dependency, setup_state  # , verify_jwt

debug = settings_dependency().DEBUG
API_VERSION = "v1"

# Multi-worker configuration
import os

WORKER_COUNT = int(os.getenv("WORKER_COUNT", "1"))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
WORKER_ID = os.getenv("WORKER_ID", str(os.getpid()))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    worker_id = os.getenv("WORKER_ID", "main")
    print(f"[CORE] Starting FastAPI worker {worker_id}")
    print(f"[CORE] Starting up health service check for credserver")
    start_health_check_scheduler()

    print(f"[CORE] Starting multi-worker async blockchain processor")
    await initialize_blockchain_processor()

    # Initialize multi-worker proof systems if in multi-worker mode
    multi_worker_mode = os.getenv("MULTI_WORKER_MODE", "false").lower() == "true"
    if multi_worker_mode:
        print(f"[CORE] Initializing multi-worker proof systems (Worker: {worker_id})")

        # Import and initialize multi-worker cores
        from .core.multiworker_accumulator import (
            accumulatorCore as multiworker_accumulator,
        )
        from .core.multiworker_merkle import merkleCore as multiworker_merkle
        from .core.multiworker_smt import smtCore as multiworker_smt

        await multiworker_smt.initialize()
        await multiworker_merkle.initialize()
        await multiworker_accumulator.initialize()

        print(f"[CORE] Multi-worker proof systems initialized (Worker: {worker_id})")

    yield

    # Shutdown
    print(f"[CORE] Shutting down worker {worker_id}")
    if debug >= 3:
        print(f"[CORE] Shutting down merkle tree.")

    # Save trees (only from main worker to avoid conflicts)
    if worker_id == "main" or worker_id == "0":
        if multi_worker_mode:
            # Use multi-worker cores for saving
            from .core.multiworker_merkle import merkleCore as multiworker_merkle
            from .core.multiworker_smt import smtCore as multiworker_smt

            multiworker_merkle.save_tree_to_file("merkle_tree.pkl")
            if debug >= 3:
                print(f"[CORE] Shutting down SMT.")
            multiworker_smt.save_tree_to_file("smt.pkl")
        else:
            # Use original cores
            merkleCore.save_tree_to_file("merkle_tree.pkl")
            if debug >= 3:
                print(f"[CORE] Shutting down SMT.")
            smtCore.save_tree_to_file("smt.pkl")

    # Shutdown multi-worker proof systems
    if multi_worker_mode:
        print(f"[CORE] Shutting down multi-worker proof systems (Worker: {worker_id})")
        from .core.multiworker_accumulator import (
            accumulatorCore as multiworker_accumulator,
        )
        from .core.multiworker_merkle import merkleCore as multiworker_merkle
        from .core.multiworker_smt import smtCore as multiworker_smt

        await multiworker_smt.shutdown()
        await multiworker_merkle.shutdown()
        await multiworker_accumulator.shutdown()

    print(f"[CORE] Shutting down async blockchain processor")
    await shutdown_blockchain_processor()

    shutdown_scheduler()


app = FastAPI(lifespan=lifespan)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"message": "Validation error", "detail": str(exc)},
    )


# Health check endpoint
@app.get("/")
async def root():
    return RedirectResponse(url="/docs")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "worker_id": WORKER_ID}


# Include routers
app.include_router(auth.router, prefix=f"/auth/{API_VERSION}", tags=["auth"])
app.include_router(admin.router, prefix=f"/admin/{API_VERSION}", tags=["admin"])
app.include_router(user.router, prefix=f"/user/{API_VERSION}", tags=["user"])
app.include_router(setup.router, prefix=f"/setup/{API_VERSION}", tags=["setup"])
app.include_router(merkle.router, prefix=f"/merkle/{API_VERSION}", tags=["merkle"])
app.include_router(
    sparse_merkle.router, prefix=f"/sparse_merkle/{API_VERSION}", tags=["sparse_merkle"]
)
app.include_router(
    accumulator.router, prefix=f"/accumulator/{API_VERSION}", tags=["accumulator"]
)
app.include_router(
    blockchain.router, prefix=f"/blockchain/{API_VERSION}", tags=["blockchain"]
)

# Multi-worker startup
if __name__ == "__main__":
    import sys

    import uvicorn

    # Check if workers argument is provided
    workers = 5  # Default to 5 workers as requested
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        workers = int(sys.argv[1])

    print(f"🚀 Starting FastAPI with {workers} workers")
    print("⚠️  Multi-worker mode: Shared state will use Redis/Database")

    # Set environment variables for multi-worker support
    import os

    os.environ["MULTI_WORKER_MODE"] = "true"
    os.environ["BLOCKCHAIN_WORKERS"] = "3"
    os.environ["BLOCKCHAIN_BATCH_SIZE"] = "5"

    # Run with multiple workers
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        workers=workers,
        reload=False,  # Disable reload in multi-worker mode
        log_level="info",
    )
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


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    print(exc.errors())  # This prints all validation errors to the console
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


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


# Returns an IP address of the requestor
@app.get("/get-ip")
async def get_ip(request: Request):
    # Check 'X-Forwarded-For' for reverse proxies, ensure proxy is trusted
    forwarded = request.headers.get("X-Forwarded-For")
    ip = forwarded.split(",")[0] if forwarded else request.client.host
    return {"ip": ip}


# return env var
@app.get("/env")
def get_env(settings: settings_dependency):
    return JSONResponse(content=settings.model_dump())
