from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from .api.v1 import admin, auth, blockchain, onboarding, user
from .utils.core_utils import settings_dependency, verify_jwt

app = FastAPI()
debug = settings_dependency().DEBUG

# CORS Middleware
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add a redirect middleware for invalid JWT, this will redirect to the login page at "/"
@app.middleware("http")
async def redirect_invalid_jwt(request: Request, call_next):
    try:
        # print(f"JWT_MIDDLEWARE: Verifying JWT")
        if debug >= 6:
            print(f"JWT_MIDDLEWARE: Request URL: {request.url}")
        await verify_jwt(request)
    except HTTPException as e:
        if e.status_code == 401:
            print(f"JWT_MIDDLEWARE: Caught a 401. Redirecting to /")
    return await call_next(request)


# Load routes
API_VERSION = "v1"
app.include_router(auth.router, prefix=f"/auth/{API_VERSION}", tags=["Auth"])
app.include_router(user.router, prefix=f"/user/{API_VERSION}", tags=["User"])
app.include_router(admin.router, prefix=f"/admin/{API_VERSION}", tags=["Admin"])
app.include_router(
    blockchain.router, prefix=f"/blockchain/{API_VERSION}", tags=["Blockchain"]
)
app.include_router(onboarding.router, prefix=f"/onboarding/{API_VERSION}", tags=["Onboarding"])


# return env var
@app.get("/env")
def get_env(settings: settings_dependency):
    return JSONResponse(content=settings.dict())
