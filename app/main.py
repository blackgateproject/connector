from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.v1 import admin, auth, blockchain, user
from .utils.utils import settings_dependency

app = FastAPI()


# CORS Middleware
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load routes
API_VERSION = "v1"
app.include_router(auth.router, prefix=f"/auth/{API_VERSION}", tags=["Auth"])
app.include_router(user.router, prefix=f"/user/{API_VERSION}", tags=["User"])
app.include_router(admin.router, prefix=f"/admin/{API_VERSION}", tags=["Admin"])
app.include_router(
    blockchain.router, prefix=f"/blockchain/{API_VERSION}", tags=["Blockchain"]
)


# return env var
@app.get("/env")
def get_env(settings: settings_dependency):
    return JSONResponse(content=settings.dict())
