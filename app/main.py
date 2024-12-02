import os
from functools import lru_cache

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing_extensions import Annotated

from .api.v1 import admin, auth, user
from .core.config import Settings
from .utils.utils import get_settings_dependency

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
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(user.router, prefix="/user", tags=["User"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])


# return env var
@app.get("/env")
def get_env(settings: get_settings_dependency):
    return JSONResponse(content=settings.dict())
