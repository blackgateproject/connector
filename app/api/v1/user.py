from fastapi import APIRouter
from fastapi.responses import JSONResponse
from supabase import Client, create_client
import os

router = APIRouter()


@router.get("/auth/v1/getUsers")
async def get_users():
    return "Welcome to the users endpoint!"
