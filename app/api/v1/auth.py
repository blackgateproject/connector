from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse
from supabase import Client, create_client
from pydantic import EmailStr
import os
from uuid import UUID

router = APIRouter()
logged_in_users = []  # Local store for logged-in users


@router.post("/functions/v1/verifyUser/")
async def verify_user(request: Request):
    return "Welcome to the verify user endpoint!"