import json
from datetime import datetime, timedelta, timezone, tzinfo

import didkit
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

router = APIRouter()
@router.get("/")
async def health_check():
    """
    Onboarding Endpoint Health Check
    """
    return "Reached Onboarding Endpoint, Router Onboarding is Active"


@router.get("/generateMerkleProofs/{user_id}")
async def genMerkProofs(user_id: str):
    """
    Generate Merkle Proofs
    """

    # Ensure only onboard roles can access this endpoint
    # If they are users that need to be onboarded 
    #   - Frontend will handle wallet + keys creation, but the backend will handle the proofs
    #   - The backend will then send the proofs for user to store

    
    return "Generate Merkle Proofs"