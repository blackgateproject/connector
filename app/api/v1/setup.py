from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from supabase import Client, create_client

from ...utils.core_utils import setup_state, save_setup_state

# Initialize the API router
router = APIRouter()

@router.post("/setup")
async def setup(admin_did: str):
    if setup_state["is_setup_completed"]:
        raise HTTPException(status_code=400, detail="Setup has already been completed.")

    # Save admin DID to state.json
    setup_state["admin_did"] = admin_did
    setup_state["is_setup_completed"] = True
    save_setup_state(setup_state)

    # Update Supabase table
    # (Assuming you have a function to update the Supabase table)
    # update_supabase_setup_state(admin_did, True)

    return {"message": "Setup completed successfully."}
