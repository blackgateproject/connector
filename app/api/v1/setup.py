from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from supabase import Client, create_client

from ...credential_service.credservice import health_check
from ...utils.core_utils import save_setup_state, setup_state

router = APIRouter()


@router.get("/")
async def get_setup_status():
    if setup_state["is_setup_completed"]:
        return True
    else:
        return False


@router.post("/")
async def set_setup_true(admin_did: str):
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


@router.get("/credential-service-healthcheck")
async def credential_service_healthcheck():
    """
    Check the health of the credential service.
    """
    try:
        result = await health_check()
        if not result:
            raise ConnectionError
    except ConnectionError as e:
        print(f"Cannot Connect to Credential Server")
    except Exception as e:
        print(f"[credential_service_healthcheck()] Exception: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Error connecting to credential service: {str(e)}"
        )
