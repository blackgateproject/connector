"""
Refactored setup API endpoints with better error handling.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from ...credential_service.credservice import health_check
from ...utils.core_utils import save_setup_state, setup_state

router = APIRouter()


@router.get("/")
async def get_setup_status():
    """Get current setup status."""
    return setup_state.get("is_setup_completed", False)


@router.post("/")
async def complete_setup(admin_did: str):
    """Complete the initial setup process."""
    if setup_state.get("is_setup_completed", False):
        raise HTTPException(status_code=400, detail="Setup has already been completed.")

    try:
        # Save admin DID to state.json
        setup_state["admin_did"] = admin_did
        setup_state["is_setup_completed"] = True
        save_setup_state(setup_state)

        return {"message": "Setup completed successfully."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error completing setup: {str(e)}")


@router.get("/credential-service-healthcheck")
async def credential_service_healthcheck():
    """Check the health of the credential service."""
    try:
        result = await health_check()
        if not result:
            raise HTTPException(
                status_code=503, detail="Credential service is not responding"
            )
        return result

    except ConnectionError:
        raise HTTPException(
            status_code=503, detail="Cannot connect to credential server"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error connecting to credential service: {str(e)}"
        )
