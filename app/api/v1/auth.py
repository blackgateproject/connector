from uuid import UUID

import didkit
from fastapi import APIRouter, Depends
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from supabase import AuthApiError
from supabase.client import Client, create_client

from ...models.user import User
from ...utils.core_utils import (
    extract_user_details_for_passwordless,
    extractUserInfo,
    log_user_action,
    settings_dependency,
    verify_jwt,
)
from ...utils.web3_utils import addUserToMerkle, verifyUserOnMerkle

router = APIRouter()

debug = settings_dependency().DEBUG

# Global list to store logged-in users (Shift this to supabase DB eventually)
logged_in_users = []
challenges = {}


@router.get("/")
async def health_check():
    return "Reached Auth Endpoint, Router Auth is Active"


@router.post("/register")
async def register(request: Request, settings: settings_dependency):
    """
    User self-generates a DID, signs a VC with it and sends it here to be verified
    Takes wallet_address, didString, verifiableCredential
    :param request:
    :return:
    """
    body = await request.json()
    wallet_address = body.get("wallet_address")
    didString = body.get("didStr")
    verifiableCredential = body.get("verifiableCredential")
    usernetwork_info = body.get("usernetwork_info")
    # request_status = body.get("role_status")
    requested_role = body.get("requested_role")
    # Print the request body
    if debug:
        print(f"Recieved Data: {body}")

    # Add details to supabase table "requests"
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )
    if supabase:
        try:
            # Add the request to the supabase table
            request = (
                supabase.table("requests")
                .insert(
                    [
                        {
                            "wallet_addr": wallet_address,
                            "did_str": didString,
                            "verifiable_cred": verifiableCredential,
                            "usernetwork_info": usernetwork_info,
                            "request_status": "pending",
                            "requested_role": requested_role,
                            "isZKPSent": False,
                        }
                    ]
                )
                .execute()
            )
            # Print the request data
            if debug:
                print(f"Request Data: {request.data}")

            # Return authenticated response
            return JSONResponse(
                content={"authenticated": True, "message": "Request added to DB"},
                status_code=200,
            )
        except Exception as e:
            print(f"Error: {e}")
            return JSONResponse(
                content={"authenticated": False, "error": str(e)}, status_code=500
            )
    else:
        raise Exception("[ERROR]: Supabase client not created")


@router.get("/poll/{wallet_address}")
async def pollRequestStatus(
    request: Request, settings: settings_dependency, wallet_address: str
):
    """
    Poll the request status from the supabase table "requests"
    :param request:
    :return:
    """
    # Print the request body
    if debug:
        print(f"Recieved Data: {wallet_address}")

    # Add details to supabase table "requests"
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )
    if supabase:
        try:
            # Fetch requests table from supabase
            request = (
                supabase.table("requests")
                .select("*")
                .eq("wallet_addr", wallet_address)
                .execute()
            )
            # Print the request data
            if debug:
                print(f"Request Status: {request.data[0]}")

            if request.data:
                # Check if the request is approved but no ZKP has been sent yet
                if (
                    request.data[0]["request_status"] == "approved"
                    and request.data[0]["isZKPSent"] == False
                ):
                    # Add user to merkle tree and return the proof
                    entry = addUserToMerkle(
                        request.data[0]["did_str"],
                        request.data[0]["verifiable_cred"],
                    )
                    print(f"Added user to merkle tree: {entry}")

                    print(
                        f"Request Data after approve: \n{request.data[0]['request_status']}"
                    )
                    # Update status to accepted
                    response = (
                        supabase.table("requests")
                        .update({"isZKPSent": True, "verifiable_cred": None})
                        .eq("wallet_addr", wallet_address)
                        .execute()
                    )
                    print(
                        f"Request Data after status update: \n{response.data[0]['isZKPSent']}"
                    )
                    returnResponse = {
                        "message": f"approved request for role {request.data[0]['requested_role']}",
                        "merkle_hash": entry["userHash"],
                        "merkle_proof": entry["userProof"],
                        "merkle_root": entry["merkleRoot"],
                        "tx_hash": entry["txHash"],
                        "request_status": f"{request.data[0]['request_status']}",
                    }
                elif (
                    request.data[0]["request_status"] == "approved"
                    and request.data[0]["isZKPSent"] == True
                ):
                    print(
                        f"User already added to merkle tree: {request.data[0]['isZKPSent']}"
                    )

                    returnResponse = {
                        "message": f"User already added to merkle tree",
                        "request_status": f"{request.data[0]['request_status']}",
                    }
                elif request.data[0]["request_status"] == "rejected":
                    print(f"Request Data: {request.data[0]['request_status']}")
                    returnResponse = {
                        "message": f"Request rejected",
                        "request_status": f"{request.data[0]['request_status']}",
                    }

                elif request.data[0]["request_status"] == "pending":
                    print(f"Request Data: {request.data[0]['request_status']}")
                    returnResponse = {
                        "message": f"Request pending",
                        "request_status": f"{request.data[0]['request_status']}",
                    }
            else:
                print(f"No request found for this wallet address")
                returnResponse = {
                    "message": f"No request found for this wallet address",
                    "request_status": "not_found",
                }

                return JSONResponse(content=returnResponse, status_code=404)
            print(f"Return Response: {returnResponse}")
            return JSONResponse(content=returnResponse, status_code=200)
        except Exception as e:
            print(f"Error: {e}")
            return JSONResponse(
                content={"authenticated": False, "error": str(e)}, status_code=500
            )
    else:
        raise Exception("[ERROR]: Supabase client not created")


# Using request.json() to get the request body, forces async to be used. Need to
# ensure this is optimized to be non-blocking
#


@router.post("/verify")
async def verifyMerkle(request: Request, settings: settings_dependency):
    """
    Verify the user on the merkle tree
    NOTE:: This should just verify the tx output onchain
           doing it offchain for now
    :param request:
    :return:
    """
    body = await request.json()
    didString = body.get("didStr")
    verifiableCredential = body.get("verifiableCredential")
    merkle_hash = body.get("merkle_hash")
    merkle_proof = body.get("merkle_proof")

    # Print the request body
    if debug:
        print(f"Recieved Data: {body}")

    # Verify the user on the merkle tree
    entry = verifyUserOnMerkle(
        didString,
        verifiableCredential,
        # didString, verifiableCredential, merkle_hash, merkle_proof
    )
    if entry:
        return JSONResponse(
            content={
                "verified": True,
                "message": "User verified",
                "entry": entry,
            },
            status_code=200,
        )
    else:
        return JSONResponse(
            content={"verified": False, "message": "User not verified"}, status_code=400
        )


@router.post("/logout")
async def logout(
    request: Request, settings: settings_dependency, _: dict = Depends(verify_jwt)
):
    """
    Log the user out and remove the user from the logged_in_users list
    :param request:
    :return:
    """
    body = await request.json()
    access_token = body.get("access_token")
    uuid = body.get("uuid")

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_SERV_KEY
    )

    try:
        # Call the logout API for supabase as well
        supabase.auth.admin.sign_out(access_token)

        # Remove the user from the logged_in_users list
        for user in logged_in_users:
            if user.uuid == uuid:
                logged_in_users.remove(user)
                await log_user_action(uuid, "User logged out", settings, type="Logout")
                return JSONResponse(
                    content={"authenticated": False, "message": "User logged out"},
                    status_code=200,
                )
        return JSONResponse(
            content={"authenticated": False, "message": "User not found"},
            status_code=404,
        )
    except Exception as e:
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )
