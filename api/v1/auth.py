import datetime
import json
import random
import test
import time
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Form
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from supabase import AuthApiError
from supabase.client import Client, create_client

from ...credential_service.credservice import (
    issue_credential,
    resolve_did,
    verify_credential,
)
from ...models.requests import HashProof
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
    User self-generates a DID & sends it here to be verified from an admin controller
    Takes didString
    Request body should contain formData & networkInfo
    formData: {did, alias, selectedRole, firmwareVersion}
    networkInfo: {user_agent, user_language, location_lat, location_long, ip_address}
    :param request:
    :return:
    """
    body = await request.json()
    formData = body.get("formData")
    networkInfo = body.get("networkInfo")
    # Print the request body
    if debug:
        # print(f"Recieved Data: {body}")
        print(f"Recieved Data: {formData}")
        print(f"Recieved Data: {networkInfo}")

    # Add details to supabase table "requests"
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )
    if supabase:
        try:

            test_mode = (
                formData.get("testMode")
                if formData.get("testMode") is not None
                else False
            )

            # # For device role, approve automatically only if not in test mode
            request_status = (
                "approved"
                if formData["selected_role"] == "device" and not test_mode
                else "pending"
            )

            request = (
                supabase.table("requests")
                .insert(
                    [
                        {
                            "did_str": formData["did"],
                            "form_data": formData,
                            "network_info": networkInfo,
                            "request_status": request_status,
                            "isVCSent": False,
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
    # return JSONResponse(content=credential, status_code=200)


@router.get("/poll/{did_str}")
async def pollRequestStatus(
    request: Request, settings: settings_dependency, did_str: str
):
    """
    Poll the request status from the supabase table "requests"
    :param request:
    :return:
    """
    # Print the request body
    if debug:
        print(f"Recieved Data: {did_str}")

    # Add details to supabase table "requests"
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )
    if supabase:
        try:
            # Fetch requests table from supabase
            request = (
                supabase.table("requests").select("*").eq("did_str", did_str).execute()
            )
            # Print the request data
            # if debug:
            #     print(f"Request Status: {request.data[0]}")

            if request.data:
                # Check if the request is approved but no VC has been sent yet
                if (
                    request.data[0]["request_status"] == "approved"
                    and request.data[0]["isVCSent"] == False
                ):
                    # Fetch user formData & networkInfo from supabase table "requests"
                    formData = request.data[0]["form_data"]
                    networkInfo = request.data[0]["network_info"]

                    # Add user to merkle tree
                    merkle_data = addUserToMerkle(
                        user=formData,
                        pw=networkInfo,
                    )

                    # Remove merkleRoot and merkleProof from merkle
                    merkle_data.pop("merkleRoot", None)
                    merkle_data.pop("userProof", None)

                    # Issue a credential based on data.
                    data = {
                        "formData": formData,
                        "networkInfo": networkInfo,
                        "ZKP": merkle_data,
                    }

                    verifiableCredential = await issue_credential(data)

                    # Update status to accepted, store VC, return the VC to the user
                    response = (
                        supabase.table("requests")
                        .update(
                            {
                                "isVCSent": True,
                                "verifiable_cred": verifiableCredential,
                                "updated_at": datetime.datetime.now().isoformat(),
                            }
                        )
                        .eq("did_str", formData.get("did"))
                        .execute()
                    )
                    print(
                        f"Request Data after status update to accepted: \n{response.data[0]['isVCSent']}"
                    )
                    returnResponse = {
                        "message": f"approved request for role {formData.get('selected_role')}",
                        "verifiable_credential": verifiableCredential,
                        "request_status": f"{request.data[0]['request_status']}",
                    }
                elif (
                    request.data[0]["request_status"] == "approved"
                    and request.data[0]["isVCSent"] == True
                ):
                    print(
                        f"User already added to merkle tree: {request.data[0]['isVCSent']}"
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
                print(f"No request found for this did_str")
                returnResponse = {
                    "message": f"No request found for this did_str",
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
async def verify_user(
    request: Request,
    settings: settings_dependency,
):
    """
    Verify user on the merkle tree.
    """
    total_start_time = time.time()
    # Get the request body
    body = await request.json()

    print(f"[verify_user()] Body: {body}")

    # Check if body is a string and parse it if needed
    if isinstance(body, str):
        body = json.loads(body)

    vc_data = body.get("credential")
    did = vc_data.get("credentialSubject").get("did")
    merkleHash = vc_data.get("credentialSubject").get("ZKP").get("userHash")
    # merkleProof = zkp.merkleProof

    print(f"[verify_user()] DID: {did}")
    print(f"[verify_user()] merkleHash: {merkleHash}")

    # Verify user on the merkle tree
    result = verifyUserOnMerkle(
        merkleHash,
    )

    print(f"[verify_user()] results: {result}")
    if result["valid_Offchain"] == False or result["valid_Onchain"] == False:
        message = "Problem with verification: "
        if result["valid_Offchain"] == False:
            message += "Offchain verification failed. "
        if result["valid_Onchain"] == False:
            message += "Onchain verification failed."
    else:
        message = "User verified on merkle tree"

    # If the user is valid on both chains, return an anon user with the did in options
    if result["valid_Offchain"] and result["valid_Onchain"]:
        # Create a supabase client
        supabase: Client = create_client(
            supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
        )
        testMode = (
            vc_data.get("credentialSubject").get("testMode")
            if vc_data.get("credentialSubject")
            else False
        )
        # Once created, attempt to fetch an anon user
        if supabase:
            try:
                # DO not return a session if in testmode
                if not testMode:
                    # Add the request to the supabase table
                    response = supabase.auth.sign_in_anonymously(
                        {
                            "options": vc_data,
                        }
                    )
                    print(f"Response[Parse for access TOken + refresh]: \n{response}")

                    if response.session:
                        access_token = response.session.access_token
                        refresh_token = response.session.refresh_token
                    else:
                        access_token = ""
                        refresh_token = ""
                else:
                    access_token = ""
                    refresh_token = ""
                    print(f"Test Mode: No access token returned")

                end_time = time.time()
                duration = end_time - total_start_time

                # Placeholder for supabase code to store the duration
                # supabase.table("request_durations").insert({"did": did, "duration": duration}).execute()
                response = (
                    supabase.table("login_events")
                    .insert(
                        {
                            "did_str": did,
                            "total_auth_duration": duration,
                            "local_auth_duration": result["auth_Offchain_duration"],
                            "onchain_auth_duration": result["auth_Onchain_duration"],
                        }
                    )
                    .execute()
                )
                print(f"Added login event to supabase: \n{response}")
            except Exception as e:
                print(f"[ERROR-Supabase]: {e}")
        else:
            raise Exception("[ERROR-Supabase]: Supabase client not created")

    return JSONResponse(
        content={
            "message": message,
            "results": result,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "duration": duration,
        }
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
    # did = body.get("did")

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_SERV_KEY
    )

    try:
        # Call the logout API for supabase as well
        supabase.auth.admin.sign_out(access_token)

        # # Remove the user from the logged_in_users list
        # for user in logged_in_users:
        #     if user.uuid == did:
        #         logged_in_users.remove(user)
        #         await log_user_action(did, "User logged out", settings, type="Logout")
        #         return JSONResponse(
        #             content={"authenticated": False, "message": "User logged out"},
        #             status_code=200,
        #         )
        return JSONResponse(
            content={"authenticated": False, "message": "User not found"},
            status_code=404,
        )
    except Exception as e:
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


"""
TEST ONLY FUNCTONS
"""


@router.get("/pollTest/{did_str}")
async def testAutoApproveReq(
    request: Request, settings: settings_dependency, did_str: str
):
    """
    TESTING ONLY, DISABLE WHEN DONE, will approve any request with the wallet address
    uses approval code from pollRequestStatus, will return the same response as pollRequestStatus

    """
    # Print the request body
    if debug:
        print(f"Recieved Data: {did_str}")

    # Add details to supabase table "requests"
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )
    if supabase:
        try:
            # Fetch requests table from supabase
            request = (
                supabase.table("requests").select("*").eq("did_str", did_str).execute()
            )
            # Print the request data
            # if debug:
            #     print(f"Request Status: {request.data[0]}")
            returnResponse = {
                "authenticated": False,
                "message": "No pending request found",
            }
            entry = None
            if request.data and request.data[0]["request_status"] != "approved":
                # Existing code to add user to merkle tree and update status
                # Update status to accepted
                # 1 in 10 chance to randomly reject the request
                status = "rejected" if random.randint(1, 10) == 1 else "approved"

                # Fetch user formData & networkInfo from supabase table "requests"
                formData = request.data[0]["form_data"]
                networkInfo = request.data[0]["network_info"]

                # Add user to merkle tree
                merkle_data = addUserToMerkle(
                    user=formData,
                    pw=networkInfo,
                )
                # Remove merkleRoot and merkleProof from merkle
                merkle_data.pop("merkleRoot", None)
                merkle_data.pop("userProof", None)

                # Issue a credential based on data.
                data = {
                    "formData": formData,
                    "networkInfo": networkInfo,
                    "ZKP": merkle_data,
                }
                verifiableCredential = await issue_credential(data)

                # Update status to accepted, store VC, return the VC to the user
                response = (
                    supabase.table("requests")
                    .update(
                        {
                            "isVCSent": True,
                            "verifiable_cred": verifiableCredential,
                            "request_status": status,
                        }
                    )
                    .eq("did_str", formData.get("did"))
                    .execute()
                )
                print(f"Added user to merkle tree: {entry}")
                print(
                    f"Request Data after status update to accepted: \n{response.data[0]['isVCSent']}"
                )

                returnResponse = {
                    "message": f"approved request for role {formData.get('selected_role')}",
                    "verifiable_credential": verifiableCredential,
                    "request_status": f"{request.data[0]['request_status']}",
                }
            elif request.data and request.data[0]["request_status"] == "approved":
                # Handle already approved case

                # Fetch existing proof for did from merkle table
                entry = (
                    supabase.table("requests")
                    .select("*")
                    .eq("did", request.data[0]["did_str"])
                    .execute()
                )
                print(f"Entry: {entry.data}")
                if entry.data:
                    entry = entry.data[0]
                    returnResponse = {
                        "message": f"approved request for role {formData.get('selected_role')}",
                        "verifiable_credential": request.data[0]["verifiable_cred"],
                        "request_status": f"{request.data[0]['request_status']}",
                    }
                returnResponse = {
                    "authenticated": True,
                    "message": "Request already approved",
                    "request_status": "approved",
                }

            return JSONResponse(
                content=returnResponse,
                status_code=200,
            )
        except Exception as e:
            print(f"Error: {e}")
            return JSONResponse(
                content={"authenticated": False, "error": str(e)}, status_code=500
            )

    #         if request.data:
    #             # Check if the request is approved but no ZKP has been sent yet
    #             if (
    #                 request.data[0]["request_status"] == "approved"
    #                 and request.data[0]["isVCSent"] == False
    #             ):
    #                 # Add user to merkle tree and return the proof
    #                 entry = addUserToMerkle(
    #                     request.data[0]["did_str"],
    #                     request.data[0]["verifiable_cred"],
    #                 )
    #                 print(f"Added user to merkle tree: {entry}")

    #                 print(
    #                     f"Request Data after approve: \n{request.data[0]['request_status']}"
    #                 )
    #                 # Update status to accepted
    #                 response = (
    #                     supabase.table("requests")
    #                     .update({"isVCSent": True, "verifiable_cred": None})
    #                     .eq("wallet_addr", did_str)
    #                     .execute()
    #                 )
    #                 print(
    #                     f"Request Data after status update to accepted: \n{response.data[0]['isVCSent']}"
    #                 )
    #                 returnResponse = {
    #                     "message": f"approved request for role {request.data[0]['selected_role']}",
    #                     "merkle_hash": entry["userHash"],
    #                     "merkle_proof": entry["userProof"],
    #                     "merkle_root": entry["merkleRoot"],
    #                     "tx_hash": entry["txHash"],
    #                     "request_status": f"{request.data[0]['request_status']}",
    #                 }
    #             elif (
    #                 request.data[0]["request_status"] == "approved"
    #                 and request.data[0]["isVCSent"] == True
    #             ):
    #                 print(
    #                     f"User already added to merkle tree: {request.data[0]['isVCSent']}"
    #                 )

    #                 returnResponse = {
    #                     "message": f"User already added to merkle tree",
    #                     "request_status": f"{request.data[0]['request_status']}",
    #                 }
    #             elif request.data[0]["request_status"] == "rejected":
    #                 print(f"Request Data: {request.data[0]['request_status']}")
    #                 returnResponse = {
    #                     "message": f"Request rejected",
    #                     "request_status": f"{request.data[0]['request_status']}",
    #                 }

    #             elif request.data[0]["request_status"] == "pending":
    #                 print(f"Request Data: {request.data[0]['request_status']}")
    #                 returnResponse = {
    #                     "message": f"Request pending",
    #                     "request_status": f"{request.data[0]['request_status']}",
    #                 }
    #         else:
    #             print(f"No request found for this wallet address")
    #             returnResponse = {
    #                 "message": f"No request found for this wallet address",
    #                 "request_status": "not_found",
    #             }

    #             return JSONResponse(content=returnResponse, status_code=404)
    #         print(f"Return Response: {returnResponse}")
    #         return JSONResponse(content=returnResponse, status_code=200)
    #     except Exception as e:
    #         print(f"Error: {e}")
    #         return JSONResponse(
    #             content={"authenticated": False, "error": str(e)}, status_code=500
    #         )
    # else:
    #     raise Exception("[ERROR]: Supabase client not created")
