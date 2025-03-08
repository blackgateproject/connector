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
from ...utils.web3_utils import verifyUserOnMerkle

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
            request = supabase.table("requests").insert(
                [
                    {
                        "wallet_addr": wallet_address,
                        "did_str": didString,
                        "verifiable_cred": verifiableCredential,
                        "usernetwork_info": usernetwork_info,
                        "request_status": "pending",
                        "requested_role": requested_role
                    }
                ]
            ).execute()
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


# Using request.json() to get the request body, forces async to be used. Need to
# ensure this is optimized to be non-blocking
@router.post("/verify")
async def verify(request: Request, settings: settings_dependency):
    """
    Log the user in and return the user token along with refresh token
    :param request:
    :return:
    """
    body = await request.json()
    email = body.get("email")
    password = body.get("password")
    did = body.get("did")
    signedVc = body.get("signedVc")

    print(f"Email: {email}")
    print(f"Password: {password}")
    print(f"DID: {did}")
    print(f"Signed VC: {signedVc}")

    # supabase = await supaClient(settings_dependency)
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )
    if supabase:
        try:

            # Attempt the login with the email and password
            session = supabase.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            if debug >= 2:
                print(f"User Data: {session.user}")
                print(f"Session Data (Access Token): {session.session.access_token}")
                print(f"Session Data (Refresh Token): {session.session.refresh_token}")
            user_data = extractUserInfo(session)

            # UPDATE:: Move this to supabase when ready
            if any(UUID(user_data["id"]) == user.id for user in logged_in_users):
                raise Exception("User is already logged in")

            # Convert the user data to Pydantic User model
            user_instance = User(**user_data)

            # If not in the list, add the user to the list, If in the list raise an Exception
            # for user in logged_in_users:
            #     if user_instance.id == user.id:
            #         raise Exception("User is already logged in")
            # logged_in_users.append(user_instance)

            # # Print logged-in user information
            # if debug:
            #     print(f"Added user to local store: \n{user_instance}")

            await log_user_action(
                user_data["id"], "User logged in", settings, type="Login"
            )

            # Print user aud
            if debug >= 2:
                print(f"User Aud: {user_data['aud']}")

            # print user metadata from user_data dict
            print(f"User Metadata: {user_data["user_metadata"]}")

            # Some accounts do not have the role field set in user_metadata, assign them their email domain instead
            if not user_data["user_metadata"].get("role"):
                role = email.split("@")[1].split(".")[0]
            else:
                role = user_data["user_metadata"]["role"]
            # role = user_data.user_metadata.get("role")
            print(f"User Role: {role}")
            # Return authenticated response
            return JSONResponse(
                content={
                    "authenticated": True,
                    "role": role,
                    "uuid": user_data["id"],
                    "access_token": session.session.access_token,
                    "refresh_token": session.session.refresh_token,
                },
                status_code=200,
            )
        except AuthApiError as e:
            return JSONResponse(
                content={"authenticated": False, "error": str(e)}, status_code=401
            )
        except Exception as e:
            if "WinError 10061" in str(e):
                return JSONResponse(
                    content={
                        "authenticated": False,
                        "error": "Supabase docker image is down/not responding",
                    },
                    status_code=500,
                )
            # """
            # Elif seems wrong. The user is already logged in should be handled in the first if statement
            # """
            elif "User is already logged in" in str(
                e
            ):  # Check if the user is already logged in
                return JSONResponse(
                    content={
                        "authenticated": True,
                        "role": role,
                        "uuid": user_data["id"],
                        "error": "User is already logged in",
                        "access_token": session.session.access_token,
                        "refresh_token": session.session.refresh_token,
                    },
                    status_code=200,
                )
            return JSONResponse(
                content={"authenticated": False, "error": str(e)}, status_code=500
            )
    else:
        raise Exception("[ERROR]: Supabase client not created")


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
