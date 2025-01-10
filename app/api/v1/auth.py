from uuid import UUID

import didkit
from fastapi import APIRouter
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from supabase import AuthApiError
from supabase.client import Client, create_client

from ...models.user import User
from ...utils.pki_utils import (
    create_signing_challenge,
    sign_challenge,
    verify_signing_challenge,
)
from ...utils.utils import (
    extract_user_details_for_passwordless,
    extractUserInfo,
    log_user_action,
    settings_dependency,
)

# from ...utils.web3_utils import verify_identity_with_stateless_blockchain, verify_vc, verify_with_rsa_accumulator, get_did_from_registry

router = APIRouter()

# Global list to store logged-in users (Shift this to supabase DB eventually)
logged_in_users = []
challenges = {}


@router.get("/")
async def health_check():
    return "Reached Auth Endpoint, Router Auth is Active"


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

    # supabase = await supaClient(settings_dependency)
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )
    if supabase:
        try:
            session = supabase.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            # if debug:
            print(f"User Data: {session.user}")
            print(f"Session Data (Access Token): {session.session.access_token}")
            print(f"Session Data (Refresh Token): {session.session.refresh_token}")
            user_data = extractUserInfo(session)
            if any(UUID(user_data["id"]) == user.id for user in logged_in_users):
                raise Exception("User is already logged in")

            # Convert the user data to Pydantic User model
            user_instance = User(**user_data)

            # If not in the list, add the user to the list, If in the list raise an Exception
            for user in logged_in_users:
                if user_instance.id == user.id:
                    raise Exception("User is already logged in")
            logged_in_users.append(user_instance)

            # Print logged-in user information
            # if debug:
            #     print(f"Added user to local store: \n{user_instance}")

            await log_user_action(
                user_data["id"], "User logged in", settings, type="Login"
            )

            # Return authenticated response
            return JSONResponse(
                content={
                    "authenticated": True,
                    "role": email.split("@")[1].split(".")[0],
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
                        "role": email.split("@")[1].split(".")[0],
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
async def logout(request: Request, settings: settings_dependency):
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


@router.post("/request-signing-challenge")
async def request_signing_challenge(request: Request):
    """
    Generate a signing challenge for the client.
    """
    try:
        body = await request.json()
        print(f"Got Body:\n{body}")
        public_key_hex = body.get("public_key")
        print(f"Public Key Hex: {public_key_hex}")
        challenge = create_signing_challenge()
        print(f"Created Challenge:\n{challenge}")
        challenges[public_key_hex] = challenge
        return JSONResponse(content={"challenge": challenge}, status_code=200)
    except Exception as e:
        print(f"Error in request-signing-challenge: \n{str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/verify-signing-challenge")
async def verify_signing_challenge_endpoint(request: Request):
    """
    Verify the signing challenge response from the client.
    """
    try:
        body = await request.json()
        public_key_hex = body.get("public_key")
        signature = body.get("signature")
        challenge = body.get("challenge")
        print(f"Got Body:\n{body}")
        print(f"Public Key Hex: {public_key_hex}")
        print(f"Signature: {signature}")
        print(f"Challenge: {challenge}")
        if not challenge:
            return JSONResponse(
                content={"verified": False, "error": "No challenge found"},
                status_code=400,
            )

        verified = verify_signing_challenge(public_key_hex, challenge, signature)
        print(f"Verified: {verified}")
        if verified:
            del challenges[public_key_hex]  # Remove the challenge once verified
            return JSONResponse(content={"verified": True}, status_code=200)
        else:
            return JSONResponse(
                content={"verified": False, "error": "Verification failed"},
                status_code=400,
            )
    except Exception as e:
        print(f"Error in verify-signing-challenge: \n{str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/sign-challenge")
async def sign_challenge_endpoint(request: Request):
    """
    Sign the challenge on the server side.
    """
    try:
        body = await request.json()
        private_key_hex = body.get("private_key")
        challenge = body.get("challenge")
        print(f"Got Body:\n{body}")
        print(f"Private Key Hex: {private_key_hex}")
        print(f"Challenge: {challenge}")

        signature = sign_challenge(private_key_hex, challenge)
        print(f"Generated Signature: {signature}")

        return JSONResponse(content={"signature": signature}, status_code=200)
    except Exception as e:
        print(f"Error in sign-challenge: \n{str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)

@router.post("/get-uuid-and-2fa")
async def get_uuid_and_2fa(request: Request, settings: settings_dependency):
    body = await request.json()
    email = body.get("email")

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )

    try:
        # Get user_id and two_factor_auth from user_email_mapping view
        response = (
            supabase.table("user_email_mapping")
            .select("user_id, two_factor_auth")
            .eq("email", email)
            .single()
            .execute()
        )
        if not response.data:
            return JSONResponse(content={"error": "User not found"}, status_code=404)
        print(f"UUID and 2FA Query Response: {response.data}")
        uuid = response.data["user_id"]
        enabled2fa = response.data["two_factor_auth"]

        return JSONResponse(
            content={"uuid": uuid, "enabled2fa": enabled2fa}, status_code=200
        )
    except Exception as e:
        print(f"Error: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/set-2fa-state")
async def set_2fa_state(request: Request, settings: settings_dependency):
    """
    A 2FA enabled user is requesting to login, send a 2FA challenge
    """
    body = await request.json()
    uuid = body.get("uuid")
    state = body.get("state")

    print(f"Got UUID: {uuid}")
    print(f"Got State: {state}")
    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )

    try:
        response = (
            supabase.table("user_keys")
            .update({"sessionRequest": state})
            .eq("user_id", uuid)
            .execute()
        )

        print(f"Response: {response}")

        if response.data:
            return JSONResponse(
                content={"enabled2fa": "true" if state else "false"},
                status_code=200,
            )
        else:
            return JSONResponse(content={"enabled2fa": False}, status_code=200)
    except Exception as e:
        print(f"Error: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/query-2fa-session")
async def query_2fa_session(request: Request, settings: settings_dependency):
    body = await request.json()
    private_key = body.get("private_key")
    public_key = body.get("public_key")

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )

    try:
        response = (
            supabase.table("user_keys")
            .select("*")
            .eq("public_key", public_key)
            .single()
            .execute()
        )

        # if the sessionRequest is true, then the user is requesting to login and a 2FA challenge is sent

        if response.data:
            return JSONResponse(
                content={"sessionRequest": response.data["sessionRequest"]},
                status_code=200,
            )
        else:
            return JSONResponse(content={"sessionRequest": False}, status_code=200)
    except Exception as e:
        print(f"Error: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/2fa-login")
async def twofa_login(request: Request, settings: settings_dependency):
    """
    Since the user has accepted the request, they can now login, set isLoginAccepted in user_keys to true, the user will send their uuid
    """

    body = await request.json()
    uuid = body.get("uuid")

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )

    try:
        response = (
            supabase.table("user_keys")
            .update({"isLoginAccepted": True})
            .eq("user_id", uuid)
            .execute()
        )

        if response.data:
            return JSONResponse(
                content={"isLoginAccepted": True},
                status_code=200,
            )
        else:
            return JSONResponse(content={"isLoginAccepted": False}, status_code=200)
    except Exception as e:
        print(f"Error: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/2fa-frontend-check")
async def twofa_loggedin(request: Request, settings: settings_dependency):
    """
    Now that the user has set isLoginAccepted to true, the frontend will check if the user has logged in
    """

    body = await request.json()
    uuid = body.get("uuid")

    supabase: Client = create_client(
        supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
    )

    try:
        response = (
            supabase.table("user_keys")
            .select("isLoginAccepted")
            .eq("user_id", uuid)
            .single()
            .execute()
        )

        if response.data:
            # Set isLoginAccepted to false after the frontend has checked
            response = (
                supabase.table("user_keys")
                .update({"isLoginAccepted": False})
                .eq("user_id", uuid)
                .execute()
            )

            return JSONResponse(
                content={"isLoginAccepted": response.data["isLoginAccepted"]},
                status_code=200,
            )
        else:
            return JSONResponse(content={"isLoginAccepted": False}, status_code=200)
    except Exception as e:
        print(f"Error: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


# @router.post("/passwordless-login")
# async def passwordless_login(request: Request, settings: settings_dependency):
#     """
#     Passwordless login using W3C compliant DID and Verifiable Credentials.
#     """
#     body = await request.json()
#     did = body.get("did")
#     proof = body.get("proof")
#     context = body.get("context")
#     issuance_date = body.get("issuance_date")

#     supabase: Client = create_client(
#         supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_ANON_KEY
#     )

#     try:
#         user_response = supabase.auth.get_user_by_did(did)
#         user = user_response.user
#         user_details = extract_user_details_for_passwordless(user)

#         vc = {
#             "@context": context,
#             "type": ["VerifiableCredential"],
#             "issuer": did,
#             "issuanceDate": issuance_date,
#             "credentialSubject": {"id": user_details["id"], "proof": proof},
#         }

#         if verify_vc(vc):
#             await log_user_action(
#                 user_details["id"], "Passwordless login", settings, type="Login"
#             )
#             return JSONResponse(
#                 content={
#                     "authenticated": True,
#                     "user": user_details,
#                 },
#                 status_code=200,
#             )
#         else:
#             return JSONResponse(
#                 content={"authenticated": False, "error": "Invalid proof"},
#                 status_code=401,
#             )
#     except Exception as e:
#         return JSONResponse(
#             content={"authenticated": False, "error": str(e)}, status_code=500
#         )


# @router.post("/verify-identity")
# async def verify_identity(request: Request):
#     data = await request.json()
#     user = data.get("user")
#     identity_credential = data.get("identity_credential")
#     result = verify_identity_with_stateless_blockchain(user, identity_credential)
#     return JSONResponse(content={"result": result}, status_code=200)


# @router.post("/verify-rsa")
# async def verify_rsa(request: Request):
#     data = await request.json()
#     base = data.get("base")
#     e = data.get("e")
#     result = verify_with_rsa_accumulator(base, e)
#     return JSONResponse(content={"result": result}, status_code=200)


# @router.get("/get-did/{controller}")
# async def get_did(controller: str):
#     did = get_did_from_registry(controller)
#     return JSONResponse(content={"did": did}, status_code=200)
