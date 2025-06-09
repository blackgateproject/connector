from typing import AsyncGenerator

import aiohttp
from fastapi import Depends
from fastapi.responses import JSONResponse

from ..utils.core_utils import settings_dependency

credential_service_url = settings_dependency().CRED_SERVER_URL


# async def get_session() -> AsyncGenerator[aiohttp.ClientSession, None]:
#     """
#     Create a session for making requests to the credential service.
#     """
#     print(f"[get_session()] Credential service URL: {credential_service_url}")

#     if not credential_service_url:
#         raise ValueError("[get_session()] Credential service URL is not set.")

#     session = aiohttp.ClientSession()


#     try:
#         yield session
#     finally:
#         await session.close()
async def health_check():
    """
    Ping the credential server to check if it is active
    """

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{credential_service_url}") as response:
                if response.status == 200:
                    return JSONResponse(
                        status_code=200,
                        content={"result": True, "response": await response.json()},
                    )
                else:
                    print(f"[health_check()] Response ERR: {await response.json()}")
                    raise Exception("Credential service is not healthy.")
    except Exception as e:
        print(f"[health_check()] Exception: {str(e)}")
        raise e


async def resolve_did(did: str):
    """
    Resolve a DID using the credential service.
    """

    try:
        # Validation Checks
        if not did:
            raise ValueError("[resolve_did()] DID must be passed")
        elif did == "":
            raise ValueError("[resolve_did()] DID cannot be empty")
        elif not did.startswith("did:ethr:blackgate"):
            raise ValueError("[resolve_did()] DID must start with 'did:ethr:blackgate'")

        # Client Setup
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{credential_service_url}/resolve-did-doc?did={did}"
            ) as response:
                # Return server response
                json_response = await response.json()
                if response.status == 200:
                    return json_response
                elif response.status >= 400 and response.status < 500:
                    print(f"[resolve_did()] NOT FOUND: {json_response}")
                    raise FileNotFoundError
                else:
                    print(f"[resolve_did()] Response ERR: {json_response}")
                    raise Exception("Credential service is not healthy.")
    # Error handling for invalid server config
    except Exception as e:
        print(f"[resolve_did()] Exception: {str(e)}")
        raise e


async def issue_credential(credential: dict):
    """
    Issue a credential using the credential service.
    """
    try:
        print(f"\n\nSending DATA FOR ISSUANCE\n\n{credential}")
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{credential_service_url}/issue-vc", json=credential
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    print(f"[issue_credential()] Response ERR: {response.json()}")
                    raise Exception("Credential service is not healthy.")
    except Exception as e:
        print(f"[issue_credential()] Exception: {str(e)}")
        raise e


async def verify_credential(credential: dict):
    """
    Verify a credential using the credential service.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{credential_service_url}/verify-vc", json=credential
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    print(f"[verify_credential()] Response ERR: {await response.json()}")
                    raise Exception("Credential service is not healthy.")
    except Exception as e:
        print(f"[verify_credential()] Exception: {str(e)}")
        raise e

async def verify_presentation(presentation: dict):
    """
    Verify a presentation using the credential service.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{credential_service_url}/verify-vp", json=presentation
            ) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status >= 400 and response.status < 500:
                    print(f"[verify_presentation()] NOT FOUND: {await response.json()}")
                    raise Exception("Credential service BAD: \nReturned: " + str(await response.json()))
                else:
                    # Handle unexpected status codes
                    response_json = await response.json()
                    print(f"[verify_presentation()] Response ERR: {response_json}")
                    raise Exception("Credential service is not healthy.\nReturned: " + str(response_json))
    except Exception as e:
        print(f"[verify_presentation()] Exception: {str(e)}")
        raise e