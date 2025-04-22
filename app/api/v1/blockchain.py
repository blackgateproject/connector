import json
from datetime import datetime, timedelta, timezone, tzinfo

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...utils.core_utils import settings_dependency, verify_jwt
from ...utils.web3_utils import (  # issue_did,; issue_vc,; storeDIDonBlockchain,; storeVCOnBlockchain,
    getContractZKsync,
    w3,
)

# Initialize the API router
router = APIRouter()


# WARN:: DID For the backend is currently hardcoded in .env to
#
#        "issuer": "did:key:z6Mkee1uJkt9t2gtywnoERjzzaaYqqP4cC2qWukC6fmXZtDm"
#         "jwk":{
#                   "kty": "OKP",
#                   "crv": "Ed25519",
#                   "x": "AsFlxbPSma9sdVZoMnEuR1a998IwHi2XyxD5I1ICiHA",
#                   "d": "08GdLR7wTCCxoQdV5xSSS-0a5qo503aDOoddlRyLKIg",
#                  }


@router.get("/")
async def health_check():
    """
    Blockchain Endpoint Health Check
    """
    return "Reached Blockchain Endpoint, Router Blockchain is Active"


@router.get("/contracts-test")
async def contract_test():
    """
    Test if contracts can be fetched from /blockchain
    """
    # Retrieve and concatenate contract information for multiple contracts
    contract = getContractZKsync("Merkle")
    return {"contract": contract}


# @router.get("/issueDID")
# async def issueDid():
#     """
#     Issue a DID
#     """
#     jwk, did = await issue_did()
#     jwkJSON = json.loads(jwk)
#     cid, tx = await storeDIDonBlockchain(did, jwkJSON.get("x"))
#     print(f"[issueDid()] CID: {cid} \nTX: {tx}")
#     # Create a JSON object with the DID, cid and tx
#     response = {
#         "jwk": jwkJSON,
#         "did": did,
#         "cid": cid,
#         "tx": tx,
#     }

#     return JSONResponse(content=response, status_code=200)


# @router.post("/issueVC")
# async def issueVC(
#     request: Request,
#     settings: settings_dependency,
# ):
#     """
#     Issue a VC and sign it based on the recieved DID
#     """
#     body = await request.json()
#     jwk = body["jwk"]
#     did = body["did"]
#     user_uuid = body["uuid"]

#     signed_vc = await issue_vc(did, jwk, user_uuid)
#     print(f"Signed VC: \n{signed_vc}")

#     cid, tx = await storeVCOnBlockchain(did, signed_vc)

#     response = {
#         "vc": signed_vc,
#         "cid": cid,
#         "tx": tx,
#     }

#     return JSONResponse(content=response, status_code=200)


# @router.get("/resolveDID/{did}")
# async def resolve_did_endpoint(did: str):
#     """
#     Resolve a DID document and sign a VC
#     """
#     try:
#         # Generate didDoc
#         async def resolve_did(did):
#             return await didkit.resolve_did(did, "{}")

#         did_doc = await resolve_did(did)
#         did_doc_json = json.loads(did_doc)
#         # print(f"Resolved DID Document: {did_doc_json}\n")

#         # Sign VC
#         credential = {
#             "@context": ["https://www.w3.org/2018/credentials/v1"],
#             "type": ["VerifiableCredential"],
#             "issuer": did,
#             "credentialSubject": {"id": "did:example:123"},
#             "issuanceDate": datetime.utcnow().isoformat() + "Z",
#         }

#         print(f"[/resolveDID/{did}] Credential: {credential}")
#         proof_options = json.dumps(
#             {
#                 "proofPurpose": "assertionMethod",
#                 "verificationMethod": f"{did}#controller",
#             }
#         )

#         print(f"[/resolveDID/{did}] Proof Options: {proof_options}")
#         response = {
#             "didDocument": did_doc_json,
#             "credential": credential,
#             "proof_options": json.loads(proof_options),
#         }

#         print(f"[/resolveDID/{did}] Response: {response}")

#         return JSONResponse(content=response, status_code=200)
#     except Exception as e:
#         print(f"[/resolveDID/{did}] Error: {e}")
#         return JSONResponse(content={"error": str(e)}, status_code=400)
