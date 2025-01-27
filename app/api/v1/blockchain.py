import json
from datetime import datetime, timedelta, timezone, tzinfo

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ...utils.ipfs_utils import add_file_to_ipfs, get_file_from_ipfs
from ...utils.core_utils import settings_dependency, verify_jwt
from ...utils.web3_utils import (
    getContract,
    getContractZKsync,
    getCurrentAccumulator,
    issue_did,
    issue_vc,
    recalcAccumulator,
    setAccumulator,
    storeDIDonBlockchain,
    storeVCOnBlockchain,
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
    contract = getContractZKsync("DIDRegistry")
    contract += getContractZKsync("RSAAccumulator")
    contract += getContractZKsync("VerifiableCredentialManager")
    return {"contract": contract}


@router.get("/currentAccumulator")
async def current_accumulator():
    """
    Get Current Accumulator
    """
    accumulatorValue = getCurrentAccumulator()

    # Return the accumulator in a JSON response
    return JSONResponse(content={"Accumulator": accumulatorValue}, status_code=200)


@router.get("/issueDID")
async def issueDid():
    """
    Issue a DID
    """
    jwk, did = await issue_did()
    jwkJSON = json.loads(jwk)
    cid, tx = await storeDIDonBlockchain(did, jwkJSON.get("x"))
    print(f"[issueDid()] CID: {cid} \nTX: {tx}")
    # Create a JSON object with the DID, cid and tx
    response = {
        "jwk": jwkJSON,
        "did": did,
        "cid": cid,
        "tx": tx,
    }

    return JSONResponse(content=response, status_code=200)


@router.post("/issueVC")
async def issueVC(
    request: Request,
    settings: settings_dependency,
):
    """
    Issue a VC and sign it based on the recieved DID
    """
    body = await request.json()
    jwk = body["jwk"]
    did = body["did"]
    user_uuid = body["uuid"]

    signed_vc = await issue_vc(did, jwk, user_uuid)
    print(f"Signed VC: \n{signed_vc}")

    cid, tx = await storeVCOnBlockchain(did, signed_vc)

    response = {
        "vc": signed_vc,
        "cid": cid,
        "tx": tx,
    }

    return JSONResponse(content=response, status_code=200)


@router.get("/testUpdateACC")
async def updateAcc():
    """
    Update the Accumulator
    """
    accumulator_result = await recalcAccumulator()

    return JSONResponse(
        content={"Message": "Accumulator Updated", "Result": accumulator_result},
        status_code=200,
    )
