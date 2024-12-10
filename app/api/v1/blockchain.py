import json
from datetime import datetime, timedelta, timezone, tzinfo

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ...utils.ipfs_utils import add_file_to_ipfs, get_file_from_ipfs
from ...utils.utils import settings_dependency
from ...utils.web3_utils import (
    getContract,
    getCurrentAccumulator,
    issue_did,
    issue_vc,
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


@router.get("/contract-test")
async def contract_test():
    """
    Test Contract Endpoint
    """
    # Retrieve and concatenate contract information for multiple contracts
    contract = getContract("DIDRegistry")
    contract += getContract("RSAAccumulator")
    contract += getContract("VerifiableCredentialManager")
    return {"contract": contract}


@router.get("/currentAccumulator")
async def current_accumulator():
    """
    Get Current Accumulator
    """
    # Retrieve contract address and ABI for RSAAccumulator
    contract_address, contract_abi = getContract("RSAAccumulator")

    # Create a contract instance using web3
    contract_instance = w3.eth.contract(address=contract_address, abi=contract_abi)

    # Call the getAccumulator function from the contract
    current_accumulator = contract_instance.functions.getAccumulator().call()

    # Convert the accumulator to a hexadecimal string
    current_accumulator = current_accumulator.hex()

    # Print the current accumulator for debugging purposes
    print(f"Current Accumulator: \n{current_accumulator}")

    # Return the accumulator in a JSON response
    return JSONResponse(content={"Accumulator": current_accumulator}, status_code=200)


@router.get("/issueDID")
async def issueDid():
    """
    Issue a DID
    """
    jwk, did = await issue_did()
    jwkJSON = json.loads(jwk)
    cid, tx = await storeDIDonBlockchain(did, jwkJSON.get("x"))

    # Create a JSON object with the DID, cid and tx
    response = {
        "jwk": jwkJSON,
        "did": did,
        "cid": cid,
        "tx": tx,
    }

    return JSONResponse(content=response, status_code=200)


@router.post("/issueVC")
async def issueVC(request: Request, settings: settings_dependency):
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


# Test Getting ACC Val
@router.get("/getAcc")
async def get_acc():
    """
    Get Current Accumulator
    """

    # Call the getAccumulator function from the contract
    current_accumulator = getCurrentAccumulator()

    return JSONResponse(content={"Accumulator": current_accumulator}, status_code=200)
