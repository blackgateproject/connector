import asyncio
import datetime
import json
import random
import time
from calendar import c
from functools import lru_cache
from operator import ne
from types import NoneType
from typing import Annotated, Any, List, Optional, Tuple
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Form
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from ...core.config import Settings
from ...credential_service.credservice import (
    issue_credential,
    resolve_did,
    verify_credential,
    verify_presentation,
)
from ...models.requests import HashProof
from ...models.web3_creds import (
    FormData,
    NetworkInfo,
    VerifiableCredential,
    VerifiablePresentation,
)
from ...models.zkp import SMTMerkleProof
from ...utils.core_utils import (
    extract_user_details_for_passwordless,
    extractUserInfo,
    log_user_action,
    settings_dependency,
    verify_jwt,
)
from ...utils.web3_utils import (
    addUserToAccumulator,
    addUserToMerkle,
    addUserToSMT,
    addUserToSMTLocal,
    addUserToSMTOnChain,
    get_merkle_verifier,
    keccakHash,
    verifyUserOnAccumulator,
    verifyUserOnMerkle,
    verifyUserOnSMT,
)


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]
db_url = settings_dependency().SUPABASE_DB_URL

router = APIRouter()

debug = settings_dependency().DEBUG


def fetch_one(query: str, params: Optional[Tuple] = None) -> Optional[dict]:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            if row:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, row))
            return None


def fetch_all(query: str, params: Optional[Tuple] = None) -> list:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in rows]


def execute_query(query: str, params: Optional[Tuple] = None) -> int:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            affected = cur.rowcount
            conn.commit()
            return affected


def execute_returning(query: str, params: Optional[Tuple] = None) -> Optional[dict]:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            if row:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, row))
            return None


@router.get("/")
async def health_check():
    return "Reached Auth Endpoint, Router Auth is Active"


@router.post("/register")
async def register(formData: FormData, networkInfo: NetworkInfo) -> JSONResponse:
    # Debugging output
    if debug >= 0:
        print(f"Recieved Data: {formData}")
        print(f"Recieved Data: {networkInfo}")

    # Auto-approve all requests for devices or test_mode users/devices
    request_status = (
        "approved"
        if formData.selected_role == "device" and not formData.testMode
        else "pending"
    )

    # Compute the total time for creating the wallet
    total_time = int(formData.walletCreateTime) + int(formData.walletEncryptTime)

    # Prepare the data to be inserted into the requests table
    requests_data = {
        "did_str": formData.did,
        "form_data": formData.model_dump_json(),
        "network_info": networkInfo.model_dump_json(),
        "request_status": request_status,
        "isVCSent": False,
        "wallet_generate_time": formData.walletCreateTime,
        "total_time": total_time,
    }

    if debug >= 0:
        print(f"\n\nTimes: {formData.walletCreateTime}, {formData.walletEncryptTime}")

    # Prepare the SQL query to insert the request
    try:
        query = """
            INSERT INTO requests (did_str, form_data, network_info, request_status, "isVCSent", wallet_generate_time, total_time)
            VALUES (%(did_str)s, %(form_data)s, %(network_info)s, %(request_status)s, %(isVCSent)s, %(wallet_generate_time)s, %(total_time)s)
        """
        execute_query(query, requests_data)
        return JSONResponse(
            content={"authenticated": True, "message": "Request added to DB"},
            status_code=200,
        )
    except Exception as e:
        print(f"[ERROR] psycopg in /register encountered: {e}")
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


@router.get("/poll/{did_str}")
async def pollRequestStatus(did_str: str) -> JSONResponse:
    if debug >= 0:
        print(f"Recieved Data: {did_str}")

    try:
        query = "SELECT * FROM requests WHERE did_str = %s"
        rows = fetch_all(query, (did_str,))
        returnResponse = {}
        if rows:
            req = rows[0]

            # Load formData and networkInfo from supabase using Pydantic models
            if isinstance(req["form_data"], str):
                try:
                    req["form_data"] = FormData.model_validate_json(req["form_data"])
                except Exception as e:
                    print(f"Error parsing form_data: {e}")
                    req["form_data"] = json.loads(req["form_data"])
            elif isinstance(req["form_data"], dict):
                req["form_data"] = FormData.model_validate(req["form_data"])

            if isinstance(req["network_info"], str):
                try:
                    req["network_info"] = NetworkInfo.model_validate_json(
                        req["network_info"]
                    )
                except Exception as e:
                    print(f"Error parsing network_info: {e}")
                    req["network_info"] = json.loads(req["network_info"])
            elif isinstance(req["network_info"], dict):
                req["network_info"] = NetworkInfo.model_validate(req["network_info"])

            # If request status has been set to approved then issue the credential
            if req["request_status"] == "approved" and not req["isVCSent"]:
                formData: FormData = req["form_data"]
                networkInfo: NetworkInfo = req["network_info"]
                proof_type = formData.proof_type
                public_key = did_str.replace("did:ethr:blackgate:", "")
                proofs = None  # Track proofs only for SMT
                if proof_type == "smt":
                    # Add user to the Sparse Merkle Tree (SMT) locally
                    print(f"Poll (DEBUG): Adding user to SMT locally")
                    zkpData, proofs = addUserToSMTLocal(did_str=did_str)

                    print(
                        f"About to issue credential with data: {formData}, {networkInfo}, {zkpData}"
                    )
                    # Prepare the data for issuing the credential
                    data = {
                        "formData": formData.model_dump(),
                        "networkInfo": networkInfo.model_dump(),
                        "ZKP": zkpData,
                    }
                    print(f"Issuing credential")
                    # Issue the verifiable credential
                    verifiableCredential = await issue_credential(data)

                    # Keccak hash the VC
                    print(f"Keccak hashing the VC")
                    vcHash = await keccakHash(
                        json.dumps(verifiableCredential, sort_keys=True).encode("utf-8")
                    )

                    # Debug Statement
                    if debug >= 0:
                        print(f"VC Hash: {vcHash}")

                    # Send data onchain
                    print(f"Sending data onchain")
                    fog_node_publicKey = (
                        verifiableCredential.get("credential").get("issuer").get("id")
                    ).replace("did:ethr:blackgate:", "")

                    onChainResults = addUserToSMTOnChain(
                        merkleRoot=zkpData["merkleRoot"],
                        vc_hash=vcHash,
                        device_id=formData.device_id,
                        fog_node_pubkey=fog_node_publicKey,
                    )
                    print(f"OnChain Results: {onChainResults}")

                elif proof_type == "merkle":
                    merkle_data = addUserToMerkle(user=did_str, pw=public_key)
                elif proof_type == "accumulator":
                    merkle_data = addUserToAccumulator(did=did_str, vc=public_key)
                else:
                    merkle_data = {}

                print(f"Updating request status in Postgres")
                update_query = """
                    UPDATE requests
                    SET "isVCSent" = TRUE,
                        verifiable_cred = %s,
                        updated_at = %s
                    WHERE did_str = %s
                    RETURNING *
                """
                execute_query(
                    update_query,
                    (
                        json.dumps(verifiableCredential),
                        datetime.datetime.now().isoformat(),
                        formData.did,
                    ),
                )

                # Build the response, only include proofs if SMT
                returnResponse = {
                    "message": f"Request approved for role '{formData.selected_role}' using ZKP '{proof_type}'",
                    "verifiable_credential": verifiableCredential,
                    "request_status": f"{req['request_status']}",
                }
                if proof_type == "smt" and proofs is not None:
                    returnResponse["smt_proofs"] = proofs
            elif req["request_status"] == "approved" and req["isVCSent"]:
                # If the request is already approved and the VC is sent, return the verifiable credential
                returnResponse |= {
                    "message": f"User already added to ZKP module",
                    "request_status": f"{req['request_status']}",
                }
            elif req["request_status"] == "rejected":
                # If the request is rejected, return a rejection message
                returnResponse |= {
                    "message": f"Request rejected",
                    "request_status": f"{req['request_status']}",
                }
            elif req["request_status"] == "pending":
                # If the request is still pending, return a pending message
                returnResponse |= {
                    "message": f"Request pending",
                    "request_status": f"{req['request_status']}",
                }
        else:
            # If no request is found for the given did_str, return a not found message
            print(f"No request found for this did_str")
            returnResponse = {
                "message": f"No request found for this did_str",
                "request_status": "not_found",
            }
            return JSONResponse(content=returnResponse, status_code=404)
        print(f"Return Response: {returnResponse}")
        return JSONResponse(content=returnResponse, status_code=200)
    except Exception as e:
        print(f"[ERR: /poll/{did_str}] Error: {e}")
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


@router.post("/verify")
# Takes VP and optionally a MerkleProof
async def verify_user(verifiablePresentation: VerifiablePresentation) -> JSONResponse:
    """
    Verify user.
    It takes the VP, verifies it and then extracts the VC and verifies it after which the ZKP is finally verified
    IF proof type is SMT, then a MerkleProof is expected in the body.
    """
    total_start_time = time.time()

    # Verify the VP first
    vp_response = await verify_presentation(verifiablePresentation.serialize())
    if not vp_response.get("verified", False):
        return JSONResponse(
            content={"error": "Invalid Verifiable Presentation"}, status_code=400
        )
    print(f"\n\n[verify_user()] VP Response: {vp_response.get("verified")}")

    # print(f"[verify_user()] VCs in VP: {verifiablePresentation.verifiableCredential[0].model_dump()}")
    # print(f"[verify_user()] TYPEOF [VCs in VP]: {type(verifiablePresentation.verifiableCredential[0].model_dump())}")
    # print(f"[verify_user()] TYPEOF [VCs in VP]: {type(json.dumps(verifiablePresentation.verifiableCredential[0].model_dump()))}")
    # Verify the VC within the VP
    if vp_response.get("verified") == True:
        # Extract the first VC from the VP
        verifiableCredential: VerifiableCredential = (
            verifiablePresentation.verifiableCredential[0].serialize()
        )

        # Verify the VC using the credential service
        vc_response = await verify_credential({"credential": verifiableCredential})

        # Error response if not verified
        if not vc_response.get("verified", False):
            print(f"[verify_user()] VC Response: {vc_response.get("verified")}")
            return JSONResponse(
                content={"error": "Invalid Verifiable Credential"}, status_code=400
            )
        print(f"[verify_user()] VC Response: {vc_response.get("verified")}")
    else:
        print(f"\n\n\nVP NOT VERIFIED\n\n\n")

    # Extract the credentialSubject from the VC
    credentialSubject = verifiableCredential.get("credentialSubject")
    if not credentialSubject:
        return JSONResponse(
            content={"error": "Missing 'credentialSubject' in Verifiable Credential."},
            status_code=400,
        )

    # All 3 proof types require these
    did = credentialSubject.get("did")
    proof_type = credentialSubject.get("proof_type")
    cred_ZKP = credentialSubject.get("ZKP")

    # ZKP handling
    if proof_type == "merkle":
        # Handle Merkle proof type
        merkleHash = cred_ZKP.get("userHash")
        txHash = cred_ZKP.get("txHash")
        print(f"[verify_user()] txHash: {txHash}")
        print(f"[verify_user()] merkleHash: {merkleHash}")
    elif proof_type == "smt":
        # Handle Sparse Merkle Tree (SMT) proof type
        index = cred_ZKP.get("userIndex")
        if index is None:
            return JSONResponse(
                content={"error": "Missing 'index' in ZKP for SMT proof."},
                status_code=400,
            )
        merkleHash = cred_ZKP.get("userHash")
        print(f"[verify_user()] index: {index}")
        print(f"[verify_user()] merkleHash: {merkleHash}")
    elif proof_type == "accumulator":
        # Handle Accumulator proof type
        data_hash = cred_ZKP.get("dataHash")
        acc_val = cred_ZKP.get("accVal")
        proof = cred_ZKP.get("proof")
        prime = cred_ZKP.get("prime")
        print(f"[verify_user()] data_hash: {data_hash}")
        print(f"[verify_user()] acc_val: {acc_val}")
        print(f"[verify_user()] proof: {proof}")
        print(f"[verify_user()] prime: {prime}")
    else:
        raise Exception(f"[ERROR]: Invalid proof type: {proof_type}")

    print(f"[verify_user()] Proof Type: {proof_type}")
    print(f"[verify_user()] DID: {did}")

    access_token = ""
    refresh_token = ""
    duration = 0

    if proof_type == "smt":
        # Fetch formData from the did using psycopg
        query = "SELECT form_data FROM requests WHERE did_str = %s"
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(query, (did,))
                row = cur.fetchone()
                if row:
                    form_data = row[0]
                    if isinstance(form_data, str):
                        # Load as a formData model
                        form_data = FormData.model_validate_json(form_data)
                    elif isinstance(form_data, dict):
                        # If it's already a dict, just use it
                        form_data = FormData.model_validate(form_data)
                else:
                    form_data = {}
        print(f"[verify_user()] form_data: {form_data}")

        # Get the SMT_Proofs from the verifiablePresentation
        smt_proof: SMTMerkleProof = verifiablePresentation.smt_proofs
        if not smt_proof:
            print(f"[verify_user()] Missing 'smt_proofs' in Verifiable Presentation.")
            return JSONResponse(
                content={"error": "Missing 'smt_proofs' in Verifiable Presentation."},
                status_code=400,
            )

        # Verify the user on the Sparse Merkle Tree (SMT)
        result, updated_smtProofs = verifyUserOnSMT(did_str=did, smt_proof=smt_proof)
    elif proof_type == "merkle":
        result = verifyUserOnMerkle(merkleHash)
    elif proof_type == "accumulator":
        result = verifyUserOnAccumulator(
            dataHash=data_hash, accVal=acc_val, proof=proof, prime=prime
        )

    # Process the results
    print(f"[verify_user()] results: {result}")
    if result["valid_Offchain"] == False or result["valid_Onchain"] == False:
        message = "Problem with verification: "
        if result["valid_Offchain"] == False:
            message += "Offchain verification failed. "
        if result["valid_Onchain"] == False:
            message += "Onchain verification failed."
    else:
        message = "User verified on merkle tree"

    # SMT_Only: If user fails offchain, return a 409, send updated proofs and request user to re-verify
    if not result["valid_Offchain"] and proof_type == "smt":
        print(f"[verify_user()] User failed offchain verification, returning 409")
        return JSONResponse(
            content={
                "authenticated": False,
                "message": message,
                "results": result,
                "smt_proofs": updated_smtProofs,
            },
            status_code=409,
        )

    # If the user is valid on both chains, log the event in Postgres
    if result["valid_Offchain"] and result["valid_Onchain"]:
        testMode = (
            verifiableCredential.get("credentialSubject").get("testMode")
            if verifiableCredential.get("credentialSubject")
            else False
        )
        if not testMode:
            end_time = time.time()
            duration = end_time - total_start_time
            # Insert login event into login_events table
            insert_query = """
                INSERT INTO login_events (did_str, total_auth_duration, local_auth_duration, onchain_auth_duration)
                VALUES (%s, %s, %s, %s)
            """
            try:
                with psycopg.connect(db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            insert_query,
                            (
                                did,
                                duration,
                                result.get("auth_Offchain_duration", 0),
                                result.get("auth_Onchain_duration", 0),
                            ),
                        )
                        conn.commit()
                    print(f"Added login event to Postgres for did: {did}")
                    # with conn.cursor() as cur:
                    #     # Add zkp_generation_time + vc_issuance_time to the requests table
                    #     update_query = """
                    #         UPDATE requests
                    #         SET zkp_generation_time = %s,
                    #             vc_issuance_time = %s, updated_at = %s
                    #         WHERE did_str = %s
                    #         RETURNING *
                    #     """
                    #     cur.execute(
                    #         update_query,
                    #         (
                    #             result.get("auth_Offchain_duration", 0),
                    #             result.get("auth_Onchain_duration", 0),
                    #             datetime.datetime.now().isoformat(),
                    #             did,
                    #         ),
                    #     )
                    #     conn.commit()
                    #     print(f"Added zkp_generation_time and vc_issuance_time to Postgres for did: {did}")

            except Exception as e:
                print(f"[ERROR-Postgres]: {e}")
        else:
            print(f"Test Mode: No access token returned")
            duration = 0

    return JSONResponse(
        content={
            "message": message,
            "results": result,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "duration": duration,
            **({"smt_proofs": updated_smtProofs} if proof_type == "smt" else {}),
        }
    )


@router.post("/logout")
async def logout(request: Request, _: dict = Depends(verify_jwt)) -> JSONResponse:
    body = await request.json()
    access_token = body.get("access_token")
    # did = body.get("did")
    # No direct logout with psycopg, just return success
    return JSONResponse(
        content={"authenticated": False, "message": "User logged out"},
        status_code=200,
    )


@router.post("/verify-vp")
async def verify_vp(request: Request) -> JSONResponse:
    """
    Verify a presentation using the credential service.
    """
    body = await request.json()
    if debug >= 0:
        print(f"Recieved Data: {body}")

    # Check if body is a string and parse it if needed
    if isinstance(body, str):
        body = json.loads(body)

    try:
        response = await verify_presentation(body)
        print(f"[verify_vp()] Response: {response}")
        return JSONResponse(content=response, status_code=200)
    except Exception as e:
        print(f"[verify_vp()] Exception: {str(e)}")
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )
