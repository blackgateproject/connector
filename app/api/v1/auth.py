import asyncio
import datetime
import json
import random
import time
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
from ...utils.core_utils import (
    extract_user_details_for_passwordless,
    extractUserInfo,
    log_user_action,
    settings_dependency,
    verify_jwt,
)
from ...utils.web3_utils import (
    addUserToAccmulator,
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
async def register(request: Request):
    body = await request.json()
    formData = body.get("formData")
    networkInfo = body.get("networkInfo")
    if debug >= 0:
        print(f"Recieved Data: {formData}")
        print(f"Recieved Data: {networkInfo}")

    wallet_times = formData.get("walletTimes")
    print(f"Got Wallet Times: {wallet_times}")
    wallet_generate_time = wallet_times.get("walletCreateTime")
    wallet_encrypt_time = wallet_times.get("walletEncryptTime")
    if wallet_times:
        formData.pop("wallet_generate_time", None)
        formData.pop("wallet_encrypt_time", None)
        wallet_generate_time = (
            wallet_generate_time if wallet_generate_time is not None else 0
        )
        wallet_encrypt_time = (
            wallet_encrypt_time if wallet_encrypt_time is not None else 0
        )

    test_mode = (
        formData.get("testMode") if formData.get("testMode") is not None else False
    )
    request_status = (
        "approved"
        if formData["selected_role"] == "device" and not test_mode
        else "pending"
    )
    if type(wallet_generate_time) == NoneType or type(wallet_encrypt_time) == NoneType:
        wallet_generate_time = 0
        wallet_encrypt_time = 0
    else:
        wallet_generate_time = int(wallet_generate_time)
        wallet_encrypt_time = int(wallet_encrypt_time)
    total_time = int(wallet_generate_time) + int(wallet_encrypt_time)

    requests_data = {
        "did_str": formData["did"],
        "form_data": json.dumps(formData),
        "network_info": json.dumps(networkInfo),
        "request_status": request_status,
        "isVCSent": False,
        "wallet_generate_time": wallet_generate_time,
        "total_time": total_time,
    }

    print(f"\n\nTimes: {wallet_generate_time}, {wallet_encrypt_time}")

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
        print(f"[ERROR] psycopg encountered: {e}")
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


@router.get("/poll/{did_str}")
async def pollRequestStatus(request: Request, did_str: str):
    if debug >= 0:
        print(f"Recieved Data: {did_str}")

    try:
        query = "SELECT * FROM requests WHERE did_str = %s"
        rows = fetch_all(query, (did_str,))
        returnResponse = {}
        if rows:
            req = rows[0]
            # Only decode if it's a string
            if isinstance(req["form_data"], str):
                req["form_data"] = json.loads(req["form_data"])
            if isinstance(req["network_info"], str):
                req["network_info"] = json.loads(req["network_info"])
            if req["request_status"] == "approved" and not req["isVCSent"]:
                formData = req["form_data"]
                networkInfo = req["network_info"]
                proof_type = formData.get("proof_type")
                public_key = did_str.replace("did:ethr:blackgate:", "")
                if proof_type == "smt":
                    zkpData = addUserToSMTLocal(did_str=did_str)

                    data = {
                        "formData": formData,
                        "networkInfo": networkInfo,
                        "ZKP": zkpData,
                    }
                    verifiableCredential = await issue_credential(data)

                    # if debug >= 0:
                    #     print(f"Verifiable Credential: {verifiableCredential}")
                    # Keccak hash the VC
                    vcHash = await keccakHash(
                        json.dumps(verifiableCredential, sort_keys=True).encode("utf-8")
                    )

                    if debug >= 0:
                        print(f"VC Hash: {vcHash}")

                    # Send data onchain
                    fog_node_publicKey = (
                        verifiableCredential.get("credential").get("issuer").get("id")
                    ).replace("did:ethr:blackgate:", "")
                    if formData.get("device_id") is None:
                        formData["device_id"] = "NO Device ID"

                    # Convert device_id to a string

                    if isinstance(formData["device_id"], int):
                        formData["device_id"] = str(formData["device_id"])
                    onChainResults = addUserToSMTOnChain(
                        merkleRoot=zkpData["merkleRoot"],
                        vc_hash=vcHash,
                        device_id=formData["device_id"],
                        fog_node_pubkey=fog_node_publicKey,
                    )
                    print(f"OnChain Results: {onChainResults}")

                elif proof_type == "merkle":
                    merkle_data = addUserToMerkle(user=did_str, pw=public_key)
                elif proof_type == "accumulator":
                    merkle_data = addUserToAccmulator(did=did_str, vc=public_key)
                else:
                    merkle_data = {}

                # merkle_data.pop("merkleRoot", None)
                # merkle_data.pop("userProof", None)

                # data = {
                #     "formData": formData,
                #     "networkInfo": networkInfo,
                #     "ZKP": merkle_data,
                # }

                # print(f"Data before issue_credential(): {data}")

                # verifiableCredential = await issue_credential(data)

                # SET "isVCSent" = TRUE,
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
                        formData.get("did"),
                    ),
                )
                returnResponse = {
                    "message": f"approved request for role {formData.get('selected_role')}",
                    "verifiable_credential": verifiableCredential,
                    "request_status": f"{req['request_status']}",
                }
            elif req["request_status"] == "approved" and req["isVCSent"]:
                returnResponse = {
                    "message": f"User already added to merkle tree",
                    "request_status": f"{req['request_status']}",
                }
            elif req["request_status"] == "rejected":
                returnResponse = {
                    "message": f"Request rejected",
                    "request_status": f"{req['request_status']}",
                }
            elif req["request_status"] == "pending":
                returnResponse = {
                    "message": f"Request pending",
                    "request_status": f"{req['request_status']}",
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
        print(f"[ERR_psycopg] Error: {e}")
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


@router.post("/verify")
async def verify_user(
    request: Request,
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
    proof_type = vc_data.get("credentialSubject").get("proof_type")
    cred_ZKP = vc_data.get("credentialSubject").get("ZKP")

    if proof_type == "merkle":
        merkleHash = cred_ZKP.get("userHash")
        txHash = cred_ZKP.get("txHash")
        print(f"[verify_user()] txHash: {txHash}")
        print(f"[verify_user()] merkleHash: {merkleHash}")
    elif proof_type == "smt":
        index = cred_ZKP.get("index")
        merkleHash = cred_ZKP.get("userHash")
        # This should not be used, only the hash
        networkInfo = vc_data.get("credentialSubject").get("networkInfo")
        print(f"[verify_user()] index: {index}")
        print(f"[verify_user()] merkleHash: {merkleHash}")
    elif proof_type == "accumulator":
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
        # Fetch user details from the did using psycopg
        query = "SELECT form_data FROM requests WHERE did_str = %s"
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(query, (did,))
                row = cur.fetchone()
                if row:
                    form_data = row[0]
                    if isinstance(form_data, str):
                        form_data = json.loads(form_data)
                else:
                    form_data = {}
        print(f"[verify_user()] form_data: {form_data}")
        result = verifyUserOnSMT(user_id=form_data, key=index, credentials=networkInfo)
    elif proof_type == "merkle":
        result = verifyUserOnMerkle(merkleHash)
    elif proof_type == "accumulator":
        result = verifyUserOnAccumulator(
            dataHash=data_hash, accVal=acc_val, proof=proof, prime=prime
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

    # If the user is valid on both chains, log the event in Postgres
    if result["valid_Offchain"] and result["valid_Onchain"]:
        testMode = (
            vc_data.get("credentialSubject").get("testMode")
            if vc_data.get("credentialSubject")
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
        }
    )


@router.post("/logout")
async def logout(request: Request, _: dict = Depends(verify_jwt)):
    body = await request.json()
    access_token = body.get("access_token")
    # did = body.get("did")
    # No direct logout with psycopg, just return success
    return JSONResponse(
        content={"authenticated": False, "message": "User logged out"},
        status_code=200,
    )


@router.get("/pollTest/{did_str}")
async def testAutoApproveReq(request: Request, did_str: str):
    if debug >= 0:
        print(f"Recieved Data: {did_str}")

    try:
        query = "SELECT * FROM requests WHERE did_str = %s"
        rows = fetch_all(query, (did_str,))
        returnResponse = {
            "authenticated": False,
            "message": "No pending request found",
        }
        entry = None
        if rows and rows[0]["request_status"] != "approved":
            req = rows[0]
            # Only decode if it's a string
            if isinstance(req["form_data"], str):
                req["form_data"] = json.loads(req["form_data"])
            if isinstance(req["network_info"], str):
                req["network_info"] = json.loads(req["network_info"])
            status = "rejected" if random.randint(1, 10) == 1 else "approved"

            formData = req["form_data"]
            networkInfo = req["network_info"]
            proof_type = formData.get("proof_type")
            public_key = did_str.replace("did:ethr:blackgate:", "")

            if proof_type == "smt":
                zkpData = addUserToSMTLocal(did_str=did_str)

                data = {
                    "formData": formData,
                    "networkInfo": networkInfo,
                    "ZKP": zkpData,
                }
                verifiableCredential = await issue_credential(data)

                # if debug >= 0:
                #     print(f"Verifiable Credential: {verifiableCredential}")
                # Keccak hash the VC
                vcHash = await keccakHash(
                    json.dumps(verifiableCredential, sort_keys=True).encode("utf-8")
                )

                if debug >= 0:
                    print(f"VC Hash: {vcHash}")

                # Send data onchain
                fog_node_publicKey = (
                    verifiableCredential.get("credential").get("issuer").get("id")
                ).replace("did:ethr:blackgate:", "")
                onChainResults = addUserToSMTOnChain(
                    merkleRoot=zkpData["merkleRoot"],
                    vc_hash=vcHash,
                    device_id=formData["device_id"],
                    fog_node_pubkey=fog_node_publicKey,
                )
                # print(f"OnChain Results: {onChainResults}")

            elif proof_type == "merkle":
                merkle_data = addUserToMerkle(user=did_str, pw=public_key)
            elif proof_type == "accumulator":
                merkle_data = addUserToAccmulator(did=did_str, vc=public_key)
            else:
                merkle_data = {}

            # merkle_data.pop("merkleRoot", None)
            # merkle_data.pop("userProof", None)

            # data = {
            #     "formData": formData,
            #     "networkInfo": networkInfo,
            #     "ZKP": merkle_data,
            # }
            # verifiableCredential = await issue_credential(data)

            update_query = """
                UPDATE requests
                SET "isVCSent" = TRUE,
                    verifiable_cred = %s,
                    request_status = %s
                WHERE did_str = %s
                RETURNING *
            """
            execute_query(
                update_query,
                (json.dumps(verifiableCredential), status, formData.get("did")),
            )
            returnResponse = {
                "message": f"{status} request for role '{formData.get('selected_role')}' using ZKP '{proof_type}'",
                "verifiable_credential": verifiableCredential,
                "request_status": f"{status}",
            }
        elif rows and rows[0]["request_status"] == "approved":
            req = rows[0]
            # Only decode if it's a string
            if isinstance(req["form_data"], str):
                req["form_data"] = json.loads(req["form_data"])
            returnResponse = {
                "message": f"approved request for role {req['form_data'].get('selected_role')}",
                "verifiable_credential": req["verifiable_cred"],
                "request_status": f"{req['request_status']}",
            }
        return JSONResponse(
            content=returnResponse,
            status_code=200,
        )
    except Exception as e:
        print(f"[ERR_psycopg] Error: {e}")
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )


@router.post("/verify-vp")
async def verify_vp(request: Request):
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
        return JSONResponse(content=response, status_code=200)
    except Exception as e:
        print(f"[verify_vp()] Exception: {str(e)}")
        return JSONResponse(
            content={"authenticated": False, "error": str(e)}, status_code=500
        )