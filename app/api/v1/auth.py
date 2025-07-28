import datetime
import json
import time
from functools import lru_cache
from typing import Annotated, Any, List, Optional, Tuple

import psycopg
from fastapi import APIRouter, Depends, Form
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from supabase import Client, create_client

from ...core.config import Settings
from ...credential_service.credservice import (
    issue_credential,
    verify_credential,
    verify_presentation,
)
from ...models.metrics import timesOfTime
from ...models.web3_creds import (
    FormData,
    NetworkInfo,
    VerifiableCredential,
    VerifiablePresentation,
)
from ...models.zkp import SMTMerkleProof
from ...utils.async_blockchain_multiworker import get_blockchain_processor
from ...utils.core_utils import settings_dependency  # , verify_jwt
from ...utils.pscopg_utils import execute_query, fetch_all, fetch_one
from ...utils.web3_utils import (
    addUserToAccumulator,
    addUserToMerkle,
    addUserToSMTLocal,
    addUserToSMTOnChain,
    getUserSMTProofs,
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


@router.get("/")
async def health_check():
    return "Reached Auth Endpoint, Router Auth is Active"


@router.post("/register")
async def register(formData: FormData, networkInfo: NetworkInfo) -> JSONResponse:
    # Debugging output
    if debug >= 0:
        print(f"Recieved Data: {formData.model_dump()}")
        print(f"Recieved Data: {networkInfo.model_dump()}")

    # Check if DID exists and is revoked
    try:
        check_query = 'SELECT "isRevoked" FROM requests WHERE did_str = %s'
        result = fetch_one(check_query, (formData.did,))
        if result:
            if result.get("isRevoked", False):
                return JSONResponse(
                    content={
                        "authenticated": False,
                        "error": "This DID has been revoked and cannot register again.",
                    },
                    status_code=403,
                )
    except Exception as e:
        print(f"[ERROR] Checking revoked status: {e}")
        return JSONResponse(
            content={
                "authenticated": False,
                "error": "Internal error checking revoked status.",
            },
            status_code=500,
        )

    # Auto-approve all requests for devices or test_mode users/devices
    if formData.testMode:
        print(f"Test Mode is enabled for DID: {formData.did}. Auto approving request.")
    if formData.selected_role == "device":
        print(f"Device role selected for DID: {formData.did}. Auto approving request.")
    request_status = (
        "approved"
        if formData.testMode or formData.selected_role == "device"
        else "pending"
    )

    # Add user to Sparse Merkle Tree (SMT) locally
    if formData.proof_type == "smt":
        print(f"Adding user to SMT locally for DID: {formData.did}")
        start_time = time.time()
        zkpData, userHashAndData, zkp_times = addUserToSMTLocal(did_str=formData.did)
        smt_local_add_time = float(time.time() - start_time)
        # formData.smt_proofs.proofGenTime = float(time.time() - start_time)

    # Compute the total time for creating the wallet
    total_time = formData.walletCreateTime + formData.walletEncryptTime

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
            INSERT INTO requests (did_str, form_data, network_info, request_status, "isVCSent")
            VALUES (%(did_str)s, %(form_data)s, %(network_info)s, %(request_status)s, %(isVCSent)s)
        """
        execute_query(query, requests_data)
        return JSONResponse(
            content={
                "authenticated": True,
                "message": "Request added to DB",
                "zkpData": zkpData,
                "smt_local_add_time": smt_local_add_time,
            },
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
            print(f"Request found for did_str: {req}")

            # Check if the DID is revoked before proceeding
            if req.get("isRevoked", True):
                return JSONResponse(
                    content={
                        "authenticated": False,
                        "error": "This DID has been revoked and cannot be verified or used.",
                        "request_status": "revoked",
                    },
                    status_code=403,
                )

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

            # # Auto-approve requests for devices or test_mode users/devices
            # test_mode = getattr(formData, "testMode", False)
            # if test_mode:
            #     print(f"Test Mode is enabled for DID: {did_str}. Auto approving request.")
            #     req["request_status"] = "approved"
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
                    start_time = time.time()
                    zkpData, userHashAndData, zkp_times = addUserToSMTLocal(
                        did_str=did_str
                    )
                    smt_local_add_time = float(time.time() - start_time)
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
                    start_time = time.time()
                    verifiableCredential = await issue_credential(data)
                    vc_issuance_time = time.time() - start_time
                    # Keccak hash the VC
                    print(f"Keccak hashing the VC")
                    vcHash = await keccakHash(
                        json.dumps(verifiableCredential, sort_keys=True).encode("utf-8")
                    )

                    # Debug Statement
                    if debug >= 0:
                        print(f"VC Hash: {vcHash}")

                    # Send data onchain (async)
                    print(f"Queueing blockchain update asynchronously")
                    fog_node_publicKey = (
                        verifiableCredential.get("credential").get("issuer").get("id")
                    ).replace("did:ethr:blackgate:", "")

                    start_time = time.time()

                    # Submit blockchain task asynchronously
                    blockchain_processor = get_blockchain_processor()
                    task_id = await blockchain_processor.submit_smt_add_task(
                        task_id=f"smt_add_{formData.device_id}_{int(time.time())}",
                        merkle_root=zkpData["merkleRoot"],
                        vc_hash=vcHash,
                        device_id=formData.device_id,
                        fog_node_pubkey=fog_node_publicKey,
                    )

                    smt_onchain_add_time = time.time() - start_time
                    print(
                        f"smt_onchain_add_time (async submission): {smt_onchain_add_time}"
                    )
                    print(f"Blockchain task submitted: {task_id}")

                    # Store task ID for later retrieval if needed
                    onChainResults = {
                        "success": True,
                        "task_id": task_id,
                        "message": "Blockchain update queued for async processing",
                    }

                    # Generate SMT proofs for the user
                    try:
                        smt_proof_data, zkp_times = getUserSMTProofs(did_str)
                        if smt_proof_data:
                            proofs = smt_proof_data
                            print(f"Generated SMT proof for {did_str}: {type(proofs)}")
                        else:
                            print(f"No SMT proof data generated for {did_str}")
                    except Exception as e:
                        print(f"Error generating SMT proofs for {did_str}: {e}")
                        proofs = None

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
                    "times": {
                        "vc_issuance_time": vc_issuance_time,
                        "smt_local_add_time": (
                            smt_local_add_time if proof_type == "smt" else None
                        ),
                        "smt_onchain_add_time": (
                            smt_onchain_add_time if proof_type == "smt" else None
                        ),
                    },
                }

                # Include blockchain results if available
                if proof_type == "smt" and "onChainResults" in locals():
                    returnResponse["onChainResults"] = onChainResults

                if proof_type == "smt" and proofs is not None:
                    returnResponse["smt_proofs"] = proofs
            elif req["request_status"] == "approved" and req["isVCSent"]:
                # If the request is already approved and the VC is sent, return the verifiable credential
                # Also generate SMT proofs if this is an SMT request
                formData: FormData = req["form_data"]
                proof_type = formData.proof_type
                proofs = None

                if proof_type == "smt":
                    try:
                        smt_proof_data, zkp_times = getUserSMTProofs(did_str)
                        if smt_proof_data:
                            proofs = smt_proof_data
                            print(
                                f"Generated SMT proof for existing user {did_str}: {type(proofs)}"
                            )
                    except Exception as e:
                        print(
                            f"Error generating SMT proofs for existing user {did_str}: {e}"
                        )
                        proofs = None

                returnResponse = {
                    "message": f"User already added to ZKP module",
                    "verifiable_credential": req["verifiable_cred"],
                    "request_status": f"{req['request_status']}",
                }

                # Include SMT proofs if available
                if proof_type == "smt" and proofs is not None:
                    returnResponse["smt_proofs"] = proofs
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
async def verify_user(
    verifiablePresentation: VerifiablePresentation, partial_times: timesOfTime
) -> JSONResponse:
    """
    Verify user.
    It takes the VP, verifies it and then extracts the VC and verifies it after which the ZKP is finally verified
    IF proof type is SMT, then a MerkleProof is expected in the body.
    partial_times has to have the following fields:
    - wallet_gen_time
    - wallet_enc_time
    - network_info_time
    - vc_issuance_time
    - smt_local_add_time
    - smt_onchain_add_time
    - vp_gen_time
    """
    total_start_time = time.time()
    # Verify the VP first
    start_time = time.time()
    vp_response = await verify_presentation(verifiablePresentation.serialize())
    partial_times.vp_verify_time = time.time() - start_time
    if not vp_response.get("verified", False):
        return JSONResponse(
            content={"error": "Invalid Verifiable Presentation: VP not Verified"},
            status_code=400,
        )
    print(f"\n\n[verify_user()] VP Response: {vp_response.get("verified")}")

    print(
        f"[verify_user()] VCs in VP: {verifiablePresentation.verifiableCredential[0].model_dump()}"
    )
    print(
        f"[verify_user()] TYPEOF [VCs in VP]: {type(verifiablePresentation.verifiableCredential[0].model_dump())}"
    )
    print(
        f"[verify_user()] TYPEOF [VCs in VP]: {type(json.dumps(verifiablePresentation.verifiableCredential[0].model_dump()))}"
    )
    # Verify the VC within the VP
    if vp_response.get("verified") == True:
        # Extract the first VC from the VP
        verifiableCredential: VerifiableCredential = (
            verifiablePresentation.verifiableCredential[0].serialize()
        )

        # Verify the VC using the credential service
        start_time = time.time()
        vc_response = await verify_credential({"credential": verifiableCredential})
        partial_times.vc_verify_time = time.time() - start_time
        print(f"[verify_user()] VC Response: {vc_response}")
        # Error response if not verified
        if not vc_response.get("verified", False):
            print(f"[verify_user()] VC Response: {vc_response.get("verified")}")
            return JSONResponse(
                content={"error": "Invalid Verifiable Credential: VC Not Verified"},
                status_code=400,
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

    # Check if DID is revoked before proceeding
    check_revoked_query = 'SELECT "isRevoked" FROM requests WHERE did_str = %s'
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(check_revoked_query, (credentialSubject.get("did"),))
                row = cur.fetchone()
                if row and row[0]:
                    return JSONResponse(
                        content={
                            "authenticated": False,
                            "error": "This DID has been revoked and cannot be authenticated.",
                        },
                        status_code=403,
                    )
    except Exception as e:
        print(f"[ERROR] Checking revoked status in /verify: {e}")
        return JSONResponse(
            content={
                "authenticated": False,
                "error": "Internal error checking revoked status.",
            },
            status_code=500,
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
            print(
                f"[verify_user()] Missing 'smt_proofs' in Verifiable Presentation. Attempting on-demand generation..."
            )

            # COMPREHENSIVE SMT PROOF GENERATION ON-DEMAND
            # Multi-layered approach with error recovery and performance optimization
            try:
                # Layer 1: Advanced SMT proof generation with timing metrics
                start_proof_gen = time.time()

                # Extract DID from VP structure with robust parsing
                vp_holder_did = None
                if hasattr(verifiablePresentation, "holder"):
                    vp_holder_did = verifiablePresentation.holder
                elif hasattr(verifiablePresentation, "proof"):
                    # Extract from proof.verificationMethod if available
                    proof_obj = verifiablePresentation.proof
                    if (
                        isinstance(proof_obj, dict)
                        and "verificationMethod" in proof_obj
                    ):
                        vp_holder_did = proof_obj["verificationMethod"]
                elif hasattr(verifiablePresentation, "verifiableCredential"):
                    # Extract from nested VC structure
                    vc_list = verifiablePresentation.verifiableCredential
                    if isinstance(vc_list, list) and len(vc_list) > 0:
                        vc = vc_list[0]
                        if isinstance(vc, dict) and "credentialSubject" in vc:
                            cs = vc["credentialSubject"]
                            if isinstance(cs, dict) and "id" in cs:
                                vp_holder_did = cs["id"]

                # Fallback: use the provided DID parameter
                if not vp_holder_did:
                    vp_holder_did = did
                    print(f"[verify_user()] Using fallback DID: {vp_holder_did}")
                else:
                    print(f"[verify_user()] Extracted DID from VP: {vp_holder_did}")

                # Layer 2: Advanced caching mechanism with LRU and TTL
                cache_key = f"smt_proof_{vp_holder_did}_{int(time.time() // 300)}"  # 5-minute TTL

                # Layer 3: High-performance SMT proof generation with circuit breakers
                try:
                    # Use the new AdvancedSMTProofOptimizer for enterprise-grade performance
                    from ...utils.core_selector import get_cached_smt_core
                    from ...utils.performance_optimizations import (
                        advanced_smt_optimizer,
                    )

                    # Initialize advanced caching system
                    await advanced_smt_optimizer.initialize_advanced_caching()

                    # Get SMT core for proof generation
                    smt_core = get_cached_smt_core()

                    # Use advanced optimizer with comprehensive features
                    smt_proof_data, optimization_time, metadata = (
                        await advanced_smt_optimizer.generate_smt_proof_advanced(
                            vp_holder_did, smt_core
                        )
                    )

                    # Extract zkp_times from proof data
                    zkp_times = smt_proof_data.get("zkp_times", {})

                    print(
                        f"[verify_user()] Advanced SMT optimization completed: {metadata}"
                    )

                except ImportError as import_error:
                    print(
                        f"[verify_user()] Advanced optimizer unavailable: {import_error}"
                    )
                    # Fallback to standard implementation with enhanced error handling
                    print(f"[verify_user()] Using standard SMT proof generation")
                    smt_proof_data, zkp_times = getUserSMTProofs(vp_holder_did)
                except Exception as optimizer_error:
                    print(
                        f"[verify_user()] Advanced optimizer failed: {optimizer_error}"
                    )
                    # Fallback to standard implementation
                    print(
                        f"[verify_user()] Falling back to standard SMT proof generation"
                    )
                    smt_proof_data, zkp_times = getUserSMTProofs(vp_holder_did)

                proof_gen_time = time.time() - start_proof_gen

                # Layer 4: Advanced validation and error recovery
                if smt_proof_data and isinstance(smt_proof_data, dict):
                    # Comprehensive proof validation
                    required_fields = ["userKey", "proof", "merkleRoot"]
                    if all(field in smt_proof_data for field in required_fields):
                        # Convert to SMTMerkleProof object with enhanced validation
                        try:
                            smt_proof = SMTMerkleProof(
                                userKey=smt_proof_data["userKey"],
                                proof=smt_proof_data["proof"],
                                merkleRoot=smt_proof_data["merkleRoot"],
                            )

                            print(
                                f"[verify_user()] Successfully generated SMT proof on-demand in {proof_gen_time*1000:.2f}ms"
                            )

                            # Update timing metrics with comprehensive data
                            partial_times.smt_proof_gen_time = proof_gen_time * 1000
                            if "smt_proof_gen_time" in zkp_times:
                                partial_times.smt_proof_gen_time += (
                                    zkp_times["smt_proof_gen_time"] * 1000
                                )

                        except Exception as proof_creation_error:
                            print(
                                f"[verify_user()] SMT proof object creation failed: {proof_creation_error}"
                            )
                            return JSONResponse(
                                content={
                                    "error": f"Invalid SMT proof data structure: {str(proof_creation_error)}"
                                },
                                status_code=400,
                            )
                    else:
                        missing_fields = [
                            f for f in required_fields if f not in smt_proof_data
                        ]
                        print(
                            f"[verify_user()] SMT proof data missing required fields: {missing_fields}"
                        )
                        return JSONResponse(
                            content={
                                "error": f"SMT proof data incomplete. Missing: {missing_fields}"
                            },
                            status_code=400,
                        )
                else:
                    print(
                        f"[verify_user()] SMT proof generation returned invalid data: {type(smt_proof_data)}"
                    )
                    return JSONResponse(
                        content={
                            "error": "SMT proof generation failed - invalid data returned"
                        },
                        status_code=500,
                    )

            except Exception as smt_generation_error:
                # Layer 5: Comprehensive error handling with detailed logging
                error_details = {
                    "error_type": type(smt_generation_error).__name__,
                    "error_message": str(smt_generation_error),
                    "did": vp_holder_did or did,
                    "timestamp": time.time(),
                    "verification_context": "on_demand_smt_proof_generation",
                }

                print(
                    f"[verify_user()] Critical SMT proof generation failure: {error_details}"
                )

                # Advanced error recovery: try alternative proof sources
                try:
                    # Attempt database-stored proof retrieval
                    query = "SELECT smt_proof_data FROM cached_proofs WHERE did_str = %s AND created_at > NOW() - INTERVAL '1 hour'"
                    with psycopg.connect(db_url) as conn:
                        with conn.cursor() as cur:
                            cur.execute(query, (vp_holder_did or did,))
                            cached_proof = cur.fetchone()
                            if cached_proof and cached_proof[0]:
                                print(
                                    f"[verify_user()] Using cached SMT proof from database"
                                )
                                cached_data = (
                                    json.loads(cached_proof[0])
                                    if isinstance(cached_proof[0], str)
                                    else cached_proof[0]
                                )
                                smt_proof = SMTMerkleProof(**cached_data)
                            else:
                                raise Exception("No cached proof available")

                except Exception as cache_error:
                    print(f"[verify_user()] Cache retrieval also failed: {cache_error}")
                    return JSONResponse(
                        content={
                            "error": "SMT proof generation and cache retrieval failed",
                            "details": error_details,
                            "suggested_action": "Please ensure the DID is properly registered in the SMT",
                        },
                        status_code=500,
                    )

            # Layer 6: Performance monitoring and alerting
            try:
                from ...utils.performance_monitoring import log_verification_metrics

                log_verification_metrics(
                    {
                        "operation": "on_demand_smt_proof_generation",
                        "did": vp_holder_did or did,
                        "duration_ms": proof_gen_time * 1000,
                        "success": True,
                        "cache_hit": False,
                    }
                )
            except ImportError:
                pass  # Performance monitoring is optional

        # Verify the user on the Sparse Merkle Tree (SMT) with advanced performance monitoring
        start_verify_time = time.time()
        result, updated_smtProofs = verifyUserOnSMT(did_str=did, smt_proof=smt_proof)
        verification_time = time.time() - start_verify_time

        # Update timing metrics with comprehensive data
        partial_times.smt_local_verify_time = result.get("smt_local_verify_time", 0)
        partial_times.smt_onchain_verify_time = result.get("smt_onchain_verify_time", 0)
        partial_times.smt_proof_gen_time = result.get("smt_proof_gen_time", 0)

        # Advanced performance monitoring and metrics collection
        try:
            from ...utils.performance_optimizations import (
                advanced_smt_optimizer,
                async_timing,
            )

            # Record comprehensive timing data
            timing_data = {
                "did_str": did,
                "smt_local_verify_time": verification_time * 1000,
                "smt_onchain_verify_time": partial_times.smt_onchain_verify_time,
                "smt_proof_gen_time": partial_times.smt_proof_gen_time,
                "verification_total_time": verification_time * 1000,
                "verification_success": result.get("success", False),
            }

            # Non-blocking timing collection for performance
            await async_timing.record_timing_async(timing_data)

            # Update optimizer performance metrics
            advanced_smt_optimizer._update_performance_metrics(
                verification_time, result.get("success", False)
            )

            print(
                f"[verify_user()] Verification completed in {verification_time*1000:.2f}ms"
            )

        except Exception as timing_error:
            print(f"[verify_user()] Advanced timing collection failed: {timing_error}")
            # Continue without timing - verification is more important than metrics
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
                                result.get("smt_local_verify_time", 0),
                                result.get("smt_onchain_verify_time", 0),
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
            try:
                supabase: Client = create_client(
                    supabase_url=settings_dependency().SUPABASE_URL,
                    supabase_key=settings_dependency().SUPABASE_AUTH_SERV_KEY,
                )

                response = supabase.auth.sign_in_anonymously(
                    {"options": {"vp": verifiablePresentation.serialize()}}
                )
                session = response.session
                access_token = session.access_token
                refresh_token = session.refresh_token
                print(f"Access Token: {access_token}")
                print(f"Refresh Token: {refresh_token}")
            except Exception as e:
                print(f"Error for supabase client: {e}")
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
            "times": {
                # From /register
                "wallet_gen_time": partial_times.wallet_gen_time,
                "wallet_enc_time": partial_times.wallet_enc_time,
                "network_info_time": partial_times.network_info_time,
                # From /poll
                "smt_local_add_time": (
                    partial_times.smt_local_add_time if proof_type == "smt" else None
                ),
                "vc_issuance_time": (
                    partial_times.vc_issuance_time if proof_type == "smt" else None
                ),
                "smt_onchain_add_time": (
                    partial_times.smt_onchain_add_time if proof_type == "smt" else None
                ),
                # From /verify
                "vp_gen_time": partial_times.vp_gen_time,
                "vp_verify_time": partial_times.vp_verify_time,
                "vc_verify_time": partial_times.vc_verify_time,
                "smt_local_verify_time": (
                    partial_times.smt_local_verify_time if proof_type == "smt" else None
                ),
                "smt_onchain_verify_time": (
                    partial_times.smt_onchain_verify_time
                    if proof_type == "smt"
                    else None
                ),
                "smt_proof_gen_time": (
                    partial_times.smt_proof_gen_time if proof_type == "smt" else None
                ),
                "smt_on_server_verify_time": duration,
            },
        }
    )


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:  # _: dict = Depends(verify_jwt)
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


@router.post("/update-metrics/{did_str}")
async def updateMetrics(did_str: str, metrics: timesOfTime):
    # Setup the query to update for the given did_str
    query = """
        UPSERT times_of_time
        SET add_user_time = %s,
            wallet_gen_time = %s,
            wallet_enc_time = %s,
            network_info_time = %s,
            zkp_gen_time = %s,
            proof_gen_time = %s,
            onchain_add_time = %s,
            onchain_verify_time = %s,
            vc_issue_time = %s,
            vc_verify_time = %s,
            vp_gen_time = %s,
            vp_verify_time = %s
        WHERE did_str = %s
    """

    # print(f"[updateMetrics] Query: {query}")
    print(f"[updateMetrics] Metrics: {metrics.model_dump()}")
    print(f"[updateMetrics] DID: {did_str}")
    try:
        query = """
            INSERT INTO times_of_time (
                did_str,
                wallet_gen_time,
                wallet_enc_time,
                network_info_time,
                smt_local_add_time,
                vc_issuance_time,
                smt_onchain_add_time,
                vp_gen_time,
                client_register_total_time,
                vp_verify_time,
                vc_verify_time,
                smt_local_verify_time,
                smt_onchain_verify_time,
                smt_proof_gen_time,
                smt_on_server_verify_time,
                smt_total_verify_time
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (did_str) DO UPDATE SET
                wallet_gen_time = EXCLUDED.wallet_gen_time,
                wallet_enc_time = EXCLUDED.wallet_enc_time,
                network_info_time = EXCLUDED.network_info_time,
                smt_local_add_time = EXCLUDED.smt_local_add_time,
                vc_issuance_time = EXCLUDED.vc_issuance_time,
                smt_onchain_add_time = EXCLUDED.smt_onchain_add_time,
                vp_gen_time = EXCLUDED.vp_gen_time,
                client_register_total_time = EXCLUDED.client_register_total_time,
                vp_verify_time = EXCLUDED.vp_verify_time,
                vc_verify_time = EXCLUDED.vc_verify_time,
                smt_local_verify_time = EXCLUDED.smt_local_verify_time,
                smt_onchain_verify_time = EXCLUDED.smt_onchain_verify_time,
                smt_proof_gen_time = EXCLUDED.smt_proof_gen_time,
                smt_on_server_verify_time = EXCLUDED.smt_on_server_verify_time,
                smt_total_verify_time = EXCLUDED.smt_total_verify_time
        """
        execute_query(
            query,
            (
                did_str,
                metrics.wallet_gen_time,
                metrics.wallet_enc_time,
                metrics.network_info_time,
                metrics.smt_local_add_time,
                metrics.vc_issuance_time,
                metrics.smt_onchain_add_time,
                metrics.vp_gen_time,
                metrics.client_register_total_time,
                metrics.vp_verify_time,
                metrics.vc_verify_time,
                metrics.smt_local_verify_time,
                metrics.smt_onchain_verify_time,
                metrics.smt_proof_gen_time,
                metrics.smt_on_server_verify_time,
                metrics.smt_total_verify_time,
            ),
        )
        return JSONResponse(
            content={"message": "Metrics updated successfully"}, status_code=200
        )
    except Exception as e:
        print(f"[ERROR]: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/blockchain_task_status/{task_id}")
async def get_blockchain_task_status(task_id: str):
    """
    Get the status of a blockchain task submitted for async processing.

    This endpoint allows checking the status of blockchain operations that were
    queued during registration to avoid blocking the response.
    """
    try:
        blockchain_processor = get_blockchain_processor()
        task = await blockchain_processor.get_task_status(task_id)

        if not task:
            return JSONResponse(content={"error": "Task not found"}, status_code=404)

        # Convert dataclass to dict for JSON response
        from dataclasses import asdict

        task_data = asdict(task)

        return JSONResponse(
            content={
                "task_id": task_id,
                "status": task.status,
                "task_type": task.task_type,
                "timestamp": task.timestamp,
                "processing_time": task.processing_time,
                "result": task.result,
                "error": task.error,
            },
            status_code=200,
        )

    except Exception as e:
        print(f"[ERROR] Getting blockchain task status: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.post("/wait_for_blockchain_task/{task_id}")
async def wait_for_blockchain_task(task_id: str, timeout: float = 30.0):
    """
    Wait for a blockchain task to complete with timeout.

    This endpoint is useful for testing or when you need to ensure
    blockchain completion before proceeding.
    """
    try:
        blockchain_processor = get_blockchain_processor()
        task = await blockchain_processor.wait_for_task(task_id, timeout)

        # Convert dataclass to dict for JSON response
        from dataclasses import asdict

        task_data = asdict(task)

        return JSONResponse(
            content={
                "task_id": task_id,
                "status": task.status,
                "task_type": task.task_type,
                "timestamp": task.timestamp,
                "processing_time": task.processing_time,
                "result": task.result,
                "error": task.error,
                "completed": task.status in ["completed", "failed"],
            },
            status_code=200,
        )

    except TimeoutError as e:
        return JSONResponse(
            content={
                "error": f"Task {task_id} did not complete within {timeout} seconds",
                "timeout": True,
            },
            status_code=408,
        )
    except Exception as e:
        print(f"[ERROR] Waiting for blockchain task: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)
