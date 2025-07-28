"""
Parallel Performance Testing Framework for Blackgate Connector

This module provides comprehensive load testing capabilities for the registration
and verification process, measuring detailed timing metrics for each user.
"""

import asyncio
import base64
import hashlib
import json
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import httpx
import psycopg
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import BaseModel

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class UserMetrics:
    """Comprehensive timing metrics for a single user throughout the full process."""

    did_str: str
    private_key: str = ""  # Store the private key for JWT signing
    wallet_gen_time: float = 0.0
    wallet_enc_time: float = 0.0
    network_info_time: float = 0.0
    smt_local_add_time: float = 0.0
    vc_issuance_time: float = 0.0
    smt_onchain_add_time: float = 0.0
    vp_gen_time: float = 0.0
    client_register_total_time: float = 0.0
    vp_verify_time: float = 0.0
    vc_verify_time: float = 0.0
    smt_local_verify_time: float = 0.0
    smt_onchain_verify_time: float = 0.0
    smt_proof_gen_time: float = 0.0
    smt_on_server_verify_time: float = 0.0
    smt_total_verify_time: float = 0.0

    # Additional tracking fields
    registration_start_time: float = 0.0
    registration_end_time: float = 0.0
    verification_start_time: float = 0.0
    verification_end_time: float = 0.0
    total_process_time: float = 0.0
    success: bool = False
    error_message: str = ""


@dataclass
class LoadTestResult:
    """Aggregated results from a load test run."""

    total_users: int
    successful_users: int
    failed_users: int
    test_duration: float
    avg_registration_time: float
    avg_verification_time: float
    avg_total_time: float
    min_total_time: float
    max_total_time: float
    percentile_95_time: float
    percentile_99_time: float
    throughput_per_second: float
    error_rate: float
    user_metrics: List[UserMetrics]
    errors: List[str]


class PerformanceTestClient:
    """High-performance HTTP client for load testing."""

    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate_ethereum_keypair(self) -> Tuple[str, str]:
        """Generate a real Ethereum private key and corresponding DID."""
        # Generate a random private key
        account = Account.create()
        private_key = account.key.hex()
        # Use the address (without 0x prefix) as the DID identifier
        did_identifier = account.address[2:]  # Remove '0x' prefix
        did = f"did:ethr:blackgate:0x{did_identifier}"
        return private_key, did

    async def create_session(self) -> httpx.AsyncClient:
        """Create an async HTTP session with optimized settings."""
        return httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout),
            limits=httpx.Limits(
                max_keepalive_connections=100,
                max_connections=500,
                keepalive_expiry=30.0,
            ),
            http2=True,
        )

    def generate_test_user_data(self, user_id: str) -> Tuple[Dict, Dict, str]:
        """Generate realistic test data for a user with real Ethereum keys."""
        # Generate real Ethereum keypair
        private_key, did = self.generate_ethereum_keypair()

        # Simulate wallet creation timing
        wallet_gen_start = time.time()
        time.sleep(0.01)  # Simulate wallet generation delay
        wallet_gen_time = time.time() - wallet_gen_start

        # Simulate wallet encryption timing
        wallet_enc_start = time.time()
        time.sleep(0.005)  # Simulate encryption delay
        wallet_enc_time = time.time() - wallet_enc_start

        # Simulate network info gathering timing
        network_info_start = time.time()
        time.sleep(0.002)  # Simulate network info gathering
        network_info_time = time.time() - network_info_start

        form_data = {
            "alias": f"load_test_user_{user_id}",
            "device_id": f"device_{user_id}_{int(time.time())}",
            "did": did,  # Use real DID derived from private key
            "firmware_version": "2.0.0",
            "proof_type": "smt",
            "selected_role": "device",
            "testMode": True,
            "walletCreateTime": wallet_gen_time,
            "walletEncryptTime": wallet_enc_time,
        }

        network_info = {
            "ip_address": f"192.168.{(int(user_id) % 255) + 1}.{(int(user_id) % 254) + 1}",
            "user_agent": f"LoadTestAgent/1.0 User{user_id}",
            "location_lat": 40.7128 + (int(user_id) % 100) * 0.001,
            "location_long": -74.0060 + (int(user_id) % 100) * 0.001,
            "user_language": "en-US",
            "user_info_time": network_info_time,
        }

        return form_data, network_info, private_key

    async def register_user(
        self, session: httpx.AsyncClient, user_id: str
    ) -> UserMetrics:
        """Register a single user and measure timing."""
        metrics = UserMetrics(did_str="")
        metrics.registration_start_time = time.time()

        try:
            # Generate test data and capture frontend timing
            form_data, network_info, private_key = self.generate_test_user_data(user_id)
            metrics.did_str = form_data["did"]
            metrics.private_key = private_key
            metrics.wallet_gen_time = form_data["walletCreateTime"]
            metrics.wallet_enc_time = form_data["walletEncryptTime"]
            metrics.network_info_time = network_info["user_info_time"]

            # Call /register endpoint
            register_start = time.time()
            response = await session.post(
                "/auth/v1/register",
                json={"formData": form_data, "networkInfo": network_info},
                timeout=self.timeout,
            )
            register_end = time.time()

            if response.status_code == 200:
                register_data = response.json()
                metrics.smt_local_add_time = register_data.get(
                    "smt_local_add_time", 0.0
                )
                metrics.registration_end_time = register_end
                logger.info(f"User {user_id} registered successfully")
                return metrics
            else:
                metrics.error_message = (
                    f"Registration failed: {response.status_code} - {response.text}"
                )
                logger.error(
                    f"Registration failed for user {user_id}: {metrics.error_message}"
                )
                return metrics

        except Exception as e:
            metrics.error_message = f"Registration exception: {str(e)}"
            logger.error(f"Registration exception for user {user_id}: {str(e)}")
            return metrics

    async def poll_user_status(
        self, session: httpx.AsyncClient, did_str: str, max_polls: int = 30
    ) -> Dict:
        """Poll user status until approved or timeout."""
        poll_interval = 2  # seconds

        for attempt in range(max_polls):
            try:
                response = await session.get(f"/auth/v1/poll/{did_str}")
                if response.status_code == 200:
                    data = response.json()
                    # Check if user is approved and has verifiable credential
                    if (
                        data.get("request_status") == "approved"
                        and data.get("verifiable_credential") is not None
                    ):
                        return data
                await asyncio.sleep(poll_interval)
            except Exception as e:
                logger.error(f"Polling error for {did_str}: {str(e)}")
                await asyncio.sleep(poll_interval)

        raise Exception(f"Polling timeout for {did_str}")

    async def verify_user(
        self, session: httpx.AsyncClient, metrics: UserMetrics, poll_data: Dict
    ) -> UserMetrics:
        """Verify a user and measure verification timing."""
        metrics.verification_start_time = time.time()

        try:
            # Extract verifiable credential from poll response (nested under credential key)
            verifiable_credential_wrapper = poll_data.get("verifiable_credential")
            if not verifiable_credential_wrapper:
                metrics.error_message = "No verifiable credential in poll response"
                return metrics

            verifiable_credential = verifiable_credential_wrapper.get("credential", {})
            if not verifiable_credential:
                metrics.error_message = (
                    "No credential found in verifiable credential wrapper"
                )
                return metrics

            # Generate VP timing (creating JWS manually with correct structure)
            vp_gen_start = time.time()

            import base64
            import hashlib
            import json
            from datetime import datetime, timedelta

            # Extract credential JWT from poll response
            credential_jwt = None
            if isinstance(verifiable_credential, dict):
                # Check if credential is nested under "credential" key
                if "credential" in verifiable_credential:
                    credential_data = verifiable_credential["credential"]
                    if (
                        isinstance(credential_data, dict)
                        and "proof" in credential_data
                        and "jwt" in credential_data["proof"]
                    ):
                        credential_jwt = credential_data["proof"]["jwt"]
                # Check if credential has direct proof structure
                elif (
                    "proof" in verifiable_credential
                    and "jwt" in verifiable_credential["proof"]
                ):
                    credential_jwt = verifiable_credential["proof"]["jwt"]

            if not credential_jwt:
                raise Exception(
                    f"Could not extract credential JWT from poll response: {verifiable_credential}"
                )

            # Get holder DID from form data
            holder_did = metrics.did_str
            current_time = int(time.time())

            # Create the VP object that goes inside the JWT payload (matches working example)
            vp_object = {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": [
                    credential_jwt
                ],  # Array of JWT strings, not objects
            }

            # Create the JWT payload that contains the VP (matches working structure)
            jwt_payload = {
                "iat": current_time,
                "exp": current_time + 86400,  # 24 hours
                "vp": vp_object,
                "nbf": current_time - 60,  # Valid from 1 minute ago
                "issuanceDate": datetime.utcnow().isoformat() + "Z",
                "iss": holder_did,
                "aud": [
                    "did:ethr:blackgate:0x0296682f5bdad65fddd218171cf8dc20fb96978a244b4ebd91058e9a7838747c6e"
                ],  # Issuer DID
                "nonce": f"test_nonce_{current_time}",
            }

            # Create JWS header
            jws_header = {"alg": "ES256K", "typ": "JWT"}

            # Encode header and payload
            header_encoded = (
                base64.urlsafe_b64encode(
                    json.dumps(jws_header, separators=(",", ":")).encode()
                )
                .decode()
                .rstrip("=")
            )

            payload_encoded = (
                base64.urlsafe_b64encode(
                    json.dumps(jwt_payload, separators=(",", ":")).encode()
                )
                .decode()
                .rstrip("=")
            )

            # Create signing input
            signing_input = f"{header_encoded}.{payload_encoded}"

            # Sign with real Ethereum private key (using hash-based signing for JWT)
            account = Account.from_key(metrics.private_key)
            # Create message hash for signing (standard JWT ES256K signing)
            message_hash = hashlib.sha256(signing_input.encode("utf-8")).digest()

            # Use low-level signing for JWT (no Ethereum message wrapper)
            # This creates a recoverable signature which we'll format for JWT
            from eth_utils import to_bytes

            signature_obj = account._key_obj.sign_msg_hash(message_hash)

            # Convert to JWT format: r + s (64 bytes total, no recovery byte)
            r = signature_obj.r.to_bytes(32, "big")
            s = signature_obj.s.to_bytes(32, "big")
            signature_bytes = r + s
            signature_encoded = (
                base64.urlsafe_b64encode(signature_bytes).decode().rstrip("=")
            )

            # Complete JWS
            jws_token = f"{signing_input}.{signature_encoded}"

            # Extract SMT proof data from credential for smt_proofs field
            zkp_data = verifiable_credential.get("credentialSubject", {}).get("ZKP", {})
            smt_proofs = None
            if zkp_data:
                # Create proper SMT proof structure based on SMTMerkleProof model
                user_index = int(zkp_data.get("userIndex", "0"))
                user_hash = zkp_data.get("userHash", "")
                merkle_root = zkp_data.get("merkleRoot", "")

                smt_proofs = {
                    "key": user_index,
                    "proof": [
                        {
                            "sibling_hash": base64.b64encode(
                                bytes.fromhex(user_hash[:64])
                            ).decode(),  # Convert hex to base64
                            "is_right": False,  # Simplified - in real implementation this would be calculated from tree structure
                        }
                    ],
                    "smt_proof_gen_time": 0.001,  # Mock timing
                }

            # Create the final verifiable presentation (matches working example structure)
            # Important: The VP object sent to verify endpoint should match what's in working example
            verifiable_presentation = {
                "iat": jwt_payload["iat"],
                "nbf": jwt_payload["nbf"],
                "issuanceDate": jwt_payload["issuanceDate"],
                "nonce": jwt_payload["nonce"],
                "verifiableCredential": [
                    {
                        # Recreate the VC structure from the JWT for the final VP
                        "credentialSubject": verifiable_credential.get(
                            "credentialSubject", {}
                        ),
                        "issuer": verifiable_credential.get("issuer", {}),
                        "type": verifiable_credential.get(
                            "type", ["VerifiableCredential"]
                        ),
                        "@context": verifiable_credential.get(
                            "@context", ["https://www.w3.org/2018/credentials/v1"]
                        ),
                        "issuanceDate": verifiable_credential.get("issuanceDate", ""),
                        "proof": {"type": "JwtProof2020", "jwt": credential_jwt},
                    }
                ],
                "holder": holder_did,
                "verifier": [
                    "did:ethr:blackgate:0x0296682f5bdad65fddd218171cf8dc20fb96978a244b4ebd91058e9a7838747c6e"
                ],
                "type": ["VerifiablePresentation"],
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "expirationDate": datetime.fromtimestamp(jwt_payload["exp"]).isoformat()
                + "Z",
                "proof": {"type": "JwtProof2020", "jwt": jws_token},
                "smt_proofs": smt_proofs,  # Include SMT proofs
            }

            metrics.vp_gen_time = time.time() - vp_gen_start

            # Create partial times for verification
            partial_times = {
                "wallet_gen_time": metrics.wallet_gen_time,
                "wallet_enc_time": metrics.wallet_enc_time,
                "network_info_time": metrics.network_info_time,
                "smt_local_add_time": metrics.smt_local_add_time,
                "vc_issuance_time": poll_data.get("vc_issuance_time", 0.0),
                "smt_onchain_add_time": poll_data.get("smt_onchain_add_time", 0.0),
                "vp_gen_time": metrics.vp_gen_time,
                "client_register_total_time": metrics.registration_end_time
                - metrics.registration_start_time,
                "vp_verify_time": 0.0,
                "vc_verify_time": 0.0,
                "smt_local_verify_time": 0.0,
                "smt_onchain_verify_time": 0.0,
                "smt_proof_gen_time": 0.0,
                "smt_on_server_verify_time": 0.0,
                "smt_total_verify_time": 0.0,
            }

            # Call /verify endpoint
            verify_payload = {
                "verifiablePresentation": verifiable_presentation,
                "partial_times": partial_times,
            }

            response = await session.post(
                "/auth/v1/verify", json=verify_payload, timeout=self.timeout
            )

            metrics.verification_end_time = time.time()

            if response.status_code == 200:
                verify_data = response.json()
                # Extract timing data from verification response
                # Note: The actual implementation may return timing data differently
                metrics.success = True
                logger.info(f"User {metrics.did_str} verified successfully")
            else:
                metrics.error_message = (
                    f"Verification failed: {response.status_code} - {response.text}"
                )
                logger.error(
                    f"Verification failed for {metrics.did_str}: {metrics.error_message}"
                )

            return metrics

        except Exception as e:
            metrics.error_message = f"Verification exception: {str(e)}"
            logger.error(f"Verification exception for {metrics.did_str}: {str(e)}")
            return metrics

    async def process_single_user(
        self, session: httpx.AsyncClient, user_id: str
    ) -> UserMetrics:
        """Complete registration and verification process for a single user."""
        total_start = time.time()

        # Register user
        metrics = await self.register_user(session, user_id)
        if metrics.error_message:
            return metrics

        try:
            # Poll for completion
            poll_data = await self.poll_user_status(session, metrics.did_str)
            metrics.vc_issuance_time = poll_data.get("vc_issuance_time", 0.0)
            metrics.smt_onchain_add_time = poll_data.get("smt_onchain_add_time", 0.0)

            # Verify user
            metrics = await self.verify_user(session, metrics, poll_data)

        except Exception as e:
            metrics.error_message = f"Process exception: {str(e)}"
            logger.error(f"Process exception for user {user_id}: {str(e)}")

        metrics.total_process_time = time.time() - total_start
        return metrics


class LoadTestRunner:
    """Main class for running parallel load tests."""

    def __init__(self, base_url: str = "http://localhost:8000", db_url: str = None):
        self.client = PerformanceTestClient(base_url)
        self.db_url = db_url

    async def run_load_test(
        self, num_users: int, max_concurrent: int = 50
    ) -> LoadTestResult:
        """Run a parallel load test with the specified number of users."""
        logger.info(
            f"Starting load test with {num_users} users, max concurrent: {max_concurrent}"
        )

        test_start_time = time.time()
        user_metrics: List[UserMetrics] = []
        errors: List[str] = []

        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_user_with_semaphore(user_id: str) -> UserMetrics:
            async with semaphore:
                async with await self.client.create_session() as session:
                    return await self.client.process_single_user(session, user_id)

        # Create tasks for all users
        tasks = [process_user_with_semaphore(str(i)) for i in range(num_users)]

        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                error_msg = f"Task exception: {str(result)}"
                errors.append(error_msg)
                logger.error(error_msg)
            elif isinstance(result, UserMetrics):
                user_metrics.append(result)
                if result.error_message:
                    errors.append(result.error_message)

        test_end_time = time.time()
        test_duration = test_end_time - test_start_time

        # Store metrics in database if available
        if self.db_url:
            await self.store_metrics_in_db(user_metrics)

        # Calculate statistics
        return self._calculate_test_results(
            user_metrics, errors, test_duration, num_users
        )

    def _calculate_test_results(
        self,
        user_metrics: List[UserMetrics],
        errors: List[str],
        test_duration: float,
        total_users: int,
    ) -> LoadTestResult:
        """Calculate aggregated test results."""
        successful_users = len([m for m in user_metrics if m.success])
        failed_users = len(user_metrics) - successful_users

        if successful_users > 0:
            successful_metrics = [m for m in user_metrics if m.success]

            reg_times = [
                m.registration_end_time - m.registration_start_time
                for m in successful_metrics
                if m.registration_end_time > 0
            ]
            ver_times = [
                m.verification_end_time - m.verification_start_time
                for m in successful_metrics
                if m.verification_end_time > 0
            ]
            total_times = [
                m.total_process_time
                for m in successful_metrics
                if m.total_process_time > 0
            ]

            avg_registration_time = sum(reg_times) / len(reg_times) if reg_times else 0
            avg_verification_time = sum(ver_times) / len(ver_times) if ver_times else 0
            avg_total_time = sum(total_times) / len(total_times) if total_times else 0

            min_total_time = min(total_times) if total_times else 0
            max_total_time = max(total_times) if total_times else 0

            # Calculate percentiles
            sorted_times = sorted(total_times) if total_times else [0]
            percentile_95_time = (
                sorted_times[int(0.95 * len(sorted_times))] if sorted_times else 0
            )
            percentile_99_time = (
                sorted_times[int(0.99 * len(sorted_times))] if sorted_times else 0
            )
        else:
            avg_registration_time = avg_verification_time = avg_total_time = 0
            min_total_time = max_total_time = percentile_95_time = (
                percentile_99_time
            ) = 0

        throughput_per_second = (
            successful_users / test_duration if test_duration > 0 else 0
        )
        error_rate = failed_users / total_users if total_users > 0 else 0

        return LoadTestResult(
            total_users=total_users,
            successful_users=successful_users,
            failed_users=failed_users,
            test_duration=test_duration,
            avg_registration_time=avg_registration_time,
            avg_verification_time=avg_verification_time,
            avg_total_time=avg_total_time,
            min_total_time=min_total_time,
            max_total_time=max_total_time,
            percentile_95_time=percentile_95_time,
            percentile_99_time=percentile_99_time,
            throughput_per_second=throughput_per_second,
            error_rate=error_rate,
            user_metrics=user_metrics,
            errors=errors,
        )

    async def store_metrics_in_db(self, user_metrics: List[UserMetrics]):
        """Store individual user metrics in the times_of_time table."""
        if not self.db_url:
            logger.warning("No database URL provided, skipping metrics storage")
            return

        try:
            async with await asyncio.to_thread(psycopg.connect, self.db_url) as conn:
                async with conn.cursor() as cur:
                    query = """
                        INSERT INTO times_of_time (
                            did_str, wallet_gen_time, wallet_enc_time, network_info_time,
                            smt_local_add_time, vc_issuance_time, smt_onchain_add_time,
                            vp_gen_time, client_register_total_time, vp_verify_time,
                            vc_verify_time, smt_local_verify_time, smt_onchain_verify_time,
                            smt_proof_gen_time, smt_on_server_verify_time, smt_total_verify_time
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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

                    for metrics in user_metrics:
                        if metrics.success:  # Only store successful completions
                            await cur.execute(
                                query,
                                (
                                    metrics.did_str,
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

                    await conn.commit()
                    logger.info(
                        f"Stored {len([m for m in user_metrics if m.success])} user metrics in database"
                    )

        except Exception as e:
            logger.error(f"Failed to store metrics in database: {str(e)}")


def generate_load_test_report(result: LoadTestResult, output_file: str = None) -> str:
    """Generate a comprehensive load test report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""
# Load Test Report - {timestamp}

## Test Summary
- **Total Users**: {result.total_users}
- **Successful Users**: {result.successful_users}
- **Failed Users**: {result.failed_users}
- **Success Rate**: {((result.successful_users / result.total_users) * 100):.2f}%
- **Test Duration**: {result.test_duration:.2f} seconds
- **Throughput**: {result.throughput_per_second:.2f} users/second

## Performance Metrics
- **Average Registration Time**: {result.avg_registration_time:.3f}s
- **Average Verification Time**: {result.avg_verification_time:.3f}s
- **Average Total Time**: {result.avg_total_time:.3f}s
- **Minimum Total Time**: {result.min_total_time:.3f}s
- **Maximum Total Time**: {result.max_total_time:.3f}s
- **95th Percentile**: {result.percentile_95_time:.3f}s
- **99th Percentile**: {result.percentile_99_time:.3f}s

## Detailed Timing Breakdown (Successful Users)
"""

    if result.successful_users > 0:
        successful_metrics = [m for m in result.user_metrics if m.success]

        # Calculate averages for each metric
        avg_wallet_gen = sum(m.wallet_gen_time for m in successful_metrics) / len(
            successful_metrics
        )
        avg_wallet_enc = sum(m.wallet_enc_time for m in successful_metrics) / len(
            successful_metrics
        )
        avg_network_info = sum(m.network_info_time for m in successful_metrics) / len(
            successful_metrics
        )
        avg_smt_local_add = sum(m.smt_local_add_time for m in successful_metrics) / len(
            successful_metrics
        )
        avg_vc_issuance = sum(m.vc_issuance_time for m in successful_metrics) / len(
            successful_metrics
        )
        avg_smt_onchain_add = sum(
            m.smt_onchain_add_time for m in successful_metrics
        ) / len(successful_metrics)
        avg_vp_gen = sum(m.vp_gen_time for m in successful_metrics) / len(
            successful_metrics
        )

        report += f"""
- **Wallet Generation Time**: {avg_wallet_gen:.4f}s
- **Wallet Encryption Time**: {avg_wallet_enc:.4f}s
- **Network Info Time**: {avg_network_info:.4f}s
- **SMT Local Add Time**: {avg_smt_local_add:.4f}s
- **VC Issuance Time**: {avg_vc_issuance:.4f}s
- **SMT Onchain Add Time**: {avg_smt_onchain_add:.4f}s
- **VP Generation Time**: {avg_vp_gen:.4f}s
"""

    if result.errors:
        report += f"\n## Errors ({len(result.errors)} total)\n"
        error_counts = {}
        for error in result.errors:
            error_type = error.split(":")[0] if ":" in error else "Unknown"
            error_counts[error_type] = error_counts.get(error_type, 0) + 1

        for error_type, count in error_counts.items():
            report += f"- **{error_type}**: {count} occurrences\n"

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        logger.info(f"Report saved to {output_file}")

    return report
