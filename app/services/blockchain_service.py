"""
Blockchain service for Web3 and cryptographic operations.
"""

from typing import Any, Dict

from fastapi.responses import JSONResponse

from ..utils.web3_utils import (
    addUserToAccumulator,
    addUserToMerkle,
    addUserToSMT,
    getBlockchainModulus,
    getContractZKsync,
    verifyUserOnAccumulator,
    verifyUserOnMerkle,
    verifyUserOnSMT,
)
from .base_service import BaseService


class BlockchainService(BaseService):
    """Service for blockchain and cryptographic operations."""

    def get_contract_info(self) -> JSONResponse:
        """Get contract information for testing."""
        try:
            # Retrieve and concatenate contract information
            contract_info = getContractZKsync("Merkle")
            contract_info += getContractZKsync("RSAAccumulator")

            return JSONResponse(content={"contract": contract_info}, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error fetching contract info", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def add_user_to_merkle(self, user_id: str, credentials: str) -> JSONResponse:
        """Add user to Merkle tree."""
        try:
            data = addUserToMerkle(user_id, credentials)
            success_response = self.create_success_response(
                "User added to merkle tree", {"data": data}
            )
            return JSONResponse(content=success_response, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error adding user to merkle tree", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def verify_user_on_merkle(self, merkle_hash: str) -> JSONResponse:
        """Verify user on Merkle tree."""
        try:
            self.log_debug(f"Verifying merkle hash: {merkle_hash}")
            result = verifyUserOnMerkle(merkle_hash)

            success_response = self.create_success_response(
                "User verified on merkle tree", {"results": result}
            )
            return JSONResponse(content=success_response, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error verifying user on merkle tree", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def add_user_to_smt(self, user_id: str, credentials: str) -> JSONResponse:
        """Add user to Sparse Merkle Tree."""
        try:
            self.log_debug(
                f"Adding user to SMT - ID: {user_id}, credentials: {credentials}"
            )
            data = addUserToSMT(user_id, credentials)

            success_response = self.create_success_response(
                "User added to SMT tree", {"data": data}
            )
            return JSONResponse(content=success_response, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error adding user to SMT tree", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def verify_user_on_smt(
        self, smt_hash: str, smt_key: str, smt_proof: str
    ) -> JSONResponse:
        """Verify user on Sparse Merkle Tree."""
        try:
            self.log_debug(f"Verifying SMT - Hash: {smt_hash}, Proof: {smt_proof}")
            result = verifyUserOnSMT(smt_hash, smt_key, smt_proof)

            message = (
                "User verified on SMT tree"
                if result.get("valid_Offchain")
                else "User not verified on SMT tree"
            )

            response_data = self.create_success_response(message, {"results": result})
            return JSONResponse(content=response_data, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error verifying user on SMT tree", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def add_user_to_accumulator(self, did_str: str, vc: str) -> JSONResponse:
        """Add user to accumulator."""
        try:
            data = addUserToAccumulator(did_str, vc)
            success_response = self.create_success_response(
                "User added to Accumulator successfully", {"data": data}
            )
            return JSONResponse(content=success_response, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error adding user to Accumulator", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def verify_user_on_accumulator(
        self, data_hash: str, acc_val: str, proof: str, prime: str
    ) -> JSONResponse:
        """Verify user on accumulator."""
        try:
            result = verifyUserOnAccumulator(
                dataHash=data_hash,
                accVal=acc_val,
                proof=proof,
                prime=prime,
            )

            message = (
                "User verified on Accumulator successfully"
                if result
                else "User not verified on Accumulator"
            )

            response_data = self.create_success_response(message, {"data": result})
            return JSONResponse(content=response_data, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error verifying user on Accumulator", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def get_accumulator_modulus(self) -> JSONResponse:
        """Get accumulator modulus."""
        try:
            data = getBlockchainModulus()
            return JSONResponse(content={"data": data}, status_code=200)
        except Exception as e:
            error_response = self.create_error_response(
                "Error getting accumulator modulus", e
            )
            return JSONResponse(content=error_response, status_code=500)
