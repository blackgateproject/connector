"""
Authentication service for handling user registration and verification.
"""

import json
import time
from typing import Any, Dict, Optional

from fastapi.responses import JSONResponse

from ..credential_service.credservice import issue_credential
from ..models.web3_creds import FormData, NetworkInfo
from ..utils.pscopg_utils import execute_query, fetch_all, fetch_one
from ..utils.web3_utils import addUserToSMTLocal
from .base_service import BaseService


class AuthService(BaseService):
    """Service for authentication-related operations."""

    def check_revoked_status(self, did: str) -> Optional[Dict[str, Any]]:
        """Check if DID is revoked."""
        try:
            check_query = 'SELECT "isRevoked" FROM requests WHERE did_str = %s'
            result = fetch_one(check_query, (did,))
            if result and result.get("isRevoked", False):
                return self.create_error_response(
                    "This DID has been revoked and cannot register again."
                )
        except Exception as e:
            return self.create_error_response(
                "Internal error checking revoked status.", e
            )
        return None

    def should_auto_approve(self, form_data: FormData) -> bool:
        """Determine if request should be auto-approved."""
        return form_data.testMode or form_data.selected_role == "device"

    def add_user_to_smt(self, did: str) -> tuple[Dict[str, Any], float]:
        """Add user to Sparse Merkle Tree locally."""
        self.log_debug(f"Adding user to SMT locally for DID: {did}")
        start_time = time.time()
        zkp_data = addUserToSMTLocal(did_str=did)
        smt_local_add_time = float(time.time() - start_time)
        return zkp_data, smt_local_add_time

    def prepare_request_data(
        self, form_data: FormData, network_info: NetworkInfo, request_status: str
    ) -> Dict[str, Any]:
        """Prepare data for database insertion."""
        total_time = form_data.walletCreateTime + form_data.walletEncryptTime

        return {
            "did_str": form_data.did,
            "form_data": form_data.model_dump_json(),
            "network_info": network_info.model_dump_json(),
            "request_status": request_status,
            "isVCSent": False,
            "wallet_generate_time": form_data.walletCreateTime,
            "total_time": total_time,
        }

    def register_user(
        self, form_data: FormData, network_info: NetworkInfo
    ) -> JSONResponse:
        """Handle user registration process."""
        self.log_debug(f"Received Data: {form_data.model_dump()}")
        self.log_debug(f"Received Data: {network_info.model_dump()}")

        # Check revoked status
        revoked_error = self.check_revoked_status(form_data.did)
        if revoked_error:
            return JSONResponse(content=revoked_error, status_code=403)

        # Determine request status
        if self.should_auto_approve(form_data):
            self.log_debug(f"Auto approving request for DID: {form_data.did}")
        request_status = (
            "approved" if self.should_auto_approve(form_data) else "pending"
        )

        # Initialize response data
        zkp_data = {}
        smt_local_add_time = 0

        # Add user to SMT if proof type is smt
        if form_data.proof_type == "smt":
            zkp_data, smt_local_add_time = self.add_user_to_smt(form_data.did)

        # Prepare and insert data
        request_data = self.prepare_request_data(
            form_data, network_info, request_status
        )

        try:
            query = """
                INSERT INTO requests (did_str, form_data, network_info, request_status, "isVCSent")
                VALUES (%(did_str)s, %(form_data)s, %(network_info)s, %(request_status)s, %(isVCSent)s)
            """
            execute_query(query, request_data)

            response_data = self.create_success_response(
                "Request added to DB",
                {
                    "zkpData": zkp_data,
                    "smt_local_add_time": smt_local_add_time,
                },
            )
            return JSONResponse(content=response_data, status_code=200)

        except Exception as e:
            error_response = self.create_error_response(
                "Error adding request to database", e
            )
            return JSONResponse(content=error_response, status_code=500)

    def get_request_by_did(self, did_str: str) -> Optional[Dict[str, Any]]:
        """Get request data by DID string."""
        try:
            query = "SELECT * FROM requests WHERE did_str = %s"
            rows = fetch_all(query, (did_str,))
            return rows[0] if rows else None
        except Exception as e:
            self.log_debug(f"Error fetching request: {e}")
            return None

    def parse_request_data(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and validate request data from database."""
        # Parse form_data
        if isinstance(request_data["form_data"], str):
            try:
                request_data["form_data"] = FormData.model_validate_json(
                    request_data["form_data"]
                )
            except Exception as e:
                self.log_debug(f"Error parsing form_data: {e}")
                request_data["form_data"] = json.loads(request_data["form_data"])
        elif isinstance(request_data["form_data"], dict):
            request_data["form_data"] = FormData.model_validate(
                request_data["form_data"]
            )

        # Parse network_info
        if isinstance(request_data["network_info"], str):
            try:
                request_data["network_info"] = NetworkInfo.model_validate_json(
                    request_data["network_info"]
                )
            except Exception as e:
                self.log_debug(f"Error parsing network_info: {e}")
                request_data["network_info"] = json.loads(request_data["network_info"])
        elif isinstance(request_data["network_info"], dict):
            request_data["network_info"] = NetworkInfo.model_validate(
                request_data["network_info"]
            )

        return request_data

    def poll_request_status(self, did_str: str) -> JSONResponse:
        """Poll request status for a given DID."""
        self.log_debug(f"Polling status for DID: {did_str}")

        request_data = self.get_request_by_did(did_str)
        if not request_data:
            error_response = self.create_error_response("No request found for this DID")
            return JSONResponse(content=error_response, status_code=404)

        # Check if revoked
        if request_data.get("isRevoked", True):
            error_response = self.create_error_response(
                "This DID has been revoked and cannot be verified or used."
            )
            error_response["request_status"] = "revoked"
            return JSONResponse(content=error_response, status_code=403)

        # Parse request data
        request_data = self.parse_request_data(request_data)

        # Handle approved requests that haven't been processed
        if (
            request_data["request_status"] == "approved"
            and not request_data["isVCSent"]
        ):
            # This would contain the credential issuance logic
            # For now, return the current status
            pass

        response_data = self.create_success_response(
            "Request status retrieved", {"request": request_data}
        )
        return JSONResponse(content=response_data, status_code=200)
