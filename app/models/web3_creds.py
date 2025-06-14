from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from ..models.zkp import SMTMerkleProof


class FormData(BaseModel):
    """
    Represents the form data for a web3 credential.
    This is used to capture the data that will be included in the credential.
    """

    alias: str
    device_id: Optional[str] = None
    did: str
    firmware_version: Optional[str] = None
    proof_type: str
    selected_role: str
    testMode: Optional[bool] = None
    walletCreateTime: Optional[float] = 0
    walletEncryptTime: Optional[float] = 0


# Might have to change this to suit other ZKP types
class ZKP(BaseModel):
    userHash: str
    userIndex: str
    merkleRoot: str


class NetworkInfo(BaseModel):
    ip_address: str
    user_agent: str
    location_lat: float
    location_long: float
    user_language: str


class Issuer(BaseModel):
    id: str


class Proof(BaseModel):
    type: str
    jwt: str


class CredentialSubject(BaseModel):
    ZKP: ZKP
    networkInfo: Optional[NetworkInfo] = None
    did: str
    alias: str
    proof_type: str
    selected_role: str
    firmware_version: str
    testMode: Optional[bool] = None
    device_id: Optional[str] = None
    walletCreateTime: Optional[float] = 0
    walletEncryptTime: Optional[float] = 0


class VerifiableCredential(BaseModel):
    credentialSubject: CredentialSubject
    issuer: Issuer
    type: List[str]
    context_: List[str] = Field(..., alias="@context")
    issuanceDate: str
    proof: Proof

    class Config:
        validate_by_name = True

    def serialize(self, **kwargs) -> Dict:
        """Convert the VerifiablePresentation to a JSON-serializable dict."""
        return self.model_dump(by_alias=True, exclude_none=True, **kwargs)


class VerifiablePresentation(BaseModel):
    iat: int
    nbf: int
    issuanceDate: str
    nonce: str
    verifiableCredential: List[VerifiableCredential]
    holder: str
    verifier: List[str]
    type: List[str]
    context_: List[str] = Field(..., alias="@context")
    expirationDate: str
    proof: Proof
    smt_proofs: Optional[SMTMerkleProof] = None

    class Config:
        validate_by_name = True

    def serialize(self, **kwargs) -> Dict:
        """Convert the VerifiablePresentation to a JSON-serializable dict."""
        return self.model_dump(by_alias=True, exclude_none=True, **kwargs)
