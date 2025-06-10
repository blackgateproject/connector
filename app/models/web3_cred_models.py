from pydantic import BaseModel, Field
from typing import List, Dict, Optional

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


class WalletTimes(BaseModel):
    walletCreateTime: Optional[float] = None
    walletEncryptTime: Optional[float] = None


class CredentialSubject(BaseModel):
    did: str
    alias: int
    testMode: Optional[bool] = None
    device_id: Optional[int] = None
    proof_type: str
    walletTimes: WalletTimes
    selected_role: str
    firmware_version: str
    networkInfo: NetworkInfo
    ZKP: ZKP


class Issuer(BaseModel):
    id: str


class Proof(BaseModel):
    type: str
    jwt: str


class VerifiableCredential(BaseModel):
    credentialSubject: CredentialSubject
    issuer: Issuer
    type: List[str]
    context_: List[str] = Field(..., alias="@context")
    issuanceDate: str
    proof: Proof

    class Config:
        validate_by_name = True


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

    class Config:
        validate_by_name = True
