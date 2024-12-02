from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field
from sqlmodel import Field, SQLModel


class LoginRequest(BaseModel):
    username: str
    password: str  # This field is still required for password-based users




class ChallengeRequest(BaseModel):
    address: str  # Ethereum address for the challenge


# SignRequest schema
class SignRequest(BaseModel):
    address: str
    message: str
    signature: str


class VerifyRequest(BaseModel):
    address: str  # Ethereum address
    message: str  # Message to be verified
    signature: str  # Signed message


class RegisterDID(BaseModel):
    user: str
    public_key: str


class IssueVC(BaseModel):
    holder: str
    credential_hash: str


class RevokeVC(BaseModel):
    holder: str
    credential_hash: str
