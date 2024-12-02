from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field
from sqlmodel import Field, SQLModel


class UserIdentity(BaseModel):
    id: UUID
    identity_id: UUID
    user_id: UUID
    identity_data: dict  # This can be expanded if specific fields are known, like email, phone_verified, etc.
    provider: str
    created_at: datetime
    last_sign_in_at: datetime
    updated_at: datetime


class User(BaseModel):
    id: UUID
    app_metadata: dict
    user_metadata: dict
    aud: str
    confirmation_sent_at: Optional[datetime]
    recovery_sent_at: Optional[datetime]
    email_change_sent_at: Optional[datetime]
    new_email: Optional[EmailStr]
    new_phone: Optional[str]
    invited_at: Optional[datetime]
    action_link: Optional[str]
    email: EmailStr
    phone: Optional[str]
    created_at: datetime
    confirmed_at: datetime
    email_confirmed_at: datetime
    phone_confirmed_at: Optional[datetime]
    last_sign_in_at: datetime
    role: str
    updated_at: datetime
    identities: List[UserIdentity]
    is_anonymous: bool
    factors: Optional[List[str]]


class Session(BaseModel):
    provider_token: Optional[str]
    provider_refresh_token: Optional[str]
    access_token: str
    refresh_token: str
    expires_in: int
    expires_at: int
    token_type: str
    user: User


# Models
class User1(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    username: str
    email: str
    phone: str
    password_hash: str
    public_key: str = Field(nullable=True)
    private_key: str = Field(nullable=True)
    blockchain_address: str = Field(nullable=True)
    role: str
    did: str = Field(nullable=True)
    access_token: str = Field(default=None, nullable=True)
    isPWLess: bool
    isOnline: bool


class LoginRequest(BaseModel):
    username: str
    password: str  # This field is still required for password-based users


class Token(BaseModel):
    access_token: str
    token_type: str


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
