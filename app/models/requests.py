from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field
from sqlmodel import Field, SQLModel


class HashProof(BaseModel):
    """
    HashProof model for the request body.
    :param did: The DID of the user. Type str.
    :param merkleHash: The hash of the user. Type str.
    # :param merkleProof: The proof of the user. Type list[list[str]].
    """

    did: str
    merkleHash: str
    # merkleProof: list[list[str]]


class MerkleInput(BaseModel):
    """
    MerkleInput model for the request body.
    """

    user_id: str
    credentials: dict
