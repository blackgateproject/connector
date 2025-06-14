import base64
import hashlib
import random
import time
from typing import List

from pydantic import BaseModel


class MerkleProofElement(BaseModel):
    sibling_hash: str  # base64 encoded hash
    is_right: bool


class SMTMerkleProof(BaseModel):
    key: int
    proof: List[MerkleProofElement]
