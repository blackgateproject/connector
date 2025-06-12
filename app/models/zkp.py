import hashlib
import random
import time
import base64
from pydantic import BaseModel
from typing import List


class MerkleProofElement(BaseModel):
    sibling_hash: str  # base64 encoded hash
    is_right: bool


class MerkleProof(BaseModel):
    key: int
    proof: List[MerkleProofElement]
