import base64
import hashlib
import random
import time
from typing import Dict, List, Optional

from pydantic import BaseModel


class MerkleProofElement(BaseModel):
    sibling_hash: str  # base64 encoded hash
    is_right: bool


class SMTMerkleProof(BaseModel):
    smt_proof_gen_time: Optional[float] = None
    key: int
    proof: List[MerkleProofElement]

    def serialize(self, **kwargs) -> Dict:
        """Convert the SMTMerkleProof to a JSON-serializable dict."""
        return self.model_dump(by_alias=True, exclude_none=True, **kwargs)
