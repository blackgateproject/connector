import base64
import hashlib
import random
import time

from ..models.zkp import MerkleProofElement, SMTMerkleProof


# ./SMT.py
class sparseMerkleTreeUtils:
    def __init__(self, depth=32):  # Depth 16 can handle up to 65,536 unique keys
        self.depth = depth
        self.nodes = {}
        self.default_hashes = self._precompute_default_hashes()
        self.used_indexes = set()

    def _precompute_default_hashes(self) -> list:
        hashes = []
        h = hashlib.sha256(b"empty").digest()
        for _ in range(self.depth + 1):
            hashes.append(h)
            h = hashlib.sha256(h + h).digest()
        return hashes

    def _hash(self, left, right) -> bytes:
        return hashlib.sha256(left + right).digest()

    def _get_node(self, position, level):
        return self.nodes.get((position, level), self.default_hashes[level])

    def _index_to_position(self, index) -> int:
        key_bin = bin(index)[2:].zfill(self.depth)
        return int(key_bin, 2)

    def _find_smallest_empty_index(self) -> int:
        index = 0
        while index in self.used_indexes:
            index += 1
        return index

    def add_user_auto(self, value_raw):
        """Add user at the smallest empty index."""
        index = self._find_smallest_empty_index()
        return self.update_with_key(index, value_raw)

    def update_with_key(self, key, value_raw):
        """Manually update or insert at a specified key."""
        pos = self._index_to_position(key)
        self.used_indexes.add(key)

        value_hash = hashlib.sha256(value_raw.encode()).digest()
        self.nodes[(pos, self.depth)] = value_hash

        current_hash = value_hash
        for level in reversed(range(self.depth)):
            is_right = pos % 2
            sibling_pos = pos - 1 if is_right else pos + 1
            sibling_hash = self._get_node(sibling_pos, level + 1)

            if is_right:
                current_hash = self._hash(sibling_hash, current_hash)
            else:
                current_hash = self._hash(current_hash, sibling_hash)

            pos //= 2
            self.nodes[(pos, level)] = current_hash

        return key, current_hash

    def delete(self, key):
        """Delete a value at a given key (set it to default hash)."""
        if key not in self.used_indexes:
            raise ValueError("Key not found in the tree.")

        pos = self._index_to_position(key)
        value_hash = self.default_hashes[self.depth]
        self.nodes[(pos, self.depth)] = value_hash
        self.used_indexes.remove(key)

        current_hash = value_hash
        for level in reversed(range(self.depth)):
            is_right = pos % 2
            sibling_pos = pos - 1 if is_right else pos + 1
            sibling_hash = self._get_node(sibling_pos, level + 1)

            if is_right:
                current_hash = self._hash(sibling_hash, current_hash)
            else:
                current_hash = self._hash(current_hash, sibling_hash)

            pos //= 2
            self.nodes[(pos, level)] = current_hash

        return key, current_hash

    def get_root(self):
        return self._get_node(0, 0)

    def generate_proof(self, key) -> SMTMerkleProof:
        pos = self._index_to_position(key)
        proof = []

        for level in reversed(range(self.depth)):
            is_right = pos % 2
            sibling_pos = pos - 1 if is_right else pos + 1
            sibling_hash = self._get_node(sibling_pos, level + 1)
            proof.append(
                MerkleProofElement(
                    sibling_hash=base64.b64encode(sibling_hash).decode(),
                    is_right=is_right,
                )
            )
            pos //= 2

        return SMTMerkleProof(key=key, proof=proof)

    def verify_proof(self, key, value_raw, proof: SMTMerkleProof, root_hash):
        value_hash = hashlib.sha256(value_raw.encode()).digest()
        current_hash = value_hash

        for element in proof.proof:
            sibling_hash = base64.b64decode(element.sibling_hash)
            if element.is_right:
                current_hash = hashlib.sha256(sibling_hash + current_hash).digest()
            else:
                current_hash = hashlib.sha256(current_hash + sibling_hash).digest()

        return current_hash == root_hash

    def serialize(self):
        """Convert the SMT to a JSON-serializable dict."""
        return {
            "depth": self.depth,
            "nodes": {
                f"{pos},{level}": base64.b64encode(node_hash).decode()
                for (pos, level), node_hash in self.nodes.items()
            },
            "default_hashes": [
                base64.b64encode(h).decode() for h in self.default_hashes
            ],
        }

    @classmethod
    def deserialize(cls, data):
        """Recreate SMT from serialized data."""
        tree = cls(depth=data["depth"])
        tree.nodes = {
            tuple(map(int, key.split(","))): base64.b64decode(value)
            for key, value in data["nodes"].items()
        }
        tree.default_hashes = [base64.b64decode(h) for h in data["default_hashes"]]
        return tree
