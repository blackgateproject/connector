import hashlib
import json
import os
import pickle
from functools import lru_cache
from typing import Annotated

import requests
from app.core.config import Settings
from fastapi import Depends
from supabase import Client, create_client

from ..models.zkp import MerkleProofElement, SMTMerkleProof

# from SMT import SparseMerkleTree  # Your SMT class
from ..utils.sparseMerkle_utils import sparseMerkleTreeUtils


@lru_cache
def get_settings():
    return Settings()


settings_dependency = Annotated[Settings, Depends(get_settings)]


SUPABASE_URL = settings_dependency().SUPABASE_URL
SUPABASE_AUTH_ANON_KEY = settings_dependency().SUPABASE_AUTH_ANON_KEY


# ./SMTHandler.py
# class SparseRollupGenerator:
class sparseMerkleTree:
    def __init__(self):
        # self.supabase: Client = create_client(supabase_url=SUPABASE_URL, supabase_key=SUPABASE_AUTH_ANON_KEY)
        self.smt = sparseMerkleTreeUtils(depth=16)
        print(f"[CORE] SMT Initialized. \n{type(self.smt)}")

    def _hash_user_data(self, user_id, credentials) -> str:
        return hashlib.sha256(f"{user_id}|{credentials}".encode()).hexdigest()

    def add_user(self, did_str, credentials):
        # print(f"[SMT->add_user()]: (DEBUG) Entered add_user for {did_str}")
        try:
            # Parse out the prefix "did:ethr:blackgate:0x" from the did_str
            print(f"[SMT->add_user()]: (DEBUG) Adding user: \n\tDID: {did_str}\n\tCredentials: {credentials}")
            key, current_hash = self.smt.add_user_auto(f"{did_str}|{credentials}")
            # print(f"[SMT->add_user()]: User {did_str} added. Current root: {self.smt.get_root().hex()}")
            # stuff = self._store_tree()
            proof = self.smt.generate_proof(key)
            data = {
                "index": str(key),
                "userHash": current_hash.hex(),
                "root": self.smt.get_root().hex(),
            }
            # print(f"[SMT->add_user()]: Tree stored. Data: {data}")
            return data, proof.model_dump(mode="json")
        except Exception as e:
            print(f"[SMT->add_user() ERROR]: {e}")
            raise

    def verify_user(self, user_id: str, credentials, provided_proof: SMTMerkleProof):
        print(f"[SMT->verify_user()]: (DEBUG) Verifying user {user_id}")
        print(f"[SMT->verify_user()]: (DEBUG) Credentials: {credentials}")
        print(f"[SMT->verify_user()]: (DEBUG) Provided proof: {provided_proof.model_dump(mode='json')}")

        # Deserialize the JSON proof into MerkleProof object
        if isinstance(provided_proof, str):
            print(f"[SMT->verify_user()]: (DEBUG) Provided proof is a str, converting to SMTMerkleProof")
            provided_proof = SMTMerkleProof.model_validate_json(provided_proof)
        elif isinstance(provided_proof, dict):
            print(f"[SMT->verify_user()]: (DEBUG) Provided proof is a dict, converting to SMTMerkleProof")
            provided_proof = SMTMerkleProof(**provided_proof)
        else:
            print(f"[SMT->verify_user()]: (DEBUG) Provided proof is already an SMTMerkleProof instance")
            print(f"[SMT->verify_user()]: (DEBUG) Proof Type: {type(provided_proof)}")

        value_raw = f"{user_id}|{credentials}"
        key = provided_proof.key
        print(f"[SMT->verify_user()]: (DEBUG) Key from proof: {key}")
        root_hash = self.smt.get_root()
        if self.smt.verify_proof(value_raw=value_raw, proof=provided_proof, root_hash=root_hash):
            return True, provided_proof
        

        # Fallback verification
        if key in self.smt.used_indexes:
            print(f"[SMT->verify_user()]: (DEBUG) User ID found in used indexes, using fallback verification")
            fresh_proof = self.smt.generate_proof(key=key)
            if self.smt.verify_proof(value_raw=value_raw, proof=fresh_proof, root_hash=root_hash):
                return True, fresh_proof
        print(f"[SMT->verify_user()]: (DEBUG) SMT Proof Verification failed for user {user_id}")
        print(f"[SMT->verify_user()]: (DEBUG) Fallback Indexes: {self.smt.used_indexes}")
        return False, provided_proof

    def update_user(self, user_id, new_credentials):
        self.smt.update_with_key(user_id, f"{user_id}|{new_credentials}")
        self._store_tree()

    def delete_user(self, user_id):
        self.smt.delete(user_id)
        self._store_tree()

    def _store_tree(self):
        serialized_tree = self.smt.serialize()
        root_hash = self.smt.get_root().hex()
        data_entry = {
            "id": "main_tree",
            "tree_data": serialized_tree,
            "root": root_hash,
        }
        # self.supabase.table("smt_store").upsert(data_entry).execute()

        # Awais:: added return statement
        return data_entry

    # def load_tree(self):
    #     response = (
    #         self.supabase.table("smt_store")
    #         .select("tree_data")
    #         .eq("id", "main_tree")
    #         .limit(1)
    #         .execute()
    #     )
    #     if response.data:
    #         tree_data = response.data[0]["tree_data"]
    #         self.smt = sparseMerkleTreeUtils.deserialize(tree_data)

    def get_root(self) -> str:
        return self.smt.get_root().hex()

    def print_tree(self):
        self.smt.print_tree()

    def save_tree_to_file(self, filename):
        """Save the Merkle tree to a file."""
        print(f"[CORE] SMT Print. {self.smt.serialize()}")
        with open(filename, "wb") as file:
            pickle.dump(self.smt, file)

    @staticmethod
    def load_tree_from_file(filename):
        """Load the Merkle tree from a file."""
        if os.path.exists(filename):
            if os.path.getsize(filename) > 0:  # Ensure the file is not empty
                try:
                    with open(filename, "rb") as file:
                        smt = pickle.load(file)
                        if isinstance(
                            smt, sparseMerkleTreeUtils
                        ):  # Check if it's the tree utils only
                            new_instance = sparseMerkleTree()
                            new_instance.smt = smt  # Assign the loaded tree
                            return new_instance
                        elif isinstance(
                            smt, sparseMerkleTree
                        ):  # If already the correct type
                            return smt
                except (EOFError, pickle.UnpicklingError):
                    print(
                        f"[ERROR] Corrupted or unreadable file: {filename}. Please regenerate it."
                    )
                    return sparseMerkleTree()
            else:
                print(f"[ERROR] File {filename} is empty.")
                return sparseMerkleTree()
        else:
            print(f"[ERROR] File {filename} does not exist.")
            return sparseMerkleTree()


# Load merkle tree from file if it exists
smt_file = "smt.pkl"
if os.path.exists(smt_file):
    smtCore = sparseMerkleTree.load_tree_from_file(smt_file)
else:
    smtCore = sparseMerkleTree()
