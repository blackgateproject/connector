import hashlib
import json
import os
import pickle
from functools import lru_cache
from typing import Annotated

import requests
from fastapi import Depends
from supabase import Client, create_client

from app.core.config import Settings

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

    def _hash_user_data(self, user_id, credentials):
        return hashlib.sha256(f"{user_id}|{credentials}".encode()).hexdigest()

    def add_user(self, user_id, credentials):
        # print(f"[SMT->add_user()]: (DEBUG) Entered add_user for {user_id}")
        try:
            key, current_hash = self.smt.add_user_auto(
                f"{user_id}|{credentials}")
            # print(f"[SMT->add_user()]: User {user_id} added. Current root: {self.smt.get_root().hex()}")
            # stuff = self._store_tree()
            # proof = self.smt.generate_proof(int(user_id))
            data = {
                # "_store_tree()": stuff,
                "index": str(key),
                "userHash": current_hash.hex(),
                # "proof": json.dumps(
                # "proof": 
                #     [(sibling.hex(), is_right) for sibling, is_right in proof]
                # ),
            }
            # print(f"[SMT->add_user()]: Tree stored. Data: {data}")
            return data
        except Exception as e:
            print(f"[SMT->add_user() ERROR]: {e}")
            raise

    def verify_user(self, user_id, key,credentials):
        # key = int.from_bytes(key.encode(), "big")
        # Expected method should be to use the user hash and the key + proof for verification
        proof = self.smt.generate_proof(int(key))
        root = self.smt.get_root()
        return self.smt.verify_proof(int(key), f"{user_id}|{credentials}", proof, root)

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

    def get_root(self):
        return self.smt.get_root().hex()

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
