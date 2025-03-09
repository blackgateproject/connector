import os
import pickle

from multiproof.standard import LeafValue, StandardMerkleTree, StandardMerkleTreeData

from ..utils.merkle_utils import merkleTreeUtils


# class merkleClass:
#     """
#     Class based on multiproof, python port of openzeppelin's merkle tree
#     NOTE:: does not include methods to add or remove leaves, just to create one from data
#     """

    # def __init__(self):
    #     # Initialize the Merkle tree
    #     # Test code
    #     values = [
    #         [
    #             "did:ethr:0xb46CAD0D8F7526695aA1aD3e94d1464860D0a7e6",
    #             '{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/ns/did/v1"],"type":["VerifiableCredential"],"credentialSubject":{"id":"did:example:123"},"issuer":"did:ethr:0xb46CAD0D8F7526695aA1aD3e94d1464860D0a7e6","issuanceDate":"2025-03-09T05:09:56.063Z","proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:ethr:0xb46CAD0D8F7526695aA1aD3e94d1464860D0a7e6#controller","created":"2025-03-09T05:09:56.064Z","jws":"eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..Vp-fE7vGIZ72x_dVkYkPhl_btsr4wwuIbhykP-Cm4gpjco3gf8BFqXZgJT0d2DVepVEuPZHCLCKi1zYPtqP3pg"}}',
    #         ],
    #         [
    #             "did:ethr:0xb46CAD0D8F7526695aA1aD3e94d1464860D0a7e2",
    #             '{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/ns/did/v1"],"type":["VerifiableCredential"],"credentialSubject":{"id":"did:example:123"},"issuer":"did:ethr:0xb46CAD0D8F7526695aA1aD3e94d1464860D0a7e6","issuanceDate":"2025-03-09T05:09:56.063Z","proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:ethr:0xb46CAD0D8F7526695aA1aD3e94d1464860D0a7e6#controller","created":"2025-03-09T05:09:56.064Z","jws":"eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..Vp-fE7vGIZ72x_dVkYkPhl_btsr4wwuIbhykP-Cm4gpjco3gf8BFqXZgJT0d2DVepVEuPZHCLCKi1zYPtqP3pg"}}',
    #         ],
    #     ]

    #     # Build the Merkle tree. Set the encoding to match the values.
    #     tree = StandardMerkleTree.of(values, ["string", "string"])
    #     print(f"[CORE] Merkle Tree Root: {tree.root}")
    #     # Print the tree structure
    #     print(f"[CORE] Merkle Tree Structure: \n{tree.to_json()}")

    #     print(f"[CORE] Merkle Tree Initialized.")

    #     # Generate proof for did:ethr:0xb46CAD0D8F7526695aA1aD3e94d1464860D0a7e6
    #     for i, leaf in enumerate(tree.values):
    #         if leaf.value[0] == "did:ethr:0xb46CAD0D8F7526695aA1aD3e94d1464860D0a7e6":
    #             proof = tree.get_proof(i)
    #             print(f"[CORE] Value: {leaf.value}")
    #             print(f"[CORE] Proof: {proof}")


class abdMerkleClass:
    def __init__(self):
        # Initialize Supabase client
        self.merkle_tree = merkleTreeUtils()
        self.merkle_tree = None
        print(f"[CORE] Merkle Tree Initialized.")

    def add_user(self, user_id, credentials):
        """Add a user to the Merkle Tree and create a hash entry in the proofs table."""
        data = f"{user_id}|{credentials}"
        hash_value = self.merkle_tree.hash(data)
        self.merkle_tree.add_leaf(data)
        proof = self.merkle_tree.get_proof(hash_value)

        data_entry = {
            "hash": hash_value,
            "proof": proof,  # Empty proof initially, will be updated in `_update_proofs`
        }
        # response = self.supabase.table("proofs").upsert(data_entry).execute()
        # if response.status_code != 200:
        #     raise Exception(
        #         f"Error creating hash entry for user {user_id}: {response.error}"
        #     )
        print(f"Hash entry created for user {user_id} with hash {hash_value}.")

        self._update_proofs()

        return data_entry

    def update_user(self, old_credentials, new_credentials):
        """Update a user's credentials in the Merkle Tree."""
        self.merkle_tree.delete_leaf(old_credentials)
        self.merkle_tree.add_leaf(new_credentials)
        self._update_proofs()

    def delete_user(self, credentials):
        """Delete a user from the Merkle Tree."""
        self.merkle_tree.delete_leaf(credentials)
        self._update_proofs()

    def _update_proofs(self):
        """Recalculate and store proofs for all leaves in the Merkle tree."""
        for leaf in self.merkle_tree.leaves:
            proof = self.merkle_tree.get_proof(leaf)
            self._store_proof(leaf, proof)
        print("All proofs updated and stored in Supabase.")

    def _store_proof(self, hash_value, proof):
        """Store or update a proof in the Supabase `proofs` table."""
        data = {"hash": hash_value, "proof": proof}
        # response = self.supabase.table("proofs").upsert(data).execute()
        print(f"Proof stored successfully for hash {hash_value}.")

    def print_tree(self):
        print(self.merkle_tree.print_tree())
        print(self.merkle_tree.tree)

    def getroot(self):
        return self.merkle_tree.get_root()

    # def getproof(self, hash_value):
    #     """Fetch proof from Supabase for a given hash."""
    # response = (
    #     self.supabase.table("proofs")
    #     .select("proof")
    #     .eq("hash", hash_value)
    #     .execute()
    # )

    # if response.data:
    #     print(response.data[0]["proof"])
    #     return response.data[0]["proof"]  # Return the proof if found
    # else:
    #     print(f"No proof found for hash {hash_value}.")
    #     return None  # Return None if proof does not exist

    def verify_proof(self, id, creds):
        """Verify a Merkle proof for a specific leaf and root."""
        data = f"{id}|{creds}"
        hash_value = self.merkle_tree.hash(data)
        valid = self.merkle_tree.verify_proof(
            hash_value, self.merkle_tree.get_proof(hash_value), self.getroot()
        )
        return valid

    # def _send_to_zksync(self):
    #     """Send the latest root to zkSync to generate a ZK-SNARK proof."""
    #     root = self.merkle_tree.get_root()
    #     data = {"merkle_root": root}
    #     response = requests.post(self.zk_sync_url, json=data)

    #     if response.status_code != 200:
    #         raise Exception(f"Error sending root to zkSync: {response.text}")

    #     print(f"zkSync Response: {response.json()}")
    def save_tree_to_file(self, filename):
        """Save the Merkle tree to a file."""
        with open(filename, "wb") as file:
            pickle.dump(self.merkle_tree, file)

    @staticmethod
    def load_tree_from_file(filename):
        """Load the Merkle tree from a file."""
        if os.path.exists(filename):
            with open(filename, "rb") as file:
                merkle_tree = pickle.load(file)
                print(f"[CORE] Merkle tree loaded from {filename}.")
                return merkle_tree
        else:
            print(f"File {filename} does not exist.")


# Load merkle tree from file if it exists
merkle_tree_file = "merkle_tree.pkl"
if os.path.exists(merkle_tree_file):
    merkleCore = abdMerkleClass.load_tree_from_file(merkle_tree_file)
else:
    merkleCore = abdMerkleClass()

# testClass = merkleClass()

# users = [
#     {"uuid": "1234567", "pw": "aqweqew"},
#     {"uuid": "1234123567", "pw": "aqw123eqew"},
#     {"uuid": "123452367", "pw": "22332"},
#     {"uuid": "231234123567", "pw": "aqw123eqe123w"},
#     {"uuid": "123452123367", "pw": "22331122"},
#     {"uuid": "123452123367", "pw": "22331122"},
#     {"uuid": "123452123367", "pw": "22331122"},
#     {"uuid": "123452123367", "pw": "22331122"},
# ]
# # Store the proofs for each user
# dataEntries = []

# for i, user in enumerate(users, start=1):
#     print(f"[MRK_TEST] Adding User{i}: {user['uuid']}")
#     # merkleCore.add_user(user["uuid"], user["pw"])
#     dataEntries.append(merkleCore.add_user(user["uuid"], user["pw"]))
#     print(f"[MRK_TEST] User{i} added successfully.")


# for i, user in enumerate(users, start=1):
#     print(f"[MRK_TEST] Verifying User{i}: {user['uuid']}")
#     valid = merkleCore.verify_proof(user["uuid"], user["pw"])
#     if valid:
#         print(f"[MRK_TEST] Proof for User{i} is valid.")
#     else:
#         print(f"[MRK_TEST] Proof for User{i} is invalid.")
