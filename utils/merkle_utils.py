import hashlib


class merkleTreeUtils:
    def __init__(self):
        self.leaves = []
        self.tree = []

    def hash(self, data):
        """Generate a SHA-256 hash for the given data."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def add_leaf(self, data):
        """Add a new leaf to the Merkle Tree and rebuild the tree."""
        self.leaves.append(self.hash(data))
        self._build_tree()

    def delete_leaf(self, data):
        """Delete a leaf from the Merkle Tree and rebuild."""
        hashed_data = self.hash(data)
        if hashed_data in self.leaves:
            self.leaves.remove(hashed_data)
            self._build_tree()
        else:
            raise ValueError("Data not found in the tree.")

    def _build_tree(self):
        """Build the Merkle Tree from the leaves."""
        # Hash each leaf first
        nodes = self.leaves[:]
        tree = [nodes]  # Start the tree with Level 0 (leaves)

        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    combined_hash = self.hash(nodes[i] + nodes[i + 1])
                else:
                    combined_hash = self.hash(
                        nodes[i] + nodes[i]
                    )  # Duplicate unpaired node
                next_level.append(combined_hash)
            nodes = next_level
            tree.append(nodes)

        # Special case: Single leaf (hash with itself to create root)
        if len(tree[0]) == 1:  # Only one node in Level 0
            root = self.hash(nodes[0] + nodes[0])  # Hash the single node with itself
            tree.append([root])

        self.tree = tree

    def get_root(self):
        """Return the Merkle root."""
        # print(self.tree[-1][0])
        return self.tree[-1][0] if self.tree else None

    def get_proof(self, data):

        hashed_data = data

        if hashed_data not in self.leaves:
            raise ValueError("Data not found in the tree.")

        proof = []
        index = self.leaves.index(hashed_data)

        # If there is only one leaf, proof is just its own hash on either side
        if len(self.leaves) == 1:
            proof.append((hashed_data, "right"))  # or "left", depending on preference
            return proof

        # # If the total number of leaves is odd and this is the last node
        # if len(self.leaves) % 2 == 1 and index == len(self.leaves) - 1:
        #     proof.append(
        #         (hashed_data, "right")
        #     )  # Hash itself first before the normal process

        # Standard proof generation for multiple leaves
        for level in self.tree[:-1]:
            # Check if index is at the last node of an odd-numbered level
            if len(level) % 2 == 1 and index == len(level) - 1:
                proof.append((level[index], "right"))  # Last node hashes with itself

            is_right = index % 2
            pair_index = index - 1 if is_right else index + 1

            if pair_index < len(level):
                proof.append((level[pair_index], "left" if is_right else "right"))

            index //= 2

        return proof

    def print_tree(self):
        """Print the Merkle Tree in a readable format."""
        print("Merkle Tree Structure:")
        for level, nodes in enumerate(self.tree):
            print(f"Level {len(self.tree) - level - 1}: {nodes}")

    def verify_proof(self, leaf_data, proof, root):
        """
        Verify a Merkle proof for a given leaf data.
        Args:
            leaf_data (str): The original data (e.g., "user123|password123").
            proof (list): A list of tuples, where each tuple contains a hash and its direction ('left' or 'right').
            root (str): The expected Merkle root.
        Returns:
            bool: True if the proof is valid, False otherwise.
        """
        computed_hash = leaf_data  # Start with the hash of the leaf data

        for sibling_hash, direction in proof:
            if direction == "left":
                computed_hash = self.hash(sibling_hash + computed_hash)
            elif direction == "right":
                computed_hash = self.hash(computed_hash + sibling_hash)
            else:
                raise ValueError(
                    "Invalid direction in proof. Must be 'left' or 'right'."
                )

        # Compare the computed hash with the expected root
        return computed_hash == root
